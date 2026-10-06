#![cfg_attr(feature = "test-support", allow(dead_code))]
//! The socket transports against a local WebSocket peer (LLP 0059.000
//! §3.12): upgrade, text frames (fragmented and extended-length), a ping, the
//! closing handshake, an over-limit frame, a binary frame, a refused
//! handshake, a connection dropped without a close, and an abort.
use super::*;
use crate::stdlib::abort::AbortController;
use std::net::TcpStream;
use std::sync::mpsc::{channel, Receiver, Sender};

/// A server frame (never masked).
fn frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![if fin { 0x80 } else { 0 } | opcode];
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n < 65536 => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// One client frame, unmasked: (fin, opcode, payload), or `None` at the end.
fn client_frame(s: &mut impl Read) -> Option<(bool, u8, Vec<u8>)> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).ok()?;
    assert!(head[1] & 0x80 != 0, "a client frame is masked");
    let len = match head[1] & 0x7f {
        126 => {
            let mut bytes = [0u8; 2];
            s.read_exact(&mut bytes).ok()?;
            u16::from_be_bytes(bytes) as usize
        }
        127 => {
            let mut bytes = [0u8; 8];
            s.read_exact(&mut bytes).ok()?;
            usize::try_from(u64::from_be_bytes(bytes)).ok()?
        }
        len => len as usize,
    };
    let mut mask = [0u8; 4];
    s.read_exact(&mut mask).ok()?;
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).ok()?;
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    Some((head[0] & 0x80 != 0, head[0] & 0x0f, payload))
}

/// A local peer; what it saw from the client arrives on the receiver.
pub fn peer() -> (u16, Receiver<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (saw, seen) = channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let (stream, saw) = (stream.unwrap(), saw.clone());
            std::thread::spawn(move || serve(stream, saw));
        }
    });
    (port, seen)
}

fn serve(mut s: TcpStream, saw: Sender<String>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let path = head.split(' ').nth(1).unwrap_or("").to_string();
    if path == "/refuse" {
        let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        return;
    }
    let key = head
        .lines()
        .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
        .unwrap()
        .trim();
    let accept = crate::stdlib::websocket::accept_key(key);
    let selected = if path == "/protocol" && head.contains("Sec-WebSocket-Protocol: chat") {
        "Sec-WebSocket-Protocol: chat\r\n"
    } else {
        ""
    };
    let _ = write!(s, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n{selected}\r\n");
    let mut out = Vec::new();
    match path.as_str() {
        "/three" => {
            out.extend(frame(true, 1, b"one"));
            out.extend(frame(false, 1, b"t"));
            out.extend(frame(true, 9, b"are you there"));
            out.extend(frame(true, 0, b"wo"));
            out.extend(frame(true, 1, &[b'3'; 300]));
            let mut close = 1000u16.to_be_bytes().to_vec();
            close.extend_from_slice(b"bye");
            out.extend(frame(true, 8, &close));
        }
        "/big" => out.extend(frame(true, 1, &[b'x'; 2000])),
        "/binary" => out.extend(frame(true, 2, &[1, 2, 3])),
        "/legacy-large" => {
            out.extend([0x82, 127]);
            out.extend_from_slice(&(64u64 << 20).to_be_bytes());
        }
        "/legacy-fragment" => {
            out.extend(frame(false, 2, &[1, 2, 3]));
            out.extend(frame(true, 0, &[4; 64]));
        }
        "/drop" => out.extend(frame(true, 1, b"x")),
        "/peer-close" => {
            let mut close = 1000u16.to_be_bytes().to_vec();
            close.extend_from_slice(b"peer");
            out.extend(frame(true, 8, &close));
        }
        "/echo" | "/protocol" | "/drain" | "/never" | "/no-read" => {}
        _ => out.extend(frame(true, 1, b"held")),
    }
    let _ = s.write_all(&out);
    if path == "/drop" {
        let _ = s.shutdown(Shutdown::Both);
        return;
    }
    if path == "/no-read" {
        std::thread::sleep(Duration::from_millis(300));
        let _ = s.shutdown(Shutdown::Both);
        return;
    }
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    if path == "/drain" {
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut message: Option<(u8, Vec<u8>)> = None;
    while let Some((fin, opcode, payload)) = client_frame(&mut s) {
        if matches!(opcode, 1 | 2) {
            message = Some((opcode, Vec::new()));
        }
        if matches!(opcode, 0..=2) {
            let Some((_kind, whole)) = message.as_mut() else {
                return;
            };
            whole.extend_from_slice(&payload);
            if fin {
                let (kind, whole) = message.take().unwrap();
                let _ = saw.send(format!("{path} message {kind} {}", whole.len()));
                if matches!(path.as_str(), "/echo" | "/protocol") {
                    let _ = s.write_all(&frame(true, kind, &whole));
                }
            }
            continue;
        }
        let text = String::from_utf8_lossy(&payload).into_owned();
        let report = match opcode {
            0xA => format!("{path} pong {text}"),
            0x8 if payload.len() >= 2 => format!(
                "{path} close {} {}",
                u16::from_be_bytes([payload[0], payload[1]]),
                String::from_utf8_lossy(&payload[2..])
            ),
            other => format!("{path} opcode {other}"),
        };
        let _ = saw.send(report);
        if opcode == 0x8 {
            if matches!(path.as_str(), "/echo" | "/protocol" | "/drain") {
                let _ = s.write_all(&frame(true, 8, &payload));
            }
            if path == "/peer-close" {
                s.set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                while let Some((_, later_opcode, later_payload)) = client_frame(&mut s) {
                    let _ = saw.send(format!(
                        "{path} after-close {later_opcode} {}",
                        later_payload.len()
                    ));
                }
            }
            break;
        }
    }
    let _ = saw.send(format!("{path} gone"));
}

fn open_on(
    transport: &dyn SocketTransport,
    port: u16,
    path: &str,
    signal: &AbortSignal,
) -> Result<Box<dyn MessageSource>, HostError> {
    let url = url::Url::parse(&format!("ws://127.0.0.1:{port}{path}")).unwrap();
    transport.connect(&url, 1024, signal)
}

fn text(s: &str) -> Incoming {
    Incoming::Text(s.into())
}

fn wait(seen: &Receiver<String>) -> String {
    seen.recv_timeout(Duration::from_secs(5))
        .expect("the peer reports")
}

fn server_handshake<W: Read + Write + ?Sized>(wire: &mut W) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        wire.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let key = head
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
        .unwrap()
        .trim();
    let accept = crate::stdlib::websocket::accept_key(key);
    write!(wire, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").unwrap();
    wire.flush().unwrap();
}

/// The whole conversation, on whichever transport: shared by the Rust
/// transport's test and the Darwin one's.
pub(crate) fn conversation(transport: &dyn SocketTransport) {
    let (port, seen) = peer();
    let none = AbortSignal::default();
    let mut s = open_on(transport, port, "/three", &none).unwrap();
    assert_eq!(s.next().unwrap(), text("one"));
    assert_eq!(
        s.next().unwrap(),
        text("two"),
        "fragments join; a ping between"
    );
    assert_eq!(
        s.next().unwrap(),
        text(&"3".repeat(300)),
        "an extended length"
    );
    assert_eq!(
        s.next().unwrap(),
        Incoming::Closed {
            code: 1000,
            reason: "bye".into()
        }
    );
    assert_eq!(wait(&seen), "/three pong are you there");
    assert_eq!(
        wait(&seen),
        "/three close 1000 bye",
        "the closing handshake is answered"
    );
    drop(s);

    let mut s = open_on(transport, port, "/big", &none).unwrap();
    assert_eq!(s.next().unwrap(), Incoming::TooLarge);
    drop(s);
    let mut s = open_on(transport, port, "/binary", &none).unwrap();
    assert!(matches!(s.next().unwrap(), Incoming::Binary(_)));
    drop(s);
    let mut s = open_on(transport, port, "/drop", &none).unwrap();
    assert_eq!(s.next().unwrap(), text("x"));
    assert!(matches!(
        s.next().unwrap(),
        Incoming::Closed { code: 1006, .. }
    ));
    drop(s);
    let refused = open_on(transport, port, "/refuse", &none).err().unwrap();
    assert!(refused.to_string().contains("did not open"), "{refused}");

    // Aborting ends a blocked read, and the peer sees the connection go.
    let abort = AbortController::new();
    let mut s = open_on(transport, port, "/hold", &abort.signal()).unwrap();
    assert_eq!(s.next().unwrap(), text("held"));
    let aborter = abort.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        aborter.abort();
    });
    assert!(s.next().is_err(), "an abort is an error, not a close");
    drop(s);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match seen.recv_timeout(left).expect("the peer saw the socket go") {
            gone if gone == "/hold gone" => break,
            _ => {}
        }
    }

    let url = url::Url::parse(&format!("ws://127.0.0.1:{port}/protocol")).unwrap();
    let mut s = transport
        .connect_with_protocols(&url, 128 << 10, &none, &["chat".into()])
        .unwrap();
    assert_eq!(s.protocol(), "chat");
    s.send_text("hello").unwrap();
    assert_eq!(s.next().unwrap(), text("hello"));
    assert_eq!(wait(&seen), "/protocol message 1 5");
    s.send_binary(&[1, 2, 3, 4]).unwrap();
    assert_eq!(
        s.next_event().unwrap(),
        Event::Message(Message::Binary(vec![1, 2, 3, 4]))
    );
    assert_eq!(wait(&seen), "/protocol message 2 4");
    let fragmented = "x".repeat((FRAGMENT * 2) + 7);
    s.send_text(&fragmented).unwrap();
    assert_eq!(s.next().unwrap(), text(&fragmented));
    assert_eq!(
        wait(&seen),
        format!("/protocol message 1 {}", fragmented.len())
    );
    s.close(3001, "done").unwrap();
    assert_eq!(
        s.next().unwrap(),
        Incoming::Closed {
            code: 3001,
            reason: "done".into()
        }
    );
    assert_eq!(wait(&seen), "/protocol close 3001 done");
    let before = s.buffered_amount();
    s.send_text("discarded").unwrap();
    assert_eq!(s.buffered_amount(), before + "discarded".len());
    drop(s);
    assert_eq!(wait(&seen), "/protocol gone");

    // The close and a following send race at both transport boundaries. The
    // data is accounted per WHATWG, but a close already handed to the
    // platform wins and the peer never receives the later message.
    let mut s = open_on(transport, port, "/echo", &none).unwrap();
    s.sender().unwrap().close(None, "").unwrap();
    let before = s.buffered_amount();
    s.send_text("after-close").unwrap();
    assert_eq!(s.buffered_amount(), before + "after-close".len());
    assert!(matches!(
        s.next().unwrap(),
        Incoming::Closed {
            code: 1000 | 1005,
            reason
        } if reason.is_empty()
    ));
    assert!(matches!(
        wait(&seen).as_str(),
        "/echo opcode 8" | "/echo close 1000 "
    ));
    assert_eq!(wait(&seen), "/echo gone");

    // Race sends with a peer-initiated close. Frames accepted before the peer
    // close may precede our close reply, but nothing may follow that reply.
    let mut s = open_on(transport, port, "/peer-close", &none).unwrap();
    let sender = s.sender().unwrap();
    let racer = Arc::clone(&sender);
    let sending = std::thread::spawn(move || {
        for _ in 0..4 {
            racer.send_text("racing").unwrap();
            std::thread::yield_now();
        }
    });
    assert_eq!(
        s.next().unwrap(),
        Incoming::Closed {
            code: 1000,
            reason: "peer".into()
        }
    );
    sending.join().unwrap();
    sender.send_text("after-peer-close").unwrap();
    assert!(
        sender.buffered_amount() >= "after-peer-close".len(),
        "the discarded post-close payload remains accounted even while earlier racing sends complete"
    );
    loop {
        let report = wait(&seen);
        if report == "/peer-close close 1000 peer" {
            break;
        }
        assert!(report.starts_with("/peer-close message 1 "), "{report}");
    }
    loop {
        let report = wait(&seen);
        if report == "/peer-close gone" {
            break;
        }
        assert_eq!(
            report, "/peer-close after-close 1 6",
            "only sends admitted before the peer-close callback may still be in flight"
        );
    }

    let mut s = open_on(transport, port, "/drain", &none).unwrap();
    let payload = vec![7; 8 << 20];
    s.send_binary(&payload).unwrap();
    assert!(
        s.buffered_amount() > 0,
        "queued bytes are accounted immediately"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while s.buffered_amount() != 0 && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(
        s.buffered_amount(),
        0,
        "sent bytes drain from bufferedAmount"
    );
    assert_eq!(wait(&seen), format!("/drain message 2 {}", payload.len()));
    s.close(1000, "").unwrap();
    assert!(matches!(
        s.next().unwrap(),
        Incoming::Closed { code: 1000, .. }
    ));

    // A non-reading peer cannot make the native send queue grow without
    // bound. Repeated data eventually fails the connection at the per-socket
    // byte/message ceiling; further sends only affect bufferedAmount.
    let mut s = open_on(transport, port, "/no-read", &none).unwrap();
    let chunk = vec![9; 1 << 20];
    for _ in 0..32 {
        s.send_binary(&chunk).unwrap();
    }
    assert!(matches!(s.next(), Ok(Incoming::Closed { .. }) | Err(_)));
}

#[test]
fn legacy_binary_next_returns_the_first_frames_declared_length_without_payload() {
    let (port, _seen) = peer();
    let transport = TcpSocketTransport::new();
    let none = AbortSignal::default();

    let mut large = open_on(&transport, port, "/legacy-large", &none).unwrap();
    assert_eq!(large.next().unwrap(), Incoming::Binary(64 << 20));
    drop(large);

    let mut fragmented = open_on(&transport, port, "/legacy-fragment", &none).unwrap();
    assert_eq!(fragmented.next().unwrap(), Incoming::Binary(3));
}

#[test]
fn an_ipv6_literal_is_bracketed_in_the_host_header() {
    let listener = std::net::TcpListener::bind("[::1]:0").expect("IPv6 loopback");
    let port = listener.local_addr().unwrap().port();
    let (reported, host) = channel();
    let peer = std::thread::spawn(move || {
        let mut stream = listener.accept().unwrap().0;
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        reported
            .send(
                head.lines()
                    .find(|line| line.starts_with("Host: "))
                    .unwrap()
                    .to_string(),
            )
            .unwrap();
        let key = head
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .trim();
        let accept = crate::stdlib::websocket::accept_key(key);
        write!(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").unwrap();
        stream.write_all(&frame(true, 8, &[])).unwrap();
    });
    let url = url::Url::parse(&format!("ws://[::1]:{port}/")).unwrap();
    let mut socket = TcpSocketTransport::new()
        .connect(&url, 1024, &AbortSignal::default())
        .unwrap();
    assert!(matches!(socket.next(), Ok(Incoming::Closed { .. })));
    assert_eq!(host.recv().unwrap(), format!("Host: [::1]:{port}"));
    peer.join().unwrap();
}

#[test]
fn the_rust_transport_holds_the_whole_conversation() {
    conversation(&TcpSocketTransport::new());
}

#[test]
fn close_and_fin_between_receives_preserve_the_peer_close_and_reply() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (close_now, close_requested) = channel();
    let (close_sent, close_observed) = channel();
    let (reported, report) = channel();
    let peer = std::thread::spawn(move || {
        let mut stream = listener.accept().unwrap().0;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        server_handshake(&mut stream);
        stream.write_all(&frame(true, 1, b"first")).unwrap();
        close_requested.recv().unwrap();
        let mut close = 3001u16.to_be_bytes().to_vec();
        close.extend_from_slice(b"between");
        stream.write_all(&frame(true, 0x8, &close)).unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        close_sent.send(()).unwrap();
        reported.send(client_frame(&mut stream)).unwrap();
    });

    let mut socket = open_on(
        &TcpSocketTransport::new(),
        port,
        "/close-fin",
        &AbortSignal::default(),
    )
    .unwrap();
    assert_eq!(socket.next().unwrap(), text("first"));
    close_now.send(()).unwrap();
    close_observed.recv().unwrap();
    // Give poll/WSAPoll time to observe the terminal state while receive
    // demand is paused. The peer's buffered Close must remain unread.
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        socket.next().unwrap(),
        Incoming::Closed {
            code: 3001,
            reason: "between".into(),
        }
    );
    let (_, opcode, payload) = report
        .recv_timeout(Duration::from_secs(3))
        .expect("the peer received the close reply")
        .expect("the client sent a frame");
    assert_eq!(opcode, 0x8);
    assert_eq!(
        payload,
        [3001u16.to_be_bytes().as_slice(), b"between"].concat()
    );
    peer.join().unwrap();
}

#[test]
fn a_ping_flood_from_a_non_reading_peer_fails_cleanly() {
    const PINGS: usize = 4_096;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release_peer, released) = channel();
    let peer = std::thread::spawn(move || {
        let mut stream = listener.accept().unwrap().0;
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let key = head
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .trim();
        let accept = crate::stdlib::websocket::accept_key(key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .unwrap();

        let ping = frame(true, 0x9, &[7; 125]);
        for _ in 0..PINGS {
            if stream.write_all(&ping).is_err() {
                break;
            }
        }
        // Deliberately never read a pong. Keep the peer open long enough that
        // only the client's own bounded-queue failure can finish next().
        let _ = released.recv_timeout(Duration::from_secs(5));
    });

    let writer_gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let mut socket = open_on(
        &TcpSocketTransport::with_writer_gate(Arc::clone(&writer_gate)),
        port,
        "/ping-flood",
        &AbortSignal::default(),
    )
    .unwrap();
    let (reported, report) = channel();
    let reader = std::thread::spawn(move || {
        let _ = reported.send(socket.next());
    });
    let result = report.recv_timeout(Duration::from_secs(2));
    let _ = release_peer.send(());
    peer.join().unwrap();
    {
        let (lock, ready) = &*writer_gate;
        *lock.lock().unwrap() = true;
        ready.notify_one();
    }
    reader.join().unwrap();

    let error = result
        .expect("the ping flood must fail before the peer closes")
        .expect_err("command-capacity exhaustion is an abrupt failure");
    assert!(
        error.to_string().contains("outbound command queue is full"),
        "unexpected ping-flood failure: {error}"
    );
}

#[test]
fn control_frames_overtake_a_large_send_to_a_slow_reader() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (reported, report) = channel();
    let (pong_seen, pong_observed) = channel();
    let peer = std::thread::spawn(move || {
        let mut stream = listener.accept().unwrap().0;
        socket2::SockRef::from(&stream)
            .set_recv_buffer_size(FRAGMENT)
            .unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let key = head
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .trim();
        let accept = crate::stdlib::websocket::accept_key(key);
        write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .unwrap();

        let ping_sent = std::time::Instant::now();
        stream.write_all(&frame(true, 0x9, b"priority")).unwrap();
        let mut data_before_pong = 0;
        loop {
            let (_, opcode, payload) = client_frame(&mut stream).unwrap();
            if opcode == 0xA {
                assert_eq!(payload, b"priority");
                break;
            }
            assert!(matches!(opcode, 0x0 | 0x2), "unexpected opcode {opcode}");
            data_before_pong += payload.len();
            std::thread::sleep(Duration::from_millis(2));
        }
        let ping_latency = ping_sent.elapsed();
        pong_seen.send(()).unwrap();

        let close_sent = std::time::Instant::now();
        stream
            .write_all(&frame(true, 0x8, &1000u16.to_be_bytes()))
            .unwrap();
        let mut data_before_close = data_before_pong;
        loop {
            let (_, opcode, payload) = client_frame(&mut stream).unwrap();
            if opcode == 0x8 {
                assert_eq!(payload, 1000u16.to_be_bytes());
                break;
            }
            assert!(matches!(opcode, 0x0 | 0x2), "unexpected opcode {opcode}");
            data_before_close += payload.len();
            std::thread::sleep(Duration::from_millis(2));
        }
        reported
            .send((
                ping_latency,
                close_sent.elapsed(),
                data_before_pong,
                data_before_close,
            ))
            .unwrap();
    });

    let mut socket = open_on(
        &TcpSocketTransport::new(),
        port,
        "/slow-control",
        &AbortSignal::default(),
    )
    .unwrap();
    let payload = vec![5; 8 << 20];
    socket.send_binary(&payload).unwrap();
    pong_observed
        .recv_timeout(Duration::from_secs(2))
        .expect("the pump answered ping without a posted receive");
    assert_eq!(
        socket.next().unwrap(),
        Incoming::Closed {
            code: 1000,
            reason: String::new(),
        }
    );
    let (ping_latency, close_latency, before_pong, before_close) = report
        .recv_timeout(Duration::from_secs(5))
        .expect("the slow peer received both control replies");
    peer.join().unwrap();
    assert!(
        before_pong < payload.len(),
        "pong followed the whole message"
    );
    assert!(
        before_close < payload.len(),
        "close reply followed the whole message"
    );
    assert!(
        ping_latency < Duration::from_secs(2),
        "pong latency was {ping_latency:?}"
    );
    assert!(
        close_latency < Duration::from_secs(2),
        "close latency was {close_latency:?}"
    );
    eprintln!(
        "full-duplex control latency: ping={ping_latency:?}, close={close_latency:?}, bytes before pong={before_pong}, bytes before close={before_close}"
    );
}

#[cfg(test)]
fn stalled_peer(
    secure: bool,
    flood_pongs: bool,
) -> (
    TcpSocketTransport,
    String,
    Sender<()>,
    Arc<PumpObserver>,
    std::thread::JoinHandle<()>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (release_peer, released) = channel();
    let observer = Arc::new(PumpObserver::default());
    let (transport, server) = if secure {
        let (_, client, server) = local_tls();
        (
            TcpSocketTransport::with_tls_and_pump_observer(client, Arc::clone(&observer)),
            Some(server),
        )
    } else {
        (
            TcpSocketTransport::with_pump_observer(Arc::clone(&observer)),
            None,
        )
    };
    let peer = std::thread::spawn(move || {
        let tcp = listener.accept().unwrap().0;
        socket2::SockRef::from(&tcp)
            .set_recv_buffer_size(1024)
            .unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let hold = |wire: &mut (dyn ReadWrite + '_)| {
            server_handshake(wire);
            if flood_pongs {
                let pong = frame(true, 0xA, &[7; 125]);
                while wire.write_all(&pong).is_ok() {}
            } else {
                // After the handshake, neither read nor write until the
                // client's own no-progress deadline has failed the socket.
                let _ = released.recv_timeout(Duration::from_secs(5));
            }
        };
        if let Some(server) = server {
            let connection = rustls::ServerConnection::new(server).unwrap();
            let mut wire = rustls::StreamOwned::new(connection, tcp);
            hold(&mut wire);
        } else {
            let mut wire = tcp;
            hold(&mut wire);
        }
    });

    let scheme = if secure { "wss" } else { "ws" };
    (
        transport,
        format!("{scheme}://localhost:{port}/stall"),
        release_peer,
        observer,
        peer,
    )
}

#[cfg(test)]
trait ReadWrite: Read + Write {}
#[cfg(test)]
impl<T: Read + Write> ReadWrite for T {}

#[cfg(test)]
fn assert_stall_deadline(secure: bool, flood_pongs: bool) {
    let (transport, url, release_peer, observer, peer) = stalled_peer(secure, flood_pongs);
    let mut socket = transport
        .connect(
            &url::Url::parse(&url).unwrap(),
            1024,
            &AbortSignal::default(),
        )
        .unwrap();
    socket.send_binary(&vec![5u8; 8 * 1024 * 1024]).unwrap();
    let started = std::time::Instant::now();
    let error = socket
        .next()
        .expect_err("the client's no-progress deadline must fail the socket");
    let elapsed = started.elapsed();
    assert!(
        error
            .to_string()
            .contains("the socket write made no progress before its deadline"),
        "unexpected stalled-write failure: {error}"
    );
    assert!(
        elapsed >= WRITE_STALL_TIMEOUT && elapsed < Duration::from_secs(3),
        "the {:?} stall fired after {elapsed:?}, expected near {WRITE_STALL_TIMEOUT:?}",
        if secure { "TLS" } else { "plaintext" }
    );
    assert!(
        observer.network_bytes.load(Ordering::Acquire) > 0,
        "the test must partially write the frame before it stalls"
    );
    eprintln!(
        "{} stalled write failed after {elapsed:?} with {} network bytes written{}",
        if secure { "TLS" } else { "plaintext" },
        observer.network_bytes.load(Ordering::Acquire),
        if flood_pongs {
            " during a pong flood"
        } else {
            ""
        }
    );
    let _ = release_peer.send(());
    drop(socket);
    peer.join().unwrap();
}

#[test]
fn silent_peer_stalls_plaintext_and_partial_tls_writes_at_the_deadline() {
    assert_stall_deadline(false, false);
    assert_stall_deadline(true, false);
}

#[test]
fn pong_flood_cannot_starve_the_stalled_write_deadline() {
    assert_stall_deadline(false, true);
}

const LOCAL_CERT: &str = "MIIBcDCCARagAwIBAgIJAL/L9Qemvq28MAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yNjEwMDQxMzQ2MTBaFw0yNzEwMDQxMzQ2MTBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB+9b/H/REalNbaY5CeIowEsLfdmeVL8M/iQgCo4BrJM+IgYXRIUDI6EdvgZkkyBFTr8dIRFr/5u/AX/0vRU3p2jUTBPMBoGA1UdEQQTMBGCCWxvY2FsaG9zdIcEfwAAATAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAKBggqhkjOPQQDAgNIADBFAiBU7Mu0QDVetJW9tm7u7aoPrVQcEqkO0IUkZ0aMgPA6GwIhAPMuBqpj21v+kfb7/bCjL94nmzgQkNzpdDPei6+PzVpa";
const LOCAL_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgNuGe4B07FBTDauLEJyJRWafyt3Hlvuh33z/wS96uBu2hRANCAAQfvW/x/0RGpTW2mOQniKMBLC33ZnlS/DP4kIAqOAayTPiIGF0SFAyOhHb4GZJMgRU6/HSERa/+bvwF/9L0VN6d";

fn local_tls() -> (
    Vec<u8>,
    Arc<rustls::ClientConfig>,
    Arc<rustls::ServerConfig>,
) {
    use base64::Engine as _;
    let cert_bytes = base64::engine::general_purpose::STANDARD
        .decode(LOCAL_CERT)
        .unwrap();
    let cert = rustls::pki_types::CertificateDer::from(cert_bytes.clone());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        base64::engine::general_purpose::STANDARD
            .decode(LOCAL_KEY)
            .unwrap(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    (cert_bytes, Arc::new(client), Arc::new(server))
}

#[test]
fn zero_from_write_tls_is_an_abnormal_close() {
    struct ZeroWriter;
    impl Write for ZeroWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Ok(0)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let (_, client, _) = local_tls();
    let name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    let mut connection = rustls::ClientConnection::new(client, name).unwrap();
    assert!(
        connection.wants_write(),
        "the real rustls path has TLS bytes pending"
    );
    assert!(matches!(
        write_tls_progress(&mut connection, &mut ZeroWriter).unwrap(),
        WriteProgress::Eof
    ));
}

pub(crate) fn tls_echo_peer() -> (
    u16,
    Vec<u8>,
    Arc<rustls::ClientConfig>,
    std::thread::JoinHandle<()>,
) {
    let (certificate, client, server) = local_tls();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = std::thread::spawn(move || {
        let tcp = listener.accept().unwrap().0;
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let connection = rustls::ServerConnection::new(server).unwrap();
        let mut wire = rustls::StreamOwned::new(connection, tcp);
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            wire.read_exact(&mut byte).unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let key = head
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .trim();
        let accept = crate::stdlib::websocket::accept_key(key);
        write!(wire, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").unwrap();
        let (fin, opcode, payload) = client_frame(&mut wire).unwrap();
        assert!(fin);
        assert_eq!(opcode, 1);
        wire.write_all(&frame(true, 1, &payload)).unwrap();
        let (fin, opcode, payload) = client_frame(&mut wire).unwrap();
        assert!(fin);
        assert_eq!(opcode, 8);
        wire.write_all(&frame(true, 8, &payload)).unwrap();
    });
    (port, certificate, client, peer)
}

#[test]
fn the_rust_transport_echoes_and_closes_over_local_tls() {
    let (port, _certificate, client, peer) = tls_echo_peer();
    let transport = TcpSocketTransport::with_tls(client);
    let url = url::Url::parse(&format!("wss://localhost:{port}/echo")).unwrap();
    let mut socket = transport
        .connect(&url, 1024, &AbortSignal::default())
        .unwrap();
    socket.send_text("secure").unwrap();
    assert_eq!(socket.next().unwrap(), text("secure"));
    socket.close(1000, "tls done").unwrap();
    assert_eq!(
        socket.next().unwrap(),
        Incoming::Closed {
            code: 1000,
            reason: "tls done".into(),
        }
    );
    peer.join().unwrap();
}

/// Go through the production connection path, then inspect and read a clone of
/// the retained socket. Nonblocking mode is a property of the underlying
/// socket on every supported platform, including Windows' duplicated handle.
#[test]
fn retained_plain_and_tls_sockets_are_nonblocking_after_the_handshake() {
    for secure in [false, true] {
        let (transport, url, peer) = if secure {
            let (port, _, client, peer) = tls_echo_peer();
            (
                TcpSocketTransport::with_tls(client),
                format!("wss://localhost:{port}/echo"),
                Some(peer),
            )
        } else {
            let (port, _seen) = peer();
            (
                TcpSocketTransport::new(),
                format!("ws://127.0.0.1:{port}/echo"),
                None,
            )
        };
        let mut socket = transport
            .open_socket(
                &url::Url::parse(&url).unwrap(),
                1024,
                &AbortSignal::default(),
                &[],
            )
            .unwrap();
        let mut retained = socket.shutdown.try_clone().unwrap();
        assert_eq!(retained.read_timeout().unwrap(), None);
        assert_eq!(retained.write_timeout().unwrap(), None);
        let idle = retained.read(&mut [0; 1]);
        assert!(
            matches!(idle, Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "idle retained socket was not nonblocking: {idle:?}"
        );
        socket.send_text("after idle").unwrap();
        assert_eq!(socket.next().unwrap(), text("after idle"));
        socket.close(1000, "done").unwrap();
        assert_eq!(
            socket.next().unwrap(),
            Incoming::Closed {
                code: 1000,
                reason: "done".into()
            }
        );
        if let Some(peer) = peer {
            peer.join().unwrap();
        }
    }
}

#[test]
fn an_idle_connection_blocks_without_periodic_wakeups() {
    let (port, _seen) = peer();
    let observer = Arc::new(PumpObserver::default());
    let transport = TcpSocketTransport::with_pump_observer(Arc::clone(&observer));
    let socket = open_on(&transport, port, "/never", &AbortSignal::default()).unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !observer.parked.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(
        observer.parked.load(Ordering::Acquire),
        "the pump never entered its readiness wait"
    );
    // The socket's one initial writable edge can arrive after open returns.
    // Let setup readiness settle before measuring the idle interval.
    std::thread::sleep(Duration::from_millis(50));
    while !observer.parked.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    let returns = observer.returns.load(Ordering::Acquire);
    std::thread::sleep(Duration::from_millis(150));
    assert!(observer.parked.load(Ordering::Acquire));
    assert_eq!(
        observer.returns.load(Ordering::Acquire),
        returns,
        "an idle pump returned from readiness without a command or socket event"
    );
    drop(socket);
}

#[cfg(test)]
fn idle_peer_for_exit_test() -> (u16, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = std::thread::spawn(move || {
        let mut stream = listener.accept().unwrap().0;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        server_handshake(&mut stream);
        let mut byte = [0u8; 1];
        while stream.read(&mut byte).unwrap_or(0) != 0 {}
    });
    (port, peer)
}

#[cfg(test)]
fn wait_for_pump_exit(observer: &PumpObserver, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !observer.exited.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(
        observer.exited.load(Ordering::Acquire),
        "the {what} pump did not exit"
    );
}

#[test]
fn abort_wakes_and_ends_an_idle_pump() {
    let (port, peer) = idle_peer_for_exit_test();
    let observer = Arc::new(PumpObserver::default());
    let transport = TcpSocketTransport::with_pump_observer(Arc::clone(&observer));
    let controller = AbortController::new();
    let mut socket = open_on(&transport, port, "/idle-abort", &controller.signal()).unwrap();
    controller.abort();
    wait_for_pump_exit(&observer, "aborted idle");
    assert!(socket.next().is_err(), "abort remains an error, not EOF");
    drop(socket);
    peer.join().unwrap();
}

#[test]
fn dropping_the_last_handles_ends_an_idle_pump() {
    let (port, peer) = idle_peer_for_exit_test();
    let observer = Arc::new(PumpObserver::default());
    let transport = TcpSocketTransport::with_pump_observer(Arc::clone(&observer));
    let socket = open_on(&transport, port, "/idle-drop", &AbortSignal::default()).unwrap();
    let sender = socket.sender().unwrap();
    drop(sender);
    drop(socket);
    wait_for_pump_exit(&observer, "last-handle drop");
    peer.join().unwrap();
}

#[test]
fn a_real_peer_reset_closes_the_idle_pump_without_spinning() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (reset_now, reset_requested) = channel();
    let peer = std::thread::spawn(move || {
        let mut stream = listener.accept().unwrap().0;
        server_handshake(&mut stream);
        reset_requested.recv().unwrap();
        socket2::SockRef::from(&stream)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
    });
    let observer = Arc::new(PumpObserver::default());
    let transport = TcpSocketTransport::with_pump_observer(Arc::clone(&observer));
    let mut socket = transport
        .open_socket(
            &url::Url::parse(&format!("ws://127.0.0.1:{port}/never")).unwrap(),
            1024,
            &AbortSignal::default(),
            &[],
        )
        .unwrap();

    reset_now.send(()).unwrap();
    let started = std::time::Instant::now();
    wait_for_pump_exit(&observer, "reset");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        socket.next().unwrap(),
        Incoming::Closed {
            code: 1006,
            reason: String::new(),
        }
    );
    assert!(!observer.parked.load(Ordering::Acquire));
    peer.join().unwrap();
}

#[test]
fn sha1_is_sha1() {
    let hex = |b: [u8; 20]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    assert_eq!(
        hex(crate::stdlib::websocket::sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex(crate::stdlib::websocket::sha1(b"")),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
    // RFC 6455 §1.3's worked example.
    assert_eq!(
        crate::stdlib::websocket::accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    );
}
