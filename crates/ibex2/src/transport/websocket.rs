//! A WebSocket client off Apple (RFC 6455): TCP from the standard
//! library, TLS from the same rustls and trust store as `RustlsHttpTransport`.
//! One readiness-driven I/O pump owns each socket and rustls connection. It
//! multiplexes the bounded outbound queue with requested receives, so control
//! frames remain live while a large data message drains.
//! @ref LLP 0057#3-the-boundary — the platform owns the socket and TLS

use crate::boundary::HostError;
use crate::stdlib::abort::{AbortRegistration, AbortSignal};
use crate::stdlib::websocket::{
    Event, Incoming, Message, MessageSender, MessageSource, SocketTransport,
};
use mio::net::TcpStream as MioTcpStream;
use mio::{Events, Interest, Poll, Token, Waker};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream as StdTcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc, Mutex,
};
use std::time::{Duration, Instant};

const MAX_HEAD: usize = 16 << 10;
const FRAGMENT: usize = 16 << 10;
const MAX_OUTBOUND_BYTES: usize = 16 << 20;
const MAX_OUTBOUND_MESSAGES: usize = 256;
// @ref LLP 0059.000#312-websocket--delegating-capability-bearing-author-required — data and control frames share one bounded command channel
const MAX_OUTBOUND_COMMANDS: usize = MAX_OUTBOUND_MESSAGES + 16;
const MAX_READ_FRAMES_PER_TURN: usize = 32;
const SOCKET_TOKEN: Token = Token(0);
const WAKE_TOKEN: Token = Token(1);
const OPEN: u8 = 1;
const CLOSING: u8 = 2;
const CLOSED: u8 = 3;

/// Plaintext `ws:` and rustls `wss:`, one connection per socket. The trust
/// store loads on the first `wss:` open, never at construction (a host that
/// opens no socket pays nothing at boot).
#[derive(Default)]
pub struct TcpSocketTransport {
    tls: std::sync::OnceLock<Arc<rustls::ClientConfig>>,
    #[cfg(test)]
    writer_gate: Option<Arc<(Mutex<bool>, std::sync::Condvar)>>,
    #[cfg(test)]
    pump_observer: Option<Arc<PumpObserver>>,
}

#[cfg(test)]
#[derive(Default)]
struct PumpObserver {
    parked: std::sync::atomic::AtomicBool,
    exited: std::sync::atomic::AtomicBool,
    returns: AtomicUsize,
    network_bytes: AtomicUsize,
}

impl TcpSocketTransport {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn with_tls(config: Arc<rustls::ClientConfig>) -> Self {
        let tls = std::sync::OnceLock::new();
        tls.set(config).expect("a fresh TLS configuration");
        Self {
            tls,
            writer_gate: None,
            pump_observer: None,
        }
    }

    #[cfg(test)]
    fn with_writer_gate(gate: Arc<(Mutex<bool>, std::sync::Condvar)>) -> Self {
        Self {
            tls: std::sync::OnceLock::new(),
            writer_gate: Some(gate),
            pump_observer: None,
        }
    }

    #[cfg(test)]
    fn with_pump_observer(observer: Arc<PumpObserver>) -> Self {
        Self {
            tls: std::sync::OnceLock::new(),
            writer_gate: None,
            pump_observer: Some(observer),
        }
    }

    #[cfg(test)]
    fn with_tls_and_pump_observer(
        config: Arc<rustls::ClientConfig>,
        observer: Arc<PumpObserver>,
    ) -> Self {
        let tls = std::sync::OnceLock::new();
        tls.set(config).expect("a fresh TLS configuration");
        Self {
            tls,
            writer_gate: None,
            pump_observer: Some(observer),
        }
    }

    fn tls(&self) -> Arc<rustls::ClientConfig> {
        self.tls.get_or_init(tls_config).clone()
    }
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
            let _ = roots.add(cert);
        }
        if roots.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        Arc::new(tls)
    }
}

fn failed(what: impl std::fmt::Display) -> HostError {
    HostError::Failed(format!("the socket did not open: {what}"))
}

enum HandshakeWire {
    Plain(StdTcpStream),
    Tls {
        stream: Box<rustls::StreamOwned<rustls::ClientConnection, StdTcpStream>>,
    },
}

impl HandshakeWire {
    fn into_nonblocking(self) -> std::io::Result<Wire> {
        let convert = |tcp: StdTcpStream| {
            tcp.set_read_timeout(None)?;
            tcp.set_write_timeout(None)?;
            tcp.set_nonblocking(true)?;
            Ok::<_, std::io::Error>(MioTcpStream::from_std(tcp))
        };
        match self {
            Self::Plain(tcp) => convert(tcp).map(Wire::Plain),
            Self::Tls { stream } => {
                let rustls::StreamOwned { conn, sock } = *stream;
                Ok(Wire::Tls {
                    conn: Box::new(conn),
                    sock: convert(sock)?,
                })
            }
        }
    }
}

impl Read for HandshakeWire {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(out),
            Self::Tls { stream } => stream.read(out),
        }
    }
}
impl Write for HandshakeWire {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(bytes),
            Self::Tls { stream } => stream.write(bytes),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls { stream } => stream.flush(),
        }
    }
}

enum Wire {
    Plain(MioTcpStream),
    Tls {
        conn: Box<rustls::ClientConnection>,
        sock: MioTcpStream,
    },
}

impl Wire {
    fn tcp_mut(&mut self) -> &mut MioTcpStream {
        match self {
            Self::Plain(tcp) => tcp,
            Self::Tls { sock, .. } => sock,
        }
    }
}

impl SocketTransport for TcpSocketTransport {
    fn connect(
        &self,
        url: &url::Url,
        max_message: usize,
        signal: &AbortSignal,
    ) -> Result<Box<dyn MessageSource>, HostError> {
        self.connect_with_protocols(url, max_message, signal, &[])
    }

    fn connect_with_protocols(
        &self,
        url: &url::Url,
        max_message: usize,
        signal: &AbortSignal,
        protocols: &[String],
    ) -> Result<Box<dyn MessageSource>, HostError> {
        self.open_socket(url, max_message, signal, protocols)
            .map(|socket| Box::new(socket) as Box<dyn MessageSource>)
    }
}

impl TcpSocketTransport {
    fn open_socket(
        &self,
        url: &url::Url,
        max_message: usize,
        signal: &AbortSignal,
        protocols: &[String],
    ) -> Result<Socket, HostError> {
        let host = url.host_str().ok_or_else(|| failed("no host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| failed("no port"))?;
        let addrs: Vec<_> = (host.trim_start_matches('[').trim_end_matches(']'), port)
            .to_socket_addrs()
            .map_err(failed)?
            .collect();
        signal.check()?;
        // Establish both readiness resources before a server can observe a TCP
        // connection or successful WebSocket upgrade. The Waker is mio's
        // platform primitive (EVFILT_USER/eventfd/IOCP), not a second socket.
        let poll = Poll::new().map_err(failed)?;
        let wake = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN).map_err(failed)?);
        let mut last = failed("no resolved address");
        let mut tcp = None;
        for address in addrs {
            signal.check()?;
            match super::rustls_http::connect_socket(address, Duration::from_secs(10), signal) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = failed(e),
            }
        }
        let tcp = tcp.ok_or(last)?;
        tcp.set_nodelay(true).map_err(failed)?;
        // Aborting wakes Poll even when the connection is completely idle.
        // Shutdown is retained as a second, idempotent way to make socket I/O
        // observe cancellation if it races the wake.
        let registration = {
            let socket = tcp.try_clone().map_err(failed)?;
            let wake = Arc::clone(&wake);
            signal.register(move || {
                let _ = socket.shutdown(Shutdown::Both);
                let _ = wake.wake();
            })
        };
        signal.check()?;
        let shutdown = tcp.try_clone().map_err(failed)?;
        tcp.set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(failed)?;
        let mut wire = if url.scheme() == "wss" {
            let name = rustls::pki_types::ServerName::try_from(
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string(),
            )
            .map_err(failed)?;
            let tls = rustls::ClientConnection::new(self.tls(), name).map_err(failed)?;
            HandshakeWire::Tls {
                stream: Box::new(rustls::StreamOwned::new(tls, tcp)),
            }
        } else {
            HandshakeWire::Plain(tcp)
        };
        let (buffered, protocol) =
            handshake(&mut wire, url, protocols).map_err(|e| match signal.check() {
                Err(aborted) => aborted,
                Ok(()) => e,
            })?;
        // The connector (including Windows' select + SO_ERROR path) has
        // already proved this socket connected. Convert that exact retained
        // handle after the bounded blocking handshake; mio does not reconnect.
        let mut wire = wire.into_nonblocking().map_err(failed)?;
        poll.registry()
            .register(
                wire.tcp_mut(),
                SOCKET_TOKEN,
                Interest::READABLE.add(Interest::WRITABLE),
            )
            .map_err(failed)?;
        let buffered_amount = Arc::new(AtomicUsize::new(0));
        let command_count = Arc::new(AtomicUsize::new(0));
        let send_state = Arc::new(Mutex::new(SendState {
            phase: OPEN,
            queued_bytes: 0,
            queued_messages: 0,
            terminal: None,
        }));
        let (commands, outgoing) = mpsc::sync_channel(MAX_OUTBOUND_COMMANDS);
        let (requests, incoming) = mpsc::sync_channel(1);
        let sender = Arc::new(TcpSender {
            commands,
            wake: Arc::clone(&wake),
            command_count: Arc::clone(&command_count),
            buffered: Arc::clone(&buffered_amount),
            state: Arc::clone(&send_state),
            shutdown: shutdown.try_clone().map_err(failed)?,
        });
        let pump_shutdown = shutdown.try_clone().map_err(failed)?;
        let pump_signal = signal.clone();
        #[cfg(test)]
        let writer_gate = self.writer_gate.clone();
        #[cfg(test)]
        let pump_observer = self.pump_observer.clone();
        let pump_wake = Arc::clone(&wake);
        std::thread::spawn(move || {
            pump_loop(
                wire,
                buffered,
                max_message,
                outgoing,
                incoming,
                poll,
                pump_wake,
                pump_shutdown,
                buffered_amount,
                command_count,
                send_state,
                pump_signal,
                #[cfg(test)]
                writer_gate,
                #[cfg(test)]
                pump_observer,
            )
        });
        Ok(Socket {
            requests,
            wake,
            shutdown,
            signal: signal.clone(),
            _registration: registration,
            sender,
            protocol,
        })
    }
}

/// Send the opening handshake and check the answer. Returns bytes read past
/// the head (the first frames, if the server was quick).
fn handshake(
    wire: &mut HandshakeWire,
    url: &url::Url,
    protocols: &[String],
) -> Result<(Vec<u8>, String), HostError> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(failed)?;
    use base64::Engine as _;
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);
    let serialized_host = match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(url::Host::Ipv4(address)) => address.to_string(),
        Some(url::Host::Domain(domain)) => domain.to_string(),
        None => String::new(),
    };
    let host = match url.port() {
        Some(port) => format!("{serialized_host}:{port}"),
        None => serialized_host,
    };
    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let protocols_header = if protocols.is_empty() {
        String::new()
    } else {
        format!("Sec-WebSocket-Protocol: {}\r\n", protocols.join(", "))
    };
    let head = format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{protocols_header}\r\n"
    );
    wire.write_all(head.as_bytes()).map_err(failed)?;
    wire.flush().map_err(failed)?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(at) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if bytes.len() > MAX_HEAD {
            return Err(failed("the handshake's headers exceed 16 KiB"));
        }
        match wire.read(&mut chunk).map_err(failed)? {
            0 => return Err(failed("the connection closed during the handshake")),
            n => bytes.extend_from_slice(&chunk[..n]),
        }
    };
    let text = String::from_utf8_lossy(&bytes[..end]).into_owned();
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| failed("not an HTTP answer"))?;
    if status != 101 {
        return Err(failed(format!("HTTP {status}")));
    }
    let header = |name: &str| {
        text.split("\r\n").skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    };
    let expected = crate::stdlib::websocket::accept_key(&key);
    let upgrade = header("upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let connection = header("connection").is_some_and(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
    });
    if !upgrade || !connection || header("sec-websocket-accept").as_deref() != Some(&expected) {
        return Err(failed("the server's handshake was not a WebSocket upgrade"));
    }
    if header("sec-websocket-extensions").is_some() {
        return Err(failed("the server chose an extension never offered"));
    }
    let selected = header("sec-websocket-protocol").unwrap_or_default();
    if !selected.is_empty() && !protocols.iter().any(|value| value == &selected) {
        return Err(failed("the server chose a subprotocol never offered"));
    }
    Ok((bytes[end..].to_vec(), selected))
}

struct Socket {
    requests: mpsc::SyncSender<ReceiveRequest>,
    wake: Arc<Waker>,
    shutdown: StdTcpStream,
    signal: AbortSignal,
    _registration: AbortRegistration,
    sender: Arc<TcpSender>,
    protocol: String,
}

fn protocol(what: &str) -> HostError {
    HostError::Failed(format!("the socket broke the protocol: {what}"))
}

enum Command {
    Data {
        opcode: u8,
        payload: Vec<u8>,
        accounted: usize,
    },
    Control {
        opcode: u8,
        payload: Vec<u8>,
    },
}

struct TcpSender {
    commands: mpsc::SyncSender<Command>,
    wake: Arc<Waker>,
    command_count: Arc<AtomicUsize>,
    buffered: Arc<AtomicUsize>,
    state: Arc<Mutex<SendState>>,
    shutdown: StdTcpStream,
}

struct SendState {
    phase: u8,
    queued_bytes: usize,
    queued_messages: usize,
    terminal: Option<Result<Received, HostError>>,
}

enum CommandQueueError {
    Full,
    Closed,
    Wake(std::io::Error),
}

impl CommandQueueError {
    fn host_error(self) -> HostError {
        match self {
            Self::Full => HostError::Failed("the socket's outbound command queue is full".into()),
            Self::Closed => HostError::Failed("the socket is closed".into()),
            Self::Wake(error) => {
                HostError::Failed(format!("the socket wake notification failed: {error}"))
            }
        }
    }
}

impl TcpSender {
    fn queue(&self, state: &mut SendState, command: Command) -> Result<(), CommandQueueError> {
        if self
            .command_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_OUTBOUND_COMMANDS).then_some(count + 1)
            })
            .is_err()
        {
            state.phase = CLOSED;
            let _ = self.shutdown.shutdown(Shutdown::Both);
            let _ = self.wake.wake();
            return Err(CommandQueueError::Full);
        }
        match self.commands.try_send(command) {
            Ok(()) => {
                if let Err(error) = self.wake.wake() {
                    state.phase = CLOSED;
                    let _ = self.shutdown.shutdown(Shutdown::Both);
                    Err(CommandQueueError::Wake(error))
                } else {
                    Ok(())
                }
            }
            Err(mpsc::TrySendError::Full(_)) => {
                self.command_count.fetch_sub(1, Ordering::AcqRel);
                // A peer that does not read can prevent even a close frame
                // from draining. Fail abruptly instead of adding an unbounded
                // control-frame escape hatch beside the data quotas.
                state.phase = CLOSED;
                let _ = self.shutdown.shutdown(Shutdown::Both);
                let _ = self.wake.wake();
                Err(CommandQueueError::Full)
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.command_count.fetch_sub(1, Ordering::AcqRel);
                state.phase = CLOSED;
                let _ = self.shutdown.shutdown(Shutdown::Both);
                let _ = self.wake.wake();
                Err(CommandQueueError::Closed)
            }
        }
    }

    fn enqueue(&self, opcode: u8, payload: &[u8]) -> Result<(), HostError> {
        saturating_add(&self.buffered, payload.len());
        let mut state = self.state.lock().expect("WebSocket sender poisoned");
        if state.phase != OPEN {
            return Ok(());
        }
        if state.queued_bytes.saturating_add(payload.len()) > MAX_OUTBOUND_BYTES
            || state.queued_messages >= MAX_OUTBOUND_MESSAGES
        {
            // WHATWG says a full implementation buffer flags the socket as
            // full and closes the connection. An abrupt local failure keeps
            // memory bounded when even a close frame could sit behind a
            // non-reading peer.
            state.phase = CLOSED;
            drop(state);
            let _ = self.shutdown.shutdown(Shutdown::Both);
            let _ = self.wake.wake();
            return Ok(());
        }
        let queued = self.queue(
            &mut state,
            Command::Data {
                opcode,
                payload: payload.to_vec(),
                accounted: payload.len(),
            },
        );
        if let Err(error) = queued {
            return match error {
                // As with the byte/message quota above, the send which finds
                // a full implementation buffer fails the connection without
                // synchronously throwing into script.
                CommandQueueError::Full => Ok(()),
                CommandQueueError::Closed | CommandQueueError::Wake(_) => Err(error.host_error()),
            };
        }
        state.queued_bytes = state.queued_bytes.saturating_add(payload.len());
        state.queued_messages += 1;
        Ok(())
    }

    fn mark_closed(&self) {
        self.state.lock().expect("WebSocket sender poisoned").phase = CLOSED;
        let _ = self.wake.wake();
    }

    fn phase(&self) -> u8 {
        self.state.lock().expect("WebSocket sender poisoned").phase
    }
}

impl MessageSender for TcpSender {
    fn send_text(&self, text: &str) -> Result<(), HostError> {
        self.enqueue(0x1, text.as_bytes())
    }

    fn send_binary(&self, bytes: &[u8]) -> Result<(), HostError> {
        self.enqueue(0x2, bytes)
    }

    fn close(&self, code: Option<u16>, reason: &str) -> Result<(), HostError> {
        let mut state = self.state.lock().expect("WebSocket sender poisoned");
        if state.phase != OPEN {
            return Ok(());
        }
        state.phase = CLOSING;
        let mut payload = Vec::new();
        if let Some(code) = code {
            payload.extend_from_slice(&code.to_be_bytes());
            payload.extend_from_slice(reason.as_bytes());
        }
        self.queue(
            &mut state,
            Command::Control {
                opcode: 0x8,
                payload,
            },
        )
        .map_err(CommandQueueError::host_error)
    }

    fn buffered_amount(&self) -> usize {
        self.buffered.load(Ordering::Acquire)
    }
}

fn saturating_add(amount: &AtomicUsize, bytes: usize) {
    let _ = amount.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.saturating_add(bytes))
    });
}

/// How long one frame may wait for a peer that is not reading before the
/// connection fails. Short in unit tests so the stall path is exercised.
#[cfg(not(test))]
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(test)]
const WRITE_STALL_TIMEOUT: Duration = Duration::from_millis(500);

struct ReceiveRequest {
    binary_payload: bool,
    reply: mpsc::SyncSender<Result<Received, HostError>>,
}

struct ReceiveOperation {
    binary_payload: bool,
    message: Option<(u8, Vec<u8>)>,
}

struct Input {
    bytes: Vec<u8>,
    at: usize,
}

impl Input {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, at: 0 }
    }

    fn available(&self) -> &[u8] {
        &self.bytes[self.at..]
    }

    fn append(&mut self, bytes: &[u8]) {
        if self.at == self.bytes.len() {
            self.bytes.clear();
            self.at = 0;
        } else if self.at > 0 && self.at >= self.bytes.len() / 2 {
            self.bytes.drain(..self.at);
            self.at = 0;
        }
        self.bytes.extend_from_slice(bytes);
    }

    fn take(&mut self, count: usize) -> Vec<u8> {
        let start = self.at;
        self.at += count;
        self.bytes[start..start + count].to_vec()
    }

    fn discard(&mut self, count: usize) {
        self.at += count;
    }
}

struct ActiveData {
    opcode: u8,
    payload: Vec<u8>,
    accounted: usize,
    next: usize,
}

impl ActiveData {
    fn frame(&mut self) -> std::io::Result<(Vec<u8>, bool)> {
        if self.payload.is_empty() {
            return masked_frame(true, self.opcode, &[]).map(|frame| (frame, true));
        }
        let start = self.next;
        let end = start.saturating_add(FRAGMENT).min(self.payload.len());
        self.next = end;
        let final_fragment = end == self.payload.len();
        masked_frame(
            final_fragment,
            if start == 0 { self.opcode } else { 0 },
            &self.payload[start..end],
        )
        .map(|frame| (frame, final_fragment))
    }
}

enum FrameKind {
    Data { final_fragment: bool },
    Control { opcode: u8 },
}

struct OutgoingFrame {
    bytes: Vec<u8>,
    at: usize,
    kind: FrameKind,
}

struct Control {
    opcode: u8,
    payload: Vec<u8>,
}

enum Parse {
    NeedData(usize),
    Received(Received),
    Yield,
}

enum ControlParse {
    NeedData(usize),
    Data,
    Progress,
    Closed(Received),
    Yield,
}

enum ReadProgress {
    Bytes,
    Eof,
    Blocked,
}

enum WriteProgress {
    Blocked,
    Retry,
    Network(usize),
    Eof,
}

impl Wire {
    fn wants_write(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            Self::Tls { conn, .. } => conn.wants_write(),
        }
    }

    fn read_into(&mut self, input: &mut Input, wanted: usize) -> std::io::Result<ReadProgress> {
        let mut bytes = [0; 16 << 10];
        let wanted = wanted.min(bytes.len());
        match self {
            Self::Plain(tcp) => match tcp.read(&mut bytes[..wanted]) {
                Ok(0) => Ok(ReadProgress::Eof),
                Ok(count) => {
                    input.append(&bytes[..count]);
                    Ok(ReadProgress::Bytes)
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    Ok(ReadProgress::Blocked)
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    Ok(ReadProgress::Bytes)
                }
                Err(error) => Err(error),
            },
            Self::Tls { conn, sock } => match conn.reader().read(&mut bytes[..wanted]) {
                Ok(0) => Ok(ReadProgress::Eof),
                Ok(count) => {
                    input.append(&bytes[..count]);
                    Ok(ReadProgress::Bytes)
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    match conn.read_tls(sock) {
                        Ok(0) => Ok(ReadProgress::Eof),
                        Ok(_) => {
                            conn.process_new_packets().map_err(|error| {
                                std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                            })?;
                            Ok(ReadProgress::Bytes)
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            Ok(ReadProgress::Blocked)
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                            Ok(ReadProgress::Bytes)
                        }
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            },
        }
    }

    fn write_frame(&mut self, frame: &mut OutgoingFrame) -> std::io::Result<WriteProgress> {
        match self {
            Self::Plain(_) if frame.at == frame.bytes.len() => Ok(WriteProgress::Blocked),
            Self::Plain(tcp) => match tcp.write(&frame.bytes[frame.at..]) {
                Ok(0) => Err(std::io::ErrorKind::WriteZero.into()),
                Ok(count) => {
                    frame.at += count;
                    Ok(WriteProgress::Network(count))
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    Ok(WriteProgress::Blocked)
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    Ok(WriteProgress::Retry)
                }
                Err(error) => Err(error),
            },
            Self::Tls { conn, sock } => {
                if conn.wants_write() {
                    return write_tls_progress(conn, sock);
                }
                if frame.at == frame.bytes.len() {
                    return Ok(WriteProgress::Blocked);
                }
                let count = conn.writer().write(&frame.bytes[frame.at..])?;
                if count == 0 {
                    return Err(std::io::ErrorKind::WriteZero.into());
                }
                frame.at += count;
                Ok(WriteProgress::Retry)
            }
        }
    }

    fn frame_flushed(&self, frame: &OutgoingFrame) -> bool {
        frame.at == frame.bytes.len() && !self.wants_write()
    }

    fn write_tls_pending(&mut self) -> std::io::Result<WriteProgress> {
        let Self::Tls { conn, sock } = self else {
            return Ok(WriteProgress::Blocked);
        };
        write_tls_progress(conn, sock)
    }
}

fn write_tls_progress(
    connection: &mut rustls::ClientConnection,
    socket: &mut impl Write,
) -> std::io::Result<WriteProgress> {
    match connection.write_tls(socket) {
        Ok(0) => Ok(WriteProgress::Eof),
        Ok(count) => Ok(WriteProgress::Network(count)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(WriteProgress::Blocked),
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(WriteProgress::Retry),
        Err(error) => Err(error),
    }
}

fn parse_available(
    operation: &mut ReceiveOperation,
    input: &mut Input,
    controls: &mut std::collections::VecDeque<Control>,
    command_count: &AtomicUsize,
    state: &Arc<Mutex<SendState>>,
    limit: usize,
    frames_left: &mut usize,
) -> Result<Parse, HostError> {
    loop {
        if *frames_left == 0 {
            return Ok(Parse::Yield);
        }
        let bytes = input.available();
        if bytes.len() < 2 {
            return Ok(Parse::NeedData(2 - bytes.len()));
        }
        let (fin, opcode) = (bytes[0] & 0x80 != 0, bytes[0] & 0x0f);
        if bytes[0] & 0x70 != 0 || bytes[1] & 0x80 != 0 {
            return Err(protocol("reserved bits, or a masked server frame"));
        }
        let (head, length) = match bytes[1] & 0x7f {
            126 if bytes.len() < 4 => return Ok(Parse::NeedData(4 - bytes.len())),
            126 => (4, u16::from_be_bytes([bytes[2], bytes[3]]) as u64),
            127 if bytes.len() < 10 => return Ok(Parse::NeedData(10 - bytes.len())),
            127 => (10, u64::from_be_bytes(bytes[2..10].try_into().unwrap())),
            length => (2, length as u64),
        };
        if opcode >= 8 && (!fin || length > 125) {
            return Err(protocol("a fragmented or long control frame"));
        }
        // Preserve the receive-only API exact2 already consumes: the first
        // binary frame's declared length returns before its payload is read or
        // allocated. Event consumers use the payload-bearing path below.
        if opcode == 0x2 && operation.message.is_none() && !operation.binary_payload {
            input.discard(head);
            return Ok(Parse::Received(Received::BinaryLength(length as usize)));
        }
        if opcode < 8 {
            match (opcode, &operation.message) {
                (0x1, None) | (0x2, None) => {}
                (0x0, Some(_)) => {}
                _ => return Err(protocol("a frame out of sequence")),
            }
            let so_far = operation
                .message
                .as_ref()
                .map_or(0, |(_, message)| message.len()) as u64;
            if so_far.saturating_add(length) > limit as u64 {
                input.discard(head);
                let mut send = state.lock().expect("WebSocket sender poisoned");
                if send.phase == OPEN {
                    reserve_control(command_count)?;
                    send.phase = CLOSING;
                    controls.push_front(Control {
                        opcode: 0x8,
                        payload: 1009u16.to_be_bytes().to_vec(),
                    });
                }
                return Ok(Parse::Received(Received::TooLarge));
            }
        }
        let Ok(length) = usize::try_from(length) else {
            return Err(protocol("a frame length that does not fit this platform"));
        };
        let frame_length = head.saturating_add(length);
        if input.available().len() < frame_length {
            return Ok(Parse::NeedData(frame_length - input.available().len()));
        }
        input.discard(head);
        let payload = input.take(length);
        *frames_left -= 1;
        if opcode >= 8 {
            match opcode {
                0x8 => {
                    let code = match payload.len() {
                        0 => 1005,
                        1 => return Err(protocol("a one-byte close")),
                        _ => u16::from_be_bytes([payload[0], payload[1]]),
                    };
                    if code != 1005
                        && (!(1000..=4999).contains(&code)
                            || matches!(code, 1004 | 1005 | 1006 | 1015))
                    {
                        return Err(protocol("an invalid close code"));
                    }
                    let reason = std::str::from_utf8(payload.get(2..).unwrap_or(&[]))
                        .map_err(|_| protocol("a close reason that is not UTF-8"))?;
                    let echo = if code == 1005 {
                        vec![]
                    } else {
                        payload.clone()
                    };
                    let mut send = state.lock().expect("WebSocket sender poisoned");
                    if send.phase == OPEN {
                        command_count.fetch_sub(controls.len(), Ordering::AcqRel);
                        controls.clear();
                        reserve_control(command_count)?;
                        send.phase = CLOSING;
                        controls.push_front(Control {
                            opcode: 0x8,
                            payload: echo,
                        });
                    }
                    send.phase = CLOSED;
                    return Ok(Parse::Received(Received::Closed {
                        code,
                        reason: reason.to_string(),
                    }));
                }
                0x9 => {
                    if state.lock().expect("WebSocket sender poisoned").phase == OPEN {
                        reserve_control(command_count)?;
                        controls.push_back(Control {
                            opcode: 0xA,
                            payload,
                        });
                    }
                }
                0xA => {}
                _ => return Err(protocol("an unknown control opcode")),
            }
            continue;
        }
        if matches!(opcode, 0x1 | 0x2) {
            operation.message = Some((opcode, Vec::new()));
        }
        let (_, whole) = operation.message.as_mut().unwrap();
        whole.extend_from_slice(&payload);
        if fin {
            let (kind, bytes) = operation.message.take().unwrap();
            let received = if kind == 0x1 {
                Received::Text(
                    String::from_utf8(bytes)
                        .map_err(|_| protocol("a text message that is not UTF-8"))?,
                )
            } else {
                Received::Binary(bytes)
            };
            return Ok(Parse::Received(received));
        }
    }
}

fn parse_control_prefix(
    input: &mut Input,
    controls: &mut std::collections::VecDeque<Control>,
    command_count: &AtomicUsize,
    state: &Mutex<SendState>,
    frames_left: &mut usize,
) -> Result<ControlParse, HostError> {
    let mut progressed = false;
    loop {
        if *frames_left == 0 {
            return Ok(ControlParse::Yield);
        }
        let bytes = input.available();
        if bytes.len() < 2 {
            return Ok(if progressed {
                ControlParse::Progress
            } else {
                ControlParse::NeedData(2 - bytes.len())
            });
        }
        let (fin, opcode) = (bytes[0] & 0x80 != 0, bytes[0] & 0x0f);
        if opcode < 8 {
            return Ok(if progressed {
                ControlParse::Progress
            } else {
                ControlParse::Data
            });
        }
        if bytes[0] & 0x70 != 0 || bytes[1] & 0x80 != 0 {
            return Err(protocol("reserved bits, or a masked server frame"));
        }
        let (head, length): (usize, usize) = match bytes[1] & 0x7f {
            126 if bytes.len() < 4 => return Ok(ControlParse::NeedData(4 - bytes.len())),
            126 => (4, u16::from_be_bytes([bytes[2], bytes[3]]) as usize),
            127 if bytes.len() < 10 => return Ok(ControlParse::NeedData(10 - bytes.len())),
            127 => {
                let length = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
                let length = usize::try_from(length)
                    .map_err(|_| protocol("a frame length that does not fit this platform"))?;
                (10, length)
            }
            length => (2, length as usize),
        };
        if !fin || length > 125 {
            return Err(protocol("a fragmented or long control frame"));
        }
        let frame_length = head.saturating_add(length);
        if bytes.len() < frame_length {
            return Ok(ControlParse::NeedData(frame_length - bytes.len()));
        }
        input.discard(head);
        let payload = input.take(length);
        *frames_left -= 1;
        progressed = true;
        match opcode {
            0x8 => {
                let code = match payload.len() {
                    0 => 1005,
                    1 => return Err(protocol("a one-byte close")),
                    _ => u16::from_be_bytes([payload[0], payload[1]]),
                };
                if code != 1005
                    && (!(1000..=4999).contains(&code) || matches!(code, 1004 | 1005 | 1006 | 1015))
                {
                    return Err(protocol("an invalid close code"));
                }
                let reason = std::str::from_utf8(payload.get(2..).unwrap_or(&[]))
                    .map_err(|_| protocol("a close reason that is not UTF-8"))?
                    .to_string();
                let echo = if code == 1005 { Vec::new() } else { payload };
                let mut send = state.lock().expect("WebSocket sender poisoned");
                if send.phase == OPEN {
                    command_count.fetch_sub(controls.len(), Ordering::AcqRel);
                    controls.clear();
                    reserve_control(command_count)?;
                    controls.push_front(Control {
                        opcode: 0x8,
                        payload: echo,
                    });
                }
                send.phase = CLOSED;
                return Ok(ControlParse::Closed(Received::Closed { code, reason }));
            }
            0x9 => {
                if state.lock().expect("WebSocket sender poisoned").phase == OPEN {
                    reserve_control(command_count)?;
                    controls.push_back(Control {
                        opcode: 0xA,
                        payload,
                    });
                }
            }
            0xA => {}
            _ => return Err(protocol("an unknown control opcode")),
        }
    }
}

fn reserve_control(command_count: &AtomicUsize) -> Result<(), HostError> {
    command_count
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_OUTBOUND_COMMANDS).then_some(count + 1)
        })
        .map(|_| ())
        .map_err(|_| HostError::Failed("the socket's outbound command queue is full".into()))
}

fn finish_data(
    active: &mut Option<ActiveData>,
    buffered: &AtomicUsize,
    command_count: &AtomicUsize,
    state: &Mutex<SendState>,
) {
    let Some(data) = active.take() else {
        return;
    };
    if data.accounted != 0 {
        buffered.fetch_sub(data.accounted, Ordering::AcqRel);
    }
    command_count.fetch_sub(1, Ordering::AcqRel);
    let mut state = state.lock().expect("WebSocket sender poisoned");
    state.queued_bytes = state.queued_bytes.saturating_sub(data.accounted);
    state.queued_messages = state.queued_messages.saturating_sub(1);
}

fn publish_terminal(
    request: &mut Option<(ReceiveRequest, ReceiveOperation)>,
    requests: &mpsc::Receiver<ReceiveRequest>,
    result: Result<Received, HostError>,
    state: &Mutex<SendState>,
) {
    // Admission holds this same state lock through queue insertion. Once the
    // pump owns it, every request which observed OPEN is either active or
    // visible in `requests`, so a racing EOF cannot turn into channel closure.
    let pending = {
        let mut send = state.lock().expect("WebSocket sender poisoned");
        send.phase = CLOSED;
        let pending = request
            .take()
            .map(|(request, _)| request)
            .or_else(|| requests.try_recv().ok());
        if pending.is_none() {
            send.terminal = Some(result);
            return;
        }
        pending
    };
    if let Some(request) = pending {
        let _ = request.reply.send(result);
    }
}

fn fail_pump(
    request: &mut Option<(ReceiveRequest, ReceiveOperation)>,
    requests: &mpsc::Receiver<ReceiveRequest>,
    error: HostError,
    state: &Mutex<SendState>,
    shutdown: &StdTcpStream,
) {
    publish_terminal(request, requests, Err(error), state);
    let _ = shutdown.shutdown(Shutdown::Both);
}

fn abnormal_close() -> Received {
    Received::Closed {
        code: 1006,
        reason: String::new(),
    }
}

struct BufferedClose {
    received: Received,
    echo: Vec<u8>,
}

fn buffered_close(bytes: &[u8]) -> Result<Option<BufferedClose>, HostError> {
    let mut at = 0usize;
    while bytes.len().saturating_sub(at) >= 2 {
        let first = bytes[at];
        let second = bytes[at + 1];
        let (fin, opcode) = (first & 0x80 != 0, first & 0x0f);
        if first & 0x70 != 0 || second & 0x80 != 0 {
            return Err(protocol("reserved bits, or a masked server frame"));
        }
        let (head, length) = match second & 0x7f {
            126 if bytes.len() - at < 4 => return Ok(None),
            126 => (4, u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]) as u64),
            127 if bytes.len() - at < 10 => return Ok(None),
            127 => (
                10,
                u64::from_be_bytes(bytes[at + 2..at + 10].try_into().unwrap()),
            ),
            length => (2, length as u64),
        };
        if opcode >= 8 && (!fin || length > 125) {
            return Err(protocol("a fragmented or long control frame"));
        }
        let Ok(length) = usize::try_from(length) else {
            return Err(protocol("a frame length that does not fit this platform"));
        };
        let Some(end) = at
            .checked_add(head)
            .and_then(|payload| payload.checked_add(length))
        else {
            return Err(protocol("a frame length that does not fit this platform"));
        };
        if end > bytes.len() {
            return Ok(None);
        }
        if opcode == 0x8 {
            let payload = &bytes[at + head..end];
            let code = match payload.len() {
                0 => 1005,
                1 => return Err(protocol("a one-byte close")),
                _ => u16::from_be_bytes([payload[0], payload[1]]),
            };
            if code != 1005
                && (!(1000..=4999).contains(&code) || matches!(code, 1004 | 1005 | 1006 | 1015))
            {
                return Err(protocol("an invalid close code"));
            }
            let reason = std::str::from_utf8(payload.get(2..).unwrap_or(&[]))
                .map_err(|_| protocol("a close reason that is not UTF-8"))?;
            return Ok(Some(BufferedClose {
                received: Received::Closed {
                    code,
                    reason: reason.to_string(),
                },
                echo: if code == 1005 {
                    Vec::new()
                } else {
                    payload.to_vec()
                },
            }));
        }
        at = end;
    }
    Ok(None)
}

fn stop_polling_tcp(poll: &Poll, wire: &mut Wire, registered: &mut bool) -> Result<(), HostError> {
    if *registered {
        poll.registry()
            .deregister(wire.tcp_mut())
            .map_err(|error| {
                HostError::Failed(format!(
                    "the socket readiness deregistration failed: {error}"
                ))
            })?;
        *registered = false;
    }
    Ok(())
}

#[cfg(test)]
struct PumpExit(Option<Arc<PumpObserver>>);

#[cfg(test)]
impl Drop for PumpExit {
    fn drop(&mut self) {
        if let Some(observer) = &self.0 {
            observer.parked.store(false, Ordering::Release);
            observer.exited.store(true, Ordering::Release);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn pump_loop(
    mut wire: Wire,
    buffered_input: Vec<u8>,
    limit: usize,
    commands: mpsc::Receiver<Command>,
    requests: mpsc::Receiver<ReceiveRequest>,
    mut poll: Poll,
    _wake: Arc<Waker>,
    shutdown: StdTcpStream,
    buffered: Arc<AtomicUsize>,
    command_count: Arc<AtomicUsize>,
    state: Arc<Mutex<SendState>>,
    signal: AbortSignal,
    #[cfg(test)] writer_gate: Option<Arc<(Mutex<bool>, std::sync::Condvar)>>,
    #[cfg(test)] pump_observer: Option<Arc<PumpObserver>>,
) {
    #[cfg(test)]
    let _exit = PumpExit(pump_observer.clone());
    let mut events = Events::with_capacity(8);
    let mut input = Input::new(buffered_input);
    let mut request: Option<(ReceiveRequest, ReceiveOperation)> = None;
    let mut controls = std::collections::VecDeque::new();
    let mut active: Option<ActiveData> = None;
    let mut frame: Option<OutgoingFrame> = None;
    let mut close_written = false;
    let mut ending_after_close = false;
    let mut read_ready = !input.available().is_empty();
    let mut write_ready = true;
    let mut terminal_ready = false;
    let mut tcp_registered = true;
    let mut stall_deadline: Option<Instant> = None;

    loop {
        let mut reschedule_read = false;
        if let Err(error) = signal.check() {
            fail_pump(&mut request, &requests, error, &state, &shutdown);
            return;
        }
        if stall_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            fail_pump(
                &mut request,
                &requests,
                HostError::Failed("the socket write made no progress before its deadline".into()),
                &state,
                &shutdown,
            );
            return;
        }
        if close_written {
            while commands.try_recv().is_ok() {
                command_count.fetch_sub(1, Ordering::AcqRel);
            }
        }
        if request.is_none() {
            match requests.try_recv() {
                Ok(next) => {
                    let operation = ReceiveOperation {
                        binary_payload: next.binary_payload,
                        message: None,
                    };
                    request = Some((next, operation));
                    // A prior readable edge may have been deliberately paused
                    // while there was no receive demand. Nonblocking read is
                    // the authoritative readiness check when demand resumes.
                    read_ready = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    let _ = shutdown.shutdown(Shutdown::Both);
                    return;
                }
            }
        }

        let mut read_wanted = 0;
        let mut read_frames = MAX_READ_FRAMES_PER_TURN;
        if let Some((_, operation)) = request.as_mut() {
            match parse_available(
                operation,
                &mut input,
                &mut controls,
                &command_count,
                &state,
                limit,
                &mut read_frames,
            ) {
                Ok(Parse::Received(received)) => {
                    let is_close = matches!(received, Received::Closed { .. });
                    let (finished, _) = request.take().unwrap();
                    let _ = finished.reply.send(Ok(received));
                    reschedule_read = true;
                    if is_close {
                        ending_after_close = true;
                    }
                }
                Ok(Parse::NeedData(wanted)) => read_wanted = wanted,
                Ok(Parse::Yield) => reschedule_read = true,
                Err(error) => {
                    fail_pump(&mut request, &requests, error, &state, &shutdown);
                    return;
                }
            }
        }

        let background_read = terminal_ready
            || command_count.load(Ordering::Acquire) != 0
            || frame.is_some()
            || wire.wants_write()
            || active.is_some();
        if request.is_none() && !ending_after_close && background_read {
            let mut frames = MAX_READ_FRAMES_PER_TURN;
            match parse_control_prefix(
                &mut input,
                &mut controls,
                &command_count,
                &state,
                &mut frames,
            ) {
                Ok(ControlParse::NeedData(wanted)) => read_wanted = wanted,
                Ok(ControlParse::Data) => {
                    if !terminal_ready {
                        // Preserve receive backpressure and the legacy binary
                        // head-only contract until demand is posted.
                        read_ready = false;
                    }
                }
                Ok(ControlParse::Progress | ControlParse::Yield) => {
                    reschedule_read = true;
                }
                Ok(ControlParse::Closed(received)) => {
                    publish_terminal(&mut request, &requests, Ok(received), &state);
                    ending_after_close = true;
                    reschedule_read = true;
                }
                Err(error) => {
                    fail_pump(&mut request, &requests, error, &state, &shutdown);
                    return;
                }
            }
        }

        let should_read = read_ready
            && !ending_after_close
            && !reschedule_read
            && (request.is_some() || background_read);
        if should_read {
            let wanted = if request.is_some() {
                read_wanted.max(1)
            } else {
                16 << 10
            };
            match wire.read_into(&mut input, wanted) {
                Ok(ReadProgress::Bytes) => reschedule_read = true,
                Ok(ReadProgress::Blocked) if !terminal_ready => read_ready = false,
                Ok(ReadProgress::Blocked | ReadProgress::Eof) | Err(_) => {
                    if signal.aborted() {
                        fail_pump(
                            &mut request,
                            &requests,
                            signal.check().unwrap_err(),
                            &state,
                            &shutdown,
                        );
                        return;
                    }
                    let terminal = match buffered_close(input.available()) {
                        Ok(Some(close)) => {
                            let send = state.lock().expect("WebSocket sender poisoned");
                            if send.phase == OPEN {
                                command_count.fetch_sub(controls.len(), Ordering::AcqRel);
                                controls.clear();
                                if let Err(error) = reserve_control(&command_count) {
                                    drop(send);
                                    fail_pump(&mut request, &requests, error, &state, &shutdown);
                                    return;
                                }
                                controls.push_front(Control {
                                    opcode: 0x8,
                                    payload: close.echo,
                                });
                            }
                            drop(send);
                            close.received
                        }
                        Ok(None) => abnormal_close(),
                        Err(error) => {
                            fail_pump(&mut request, &requests, error, &state, &shutdown);
                            return;
                        }
                    };
                    if let Err(error) = stop_polling_tcp(&poll, &mut wire, &mut tcp_registered) {
                        fail_pump(&mut request, &requests, error, &state, &shutdown);
                        return;
                    }
                    let has_close =
                        matches!(terminal, Received::Closed { code, .. } if code != 1006);
                    publish_terminal(&mut request, &requests, Ok(terminal), &state);
                    if has_close && !controls.is_empty() {
                        ending_after_close = true;
                    } else {
                        let _ = shutdown.shutdown(Shutdown::Both);
                        return;
                    }
                }
            }
        }

        if frame.is_none() && !wire.wants_write() {
            if let Some(control) = controls.pop_front() {
                match masked_frame(true, control.opcode, &control.payload) {
                    Ok(bytes) => {
                        frame = Some(OutgoingFrame {
                            bytes,
                            at: 0,
                            kind: FrameKind::Control {
                                opcode: control.opcode,
                            },
                        });
                    }
                    Err(error) => {
                        fail_pump(
                            &mut request,
                            &requests,
                            HostError::Failed(error.to_string()),
                            &state,
                            &shutdown,
                        );
                        return;
                    }
                }
            } else if !close_written {
                if active.is_none() {
                    match commands.try_recv() {
                        Ok(Command::Data {
                            opcode,
                            payload,
                            accounted,
                        }) => {
                            active = Some(ActiveData {
                                opcode,
                                payload,
                                accounted,
                                next: 0,
                            });
                        }
                        Ok(Command::Control { opcode, payload }) => {
                            match masked_frame(true, opcode, &payload) {
                                Ok(bytes) => {
                                    frame = Some(OutgoingFrame {
                                        bytes,
                                        at: 0,
                                        kind: FrameKind::Control { opcode },
                                    });
                                }
                                Err(error) => {
                                    fail_pump(
                                        &mut request,
                                        &requests,
                                        HostError::Failed(error.to_string()),
                                        &state,
                                        &shutdown,
                                    );
                                    return;
                                }
                            }
                        }
                        Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => {}
                    }
                }
                if frame.is_none() {
                    if let Some(data) = active.as_mut() {
                        match data.frame() {
                            Ok((bytes, final_fragment)) => {
                                frame = Some(OutgoingFrame {
                                    bytes,
                                    at: 0,
                                    kind: FrameKind::Data { final_fragment },
                                });
                            }
                            Err(error) => {
                                fail_pump(
                                    &mut request,
                                    &requests,
                                    HostError::Failed(error.to_string()),
                                    &state,
                                    &shutdown,
                                );
                                return;
                            }
                        }
                    }
                }
            }
        }

        let writes_allowed = {
            #[cfg(test)]
            {
                writer_gate
                    .as_ref()
                    .is_none_or(|gate| *gate.0.lock().expect("WebSocket writer gate poisoned"))
            }
            #[cfg(not(test))]
            {
                true
            }
        };
        let pending_before_write = frame.is_some() || wire.wants_write();
        if pending_before_write {
            stall_deadline.get_or_insert_with(|| Instant::now() + WRITE_STALL_TIMEOUT);
        }
        let mut retry_write = false;
        if writes_allowed {
            if let Some(outgoing) = frame.as_mut() {
                let can_attempt = match &wire {
                    Wire::Plain(_) => write_ready,
                    Wire::Tls { conn, .. } => !conn.wants_write() || write_ready,
                };
                match can_attempt.then(|| wire.write_frame(outgoing)).transpose() {
                    Ok(None) => {}
                    Ok(Some(WriteProgress::Eof)) => {
                        publish_terminal(&mut request, &requests, Ok(abnormal_close()), &state);
                        let _ = shutdown.shutdown(Shutdown::Both);
                        return;
                    }
                    Ok(Some(WriteProgress::Network(_bytes))) => {
                        stall_deadline = Some(Instant::now() + WRITE_STALL_TIMEOUT);
                        retry_write = true;
                        #[cfg(test)]
                        if let Some(observer) = &pump_observer {
                            observer.network_bytes.fetch_add(_bytes, Ordering::AcqRel);
                        }
                    }
                    Ok(Some(WriteProgress::Retry)) => retry_write = true,
                    Ok(Some(WriteProgress::Blocked)) => write_ready = false,
                    Err(error) => {
                        fail_pump(
                            &mut request,
                            &requests,
                            HostError::Failed(format!("the socket write failed: {error}")),
                            &state,
                            &shutdown,
                        );
                        return;
                    }
                }
                if wire.frame_flushed(outgoing) {
                    let completed = frame.take().unwrap();
                    match completed.kind {
                        FrameKind::Data { final_fragment } if final_fragment => {
                            finish_data(&mut active, &buffered, &command_count, &state);
                        }
                        FrameKind::Data { .. } => {}
                        FrameKind::Control { opcode: 0x8 } => {
                            command_count.fetch_sub(1, Ordering::AcqRel);
                            close_written = true;
                            if active.take().is_some() {
                                command_count.fetch_sub(1, Ordering::AcqRel);
                            }
                        }
                        FrameKind::Control { .. } => {
                            command_count.fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    retry_write = true;
                }
            } else if wire.wants_write() && write_ready {
                match wire.write_tls_pending() {
                    Ok(WriteProgress::Eof) => {
                        publish_terminal(&mut request, &requests, Ok(abnormal_close()), &state);
                        let _ = shutdown.shutdown(Shutdown::Both);
                        return;
                    }
                    Ok(WriteProgress::Network(_bytes)) => {
                        stall_deadline = Some(Instant::now() + WRITE_STALL_TIMEOUT);
                        retry_write = true;
                        #[cfg(test)]
                        if let Some(observer) = &pump_observer {
                            observer.network_bytes.fetch_add(_bytes, Ordering::AcqRel);
                        }
                    }
                    Ok(WriteProgress::Retry) => retry_write = true,
                    Ok(WriteProgress::Blocked) => write_ready = false,
                    Err(error) => {
                        fail_pump(
                            &mut request,
                            &requests,
                            HostError::Failed(format!("the socket write failed: {error}")),
                            &state,
                            &shutdown,
                        );
                        return;
                    }
                }
            }
        }

        let pending_write = frame.is_some() || wire.wants_write();
        if !pending_write {
            stall_deadline = None;
        }
        if ending_after_close && close_written && !pending_write {
            let _ = shutdown.shutdown(Shutdown::Both);
            return;
        }
        // Read/parse work is deliberately bounded. Service writes and their
        // no-progress deadline first, then consume the next inbound batch
        // without entering the readiness wait while bytes are already local.
        if reschedule_read || retry_write {
            continue;
        }
        // Command admission increments before waking. Recheck immediately
        // before parking so an already-visible command does not depend on a
        // coalesced Waker notification.
        if command_count.load(Ordering::Acquire) != 0 && !pending_write {
            continue;
        }
        #[cfg(test)]
        if let Some(observer) = &pump_observer {
            observer.parked.store(true, Ordering::Release);
        }
        let timeout =
            stall_deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        let waited = poll.poll(&mut events, timeout);
        #[cfg(test)]
        if let Some(observer) = &pump_observer {
            observer.parked.store(false, Ordering::Release);
            observer.returns.fetch_add(1, Ordering::AcqRel);
        }
        match waited {
            Ok(()) => {
                for event in &events {
                    if event.token() == SOCKET_TOKEN {
                        read_ready |= event.is_readable();
                        write_ready |= event.is_writable();
                        if event.is_error() || event.is_read_closed() || event.is_write_closed() {
                            terminal_ready = true;
                            read_ready = true;
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                fail_pump(
                    &mut request,
                    &requests,
                    HostError::Failed(format!("the socket readiness wait failed: {error}")),
                    &state,
                    &shutdown,
                );
                return;
            }
        }
    }
}

fn masked_frame(fin: bool, opcode: u8, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut mask = [0u8; 4];
    getrandom::getrandom(&mut mask).map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut frame = Vec::with_capacity(payload.len().saturating_add(14));
    frame.push((if fin { 0x80 } else { 0 }) | opcode);
    match payload.len() {
        length if length < 126 => frame.push(0x80 | length as u8),
        length if length <= u16::MAX as usize => {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(&mask);
    frame.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ mask[index % 4]),
    );
    Ok(frame)
}

enum Received {
    Text(String),
    Binary(Vec<u8>),
    BinaryLength(usize),
    TooLarge,
    Closed { code: u16, reason: String },
}

impl Socket {
    fn receive(&mut self, binary_payload: bool) -> Result<Received, HostError> {
        self.signal.check()?;
        let mut state = self.sender.state.lock().expect("WebSocket sender poisoned");
        if let Some(terminal) = state.terminal.take() {
            return terminal;
        }
        if state.phase == CLOSED {
            return Ok(abnormal_close());
        }
        let (reply, received) = mpsc::sync_channel(1);
        if self
            .requests
            .send(ReceiveRequest {
                binary_payload,
                reply,
            })
            .is_err()
        {
            state.phase = CLOSED;
            return Ok(abnormal_close());
        }
        if let Err(error) = self.wake.wake() {
            state.phase = CLOSED;
            drop(state);
            let _ = self.shutdown.shutdown(Shutdown::Both);
            return Err(HostError::Failed(format!(
                "the socket wake notification failed: {error}"
            )));
        }
        drop(state);
        match received.recv() {
            Ok(result) => result,
            Err(_) => {
                self.signal.check()?;
                let mut state = self.sender.state.lock().expect("WebSocket sender poisoned");
                state
                    .terminal
                    .take()
                    .unwrap_or_else(|| Ok(abnormal_close()))
            }
        }
    }
}

impl MessageSource for Socket {
    fn next(&mut self) -> Result<Incoming, HostError> {
        Ok(match self.receive(false)? {
            Received::Text(text) => Incoming::Text(text),
            Received::Binary(bytes) => Incoming::Binary(bytes.len()),
            Received::BinaryLength(length) => Incoming::Binary(length),
            Received::TooLarge => Incoming::TooLarge,
            Received::Closed { code, reason } => Incoming::Closed { code, reason },
        })
    }

    fn next_event(&mut self) -> Result<Event, HostError> {
        Ok(match self.receive(true)? {
            Received::Text(text) => Event::Message(Message::Text(text)),
            Received::Binary(bytes) => Event::Message(Message::Binary(bytes)),
            Received::BinaryLength(_) => unreachable!("event receive requested binary bytes"),
            Received::TooLarge => {
                return Err(HostError::Failed(
                    "the socket message exceeded its configured limit".into(),
                ));
            }
            Received::Closed { code, reason } => Event::Close {
                code,
                reason,
                was_clean: code != 1006,
            },
        })
    }

    fn sender(&self) -> Option<Arc<dyn MessageSender>> {
        Some(self.sender.clone())
    }

    fn protocol(&self) -> &str {
        &self.protocol
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        if self.sender.phase() == OPEN && !self.signal.aborted() {
            let _ = self.sender.close(Some(1000), "");
        }
        self.sender.mark_closed();
        let _ = self.shutdown.shutdown(Shutdown::Both);
        let _ = self.wake.wake();
    }
}

#[cfg(any(test, feature = "test-support"))]
#[path = "websocket_tests.rs"]
pub mod tests;
