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
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc, Mutex,
};
use std::time::{Duration, Instant};

#[path = "websocket_ready.rs"]
mod readiness;

const MAX_HEAD: usize = 16 << 10;
const FRAGMENT: usize = 16 << 10;
const MAX_OUTBOUND_BYTES: usize = 16 << 20;
const MAX_OUTBOUND_MESSAGES: usize = 256;
// @ref LLP 0059.000#312-websocket--delegating-capability-bearing-author-required — data and control frames share one bounded command channel
const MAX_OUTBOUND_COMMANDS: usize = MAX_OUTBOUND_MESSAGES + 16;
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
    returns: AtomicUsize,
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

enum Wire {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Wire {
    fn tcp(&self) -> &TcpStream {
        match self {
            Self::Plain(tcp) => tcp,
            Self::Tls(tls) => &tls.sock,
        }
    }
}

impl Read for Wire {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Wire::Plain(s) => s.read(out),
            Wire::Tls(s) => s.read(out),
        }
    }
}
impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Wire::Plain(s) => s.write(bytes),
            Wire::Tls(s) => s.write(bytes),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Wire::Plain(s) => s.flush(),
            Wire::Tls(s) => s.flush(),
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
        // Aborting shuts the connection down, which ends any blocked read.
        let registration = {
            let socket = tcp.try_clone().map_err(failed)?;
            signal.register(move || {
                let _ = socket.shutdown(Shutdown::Both);
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
            Wire::Tls(Box::new(rustls::StreamOwned::new(tls, tcp)))
        } else {
            Wire::Plain(tcp)
        };
        let (buffered, protocol) =
            handshake(&mut wire, url, protocols).map_err(|e| match signal.check() {
                Err(aborted) => aborted,
                Ok(()) => e,
            })?;
        // After the bounded blocking handshake, one pump owns the retained
        // handle and drives both directions from readiness. Socket timeout
        // options are deliberately cleared: the no-progress deadline below
        // is the only write-stall clock, and an idle read blocks in poll.
        wire.tcp().set_read_timeout(None).map_err(failed)?;
        wire.tcp().set_write_timeout(None).map_err(failed)?;
        wire.tcp().set_nonblocking(true).map_err(failed)?;
        let buffered_amount = Arc::new(AtomicUsize::new(0));
        let command_count = Arc::new(AtomicUsize::new(0));
        let send_state = Arc::new(Mutex::new(SendState {
            phase: OPEN,
            queued_bytes: 0,
            queued_messages: 0,
        }));
        let (commands, outgoing) = mpsc::sync_channel(MAX_OUTBOUND_COMMANDS);
        let (requests, incoming) = mpsc::sync_channel(1);
        let (wake, waiter) = readiness::pair().map_err(failed)?;
        let sender = Arc::new(TcpSender {
            commands,
            wake: wake.clone(),
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
        std::thread::spawn(move || {
            pump_loop(
                wire,
                buffered,
                max_message,
                outgoing,
                incoming,
                waiter,
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
    wire: &mut Wire,
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
    wake: readiness::Wake,
    shutdown: TcpStream,
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
    wake: readiness::Wake,
    command_count: Arc<AtomicUsize>,
    buffered: Arc<AtomicUsize>,
    state: Arc<Mutex<SendState>>,
    shutdown: TcpStream,
}

struct SendState {
    phase: u8,
    queued_bytes: usize,
    queued_messages: usize,
}

enum CommandQueueError {
    Full,
    Closed,
}

impl CommandQueueError {
    fn host_error(self) -> HostError {
        match self {
            Self::Full => HostError::Failed("the socket's outbound command queue is full".into()),
            Self::Closed => HostError::Failed("the socket is closed".into()),
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
            return Err(CommandQueueError::Full);
        }
        match self.commands.try_send(command) {
            Ok(()) => {
                self.wake.notify();
                Ok(())
            }
            Err(mpsc::TrySendError::Full(_)) => {
                self.command_count.fetch_sub(1, Ordering::AcqRel);
                // A peer that does not read can prevent even a close frame
                // from draining. Fail abruptly instead of adding an unbounded
                // control-frame escape hatch beside the data quotas.
                state.phase = CLOSED;
                let _ = self.shutdown.shutdown(Shutdown::Both);
                Err(CommandQueueError::Full)
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.command_count.fetch_sub(1, Ordering::AcqRel);
                state.phase = CLOSED;
                let _ = self.shutdown.shutdown(Shutdown::Both);
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
                CommandQueueError::Closed => Err(error.host_error()),
            };
        }
        state.queued_bytes = state.queued_bytes.saturating_add(payload.len());
        state.queued_messages += 1;
        Ok(())
    }

    fn mark_closed(&self) {
        self.state.lock().expect("WebSocket sender poisoned").phase = CLOSED;
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
    NeedData,
    Received(Received),
}

enum ReadProgress {
    Bytes,
    Eof,
    Blocked,
}

struct WriteProgress {
    advanced: bool,
    network_bytes: usize,
}

impl Wire {
    fn wants_write(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            Self::Tls(tls) => tls.conn.wants_write(),
        }
    }

    fn read_into(&mut self, input: &mut Input) -> std::io::Result<ReadProgress> {
        let mut bytes = [0; 16 << 10];
        match self {
            Self::Plain(tcp) => match tcp.read(&mut bytes) {
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
            Self::Tls(tls) => match tls.conn.reader().read(&mut bytes) {
                Ok(0) => Ok(ReadProgress::Eof),
                Ok(count) => {
                    input.append(&bytes[..count]);
                    Ok(ReadProgress::Bytes)
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    match tls.conn.read_tls(&mut tls.sock) {
                        Ok(0) => Ok(ReadProgress::Eof),
                        Ok(_) => {
                            tls.conn.process_new_packets().map_err(|error| {
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
            Self::Plain(_) if frame.at == frame.bytes.len() => Ok(WriteProgress {
                advanced: false,
                network_bytes: 0,
            }),
            Self::Plain(tcp) => match tcp.write(&frame.bytes[frame.at..]) {
                Ok(0) => Err(std::io::ErrorKind::WriteZero.into()),
                Ok(count) => {
                    frame.at += count;
                    Ok(WriteProgress {
                        advanced: true,
                        network_bytes: count,
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(WriteProgress {
                    advanced: false,
                    network_bytes: 0,
                }),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    Ok(WriteProgress {
                        advanced: true,
                        network_bytes: 0,
                    })
                }
                Err(error) => Err(error),
            },
            Self::Tls(tls) => {
                if tls.conn.wants_write() {
                    return match tls.conn.write_tls(&mut tls.sock) {
                        Ok(0) => Err(std::io::ErrorKind::WriteZero.into()),
                        Ok(count) => Ok(WriteProgress {
                            advanced: true,
                            network_bytes: count,
                        }),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            Ok(WriteProgress {
                                advanced: false,
                                network_bytes: 0,
                            })
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                            Ok(WriteProgress {
                                advanced: true,
                                network_bytes: 0,
                            })
                        }
                        Err(error) => Err(error),
                    };
                }
                if frame.at == frame.bytes.len() {
                    return Ok(WriteProgress {
                        advanced: false,
                        network_bytes: 0,
                    });
                }
                let count = tls.conn.writer().write(&frame.bytes[frame.at..])?;
                if count == 0 {
                    return Err(std::io::ErrorKind::WriteZero.into());
                }
                frame.at += count;
                Ok(WriteProgress {
                    advanced: true,
                    network_bytes: 0,
                })
            }
        }
    }

    fn frame_flushed(&self, frame: &OutgoingFrame) -> bool {
        frame.at == frame.bytes.len() && !self.wants_write()
    }

    fn write_tls_pending(&mut self) -> std::io::Result<WriteProgress> {
        let Self::Tls(tls) = self else {
            return Ok(WriteProgress {
                advanced: false,
                network_bytes: 0,
            });
        };
        match tls.conn.write_tls(&mut tls.sock) {
            Ok(0) => Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => Ok(WriteProgress {
                advanced: true,
                network_bytes: count,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(WriteProgress {
                advanced: false,
                network_bytes: 0,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => Ok(WriteProgress {
                advanced: true,
                network_bytes: 0,
            }),
            Err(error) => Err(error),
        }
    }
}

fn parse_available(
    operation: &mut ReceiveOperation,
    input: &mut Input,
    controls: &mut std::collections::VecDeque<Control>,
    command_count: &AtomicUsize,
    state: &Arc<Mutex<SendState>>,
    limit: usize,
) -> Result<Parse, HostError> {
    loop {
        let bytes = input.available();
        if bytes.len() < 2 {
            return Ok(Parse::NeedData);
        }
        let (fin, opcode) = (bytes[0] & 0x80 != 0, bytes[0] & 0x0f);
        if bytes[0] & 0x70 != 0 || bytes[1] & 0x80 != 0 {
            return Err(protocol("reserved bits, or a masked server frame"));
        }
        let (head, length) = match bytes[1] & 0x7f {
            126 if bytes.len() < 4 => return Ok(Parse::NeedData),
            126 => (4, u16::from_be_bytes([bytes[2], bytes[3]]) as u64),
            127 if bytes.len() < 10 => return Ok(Parse::NeedData),
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
        if input.available().len() < head.saturating_add(length) {
            return Ok(Parse::NeedData);
        }
        input.discard(head);
        let payload = input.take(length);
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
                    reserve_control(command_count)?;
                    controls.push_back(Control {
                        opcode: 0xA,
                        payload,
                    });
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

fn fail_pump(
    request: &mut Option<(ReceiveRequest, ReceiveOperation)>,
    error: HostError,
    state: &Mutex<SendState>,
    shutdown: &TcpStream,
) {
    state.lock().expect("WebSocket sender poisoned").phase = CLOSED;
    if let Some((request, _)) = request.take() {
        let _ = request.reply.send(Err(error));
    }
    let _ = shutdown.shutdown(Shutdown::Both);
}

#[allow(clippy::too_many_arguments)]
fn pump_loop(
    mut wire: Wire,
    buffered_input: Vec<u8>,
    limit: usize,
    commands: mpsc::Receiver<Command>,
    requests: mpsc::Receiver<ReceiveRequest>,
    waiter: readiness::Waiter,
    shutdown: TcpStream,
    buffered: Arc<AtomicUsize>,
    command_count: Arc<AtomicUsize>,
    state: Arc<Mutex<SendState>>,
    signal: AbortSignal,
    #[cfg(test)] writer_gate: Option<Arc<(Mutex<bool>, std::sync::Condvar)>>,
    #[cfg(test)] pump_observer: Option<Arc<PumpObserver>>,
) {
    let mut input = Input::new(buffered_input);
    let mut request: Option<(ReceiveRequest, ReceiveOperation)> = None;
    let mut controls = std::collections::VecDeque::new();
    let mut active: Option<ActiveData> = None;
    let mut frame: Option<OutgoingFrame> = None;
    let mut close_written = false;
    let mut last_write_progress: Option<Instant> = None;

    loop {
        if let Err(error) = signal.check() {
            fail_pump(&mut request, error, &state, &shutdown);
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
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => return,
            }
        }

        if let Some((_, operation)) = request.as_mut() {
            match parse_available(
                operation,
                &mut input,
                &mut controls,
                &command_count,
                &state,
                limit,
            ) {
                Ok(Parse::Received(received)) => {
                    let (finished, _) = request.take().unwrap();
                    let _ = finished.reply.send(Ok(received));
                    continue;
                }
                Ok(Parse::NeedData) => {}
                Err(error) => {
                    fail_pump(&mut request, error, &state, &shutdown);
                    return;
                }
            }
        }

        if request.is_some() {
            match wire.read_into(&mut input) {
                Ok(ReadProgress::Bytes) => continue,
                Ok(ReadProgress::Eof) => {
                    state.lock().expect("WebSocket sender poisoned").phase = CLOSED;
                    let received = if signal.aborted() {
                        Err(signal.check().unwrap_err())
                    } else {
                        Ok(Received::Closed {
                            code: 1006,
                            reason: String::new(),
                        })
                    };
                    if let Some((finished, _)) = request.take() {
                        let _ = finished.reply.send(received);
                    }
                    let _ = shutdown.shutdown(Shutdown::Both);
                    return;
                }
                Ok(ReadProgress::Blocked) => {}
                Err(_) if signal.aborted() => {
                    fail_pump(&mut request, signal.check().unwrap_err(), &state, &shutdown);
                    return;
                }
                Err(_) => {
                    state.lock().expect("WebSocket sender poisoned").phase = CLOSED;
                    if let Some((finished, _)) = request.take() {
                        let _ = finished.reply.send(Ok(Received::Closed {
                            code: 1006,
                            reason: String::new(),
                        }));
                    }
                    let _ = shutdown.shutdown(Shutdown::Both);
                    return;
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
        if writes_allowed {
            if let Some(outgoing) = frame.as_mut() {
                match wire.write_frame(outgoing) {
                    Ok(progress) => {
                        if progress.network_bytes != 0 {
                            last_write_progress = Some(Instant::now());
                        }
                        if progress.advanced {
                            continue;
                        }
                    }
                    Err(error) => {
                        fail_pump(
                            &mut request,
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
                    last_write_progress = None;
                    continue;
                }
            } else if wire.wants_write() {
                match wire.write_tls_pending() {
                    Ok(progress) => {
                        if progress.network_bytes != 0 {
                            last_write_progress = Some(Instant::now());
                        }
                        if progress.advanced {
                            continue;
                        }
                    }
                    Err(error) => {
                        fail_pump(
                            &mut request,
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
        let timeout = if pending_write {
            let last = *last_write_progress.get_or_insert_with(Instant::now);
            let elapsed = last.elapsed();
            if elapsed >= WRITE_STALL_TIMEOUT {
                fail_pump(
                    &mut request,
                    HostError::Failed(
                        "the socket write made no progress before its deadline".into(),
                    ),
                    &state,
                    &shutdown,
                );
                return;
            }
            Some(WRITE_STALL_TIMEOUT - elapsed)
        } else {
            last_write_progress = None;
            None
        };
        #[cfg(test)]
        if let Some(observer) = &pump_observer {
            observer.parked.store(true, Ordering::Release);
        }
        let waited = waiter.wait(
            wire.tcp(),
            request.is_some(),
            pending_write && writes_allowed,
            timeout,
        );
        #[cfg(test)]
        if let Some(observer) = &pump_observer {
            observer.parked.store(false, Ordering::Release);
            observer.returns.fetch_add(1, Ordering::AcqRel);
        }
        match waited {
            Ok(ready) => {
                // With no read interest, a TCP read indication can only be a
                // terminal poll condition. Do not spin forever on an idle
                // connection whose peer disappeared between receive calls.
                if ready.socket_readable && request.is_none() {
                    state.lock().expect("WebSocket sender poisoned").phase = CLOSED;
                    let _ = shutdown.shutdown(Shutdown::Both);
                    return;
                }
                let _ = (ready.socket_writable, ready.woken);
            }
            Err(error) => {
                fail_pump(
                    &mut request,
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
        if self.sender.phase() == CLOSED {
            return Ok(Received::Closed {
                code: 1006,
                reason: String::new(),
            });
        }
        self.signal.check()?;
        let (reply, received) = mpsc::sync_channel(1);
        self.requests
            .send(ReceiveRequest {
                binary_payload,
                reply,
            })
            .map_err(|_| HostError::Failed("the socket is closed".into()))?;
        self.wake.notify();
        received.recv().map_err(|_| {
            self.signal.check().err().unwrap_or_else(|| {
                HostError::Failed("the socket closed before delivering a message".into())
            })
        })?
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
        self.wake.notify();
    }
}

#[cfg(any(test, feature = "test-support"))]
#[path = "websocket_tests.rs"]
pub mod tests;
