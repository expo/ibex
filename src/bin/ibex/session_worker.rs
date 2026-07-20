//! Authenticated supervisor/worker transport for terminal-owned sessions.
//!
//! The implementation in this module is intentionally private to the CLI. It
//! never becomes a JavaScript surface.
//! @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker

#![allow(dead_code)]

pub(crate) mod bounded_lane;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

pub(crate) const WORKER_BOOTSTRAP_ARG: &str = "__ibex-session-worker-v1";
pub(crate) const WORKER_BOOTSTRAP_SURFACE_ID: &str = "private:ibex:session-worker-bootstrap:v1";

const WIRE_MAGIC: [u8; 4] = *b"IBSW";
const WIRE_VERSION: u16 = 3;
const WIRE_HEADER_BYTES: usize = 48;
const WIRE_MAC_BYTES: usize = 32;
const FRAME_MAC_DOMAIN: &[u8] = b"ibex-session-worker-frame-v1\0";
const ROOT_PROOF_DOMAIN: &[u8] = b"ibex-session-root-equality-v1\0";
const SESSION_PROOF_DOMAIN: &[u8] = b"ibex-session-armed-binding-v1\0";
const MAX_BOOTSTRAP_CONFIG_BYTES: usize = 64 * 1024;
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_EVENT_PAYLOAD_BYTES: usize = 1024 * 1024;
const MAX_DISPLAY_BYTES: usize = 16 * 1024 * 1024;
const LIFECYCLE_ACK_TIMEOUT: Duration = Duration::from_secs(2);
const WORKER_EVENT_WRITE_TIMEOUT: Duration = Duration::from_millis(50);
#[cfg(unix)]
const CONTROL_FRAME_READ_TIMEOUT: Duration = Duration::from_millis(250);
#[cfg(unix)]
const SUPERVISOR_FRAME_WRITE_TIMEOUT: Duration = Duration::from_millis(100);

#[cfg(unix)]
const CONTROL_FD: i32 = 3;
#[cfg(unix)]
const BOOTSTRAP_FD: i32 = 4;
#[cfg(unix)]
const ROOT_FD: i32 = 5;
#[cfg(unix)]
const WATCHDOG_FD: i32 = 6;

#[derive(Debug, Error)]
pub(crate) enum WorkerProtocolError {
    #[error("session-worker transport I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("session-worker frame ended before its declared boundary")]
    Truncated,
    #[error("session-worker channel closed")]
    CleanEof,
    #[error("session-worker frame has invalid magic")]
    InvalidMagic,
    #[error("session-worker frame version {0} is unsupported")]
    UnsupportedVersion(u16),
    #[error("session-worker frame has nonzero reserved flags")]
    InvalidFlags,
    #[error("session-worker frame kind {0} is unknown")]
    UnknownKind(u16),
    #[error("session-worker frame direction is invalid for this endpoint")]
    WrongDirection,
    #[error("session-worker frame belongs to the wrong channel epoch")]
    WrongEpoch,
    #[error(
        "session-worker frame sequence was replayed or skipped (expected {expected}, got {actual})"
    )]
    BadSequence { expected: u64, actual: u64 },
    #[error("session-worker frame authentication failed")]
    BadMac,
    #[error("session-worker frame is larger than the bound for its kind")]
    Oversize,
    #[error("session-worker message is malformed: {0}")]
    Malformed(&'static str),
    #[error("session-worker bootstrap was invoked without its inherited authority")]
    UnauthorizedBootstrap,
    #[error("session-worker bootstrap does not name the spawning parent")]
    WrongParent,
    #[error("session-worker inherited root is not the authenticated project object")]
    WrongRoot,
    #[error("session-worker armed-session binding differs from the supervisor binding")]
    WrongSession,
    #[error("session-worker lifecycle record conflicts with an accepted request")]
    ConflictingLifecycleRecord,
    #[error("session-worker exit-code mirror is missing or out of order")]
    ExitCodeMirrorGap,
    #[error("session-worker event queue is applying backpressure")]
    Backpressure,
    #[error("session-worker child died before the authenticated bootstrap completed")]
    WorkerDied,
    #[error("session-worker platform implementation is unavailable")]
    UnsupportedPlatform,
}

/// Opaque binding to the exact armed session. Its custom Debug intentionally
/// reveals neither the fresh run nonce nor the snapshot digest.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ArmedSessionBinding {
    run_nonce: [u8; 16],
    snapshot_digest: [u8; 32],
}

impl fmt::Debug for ArmedSessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArmedSessionBinding([redacted])")
    }
}

impl ArmedSessionBinding {
    pub(crate) const fn new(run_nonce: [u8; 16], snapshot_digest: [u8; 32]) -> Self {
        Self {
            run_nonce,
            snapshot_digest,
        }
    }

    pub(crate) fn from_snapshot(
        snapshot: &capsec_semantics::arming::ArmedSnapshot,
    ) -> Result<Self, WorkerProtocolError> {
        use base64::Engine as _;

        let nonce = snapshot
            .document()
            .get("runNonce")
            .and_then(serde_json::Value::as_str)
            .ok_or(WorkerProtocolError::Malformed(
                "armed snapshot has no runNonce",
            ))?;
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(nonce)
            .map_err(|_| WorkerProtocolError::Malformed("runNonce is not base64url"))?;
        let run_nonce: [u8; 16] = nonce
            .try_into()
            .map_err(|_| WorkerProtocolError::Malformed("runNonce is not 16 bytes"))?;

        let digest = snapshot.digest().as_str().strip_prefix("sha256-").ok_or(
            WorkerProtocolError::Malformed("armed snapshot digest has the wrong domain"),
        )?;
        let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(digest)
            .map_err(|_| WorkerProtocolError::Malformed("snapshot digest is not base64url"))?;
        let snapshot_digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| WorkerProtocolError::Malformed("snapshot digest is not 32 bytes"))?;
        Ok(Self::new(run_nonce, snapshot_digest))
    }

    fn append_to(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.run_nonce);
        bytes.extend_from_slice(&self.snapshot_digest);
    }
}

struct ChannelKey([u8; 32]);

impl ChannelKey {
    fn generate() -> Result<Self, WorkerProtocolError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|error| WorkerProtocolError::Io(io::Error::other(error)))?;
        Ok(Self(bytes))
    }

    #[cfg(test)]
    fn test(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Drop for ChannelKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SessionInputMode {
    Interactive = 1,
    Transcript = 2,
    Program = 3,
    OneShot = 4,
}

/// Closed operation selected by the supervisor-owned REPL state machine. Raw
/// bytes never choose their own source shape: the worker derives every other
/// evaluation field from this authenticated discriminator and its armed role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SubmissionKind {
    Inline = 1,
    Load = 2,
    Mounts = 3,
    OperatorExit = 4,
}

impl SubmissionKind {
    fn decode(value: u8) -> Result<Self, WorkerProtocolError> {
        match value {
            1 => Ok(Self::Inline),
            2 => Ok(Self::Load),
            3 => Ok(Self::Mounts),
            4 => Ok(Self::OperatorExit),
            _ => Err(WorkerProtocolError::Malformed("unknown submission kind")),
        }
    }
}

impl SessionInputMode {
    fn decode(value: u8) -> Result<Self, WorkerProtocolError> {
        match value {
            1 => Ok(Self::Interactive),
            2 => Ok(Self::Transcript),
            3 => Ok(Self::Program),
            4 => Ok(Self::OneShot),
            _ => Err(WorkerProtocolError::Malformed("unknown input mode")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum DisplayAckDisposition {
    Displayed = 1,
    Fallback = 2,
    WriteFailed = 3,
}

impl DisplayAckDisposition {
    fn decode(value: u8) -> Result<Self, WorkerProtocolError> {
        match value {
            1 => Ok(Self::Displayed),
            2 => Ok(Self::Fallback),
            3 => Ok(Self::WriteFailed),
            _ => Err(WorkerProtocolError::Malformed(
                "unknown display acknowledgement",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum EvaluationOutcomeKind {
    Empty = 1,
    Throw = 2,
    Cancelled = 3,
    Lifecycle = 4,
    Refused = 5,
    EngineFault = 6,
}

impl EvaluationOutcomeKind {
    fn decode(value: u8) -> Result<Self, WorkerProtocolError> {
        match value {
            1 => Ok(Self::Empty),
            2 => Ok(Self::Throw),
            3 => Ok(Self::Cancelled),
            4 => Ok(Self::Lifecycle),
            5 => Ok(Self::Refused),
            6 => Ok(Self::EngineFault),
            _ => Err(WorkerProtocolError::Malformed("unknown outcome kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum WorkUnitKind {
    Evaluation = 1,
    Callback = 2,
    Timer = 3,
    MicrotaskDrain = 4,
    CompletionQuery = 5,
}

impl WorkUnitKind {
    fn decode(value: u8) -> Result<Self, WorkerProtocolError> {
        match value {
            1 => Ok(Self::Evaluation),
            2 => Ok(Self::Callback),
            3 => Ok(Self::Timer),
            4 => Ok(Self::MicrotaskDrain),
            5 => Ok(Self::CompletionQuery),
            _ => Err(WorkerProtocolError::Malformed("unknown work-unit kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum WorkUnitPhase {
    Due = 1,
    Undue = 2,
    Begin = 3,
    Suspended = 4,
    End = 5,
}

impl WorkUnitPhase {
    fn decode(value: u8) -> Result<Self, WorkerProtocolError> {
        match value {
            1 => Ok(Self::Due),
            2 => Ok(Self::Undue),
            3 => Ok(Self::Begin),
            4 => Ok(Self::Suspended),
            5 => Ok(Self::End),
            _ => Err(WorkerProtocolError::Malformed("unknown work-unit phase")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum CancellationResolution {
    Accepted = 1,
    Unavailable = 2,
    Failed = 3,
    Defeated = 4,
}

impl CancellationResolution {
    fn decode(value: u8) -> Result<Self, WorkerProtocolError> {
        match value {
            1 => Ok(Self::Accepted),
            2 => Ok(Self::Unavailable),
            3 => Ok(Self::Failed),
            4 => Ok(Self::Defeated),
            _ => Err(WorkerProtocolError::Malformed(
                "unknown cancellation resolution",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifecycleRecord {
    pub request_id: u64,
    pub status: i32,
    pub stdout_cutoff: u64,
    pub stderr_cutoff: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ControlMessage {
    SupervisorHello {
        challenge: [u8; 32],
        bootstrap_config: Vec<u8>,
    },
    WorkerHello {
        pid: u32,
        root_proof: [u8; 32],
    },
    WorkerReady {
        session_proof: [u8; 32],
    },
    Start {
        mode: SessionInputMode,
    },
    Submit {
        submission_id: u64,
        kind: SubmissionKind,
        source: Vec<u8>,
    },
    EndOfInput,
    DisplayAck {
        submission_id: u64,
        disposition: DisplayAckDisposition,
    },
    Cancel {
        request_id: u64,
        target_id: u64,
    },
    Shutdown {
        status: i32,
    },
    Resize {
        columns: u16,
        rows: u16,
    },
    LifecycleAck {
        request_id: u64,
    },
    ExitCodeAck {
        mutation_id: u64,
    },
    Ping {
        nonce: u64,
    },
    ReadyCheckpoint {
        checkpoint_id: u64,
    },
    Step {
        submission_id: u64,
        kind: u8,
        payload: Vec<u8>,
    },
    Display {
        submission_id: u64,
        tree: Vec<u8>,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
    Outcome {
        submission_id: u64,
        kind: EvaluationOutcomeKind,
        status: i32,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
        detail: Vec<u8>,
    },
    AsyncFailure {
        stdout_cutoff: u64,
        stderr_cutoff: u64,
        detail: Vec<u8>,
    },
    LifecycleCommit(LifecycleRecord),
    ExitCodeMirror {
        mutation_id: u64,
        status: i32,
    },
    WorkUnit {
        target_id: u64,
        scheduling_id: u64,
        kind: WorkUnitKind,
        phase: WorkUnitPhase,
    },
    CancellationResolved {
        request_id: u64,
        target_id: u64,
        resolution: CancellationResolution,
    },
    Quiescent,
    Pong {
        nonce: u64,
    },
    PreReceiptLoss {
        count: u64,
    },
    WorkerFault {
        stdout_cutoff: u64,
        stderr_cutoff: u64,
        detail: Vec<u8>,
    },
    ReadyCheckpointAck {
        checkpoint_id: u64,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Direction {
    SupervisorToWorker = 1,
    WorkerToSupervisor = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointRole {
    Supervisor,
    Worker,
}

impl EndpointRole {
    const fn send_direction(self) -> Direction {
        match self {
            Self::Supervisor => Direction::SupervisorToWorker,
            Self::Worker => Direction::WorkerToSupervisor,
        }
    }

    const fn receive_direction(self) -> Direction {
        match self {
            Self::Supervisor => Direction::WorkerToSupervisor,
            Self::Worker => Direction::SupervisorToWorker,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
enum MessageKind {
    SupervisorHello = 1,
    WorkerHello = 2,
    WorkerReady = 3,
    Start = 10,
    Submit = 11,
    EndOfInput = 12,
    DisplayAck = 13,
    Cancel = 14,
    Shutdown = 15,
    Resize = 16,
    LifecycleAck = 17,
    ExitCodeAck = 18,
    Ping = 19,
    ReadyCheckpoint = 20,
    Step = 100,
    Display = 101,
    Outcome = 102,
    AsyncFailure = 103,
    LifecycleCommit = 104,
    ExitCodeMirror = 105,
    WorkUnit = 106,
    CancellationResolved = 107,
    Quiescent = 108,
    Pong = 109,
    PreReceiptLoss = 110,
    WorkerFault = 111,
    ReadyCheckpointAck = 112,
}

impl MessageKind {
    fn decode(value: u16) -> Result<Self, WorkerProtocolError> {
        match value {
            1 => Ok(Self::SupervisorHello),
            2 => Ok(Self::WorkerHello),
            3 => Ok(Self::WorkerReady),
            10 => Ok(Self::Start),
            11 => Ok(Self::Submit),
            12 => Ok(Self::EndOfInput),
            13 => Ok(Self::DisplayAck),
            14 => Ok(Self::Cancel),
            15 => Ok(Self::Shutdown),
            16 => Ok(Self::Resize),
            17 => Ok(Self::LifecycleAck),
            18 => Ok(Self::ExitCodeAck),
            19 => Ok(Self::Ping),
            20 => Ok(Self::ReadyCheckpoint),
            100 => Ok(Self::Step),
            101 => Ok(Self::Display),
            102 => Ok(Self::Outcome),
            103 => Ok(Self::AsyncFailure),
            104 => Ok(Self::LifecycleCommit),
            105 => Ok(Self::ExitCodeMirror),
            106 => Ok(Self::WorkUnit),
            107 => Ok(Self::CancellationResolved),
            108 => Ok(Self::Quiescent),
            109 => Ok(Self::Pong),
            110 => Ok(Self::PreReceiptLoss),
            111 => Ok(Self::WorkerFault),
            112 => Ok(Self::ReadyCheckpointAck),
            _ => Err(WorkerProtocolError::UnknownKind(value)),
        }
    }

    const fn direction(self) -> Direction {
        match self {
            Self::SupervisorHello
            | Self::Start
            | Self::Submit
            | Self::EndOfInput
            | Self::DisplayAck
            | Self::Cancel
            | Self::Shutdown
            | Self::Resize
            | Self::LifecycleAck
            | Self::ExitCodeAck
            | Self::Ping
            | Self::ReadyCheckpoint => Direction::SupervisorToWorker,
            Self::WorkerHello
            | Self::WorkerReady
            | Self::Step
            | Self::Display
            | Self::Outcome
            | Self::AsyncFailure
            | Self::LifecycleCommit
            | Self::ExitCodeMirror
            | Self::WorkUnit
            | Self::CancellationResolved
            | Self::Quiescent
            | Self::Pong
            | Self::PreReceiptLoss
            | Self::WorkerFault
            | Self::ReadyCheckpointAck => Direction::WorkerToSupervisor,
        }
    }

    const fn maximum_payload(self) -> usize {
        match self {
            Self::Display => MAX_DISPLAY_BYTES + 32,
            Self::Submit => MAX_INPUT_BYTES + 16,
            Self::SupervisorHello => MAX_BOOTSTRAP_CONFIG_BYTES + 40,
            Self::Step | Self::Outcome | Self::AsyncFailure | Self::WorkerFault => {
                MAX_EVENT_PAYLOAD_BYTES + 32
            }
            _ => 256,
        }
    }
}

impl ControlMessage {
    /// Exact authenticated-frame charge used by the bounded worker and
    /// supervisor event lanes. The charge includes framing and MAC bytes, so
    /// dynamically sized fields cannot escape queue accounting.
    pub(crate) fn encoded_frame_size(&self) -> Result<usize, WorkerProtocolError> {
        authenticated_frame_charge(self.encode_payload()?.len())
    }

    fn kind(&self) -> MessageKind {
        match self {
            Self::SupervisorHello { .. } => MessageKind::SupervisorHello,
            Self::WorkerHello { .. } => MessageKind::WorkerHello,
            Self::WorkerReady { .. } => MessageKind::WorkerReady,
            Self::Start { .. } => MessageKind::Start,
            Self::Submit { .. } => MessageKind::Submit,
            Self::EndOfInput => MessageKind::EndOfInput,
            Self::DisplayAck { .. } => MessageKind::DisplayAck,
            Self::Cancel { .. } => MessageKind::Cancel,
            Self::Shutdown { .. } => MessageKind::Shutdown,
            Self::Resize { .. } => MessageKind::Resize,
            Self::LifecycleAck { .. } => MessageKind::LifecycleAck,
            Self::ExitCodeAck { .. } => MessageKind::ExitCodeAck,
            Self::Ping { .. } => MessageKind::Ping,
            Self::ReadyCheckpoint { .. } => MessageKind::ReadyCheckpoint,
            Self::Step { .. } => MessageKind::Step,
            Self::Display { .. } => MessageKind::Display,
            Self::Outcome { .. } => MessageKind::Outcome,
            Self::AsyncFailure { .. } => MessageKind::AsyncFailure,
            Self::LifecycleCommit(_) => MessageKind::LifecycleCommit,
            Self::ExitCodeMirror { .. } => MessageKind::ExitCodeMirror,
            Self::WorkUnit { .. } => MessageKind::WorkUnit,
            Self::CancellationResolved { .. } => MessageKind::CancellationResolved,
            Self::Quiescent => MessageKind::Quiescent,
            Self::Pong { .. } => MessageKind::Pong,
            Self::PreReceiptLoss { .. } => MessageKind::PreReceiptLoss,
            Self::WorkerFault { .. } => MessageKind::WorkerFault,
            Self::ReadyCheckpointAck { .. } => MessageKind::ReadyCheckpointAck,
        }
    }

    fn encode_payload(&self) -> Result<Vec<u8>, WorkerProtocolError> {
        let mut writer = PayloadWriter::default();
        match self {
            Self::SupervisorHello {
                challenge,
                bootstrap_config,
            } => {
                writer.fixed(challenge);
                writer.bytes(bootstrap_config)?;
            }
            Self::WorkerHello { pid, root_proof } => {
                writer.u32(*pid);
                writer.fixed(root_proof);
            }
            Self::WorkerReady { session_proof } => writer.fixed(session_proof),
            Self::Start { mode } => writer.u8(*mode as u8),
            Self::Submit {
                submission_id,
                kind,
                source,
            } => {
                writer.u64(*submission_id);
                writer.u8(*kind as u8);
                writer.bytes(source)?;
            }
            Self::EndOfInput | Self::Quiescent => {}
            Self::DisplayAck {
                submission_id,
                disposition,
            } => {
                writer.u64(*submission_id);
                writer.u8(*disposition as u8);
            }
            Self::Cancel {
                request_id,
                target_id,
            } => {
                writer.u64(*request_id);
                writer.u64(*target_id);
            }
            Self::Shutdown { status } => writer.i32(*status),
            Self::Resize { columns, rows } => {
                writer.u16(*columns);
                writer.u16(*rows);
            }
            Self::LifecycleAck { request_id } => writer.u64(*request_id),
            Self::ExitCodeAck { mutation_id } => writer.u64(*mutation_id),
            Self::Ping { nonce } | Self::Pong { nonce } => writer.u64(*nonce),
            Self::ReadyCheckpoint { checkpoint_id } => writer.u64(*checkpoint_id),
            Self::Step {
                submission_id,
                kind,
                payload,
            } => {
                writer.u64(*submission_id);
                writer.u8(*kind);
                writer.bytes(payload)?;
            }
            Self::Display {
                submission_id,
                tree,
                stdout_cutoff,
                stderr_cutoff,
            } => {
                writer.u64(*submission_id);
                writer.u64(*stdout_cutoff);
                writer.u64(*stderr_cutoff);
                writer.bytes(tree)?;
            }
            Self::Outcome {
                submission_id,
                kind,
                status,
                stdout_cutoff,
                stderr_cutoff,
                detail,
            } => {
                writer.u64(*submission_id);
                writer.u8(*kind as u8);
                writer.i32(*status);
                writer.u64(*stdout_cutoff);
                writer.u64(*stderr_cutoff);
                writer.bytes(detail)?;
            }
            Self::AsyncFailure {
                stdout_cutoff,
                stderr_cutoff,
                detail,
            }
            | Self::WorkerFault {
                stdout_cutoff,
                stderr_cutoff,
                detail,
            } => {
                writer.u64(*stdout_cutoff);
                writer.u64(*stderr_cutoff);
                writer.bytes(detail)?;
            }
            Self::LifecycleCommit(record) => {
                writer.u64(record.request_id);
                writer.i32(record.status);
                writer.u64(record.stdout_cutoff);
                writer.u64(record.stderr_cutoff);
            }
            Self::ExitCodeMirror {
                mutation_id,
                status,
            } => {
                writer.u64(*mutation_id);
                writer.i32(*status);
            }
            Self::WorkUnit {
                target_id,
                scheduling_id,
                kind,
                phase,
            } => {
                writer.u64(*target_id);
                writer.u64(*scheduling_id);
                writer.u8(*kind as u8);
                writer.u8(*phase as u8);
            }
            Self::CancellationResolved {
                request_id,
                target_id,
                resolution,
            } => {
                writer.u64(*request_id);
                writer.u64(*target_id);
                writer.u8(*resolution as u8);
            }
            Self::PreReceiptLoss { count } => writer.u64(*count),
            Self::ReadyCheckpointAck {
                checkpoint_id,
                stdout_cutoff,
                stderr_cutoff,
            } => {
                writer.u64(*checkpoint_id);
                writer.u64(*stdout_cutoff);
                writer.u64(*stderr_cutoff);
            }
        }
        let payload = writer.finish();
        if payload.len() > self.kind().maximum_payload() {
            return Err(WorkerProtocolError::Oversize);
        }
        Ok(payload)
    }

    fn decode_payload(kind: MessageKind, payload: &[u8]) -> Result<Self, WorkerProtocolError> {
        if payload.len() > kind.maximum_payload() {
            return Err(WorkerProtocolError::Oversize);
        }
        let mut reader = PayloadReader::new(payload);
        let message = match kind {
            MessageKind::SupervisorHello => Self::SupervisorHello {
                challenge: reader.fixed()?,
                bootstrap_config: reader.bytes(MAX_BOOTSTRAP_CONFIG_BYTES)?,
            },
            MessageKind::WorkerHello => Self::WorkerHello {
                pid: reader.u32()?,
                root_proof: reader.fixed()?,
            },
            MessageKind::WorkerReady => Self::WorkerReady {
                session_proof: reader.fixed()?,
            },
            MessageKind::Start => Self::Start {
                mode: SessionInputMode::decode(reader.u8()?)?,
            },
            MessageKind::Submit => Self::Submit {
                submission_id: reader.u64()?,
                kind: SubmissionKind::decode(reader.u8()?)?,
                source: reader.bytes(MAX_INPUT_BYTES)?,
            },
            MessageKind::EndOfInput => Self::EndOfInput,
            MessageKind::DisplayAck => Self::DisplayAck {
                submission_id: reader.u64()?,
                disposition: DisplayAckDisposition::decode(reader.u8()?)?,
            },
            MessageKind::Cancel => Self::Cancel {
                request_id: reader.u64()?,
                target_id: reader.u64()?,
            },
            MessageKind::Shutdown => Self::Shutdown {
                status: reader.i32()?,
            },
            MessageKind::Resize => Self::Resize {
                columns: reader.u16()?,
                rows: reader.u16()?,
            },
            MessageKind::LifecycleAck => Self::LifecycleAck {
                request_id: reader.u64()?,
            },
            MessageKind::ExitCodeAck => Self::ExitCodeAck {
                mutation_id: reader.u64()?,
            },
            MessageKind::Ping => Self::Ping {
                nonce: reader.u64()?,
            },
            MessageKind::ReadyCheckpoint => Self::ReadyCheckpoint {
                checkpoint_id: reader.u64()?,
            },
            MessageKind::Step => Self::Step {
                submission_id: reader.u64()?,
                kind: reader.u8()?,
                payload: reader.bytes(MAX_EVENT_PAYLOAD_BYTES)?,
            },
            MessageKind::Display => Self::Display {
                submission_id: reader.u64()?,
                stdout_cutoff: reader.u64()?,
                stderr_cutoff: reader.u64()?,
                tree: reader.bytes(MAX_DISPLAY_BYTES)?,
            },
            MessageKind::Outcome => Self::Outcome {
                submission_id: reader.u64()?,
                kind: EvaluationOutcomeKind::decode(reader.u8()?)?,
                status: reader.i32()?,
                stdout_cutoff: reader.u64()?,
                stderr_cutoff: reader.u64()?,
                detail: reader.bytes(MAX_EVENT_PAYLOAD_BYTES)?,
            },
            MessageKind::AsyncFailure => Self::AsyncFailure {
                stdout_cutoff: reader.u64()?,
                stderr_cutoff: reader.u64()?,
                detail: reader.bytes(MAX_EVENT_PAYLOAD_BYTES)?,
            },
            MessageKind::LifecycleCommit => Self::LifecycleCommit(LifecycleRecord {
                request_id: reader.u64()?,
                status: reader.i32()?,
                stdout_cutoff: reader.u64()?,
                stderr_cutoff: reader.u64()?,
            }),
            MessageKind::ExitCodeMirror => Self::ExitCodeMirror {
                mutation_id: reader.u64()?,
                status: reader.i32()?,
            },
            MessageKind::WorkUnit => Self::WorkUnit {
                target_id: reader.u64()?,
                scheduling_id: reader.u64()?,
                kind: WorkUnitKind::decode(reader.u8()?)?,
                phase: WorkUnitPhase::decode(reader.u8()?)?,
            },
            MessageKind::CancellationResolved => Self::CancellationResolved {
                request_id: reader.u64()?,
                target_id: reader.u64()?,
                resolution: CancellationResolution::decode(reader.u8()?)?,
            },
            MessageKind::Quiescent => Self::Quiescent,
            MessageKind::Pong => Self::Pong {
                nonce: reader.u64()?,
            },
            MessageKind::PreReceiptLoss => Self::PreReceiptLoss {
                count: reader.u64()?,
            },
            MessageKind::WorkerFault => Self::WorkerFault {
                stdout_cutoff: reader.u64()?,
                stderr_cutoff: reader.u64()?,
                detail: reader.bytes(MAX_EVENT_PAYLOAD_BYTES)?,
            },
            MessageKind::ReadyCheckpointAck => Self::ReadyCheckpointAck {
                checkpoint_id: reader.u64()?,
                stdout_cutoff: reader.u64()?,
                stderr_cutoff: reader.u64()?,
            },
        };
        reader.finish()?;
        if matches!(&message, Self::PreReceiptLoss { count: 0 }) {
            return Err(WorkerProtocolError::Malformed(
                "pre-receipt loss count must be nonzero",
            ));
        }
        Ok(message)
    }
}

pub(crate) fn authenticated_frame_charge(
    payload_bytes: usize,
) -> Result<usize, WorkerProtocolError> {
    WIRE_HEADER_BYTES
        .checked_add(payload_bytes)
        .and_then(|size| size.checked_add(WIRE_MAC_BYTES))
        .ok_or(WorkerProtocolError::Oversize)
}

#[derive(Default)]
struct PayloadWriter {
    bytes: Vec<u8>,
}

impl PayloadWriter {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i32(&mut self, value: i32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn fixed<const N: usize>(&mut self, value: &[u8; N]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), WorkerProtocolError> {
        let length = u32::try_from(value.len()).map_err(|_| WorkerProtocolError::Oversize)?;
        self.u32(length);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct PayloadReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], WorkerProtocolError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(WorkerProtocolError::Oversize)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(WorkerProtocolError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, WorkerProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WorkerProtocolError> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32, WorkerProtocolError> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, WorkerProtocolError> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }

    fn i32(&mut self) -> Result<i32, WorkerProtocolError> {
        Ok(i32::from_le_bytes(self.fixed()?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], WorkerProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WorkerProtocolError::Truncated)
    }

    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, WorkerProtocolError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(WorkerProtocolError::Oversize);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn finish(self) -> Result<(), WorkerProtocolError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WorkerProtocolError::Malformed(
                "message has trailing payload bytes",
            ))
        }
    }
}

struct AuthenticatedChannel<T> {
    io: T,
    role: EndpointRole,
    key: ChannelKey,
    session_nonce: [u8; 16],
    epoch: u64,
    next_send_sequence: u64,
    next_receive_sequence: u64,
}

impl<T: Read + Write> AuthenticatedChannel<T> {
    fn new(
        io: T,
        role: EndpointRole,
        key: ChannelKey,
        session_nonce: [u8; 16],
        epoch: u64,
    ) -> Self {
        Self {
            io,
            role,
            key,
            session_nonce,
            epoch,
            next_send_sequence: 1,
            next_receive_sequence: 1,
        }
    }

    fn send(&mut self, message: &ControlMessage) -> Result<(), WorkerProtocolError> {
        let kind = message.kind();
        if kind.direction() != self.role.send_direction() {
            return Err(WorkerProtocolError::WrongDirection);
        }
        let payload = message.encode_payload()?;
        let frame = encode_authenticated_frame(
            &self.key,
            self.session_nonce,
            self.epoch,
            self.next_send_sequence,
            kind,
            &payload,
        )?;
        self.io.write_all(&frame)?;
        self.io.flush()?;
        self.next_send_sequence = self
            .next_send_sequence
            .checked_add(1)
            .ok_or(WorkerProtocolError::Malformed("send sequence exhausted"))?;
        Ok(())
    }

    fn receive(&mut self) -> Result<ControlMessage, WorkerProtocolError> {
        let mut header = [0u8; WIRE_HEADER_BYTES];
        read_frame_header(&mut self.io, &mut header)?;
        let parsed = ParsedHeader::parse(&header)?;
        if parsed.direction != self.role.receive_direction() {
            return Err(WorkerProtocolError::WrongDirection);
        }
        if parsed.kind.direction() != parsed.direction {
            return Err(WorkerProtocolError::WrongDirection);
        }
        if parsed.session_nonce != self.session_nonce {
            return Err(WorkerProtocolError::WrongSession);
        }
        if parsed.epoch != self.epoch {
            return Err(WorkerProtocolError::WrongEpoch);
        }
        if parsed.sequence != self.next_receive_sequence {
            return Err(WorkerProtocolError::BadSequence {
                expected: self.next_receive_sequence,
                actual: parsed.sequence,
            });
        }
        if parsed.payload_length > parsed.kind.maximum_payload() {
            return Err(WorkerProtocolError::Oversize);
        }
        let mut payload = vec![0u8; parsed.payload_length];
        read_exact_or_truncated(&mut self.io, &mut payload)?;
        let mut supplied_mac = [0u8; WIRE_MAC_BYTES];
        read_exact_or_truncated(&mut self.io, &mut supplied_mac)?;
        verify_frame_mac(&self.key, &header, &payload, &supplied_mac)?;
        let message = ControlMessage::decode_payload(parsed.kind, &payload)?;
        self.next_receive_sequence = self
            .next_receive_sequence
            .checked_add(1)
            .ok_or(WorkerProtocolError::Malformed("receive sequence exhausted"))?;
        Ok(message)
    }

    fn into_inner(self) -> T {
        self.io
    }
}

#[cfg(unix)]
impl AuthenticatedChannel<std::os::unix::net::UnixStream> {
    /// Write one complete authenticated frame against one wall-clock
    /// deadline. Progress does not renew the deadline, and a partial frame
    /// never advances the channel sequence.
    fn send_until(
        &mut self,
        message: &ControlMessage,
        deadline: Instant,
    ) -> Result<(), WorkerProtocolError> {
        let kind = message.kind();
        if kind.direction() != self.role.send_direction() {
            return Err(WorkerProtocolError::WrongDirection);
        }
        let payload = message.encode_payload()?;
        let frame = encode_authenticated_frame(
            &self.key,
            self.session_nonce,
            self.epoch,
            self.next_send_sequence,
            kind,
            &payload,
        )?;
        let next_sequence = self
            .next_send_sequence
            .checked_add(1)
            .ok_or(WorkerProtocolError::Malformed("send sequence exhausted"))?;
        let was_nonblocking = unix_stream_is_nonblocking(&self.io)?;
        if !was_nonblocking {
            self.io.set_nonblocking(true)?;
        }
        let operation = unix_write_all_until(&mut self.io, &frame, deadline);
        if operation.is_ok() {
            self.next_send_sequence = next_sequence;
        }
        let restore = if was_nonblocking {
            Ok(())
        } else {
            self.io.set_nonblocking(false)
        };
        operation
            .map_err(WorkerProtocolError::Io)
            .and_then(|()| restore.map_err(WorkerProtocolError::Io))
    }

    /// Read, authenticate, and decode exactly one frame against one absolute
    /// deadline. Socket mode is restored on every path and the receive
    /// sequence changes only after a complete valid frame.
    fn receive_until(&mut self, deadline: Instant) -> Result<ControlMessage, WorkerProtocolError> {
        let was_nonblocking = unix_stream_is_nonblocking(&self.io)?;
        if !was_nonblocking {
            self.io.set_nonblocking(true)?;
        }
        let operation = (|| {
            let mut header = [0u8; WIRE_HEADER_BYTES];
            unix_read_exact_until(&mut self.io, &mut header, deadline, true)?;
            let parsed = ParsedHeader::parse(&header)?;
            if parsed.direction != self.role.receive_direction() {
                return Err(WorkerProtocolError::WrongDirection);
            }
            if parsed.kind.direction() != parsed.direction {
                return Err(WorkerProtocolError::WrongDirection);
            }
            if parsed.session_nonce != self.session_nonce {
                return Err(WorkerProtocolError::WrongSession);
            }
            if parsed.epoch != self.epoch {
                return Err(WorkerProtocolError::WrongEpoch);
            }
            if parsed.sequence != self.next_receive_sequence {
                return Err(WorkerProtocolError::BadSequence {
                    expected: self.next_receive_sequence,
                    actual: parsed.sequence,
                });
            }
            if parsed.payload_length > parsed.kind.maximum_payload() {
                return Err(WorkerProtocolError::Oversize);
            }
            let next_sequence = self
                .next_receive_sequence
                .checked_add(1)
                .ok_or(WorkerProtocolError::Malformed("receive sequence exhausted"))?;
            let mut payload = vec![0u8; parsed.payload_length];
            unix_read_exact_until(&mut self.io, &mut payload, deadline, false)?;
            let mut supplied_mac = [0u8; WIRE_MAC_BYTES];
            unix_read_exact_until(&mut self.io, &mut supplied_mac, deadline, false)?;
            verify_frame_mac(&self.key, &header, &payload, &supplied_mac)?;
            let message = ControlMessage::decode_payload(parsed.kind, &payload)?;
            Ok((message, next_sequence))
        })();
        if let Ok((_, next_sequence)) = &operation {
            self.next_receive_sequence = *next_sequence;
        }
        let restore = if was_nonblocking {
            Ok(())
        } else {
            self.io.set_nonblocking(false)
        };
        operation
            .map(|(message, _)| message)
            .and_then(|message| restore.map(|()| message).map_err(WorkerProtocolError::Io))
    }
}

#[cfg(unix)]
fn unix_stream_is_nonblocking(
    stream: &std::os::unix::net::UnixStream,
) -> Result<bool, WorkerProtocolError> {
    use std::os::fd::AsRawFd;

    let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(WorkerProtocolError::Io(io::Error::last_os_error()));
    }
    Ok(flags & libc::O_NONBLOCK != 0)
}

#[cfg(unix)]
fn unix_write_all_until(
    stream: &mut std::os::unix::net::UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(frame_deadline_error("authenticated frame write timed out"));
        }
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "authenticated frame write made no progress",
                ))
            }
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                unix_poll_until(stream, libc::POLLOUT, deadline)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unix_read_exact_until(
    stream: &mut std::os::unix::net::UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
    clean_eof_if_empty: bool,
) -> Result<(), WorkerProtocolError> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err(WorkerProtocolError::Io(frame_deadline_error(
                "authenticated frame read timed out",
            )));
        }
        match stream.read(&mut bytes[offset..]) {
            Ok(0) if offset == 0 && clean_eof_if_empty => {
                return Err(WorkerProtocolError::CleanEof)
            }
            Ok(0) => return Err(WorkerProtocolError::Truncated),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                unix_poll_until(stream, libc::POLLIN, deadline)?;
            }
            Err(error) => return Err(WorkerProtocolError::Io(error)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unix_poll_until(
    stream: &std::os::unix::net::UnixStream,
    events: libc::c_short,
    deadline: Instant,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(frame_deadline_error("authenticated frame I/O timed out"));
        }
        let remaining = deadline.duration_since(now);
        let millis = remaining
            .as_millis()
            .saturating_add(u128::from(
                !remaining.subsec_nanos().is_multiple_of(1_000_000),
            ))
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            if descriptor.revents & (events | libc::POLLHUP | libc::POLLERR) != 0 {
                return Ok(());
            }
            continue;
        }
        if result == 0 {
            return Err(frame_deadline_error("authenticated frame I/O timed out"));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn frame_deadline_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}

#[cfg(unix)]
fn deadline_after(timeout: Duration) -> Instant {
    Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now)
}

#[derive(Clone, Copy)]
struct ParsedHeader {
    kind: MessageKind,
    direction: Direction,
    session_nonce: [u8; 16],
    epoch: u64,
    sequence: u64,
    payload_length: usize,
}

impl ParsedHeader {
    fn parse(header: &[u8; WIRE_HEADER_BYTES]) -> Result<Self, WorkerProtocolError> {
        if header[0..4] != WIRE_MAGIC {
            return Err(WorkerProtocolError::InvalidMagic);
        }
        let version = u16::from_le_bytes(header[4..6].try_into().expect("fixed header slice"));
        if version != WIRE_VERSION {
            return Err(WorkerProtocolError::UnsupportedVersion(version));
        }
        let kind = MessageKind::decode(u16::from_le_bytes(
            header[6..8].try_into().expect("fixed header slice"),
        ))?;
        let direction = match header[8] {
            1 => Direction::SupervisorToWorker,
            2 => Direction::WorkerToSupervisor,
            _ => return Err(WorkerProtocolError::WrongDirection),
        };
        if header[9..12] != [0, 0, 0] {
            return Err(WorkerProtocolError::InvalidFlags);
        }
        let session_nonce = header[12..28].try_into().expect("fixed header slice");
        let epoch = u64::from_le_bytes(header[28..36].try_into().expect("fixed header slice"));
        let sequence = u64::from_le_bytes(header[36..44].try_into().expect("fixed header slice"));
        let payload_length =
            u32::from_le_bytes(header[44..48].try_into().expect("fixed header slice")) as usize;
        Ok(Self {
            kind,
            direction,
            session_nonce,
            epoch,
            sequence,
            payload_length,
        })
    }
}

fn encode_authenticated_frame(
    key: &ChannelKey,
    session_nonce: [u8; 16],
    epoch: u64,
    sequence: u64,
    kind: MessageKind,
    payload: &[u8],
) -> Result<Vec<u8>, WorkerProtocolError> {
    if payload.len() > kind.maximum_payload() {
        return Err(WorkerProtocolError::Oversize);
    }
    let payload_length = u32::try_from(payload.len()).map_err(|_| WorkerProtocolError::Oversize)?;
    let mut header = [0u8; WIRE_HEADER_BYTES];
    header[0..4].copy_from_slice(&WIRE_MAGIC);
    header[4..6].copy_from_slice(&WIRE_VERSION.to_le_bytes());
    header[6..8].copy_from_slice(&(kind as u16).to_le_bytes());
    header[8] = kind.direction() as u8;
    header[12..28].copy_from_slice(&session_nonce);
    header[28..36].copy_from_slice(&epoch.to_le_bytes());
    header[36..44].copy_from_slice(&sequence.to_le_bytes());
    header[44..48].copy_from_slice(&payload_length.to_le_bytes());
    let mac = frame_mac(key, &header, payload);
    let mut frame = Vec::with_capacity(WIRE_HEADER_BYTES + payload.len() + WIRE_MAC_BYTES);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&mac);
    Ok(frame)
}

fn frame_mac(key: &ChannelKey, header: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key");
    mac.update(FRAME_MAC_DOMAIN);
    mac.update(header);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn verify_frame_mac(
    key: &ChannelKey,
    header: &[u8],
    payload: &[u8],
    supplied: &[u8; 32],
) -> Result<(), WorkerProtocolError> {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key");
    mac.update(FRAME_MAC_DOMAIN);
    mac.update(header);
    mac.update(payload);
    mac.verify_slice(supplied)
        .map_err(|_| WorkerProtocolError::BadMac)
}

fn read_frame_header<R: Read>(
    reader: &mut R,
    header: &mut [u8; WIRE_HEADER_BYTES],
) -> Result<(), WorkerProtocolError> {
    match reader.read(&mut header[..1]) {
        Ok(0) => return Err(WorkerProtocolError::CleanEof),
        Ok(1) => {}
        Ok(_) => unreachable!("one-byte read returned too many bytes"),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => {
            return read_frame_header(reader, header)
        }
        Err(error) => return Err(WorkerProtocolError::Io(error)),
    }
    read_exact_or_truncated(reader, &mut header[1..])
}

fn read_exact_or_truncated<R: Read>(
    reader: &mut R,
    mut bytes: &mut [u8],
) -> Result<(), WorkerProtocolError> {
    while !bytes.is_empty() {
        match reader.read(bytes) {
            Ok(0) => return Err(WorkerProtocolError::Truncated),
            Ok(count) => {
                let (_, remainder) = bytes.split_at_mut(count);
                bytes = remainder;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(WorkerProtocolError::Io(error)),
        }
    }
    Ok(())
}

fn fresh_bytes<const N: usize>() -> Result<[u8; N], WorkerProtocolError> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| WorkerProtocolError::Io(io::Error::other(error)))?;
    Ok(bytes)
}

fn fresh_nonzero_u64() -> Result<u64, WorkerProtocolError> {
    loop {
        let value = u64::from_le_bytes(fresh_bytes()?);
        if value != 0 {
            return Ok(value);
        }
    }
}

fn root_proof(
    key: &ChannelKey,
    challenge: &[u8; 32],
    root: &capsec_semantics::model::ObjectIdentity,
) -> Result<[u8; 32], WorkerProtocolError> {
    let root = serde_json::to_vec(root)
        .map_err(|_| WorkerProtocolError::Malformed("root identity is not serializable"))?;
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key");
    mac.update(ROOT_PROOF_DOMAIN);
    mac.update(challenge);
    mac.update(&root);
    Ok(mac.finalize().into_bytes().into())
}

fn session_proof(
    key: &ChannelKey,
    challenge: &[u8; 32],
    binding: &ArmedSessionBinding,
    root: &capsec_semantics::model::ObjectIdentity,
) -> Result<[u8; 32], WorkerProtocolError> {
    let root = serde_json::to_vec(root)
        .map_err(|_| WorkerProtocolError::Malformed("root identity is not serializable"))?;
    let mut material = Vec::with_capacity(48 + root.len());
    binding.append_to(&mut material);
    material.extend_from_slice(&root);
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts a 32-byte key");
    mac.update(SESSION_PROOF_DOMAIN);
    mac.update(challenge);
    mac.update(&material);
    Ok(mac.finalize().into_bytes().into())
}

fn object_identity_for_directory(
    file: &std::fs::File,
) -> Result<capsec_semantics::model::ObjectIdentity, WorkerProtocolError> {
    use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};

    let metadata = file.metadata()?;
    if !metadata.file_type().is_dir() {
        return Err(WorkerProtocolError::WrongRoot);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let platform = if cfg!(any(target_os = "macos", target_os = "ios")) {
            ObjectPlatform::Apple
        } else if cfg!(target_os = "android") {
            ObjectPlatform::Android
        } else {
            ObjectPlatform::Unix
        };
        Ok(ObjectIdentity {
            platform,
            volume: NonEmptyString::new(format!("dev:{}", metadata.dev()))
                .map_err(|_| WorkerProtocolError::Malformed("invalid root volume identity"))?,
            file: NonEmptyString::new(format!("ino:{}", metadata.ino()))
                .map_err(|_| WorkerProtocolError::Malformed("invalid root file identity"))?,
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(ObjectIdentity {
            platform: ObjectPlatform::Windows,
            volume: NonEmptyString::new(format!(
                "volume:{}",
                metadata.volume_serial_number().unwrap_or(0)
            ))
            .map_err(|_| WorkerProtocolError::Malformed("invalid root volume identity"))?,
            file: NonEmptyString::new(format!("file:{}", metadata.file_index().unwrap_or(0)))
                .map_err(|_| WorkerProtocolError::Malformed("invalid root file identity"))?,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = metadata;
        Err(WorkerProtocolError::UnsupportedPlatform)
    }
}

/// An already-open project directory checked against the exact object identity
/// authenticated by startup. No path is retained or sent to the worker.
pub(crate) struct AuthenticatedRootDescriptor {
    file: std::fs::File,
    object: capsec_semantics::model::ObjectIdentity,
}

impl fmt::Debug for AuthenticatedRootDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRootDescriptor")
            .field("object", &self.object)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedRootDescriptor {
    pub(crate) fn new(
        file: std::fs::File,
        expected: &capsec_semantics::model::ObjectIdentity,
    ) -> Result<Self, WorkerProtocolError> {
        let actual = object_identity_for_directory(&file)?;
        if &actual != expected {
            return Err(WorkerProtocolError::WrongRoot);
        }
        Ok(Self {
            file,
            object: actual,
        })
    }

    pub(crate) fn object(&self) -> &capsec_semantics::model::ObjectIdentity {
        &self.object
    }

    fn try_clone(&self) -> Result<Self, WorkerProtocolError> {
        let file = self.file.try_clone()?;
        Self::new(file, &self.object)
    }
}

/// Sequence numbers are assigned only after the supervisor receives an event.
/// A restart advances the epoch and never rewinds the numeric sequence.
#[derive(Debug)]
struct SupervisorSequenceState {
    epoch: u64,
    next: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct SupervisorSequenceAllocator {
    state: Arc<Mutex<SupervisorSequenceState>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SupervisorSequenceReservation {
    pub(crate) epoch: u64,
    pub(crate) first_sequence: u64,
}

impl SupervisorSequenceAllocator {
    pub(crate) fn new(epoch: u64) -> Result<Self, WorkerProtocolError> {
        if epoch == 0 {
            return Err(WorkerProtocolError::Malformed(
                "sequence epoch must be nonzero",
            ));
        }
        Ok(Self {
            state: Arc::new(Mutex::new(SupervisorSequenceState { epoch, next: 1 })),
        })
    }

    pub(crate) fn reserve(
        &self,
        count: u64,
    ) -> Result<SupervisorSequenceReservation, WorkerProtocolError> {
        if count == 0 {
            return Err(WorkerProtocolError::Malformed(
                "supervisor sequence reservation must be nonzero",
            ));
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let first_sequence = state.next;
        state.next = state
            .next
            .checked_add(count)
            .ok_or(WorkerProtocolError::Malformed(
                "supervisor sequence exhausted",
            ))?;
        Ok(SupervisorSequenceReservation {
            epoch: state.epoch,
            first_sequence,
        })
    }

    pub(crate) fn assign<T>(&self, payload: T) -> Result<Sequenced<T>, WorkerProtocolError> {
        let reservation = self.reserve(1)?;
        Ok(Sequenced {
            epoch: reservation.epoch,
            sequence: reservation.first_sequence,
            payload,
        })
    }

    pub(crate) fn restart(&self) -> Result<(), WorkerProtocolError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(WorkerProtocolError::Malformed("sequence epoch exhausted"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sequenced<T> {
    pub epoch: u64,
    pub sequence: u64,
    pub payload: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminationCause {
    Orderly,
    Cooperative,
    Interrupt,
    EngineFault,
    BrokerFault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifecycleCommitDisposition {
    Accepted,
    IdempotentReplay,
    LaterRequestIgnored,
}

/// Supervisor-authoritative lifecycle mirror. It remains usable after the
/// worker is wedged or dead and applies the one-cause status precedence from
/// LLP 0025 §8.
#[derive(Clone, Debug)]
pub(crate) struct SupervisorLifecycleState {
    exit_code: i32,
    next_mutation_id: u64,
    accepted_lifecycle: Option<LifecycleRecord>,
    cause: Option<(TerminationCause, i32)>,
}

impl Default for SupervisorLifecycleState {
    fn default() -> Self {
        Self {
            exit_code: 0,
            next_mutation_id: 1,
            accepted_lifecycle: None,
            cause: None,
        }
    }
}

impl SupervisorLifecycleState {
    pub(crate) fn mirror_exit_code(
        &mut self,
        mutation_id: u64,
        status: i32,
    ) -> Result<(), WorkerProtocolError> {
        if mutation_id != self.next_mutation_id {
            return Err(WorkerProtocolError::ExitCodeMirrorGap);
        }
        self.exit_code = status;
        self.next_mutation_id = self
            .next_mutation_id
            .checked_add(1)
            .ok_or(WorkerProtocolError::ExitCodeMirrorGap)?;
        Ok(())
    }

    pub(crate) fn accept_lifecycle(
        &mut self,
        record: LifecycleRecord,
    ) -> Result<LifecycleCommitDisposition, WorkerProtocolError> {
        match &self.accepted_lifecycle {
            None => {
                self.accepted_lifecycle = Some(record.clone());
                self.latch_cause(TerminationCause::Cooperative, record.status);
                Ok(LifecycleCommitDisposition::Accepted)
            }
            Some(accepted) if accepted == &record => {
                Ok(LifecycleCommitDisposition::IdempotentReplay)
            }
            Some(accepted) if accepted.request_id == record.request_id => {
                Err(WorkerProtocolError::ConflictingLifecycleRecord)
            }
            Some(_) => Ok(LifecycleCommitDisposition::LaterRequestIgnored),
        }
    }

    pub(crate) fn accepted_lifecycle(&self) -> Option<&LifecycleRecord> {
        self.accepted_lifecycle.as_ref()
    }

    pub(crate) fn latch_orderly(&mut self) {
        self.latch_cause(TerminationCause::Orderly, self.exit_code);
    }

    pub(crate) fn latch_interrupt(&mut self) {
        self.latch_cause(TerminationCause::Interrupt, 130);
    }

    pub(crate) fn latch_engine_fault(&mut self) {
        if self.accepted_lifecycle.is_none() {
            self.latch_cause(TerminationCause::EngineFault, 70);
        }
    }

    pub(crate) fn latch_broker_fault(&mut self) {
        self.latch_cause(TerminationCause::BrokerFault, 141);
    }

    fn latch_cause(&mut self, cause: TerminationCause, status: i32) {
        if self.cause.is_none() {
            self.cause = Some((cause, status));
        }
    }

    pub(crate) fn cause(&self) -> Option<TerminationCause> {
        self.cause.map(|(cause, _)| cause)
    }

    pub(crate) fn final_status(&self, unreportable_cleanup_loss: bool) -> i32 {
        let (cause, status) = self
            .cause
            .unwrap_or((TerminationCause::Orderly, self.exit_code));
        if unreportable_cleanup_loss
            && matches!(
                cause,
                TerminationCause::Orderly | TerminationCause::Cooperative
            )
        {
            141
        } else {
            status
        }
    }
}

const BOOTSTRAP_MAGIC: [u8; 4] = *b"IBSB";
const BOOTSTRAP_VERSION: u16 = 1;
const BOOTSTRAP_PREFIX_BYTES: usize = 4 + 2 + 2 + 32 + 8 + 16 + 32 + 32 + 4;
const BOOTSTRAP_RECORD_BYTES: usize = BOOTSTRAP_PREFIX_BYTES + 32;
const BOOTSTRAP_MAC_DOMAIN: &[u8] = b"ibex-session-worker-bootstrap-v1\0";

struct BootstrapRecord {
    channel_key: [u8; 32],
    channel_epoch: u64,
    binding: ArmedSessionBinding,
    challenge: [u8; 32],
    parent_pid: u32,
}

impl BootstrapRecord {
    fn encode(&self) -> [u8; BOOTSTRAP_RECORD_BYTES] {
        let mut bytes = [0u8; BOOTSTRAP_RECORD_BYTES];
        bytes[0..4].copy_from_slice(&BOOTSTRAP_MAGIC);
        bytes[4..6].copy_from_slice(&BOOTSTRAP_VERSION.to_le_bytes());
        bytes[8..40].copy_from_slice(&self.channel_key);
        bytes[40..48].copy_from_slice(&self.channel_epoch.to_le_bytes());
        bytes[48..64].copy_from_slice(&self.binding.run_nonce);
        bytes[64..96].copy_from_slice(&self.binding.snapshot_digest);
        bytes[96..128].copy_from_slice(&self.challenge);
        bytes[128..132].copy_from_slice(&self.parent_pid.to_le_bytes());
        let mut mac =
            HmacSha256::new_from_slice(&self.channel_key).expect("HMAC accepts bootstrap key");
        mac.update(BOOTSTRAP_MAC_DOMAIN);
        mac.update(&bytes[..BOOTSTRAP_PREFIX_BYTES]);
        bytes[BOOTSTRAP_PREFIX_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
        bytes
    }

    fn decode(bytes: &[u8; BOOTSTRAP_RECORD_BYTES]) -> Result<Self, WorkerProtocolError> {
        if bytes[0..4] != BOOTSTRAP_MAGIC {
            return Err(WorkerProtocolError::UnauthorizedBootstrap);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().expect("fixed bootstrap slice"));
        if version != BOOTSTRAP_VERSION || bytes[6..8] != [0, 0] {
            return Err(WorkerProtocolError::UnauthorizedBootstrap);
        }
        let channel_key: [u8; 32] = bytes[8..40].try_into().expect("fixed bootstrap slice");
        let mut mac = HmacSha256::new_from_slice(&channel_key).expect("HMAC accepts bootstrap key");
        mac.update(BOOTSTRAP_MAC_DOMAIN);
        mac.update(&bytes[..BOOTSTRAP_PREFIX_BYTES]);
        mac.verify_slice(&bytes[BOOTSTRAP_PREFIX_BYTES..])
            .map_err(|_| WorkerProtocolError::UnauthorizedBootstrap)?;
        let channel_epoch =
            u64::from_le_bytes(bytes[40..48].try_into().expect("fixed bootstrap slice"));
        if channel_epoch == 0 {
            return Err(WorkerProtocolError::UnauthorizedBootstrap);
        }
        Ok(Self {
            channel_key,
            channel_epoch,
            binding: ArmedSessionBinding::new(
                bytes[48..64].try_into().expect("fixed bootstrap slice"),
                bytes[64..96].try_into().expect("fixed bootstrap slice"),
            ),
            challenge: bytes[96..128].try_into().expect("fixed bootstrap slice"),
            parent_pid: u32::from_le_bytes(
                bytes[128..132].try_into().expect("fixed bootstrap slice"),
            ),
        })
    }
}

impl Drop for BootstrapRecord {
    fn drop(&mut self) {
        self.channel_key.fill(0);
        self.binding.run_nonce.fill(0);
        self.binding.snapshot_digest.fill(0);
        self.challenge.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootstrapInvocation {
    Ordinary,
    WorkerCandidate,
    RefusedMalformed,
}

/// Classify the hidden route before clap or any runtime construction. The
/// spelling alone never authorizes it; the inherited bootstrap/control/root
/// descriptors still have to authenticate successfully.
pub(crate) fn classify_bootstrap_invocation(args: &[OsString]) -> BootstrapInvocation {
    let appearances = args
        .iter()
        .skip(1)
        .filter(|argument| argument.as_os_str() == WORKER_BOOTSTRAP_ARG)
        .count();
    match (appearances, args.len()) {
        (0, _) => BootstrapInvocation::Ordinary,
        (1, 2) => BootstrapInvocation::WorkerCandidate,
        _ => BootstrapInvocation::RefusedMalformed,
    }
}

const WORKER_CONFIG_MAGIC: [u8; 4] = *b"IBWC";
const WORKER_CONFIG_VERSION: u16 = 1;
const WORKER_CONFIG_HEADER_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum WorkerApplicationRole {
    Repl = 1,
    Inline = 2,
    File = 3,
}

impl WorkerApplicationRole {
    fn decode(value: u8) -> Result<Self, WorkerProtocolError> {
        match value {
            1 => Ok(Self::Repl),
            2 => Ok(Self::Inline),
            3 => Ok(Self::File),
            _ => Err(WorkerProtocolError::Malformed("unknown worker role")),
        }
    }
}

/// Authenticated, closed bootstrap facts needed before Runtime construction.
/// The application payload is bounded and opaque to the transport, but its
/// execution role and all supervisor-captured SessionIo facts are typed here.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct WorkerBootstrapConfiguration {
    pub session_io: crate::terminal_session::SessionIoPlan,
    pub role: WorkerApplicationRole,
    pub application: Vec<u8>,
}

impl fmt::Debug for WorkerBootstrapConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerBootstrapConfiguration")
            .field("session_io", &self.session_io)
            .field("role", &self.role)
            .field("application_bytes", &self.application.len())
            .finish()
    }
}

impl WorkerBootstrapConfiguration {
    pub(crate) fn new(
        session_io: crate::terminal_session::SessionIoPlan,
        role: WorkerApplicationRole,
        application: Vec<u8>,
    ) -> Result<Self, WorkerProtocolError> {
        let configuration = Self {
            session_io,
            role,
            application,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    fn validate(&self) -> Result<(), WorkerProtocolError> {
        use crate::terminal_session::PresentationTopology;
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        if self.application.len() > MAX_BOOTSTRAP_CONFIG_BYTES - WORKER_CONFIG_HEADER_BYTES {
            return Err(WorkerProtocolError::Oversize);
        }
        let route_is_valid = matches!(
            (self.session_io.route.entry_kind, self.session_io.route.mode),
            (ArmedEntryKind::File, ArmedExecutionMode::Program)
                | (ArmedEntryKind::Stdin, ArmedExecutionMode::Program)
                | (ArmedEntryKind::Repl, ArmedExecutionMode::Interactive)
                | (ArmedEntryKind::Repl, ArmedExecutionMode::Transcript)
                | (ArmedEntryKind::Eval, ArmedExecutionMode::OneShot)
        );
        if !route_is_valid {
            return Err(WorkerProtocolError::Malformed(
                "worker entry kind and execution mode disagree",
            ));
        }
        let role_is_valid = matches!(
            (self.role, self.session_io.route.entry_kind),
            (WorkerApplicationRole::Repl, ArmedEntryKind::Repl)
                | (WorkerApplicationRole::Inline, ArmedEntryKind::Eval)
                | (WorkerApplicationRole::Inline, ArmedEntryKind::Stdin)
                | (WorkerApplicationRole::File, ArmedEntryKind::File)
        );
        if !role_is_valid {
            return Err(WorkerProtocolError::Malformed(
                "worker role and entry kind disagree",
            ));
        }
        if self.session_io.presentation.topology
            != self.session_io.terminal_facts.presentation_topology()
        {
            return Err(WorkerProtocolError::Malformed(
                "worker presentation topology was not captured from terminal facts",
            ));
        }
        let editor_control = self.session_io.route.has_interactive_editor()
            && !matches!(
                self.session_io.presentation.topology,
                PresentationTopology::Transcript
            );
        if self.session_io.presentation.editor_control != editor_control {
            return Err(WorkerProtocolError::Malformed(
                "worker editor-control fact is inconsistent",
            ));
        }
        if self.session_io.presentation.session_ansi
            && (matches!(
                self.session_io.presentation.topology,
                PresentationTopology::Transcript
            ) || matches!(self.session_io.route.mode, ArmedExecutionMode::Transcript))
        {
            return Err(WorkerProtocolError::Malformed(
                "worker transcript presentation cannot enable ANSI",
            ));
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, WorkerProtocolError> {
        use crate::terminal_session::PresentationTopology;
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        self.validate()?;
        let application_length =
            u32::try_from(self.application.len()).map_err(|_| WorkerProtocolError::Oversize)?;
        let mut bytes = vec![0u8; WORKER_CONFIG_HEADER_BYTES];
        bytes[0..4].copy_from_slice(&WORKER_CONFIG_MAGIC);
        bytes[4..6].copy_from_slice(&WORKER_CONFIG_VERSION.to_le_bytes());
        bytes[6] = self.role as u8;
        bytes[7] = match self.session_io.route.entry_kind {
            ArmedEntryKind::File => 1,
            ArmedEntryKind::Stdin => 2,
            ArmedEntryKind::Repl => 3,
            ArmedEntryKind::Eval => 4,
        };
        bytes[8] = match self.session_io.route.mode {
            ArmedExecutionMode::Interactive => 1,
            ArmedExecutionMode::Transcript => 2,
            ArmedExecutionMode::Program => 3,
            ArmedExecutionMode::OneShot => 4,
        };
        bytes[9] = u8::from(self.session_io.terminal_facts.stdin_is_tty)
            | (u8::from(self.session_io.terminal_facts.stdout_is_tty) << 1)
            | (u8::from(self.session_io.terminal_facts.stderr_is_tty) << 2);
        bytes[10] = match self.session_io.presentation.topology {
            PresentationTopology::StdoutTty => 1,
            PresentationTopology::StderrTty => 2,
            PresentationTopology::Transcript => 3,
        };
        bytes[11] = u8::from(self.session_io.presentation.session_ansi)
            | (u8::from(self.session_io.presentation.editor_control) << 1);
        bytes[12..16].copy_from_slice(&application_length.to_le_bytes());
        bytes.extend_from_slice(&self.application);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, WorkerProtocolError> {
        use crate::terminal_session::{
            CapturedPresentation, NativeTerminalFacts, PresentationTopology,
            SelectedExecutionRoute, SessionIoPlan,
        };
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};

        if bytes.len() < WORKER_CONFIG_HEADER_BYTES || bytes.len() > MAX_BOOTSTRAP_CONFIG_BYTES {
            return Err(if bytes.len() > MAX_BOOTSTRAP_CONFIG_BYTES {
                WorkerProtocolError::Oversize
            } else {
                WorkerProtocolError::Truncated
            });
        }
        if bytes[0..4] != WORKER_CONFIG_MAGIC
            || u16::from_le_bytes(bytes[4..6].try_into().expect("fixed config slice"))
                != WORKER_CONFIG_VERSION
            || bytes[9] & !0b0000_0111 != 0
            || bytes[11] & !0b0000_0011 != 0
        {
            return Err(WorkerProtocolError::Malformed(
                "worker bootstrap configuration header is invalid",
            ));
        }
        let role = WorkerApplicationRole::decode(bytes[6])?;
        let entry_kind = match bytes[7] {
            1 => ArmedEntryKind::File,
            2 => ArmedEntryKind::Stdin,
            3 => ArmedEntryKind::Repl,
            4 => ArmedEntryKind::Eval,
            _ => return Err(WorkerProtocolError::Malformed("unknown worker entry kind")),
        };
        let mode = match bytes[8] {
            1 => ArmedExecutionMode::Interactive,
            2 => ArmedExecutionMode::Transcript,
            3 => ArmedExecutionMode::Program,
            4 => ArmedExecutionMode::OneShot,
            _ => {
                return Err(WorkerProtocolError::Malformed(
                    "unknown worker execution mode",
                ))
            }
        };
        let topology = match bytes[10] {
            1 => PresentationTopology::StdoutTty,
            2 => PresentationTopology::StderrTty,
            3 => PresentationTopology::Transcript,
            _ => {
                return Err(WorkerProtocolError::Malformed(
                    "unknown worker presentation topology",
                ))
            }
        };
        let application_length =
            u32::from_le_bytes(bytes[12..16].try_into().expect("fixed config slice")) as usize;
        if application_length != bytes.len() - WORKER_CONFIG_HEADER_BYTES {
            return Err(WorkerProtocolError::Malformed(
                "worker bootstrap configuration length disagrees",
            ));
        }
        let configuration = Self {
            session_io: SessionIoPlan {
                route: SelectedExecutionRoute { entry_kind, mode },
                terminal_facts: NativeTerminalFacts {
                    stdin_is_tty: bytes[9] & 1 != 0,
                    stdout_is_tty: bytes[9] & 2 != 0,
                    stderr_is_tty: bytes[9] & 4 != 0,
                },
                presentation: CapturedPresentation {
                    topology,
                    session_ansi: bytes[11] & 1 != 0,
                    editor_control: bytes[11] & 2 != 0,
                },
            },
            role,
            application: bytes[WORKER_CONFIG_HEADER_BYTES..].to_vec(),
        };
        configuration.validate()?;
        Ok(configuration)
    }
}

#[cfg(unix)]
pub(crate) struct WorkerSpawnSpec {
    executable: PathBuf,
    root: AuthenticatedRootDescriptor,
    binding: ArmedSessionBinding,
    bootstrap_config: Vec<u8>,
    output_topology: crate::terminal_session::OutputDestinationTopology,
    sequence_epoch: u64,
}

#[cfg(unix)]
impl WorkerSpawnSpec {
    pub(crate) fn new(
        executable: PathBuf,
        root: AuthenticatedRootDescriptor,
        binding: ArmedSessionBinding,
        bootstrap_config: WorkerBootstrapConfiguration,
        sequence_epoch: u64,
    ) -> Result<Self, WorkerProtocolError> {
        let output_topology = bootstrap_config.session_io.output_topology();
        let bootstrap_config = bootstrap_config.encode()?;
        if sequence_epoch == 0 {
            return Err(WorkerProtocolError::Malformed(
                "sequence epoch must be nonzero",
            ));
        }
        Ok(Self {
            executable,
            root,
            binding,
            bootstrap_config,
            output_topology,
            sequence_epoch,
        })
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct WorkerDeath {
    pub status: Option<i32>,
    pub signal: Option<i32>,
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) enum SupervisorEventPayload {
    Worker(ControlMessage),
    WorkerDied(WorkerDeath),
    /// The supervisor authenticated and sequenced ordinary async events but
    /// could not retain their closed payloads in its bounded delivery lane.
    /// This is not worker-side `PreReceiptLoss` and never crosses the wire.
    // @ref LLP 0024#9-asynchronous-failures
    PostReceiptLoss {
        count: u64,
        highest_dropped_sequence: u64,
    },
    /// Fixed-size supervisor-local record occupying the lane's terminal
    /// reserve. Required records and loss-accounting faults cannot disappear
    /// merely because the consumer is stalled.
    ControllerFault(bounded_lane::ControllerFaultReason),
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct SupervisorRelayAcceptanceState {
    stdout: AtomicU64,
    stderr: AtomicU64,
}

/// Supervisor-owned receipt counters shared by the control receiver and the
/// output broker after the raw relay descriptors are handed off. A worker may
/// put arbitrary cutoff values on its authenticated record; only this
/// supervisor-side acceptance state is allowed to order a diagnostic. Shared
/// topology uses the stdout cell as its canonical single counter and leaves
/// stderr at zero, matching the worker cutoff vector.
// @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker
#[cfg(unix)]
#[derive(Clone, Debug, Default)]
pub(crate) struct SupervisorRelayAcceptance {
    state: Arc<SupervisorRelayAcceptanceState>,
}

#[cfg(unix)]
impl SupervisorRelayAcceptance {
    pub(crate) fn snapshot(&self) -> (u64, u64) {
        (
            self.state.stdout.load(Ordering::Acquire),
            self.state.stderr.load(Ordering::Acquire),
        )
    }

    pub(crate) fn note_stdout(&self, amount: u64) -> Result<(), &'static str> {
        Self::note(&self.state.stdout, amount)
    }

    pub(crate) fn note_stderr(&self, amount: u64) -> Result<(), &'static str> {
        Self::note(&self.state.stderr, amount)
    }

    fn note(counter: &AtomicU64, amount: u64) -> Result<(), &'static str> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(amount)
            })
            .map(|_| ())
            .map_err(|_| "supervisor relay-acceptance counter exhausted u64")
    }
}

#[cfg(unix)]
pub(crate) enum WorkerRelayDescriptors {
    Shared {
        output: std::os::fd::OwnedFd,
    },
    Split {
        stdout: std::os::fd::OwnedFd,
        stderr: std::os::fd::OwnedFd,
    },
}

#[cfg(unix)]
pub(crate) struct WorkerRelays {
    pub(crate) descriptors: WorkerRelayDescriptors,
    pub(crate) acceptance: SupervisorRelayAcceptance,
    pub(crate) sequencer: SupervisorSequenceAllocator,
}

#[cfg(unix)]
pub(crate) struct SupervisorWorker {
    child: std::process::Child,
    channel: AuthenticatedChannel<std::os::unix::net::UnixStream>,
    watchdog: Option<std::os::unix::net::UnixStream>,
    relays: Option<WorkerRelayDescriptors>,
    expected_ready_proof: [u8; 32],
    ready: bool,
    sequencer: SupervisorSequenceAllocator,
    relay_acceptance: SupervisorRelayAcceptance,
    // Shared with the terminal owner so a lifecycle record or exit-code
    // mutation remains authoritative even when only its ACK is lost and the
    // controller thread subsequently loses the transport.
    lifecycle: Arc<Mutex<SupervisorLifecycleState>>,
}

/// Own a spawned worker until every authenticated bootstrap step and every
/// fallible supervisor field has been constructed. `std::process::Child` does
/// not terminate or reap on drop, so an ordinary `?` before handoff would
/// otherwise leave a pre-handshake worker and its process group behind.
/// @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker
#[cfg(unix)]
struct PendingSupervisorChild {
    child: Option<std::process::Child>,
}

#[cfg(unix)]
impl PendingSupervisorChild {
    fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn child(&self) -> &std::process::Child {
        self.child
            .as_ref()
            .expect("pending supervisor child is owned until handoff")
    }

    fn into_child(mut self) -> std::process::Child {
        self.child
            .take()
            .expect("pending supervisor child is handed off exactly once")
    }
}

#[cfg(unix)]
impl Drop for PendingSupervisorChild {
    fn drop(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        if child.try_wait().ok().flatten().is_none() {
            terminate_process_group(child.id());
            let _ = child.wait();
        }
    }
}

#[cfg(unix)]
fn normalize_supervisor_diagnostic_cutoffs(
    message: &mut ControlMessage,
    (stdout_cutoff, stderr_cutoff): (u64, u64),
) {
    match message {
        ControlMessage::AsyncFailure {
            stdout_cutoff: supplied_stdout,
            stderr_cutoff: supplied_stderr,
            ..
        }
        | ControlMessage::WorkerFault {
            stdout_cutoff: supplied_stdout,
            stderr_cutoff: supplied_stderr,
            ..
        } => {
            *supplied_stdout = stdout_cutoff;
            *supplied_stderr = stderr_cutoff;
        }
        _ => {}
    }
}

#[cfg(unix)]
impl SupervisorWorker {
    pub(crate) fn spawn(
        spec: WorkerSpawnSpec,
        hello_timeout: Duration,
    ) -> Result<Self, WorkerProtocolError> {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        // The supervisor owns final disposition for broken relay/control
        // writes; a process-default SIGPIPE must not bypass that decision.
        if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) } == libc::SIG_ERR {
            return Err(WorkerProtocolError::Io(io::Error::last_os_error()));
        }

        let (control_parent, control_child) = std::os::unix::net::UnixStream::pair()?;
        let (mut bootstrap_parent, bootstrap_child) = std::os::unix::net::UnixStream::pair()?;
        let (watchdog_parent, watchdog_child) = std::os::unix::net::UnixStream::pair()?;

        let control_source = duplicate_high(control_child.as_raw_fd())?;
        let bootstrap_source = duplicate_high(bootstrap_child.as_raw_fd())?;
        let root_source = duplicate_high(spec.root.file.as_raw_fd())?;
        let watchdog_source = duplicate_high(watchdog_child.as_raw_fd())?;
        let inherited = [
            (control_source.as_raw_fd(), CONTROL_FD),
            (bootstrap_source.as_raw_fd(), BOOTSTRAP_FD),
            (root_source.as_raw_fd(), ROOT_FD),
            (watchdog_source.as_raw_fd(), WATCHDOG_FD),
        ];

        let (stdout, stderr, relays) = worker_relay_stdio(spec.output_topology)?;
        let mut command = Command::new(&spec.executable);
        command
            .arg(WORKER_BOOTSTRAP_ARG)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        // The only argv payload is the fixed, registry-inventoried bootstrap
        // spelling. Secrets, root paths, and descriptor numbers are absent.
        unsafe {
            command.pre_exec(move || {
                for (source, target) in inherited {
                    if libc::dup2(source, target) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                mark_unlisted_fds_close_on_exec()?;
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::signal(libc::SIGPIPE, libc::SIG_IGN) == libc::SIG_ERR {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let pending_child = PendingSupervisorChild::new(command.spawn()?);
        drop((control_child, bootstrap_child, watchdog_child));
        drop((
            control_source,
            bootstrap_source,
            root_source,
            watchdog_source,
        ));

        let channel_key_bytes = fresh_bytes()?;
        let channel_epoch = fresh_nonzero_u64()?;
        let challenge = fresh_bytes()?;
        let record = BootstrapRecord {
            channel_key: channel_key_bytes,
            channel_epoch,
            binding: spec.binding.clone(),
            challenge,
            parent_pid: std::process::id(),
        };
        let encoded = record.encode();
        bootstrap_parent.write_all(&encoded)?;
        bootstrap_parent.shutdown(std::net::Shutdown::Both)?;
        drop(bootstrap_parent);

        let mut channel = AuthenticatedChannel::new(
            control_parent,
            EndpointRole::Supervisor,
            ChannelKey(channel_key_bytes),
            spec.binding.run_nonce,
            channel_epoch,
        );
        channel.send_until(
            &ControlMessage::SupervisorHello {
                challenge,
                bootstrap_config: spec.bootstrap_config,
            },
            deadline_after(hello_timeout),
        )?;
        let hello = channel.receive_until(deadline_after(hello_timeout));
        let (pid, supplied_root_proof) = match hello {
            Ok(ControlMessage::WorkerHello { pid, root_proof }) => (pid, root_proof),
            Ok(_) => {
                return Err(WorkerProtocolError::Malformed(
                    "worker did not send its hello first",
                ));
            }
            Err(error) => return Err(error),
        };
        if pid != pending_child.child().id()
            || supplied_root_proof
                != root_proof(&record_key(&record), &challenge, spec.root.object())?
        {
            return Err(WorkerProtocolError::WrongRoot);
        }
        let expected_ready_proof = session_proof(
            &record_key(&record),
            &challenge,
            &spec.binding,
            spec.root.object(),
        )?;
        let sequencer = SupervisorSequenceAllocator::new(spec.sequence_epoch)?;
        let child = pending_child.into_child();
        Ok(Self {
            child,
            channel,
            watchdog: Some(watchdog_parent),
            relays: Some(relays),
            expected_ready_proof,
            ready: false,
            sequencer,
            relay_acceptance: SupervisorRelayAcceptance::default(),
            lifecycle: Arc::new(Mutex::new(SupervisorLifecycleState::default())),
        })
    }

    pub(crate) fn await_ready(&mut self, timeout: Duration) -> Result<(), WorkerProtocolError> {
        if self.ready {
            return Ok(());
        }
        match self.channel.receive_until(deadline_after(timeout))? {
            ControlMessage::WorkerReady { session_proof }
                if session_proof == self.expected_ready_proof =>
            {
                self.ready = true;
                Ok(())
            }
            ControlMessage::WorkerReady { .. } => Err(WorkerProtocolError::WrongSession),
            _ => Err(WorkerProtocolError::Malformed(
                "worker sent application traffic before ready",
            )),
        }
    }

    pub(crate) fn send(&mut self, message: &ControlMessage) -> Result<(), WorkerProtocolError> {
        if !self.ready {
            return Err(WorkerProtocolError::WrongSession);
        }
        self.channel
            .send_until(message, deadline_after(SUPERVISOR_FRAME_WRITE_TIMEOUT))
    }

    /// Bound one supervisor control write without imposing a lifetime on the
    /// operation the record requests. Cancellation uses this so a worker that
    /// stopped reading its socket cannot trap the terminal owner before the
    /// second-interrupt escape path.
    // @ref LLP 0025#6-interruption-and-cancellation
    pub(crate) fn send_with_write_timeout(
        &mut self,
        message: &ControlMessage,
        timeout: Duration,
    ) -> Result<(), WorkerProtocolError> {
        if !self.ready {
            return Err(WorkerProtocolError::WrongSession);
        }
        self.channel.send_until(message, deadline_after(timeout))
    }

    pub(crate) fn receive_event(
        &mut self,
    ) -> Result<Sequenced<SupervisorEventPayload>, WorkerProtocolError> {
        let payload = self.receive_event_payload()?;
        self.sequencer.assign(payload)
    }

    /// Receive, authenticate, normalize, and durably apply a worker event
    /// without assigning its supervisor receipt sequence. The bounded
    /// controller lane owns assignment so a post-receipt loss marker can be
    /// sequenced after every dropped receipt and before the next retained
    /// event.
    pub(crate) fn receive_event_payload(
        &mut self,
    ) -> Result<SupervisorEventPayload, WorkerProtocolError> {
        if !self.ready {
            return Err(WorkerProtocolError::WrongSession);
        }
        unix_stream_wait_readable(&self.channel.io)?;
        self.receive_event_payload_until(deadline_after(CONTROL_FRAME_READ_TIMEOUT))
    }

    fn receive_event_payload_until(
        &mut self,
        deadline: Instant,
    ) -> Result<SupervisorEventPayload, WorkerProtocolError> {
        let mut message = match self.channel.receive_until(deadline) {
            Ok(message) => message,
            Err(WorkerProtocolError::CleanEof) | Err(WorkerProtocolError::Truncated) => {
                terminate_process_group(self.child.id());
                let status = self.child.wait()?;
                self.lifecycle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .latch_engine_fault();
                return Ok(SupervisorEventPayload::WorkerDied(worker_death(status)));
            }
            Err(error) => return Err(error),
        };
        normalize_supervisor_diagnostic_cutoffs(&mut message, self.relay_acceptance.snapshot());
        match &message {
            ControlMessage::LifecycleCommit(record) => {
                self.lifecycle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .accept_lifecycle(record.clone())?;
                // Acceptance is durable before ACK. A failed ACK does not
                // erase the record: the worker takes reserved disposition 69
                // while the supervisor still completes cooperative exit n.
                let _ = self.channel.send_until(
                    &ControlMessage::LifecycleAck {
                        request_id: record.request_id,
                    },
                    deadline_after(SUPERVISOR_FRAME_WRITE_TIMEOUT),
                );
            }
            ControlMessage::ExitCodeMirror {
                mutation_id,
                status,
            } => {
                self.lifecycle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .mirror_exit_code(*mutation_id, *status)?;
                // The mirrored value is authoritative once accepted even if
                // the acknowledgement cannot make the reverse trip.
                let _ = self.channel.send_until(
                    &ControlMessage::ExitCodeAck {
                        mutation_id: *mutation_id,
                    },
                    deadline_after(SUPERVISOR_FRAME_WRITE_TIMEOUT),
                );
            }
            _ => {}
        }
        Ok(SupervisorEventPayload::Worker(message))
    }

    /// Do not begin consuming a framed record until the stream is readable.
    /// This lets the supervisor service terminal, relay, and signal queues
    /// without timing out halfway through an authenticated frame.
    pub(crate) fn receive_event_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<Sequenced<SupervisorEventPayload>>, WorkerProtocolError> {
        let payload = self.receive_event_payload_timeout(timeout)?;
        payload
            .map(|payload| self.sequencer.assign(payload))
            .transpose()
    }

    pub(crate) fn receive_event_payload_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<SupervisorEventPayload>, WorkerProtocolError> {
        if !self.ready {
            return Err(WorkerProtocolError::WrongSession);
        }
        if !unix_stream_readable(&self.channel.io, timeout)? {
            return Ok(None);
        }
        self.receive_event_payload_until(deadline_after(CONTROL_FRAME_READ_TIMEOUT))
            .map(Some)
    }

    pub(crate) fn sequence_allocator(&self) -> SupervisorSequenceAllocator {
        self.sequencer.clone()
    }

    pub(crate) fn take_relays(&mut self) -> Result<WorkerRelays, WorkerProtocolError> {
        Ok(WorkerRelays {
            descriptors: self.relays.take().ok_or(WorkerProtocolError::Malformed(
                "worker output relays were already taken",
            ))?,
            acceptance: self.relay_acceptance.clone(),
            sequencer: self.sequencer.clone(),
        })
    }

    pub(crate) fn lifecycle(&self) -> SupervisorLifecycleState {
        self.lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn lifecycle_handle(&self) -> Arc<Mutex<SupervisorLifecycleState>> {
        Arc::clone(&self.lifecycle)
    }

    /// Engine-independent second-press/watchdog termination. The supervisor
    /// owns terminal restoration and broker disposition around this call.
    pub(crate) fn terminate_for_interrupt(&mut self) -> Result<WorkerDeath, WorkerProtocolError> {
        self.lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .latch_interrupt();
        self.terminate_preserving_lifecycle()
    }

    /// Freeze the worker's entire isolated process group before the terminal
    /// supervisor stops itself. This is deliberately a kernel operation rather
    /// than an authenticated application command: it must work while Hermes is
    /// stuck and cannot service the control lane.
    // @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker
    pub(crate) fn suspend_for_terminal(&mut self) -> Result<(), WorkerProtocolError> {
        signal_process_group(self.child.id(), libc::SIGSTOP)
    }

    /// Continue the isolated worker group only after the supervisor has
    /// reacquired the foreground terminal and reinstalled presentation mode.
    pub(crate) fn continue_after_terminal(&mut self) -> Result<(), WorkerProtocolError> {
        signal_process_group(self.child.id(), libc::SIGCONT)
    }

    /// Dispose the evaluator process without changing the supervisor's already
    /// latched lifecycle/fault disposition. Cooperative `process.exit` parks
    /// the engine thread by design, so shutdown on that path must not depend on
    /// the worker returning to its command loop.
    pub(crate) fn quiesce_preserving_lifecycle(&mut self) -> Result<(), WorkerProtocolError> {
        terminate_process_group(self.child.id());
        self.watchdog.take();
        Ok(())
    }

    /// Reap a worker whose process group has already been quiesced. Keeping
    /// this separate from the kill edge lets the terminal owner drain every
    /// byte accepted by the relay before it releases the worker lifetime.
    pub(crate) fn reap_preserving_lifecycle(&mut self) -> Result<WorkerDeath, WorkerProtocolError> {
        Ok(worker_death(self.child.wait()?))
    }

    pub(crate) fn terminate_preserving_lifecycle(
        &mut self,
    ) -> Result<WorkerDeath, WorkerProtocolError> {
        self.quiesce_preserving_lifecycle()?;
        self.reap_preserving_lifecycle()
    }

    pub(crate) fn wait(&mut self) -> Result<WorkerDeath, WorkerProtocolError> {
        let status = self.child.wait()?;
        self.watchdog.take();
        Ok(worker_death(status))
    }
}

#[cfg(unix)]
impl Drop for SupervisorWorker {
    fn drop(&mut self) {
        self.watchdog.take();
        if self.child.try_wait().ok().flatten().is_none() {
            terminate_process_group(self.child.id());
            let _ = self.child.wait();
        }
    }
}

fn record_key(record: &BootstrapRecord) -> ChannelKey {
    ChannelKey(record.channel_key)
}

/// Build the worker's fd-1/fd-2 topology before spawn. In shared mode both
/// `Stdio` values own duplicates of one pipe write-end, so the child receives
/// two descriptor slots backed by one open file description.
// @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker
#[cfg(unix)]
fn worker_relay_stdio(
    topology: crate::terminal_session::OutputDestinationTopology,
) -> Result<
    (
        std::process::Stdio,
        std::process::Stdio,
        WorkerRelayDescriptors,
    ),
    WorkerProtocolError,
> {
    use std::os::fd::AsRawFd;
    use std::process::Stdio;

    match topology {
        crate::terminal_session::OutputDestinationTopology::Shared { .. } => {
            let (output, stdout) = worker_relay_pipe()?;
            let stderr = duplicate_high(stdout.as_raw_fd())?;
            Ok((
                Stdio::from(stdout),
                Stdio::from(stderr),
                WorkerRelayDescriptors::Shared { output },
            ))
        }
        crate::terminal_session::OutputDestinationTopology::Split => {
            let (stdout_output, stdout) = worker_relay_pipe()?;
            let (stderr_output, stderr) = worker_relay_pipe()?;
            Ok((
                Stdio::from(stdout),
                Stdio::from(stderr),
                WorkerRelayDescriptors::Split {
                    stdout: stdout_output,
                    stderr: stderr_output,
                },
            ))
        }
    }
}

#[cfg(unix)]
fn worker_relay_pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), WorkerProtocolError>
{
    use std::os::fd::{AsRawFd, FromRawFd};

    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(WorkerProtocolError::Io(io::Error::last_os_error()));
    }
    // SAFETY: pipe returned two newly owned descriptors.
    let read = unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptors[0]) };
    let write = unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptors[1]) };
    for descriptor in [read.as_raw_fd(), write.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(WorkerProtocolError::Io(io::Error::last_os_error()));
        }
    }
    Ok((read, write))
}

#[cfg(unix)]
fn duplicate_high(fd: i32) -> Result<std::os::fd::OwnedFd, WorkerProtocolError> {
    use std::os::fd::FromRawFd;

    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64) };
    if duplicate < 0 {
        return Err(WorkerProtocolError::Io(io::Error::last_os_error()));
    }
    // SAFETY: fcntl returned a new owned descriptor.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicate) })
}

#[cfg(unix)]
fn mark_unlisted_fds_close_on_exec() -> io::Result<()> {
    let open_max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let open_max = if open_max <= 0 {
        65_536
    } else {
        open_max.min(1_048_576) as i32
    };
    for fd in 7..open_max {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unix_stream_readable(
    stream: &std::os::unix::net::UnixStream,
    timeout: Duration,
) -> Result<bool, WorkerProtocolError> {
    use std::os::fd::AsRawFd;

    let deadline = deadline_after(timeout);
    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let millis = remaining
            .as_millis()
            .saturating_add(u128::from(
                !remaining.subsec_nanos().is_multiple_of(1_000_000),
            ))
            .min(i32::MAX as u128) as i32;
        descriptor.revents = 0;
        let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if result > 0 {
            return Ok(descriptor.revents
                & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                != 0);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(WorkerProtocolError::Io(error));
        }
    }
}

#[cfg(unix)]
fn unix_stream_wait_readable(
    stream: &std::os::unix::net::UnixStream,
) -> Result<(), WorkerProtocolError> {
    use std::os::fd::AsRawFd;

    let mut descriptor = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        descriptor.revents = 0;
        let result = unsafe { libc::poll(&mut descriptor, 1, -1) };
        if result > 0
            && descriptor.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                != 0
        {
            return Ok(());
        }
        if result >= 0 {
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(WorkerProtocolError::Io(error));
        }
    }
}

#[cfg(unix)]
fn terminate_process_group(child_pid: u32) {
    let pid = i32::try_from(child_pid).unwrap_or(i32::MAX);
    if pid > 0 {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

#[cfg(unix)]
fn signal_process_group(child_pid: u32, signal: libc::c_int) -> Result<(), WorkerProtocolError> {
    let pid = i32::try_from(child_pid).map_err(|_| {
        WorkerProtocolError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker pid does not fit the platform pid type",
        ))
    })?;
    if pid <= 0 {
        return Err(WorkerProtocolError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker pid is not positive",
        )));
    }
    // `setsid` in the spawn hook makes the child pid its process-group id.
    // Signal the group so intact-adapter descendants cannot keep running while
    // the operator has suspended the terminal owner.
    if unsafe { libc::kill(-pid, signal) } != 0 {
        return Err(WorkerProtocolError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(unix)]
fn worker_death(status: std::process::ExitStatus) -> WorkerDeath {
    use std::os::unix::process::ExitStatusExt;
    WorkerDeath {
        status: status.code(),
        signal: status.signal(),
    }
}

#[cfg(unix)]
pub(crate) struct WorkerBootstrapContext {
    channel: AuthenticatedChannel<std::os::unix::net::UnixStream>,
    expected_binding: ArmedSessionBinding,
    root_object: capsec_semantics::model::ObjectIdentity,
    root_file: std::fs::File,
    challenge: [u8; 32],
    bootstrap_config: Vec<u8>,
}

#[cfg(unix)]
impl WorkerBootstrapContext {
    pub(crate) fn inherited_root_object(&self) -> &capsec_semantics::model::ObjectIdentity {
        &self.root_object
    }

    /// These descriptors must be installed into the worker's native
    /// SessionIo protected class before any project source can execute.
    const fn protected_descriptors(&self) -> [i32; 3] {
        [CONTROL_FD, ROOT_FD, WATCHDOG_FD]
    }

    /// Construct and retain the worker's descriptor policy before Runtime
    /// construction. Consuming `self` prevents a caller from authenticating
    /// the application endpoint while skipping protected-fd installation or
    /// cross-pairing a caller-selected SessionIo plan with this channel.
    pub(crate) fn protect_session_io(
        self,
    ) -> Result<ProtectedWorkerBootstrap, WorkerProtocolError> {
        let configuration = WorkerBootstrapConfiguration::decode(&self.bootstrap_config)?;
        // Install the counted worker relay before Runtime/Host construction so
        // every JavaScript-reachable fd-1/fd-2 write enters the same measured
        // path. Its private restoration, destination, and queue descriptors
        // join the protected class atomically with the authenticated control
        // descriptors below.
        // @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker
        let output_relay = crate::terminal_session::WorkerOutputRelayAdapter::install(
            configuration.session_io.output_topology(),
        )?;
        let mut protected_descriptors = self.protected_descriptors().to_vec();
        protected_descriptors.extend_from_slice(output_relay.protected_descriptors());
        let mut descriptor_policy =
            crate::terminal_session::SessionIo::new(configuration.session_io);
        for descriptor in protected_descriptors.iter().copied() {
            descriptor_policy
                .protect_descriptor(descriptor)
                .map_err(|_| {
                    WorkerProtocolError::Malformed(
                        "worker control descriptor could not be protected",
                    )
                })?;
        }
        let native_descriptor_policy = crate::host::abi::arm_terminal_session_descriptor_policy(
            configuration.session_io.route.seals_javascript_stdin(),
            protected_descriptors,
        )?;
        let terminal_facts = configuration.session_io.terminal_facts;
        let stdio_query = crate::host::abi::arm_terminal_session_stdio_query(
            terminal_facts.stdin_is_tty && !configuration.session_io.route.seals_javascript_stdin(),
            terminal_facts.stdout_is_tty,
            terminal_facts.stderr_is_tty,
        )?;
        Ok(ProtectedWorkerBootstrap {
            context: self,
            descriptor_policy,
            native_descriptor_policy,
            stdio_query,
            output_relay,
            configuration,
        })
    }

    /// Complete the handshake only after the worker independently armed its
    /// Runtime and re-derived both the exact session binding and root object.
    fn authenticate(
        mut self,
        actual_binding: &ArmedSessionBinding,
        actual_root: &capsec_semantics::model::ObjectIdentity,
        descriptor_policy: crate::terminal_session::SessionIo,
        native_descriptor_policy: crate::host::abi::TerminalSessionDescriptorPolicyGuard,
        stdio_query: crate::host::abi::TerminalSessionStdioQueryGuard,
        output_relay: crate::terminal_session::WorkerOutputRelayAdapter,
    ) -> Result<VerifiedWorkerEndpoint, WorkerProtocolError> {
        if actual_binding != &self.expected_binding {
            return Err(WorkerProtocolError::WrongSession);
        }
        if actual_root != &self.root_object {
            return Err(WorkerProtocolError::WrongRoot);
        }
        let proof = session_proof(
            &self.channel.key,
            &self.challenge,
            actual_binding,
            actual_root,
        )?;
        self.channel.send_until(
            &ControlMessage::WorkerReady {
                session_proof: proof,
            },
            deadline_after(LIFECYCLE_ACK_TIMEOUT),
        )?;
        Ok(VerifiedWorkerEndpoint {
            channel: self.channel,
            deferred_inbound: VecDeque::new(),
            _root_file: self.root_file,
            _descriptor_policy: descriptor_policy,
            _native_descriptor_policy: WorkerNativeDescriptorPolicy::Installed {
                _guard: native_descriptor_policy,
            },
            stdio_query: Some(stdio_query),
            _output_relay: Some(output_relay),
        })
    }
}

/// Bootstrap authority after the worker's protected descriptor class has
/// been installed, but before Runtime construction and session equality are
/// accepted.
#[cfg(unix)]
pub(crate) struct ProtectedWorkerBootstrap {
    context: WorkerBootstrapContext,
    descriptor_policy: crate::terminal_session::SessionIo,
    native_descriptor_policy: crate::host::abi::TerminalSessionDescriptorPolicyGuard,
    stdio_query: crate::host::abi::TerminalSessionStdioQueryGuard,
    output_relay: crate::terminal_session::WorkerOutputRelayAdapter,
    configuration: WorkerBootstrapConfiguration,
}

#[cfg(unix)]
impl ProtectedWorkerBootstrap {
    pub(crate) fn configuration(&self) -> &WorkerBootstrapConfiguration {
        &self.configuration
    }

    pub(crate) fn inherited_root_object(&self) -> &capsec_semantics::model::ObjectIdentity {
        self.context.inherited_root_object()
    }

    pub(crate) fn output_cutoff_port(&self) -> crate::terminal_session::WorkerOutputCutoffPort {
        self.output_relay.cutoff_port()
    }

    /// Open the application lane only after the newly-created Runtime has
    /// independently reproduced the armed binding and root identity.
    pub(crate) fn authenticate(
        self,
        actual_binding: &ArmedSessionBinding,
        actual_root: &capsec_semantics::model::ObjectIdentity,
    ) -> Result<VerifiedWorkerEndpoint, WorkerProtocolError> {
        self.context.authenticate(
            actual_binding,
            actual_root,
            self.descriptor_policy,
            self.native_descriptor_policy,
            self.stdio_query,
            self.output_relay,
        )
    }
}

#[cfg(unix)]
enum WorkerNativeDescriptorPolicy {
    Installed {
        _guard: crate::host::abi::TerminalSessionDescriptorPolicyGuard,
    },
    // Protocol-loop tests construct the private endpoint without a Runtime.
    #[cfg(test)]
    ProtocolOnly,
}

#[cfg(unix)]
pub(crate) struct VerifiedWorkerEndpoint {
    channel: AuthenticatedChannel<std::os::unix::net::UnixStream>,
    // A synchronous ACK exchange may legally race supervisor commands on the
    // same authenticated lane. Keep those records in order for the central
    // loop instead of misclassifying the first one as a bad ACK.
    deferred_inbound: VecDeque<ControlMessage>,
    // Keeping the descriptor open keeps the independently-authenticated root
    // object alive for the whole Runtime lifetime.
    _root_file: std::fs::File,
    // The policy must outlive the Runtime/application loop so protected
    // descriptors never silently become ordinary native descriptors.
    _descriptor_policy: crate::terminal_session::SessionIo,
    // The Host ABI guard is the policy native engine routes actually query.
    // Retain it for the full authenticated application-endpoint lifetime.
    _native_descriptor_policy: WorkerNativeDescriptorPolicy,
    // Live dimensions remain available to capability-checked JS getters even
    // while the engine owner thread is executing hostile or stuck code.
    stdio_query: Option<crate::host::abi::TerminalSessionStdioQueryGuard>,
    // Retention is part of the authenticated endpoint lifetime: dropping this
    // guard would restore ordinary fd 1/2 and silently invalidate every later
    // output cutoff.
    _output_relay: Option<crate::terminal_session::WorkerOutputRelayAdapter>,
}

#[cfg(unix)]
impl VerifiedWorkerEndpoint {
    pub(crate) fn update_terminal_dimensions(
        &self,
        columns: u16,
        rows: u16,
    ) -> Result<(), WorkerProtocolError> {
        let state = self
            .stdio_query
            .as_ref()
            .ok_or(WorkerProtocolError::Malformed(
                "verified worker omitted typed stdio query state",
            ))?;
        state.update_dimensions(columns, rows);
        Ok(())
    }

    pub(crate) fn send(&mut self, message: &ControlMessage) -> Result<(), WorkerProtocolError> {
        self.channel
            .send_until(message, deadline_after(WORKER_EVENT_WRITE_TIMEOUT))
    }

    pub(crate) fn receive(&mut self) -> Result<ControlMessage, WorkerProtocolError> {
        if let Some(message) = self.deferred_inbound.pop_front() {
            return Ok(message);
        }
        unix_stream_wait_readable(&self.channel.io)?;
        self.channel
            .receive_until(deadline_after(CONTROL_FRAME_READ_TIMEOUT))
    }

    pub(crate) fn receive_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ControlMessage>, WorkerProtocolError> {
        if let Some(message) = self.deferred_inbound.pop_front() {
            return Ok(Some(message));
        }
        if !unix_stream_readable(&self.channel.io, timeout)? {
            return Ok(None);
        }
        self.channel
            .receive_until(deadline_after(CONTROL_FRAME_READ_TIMEOUT))
            .map(Some)
    }

    fn receive_matching_ack(
        &mut self,
        timeout: Duration,
        mut matches_ack: impl FnMut(&ControlMessage) -> bool,
        mismatch: &'static str,
    ) -> Result<(), WorkerProtocolError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            if Instant::now() >= deadline {
                return Err(WorkerProtocolError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    mismatch,
                )));
            }
            let message = self.channel.receive_until(deadline)?;
            if matches_ack(&message) {
                return Ok(());
            }
            if matches!(
                message,
                ControlMessage::Start { .. }
                    | ControlMessage::Submit { .. }
                    | ControlMessage::EndOfInput
                    | ControlMessage::DisplayAck { .. }
                    | ControlMessage::Cancel { .. }
                    | ControlMessage::Shutdown { .. }
                    | ControlMessage::Resize { .. }
                    | ControlMessage::Ping { .. }
                    | ControlMessage::ReadyCheckpoint { .. }
            ) {
                self.deferred_inbound.push_back(message);
                continue;
            }
            return Err(WorkerProtocolError::Malformed(mismatch));
        }
    }

    /// Emit an application event. Handshake and supervisor-only records stay
    /// outside the callback surface; lifecycle and exit-code messages use the
    /// acknowledged methods below.
    pub(crate) fn emit(&mut self, message: &ControlMessage) -> Result<(), WorkerProtocolError> {
        if !matches!(
            message,
            ControlMessage::Step { .. }
                | ControlMessage::Outcome { .. }
                | ControlMessage::AsyncFailure { .. }
                | ControlMessage::WorkUnit { .. }
                | ControlMessage::CancellationResolved { .. }
                | ControlMessage::Quiescent
                | ControlMessage::PreReceiptLoss { .. }
                | ControlMessage::WorkerFault { .. }
                | ControlMessage::ReadyCheckpointAck { .. }
        ) {
            return Err(WorkerProtocolError::WrongDirection);
        }
        self.send(message)
    }

    pub(crate) fn send_lifecycle_commit(
        &mut self,
        record: LifecycleRecord,
    ) -> Result<(), WorkerProtocolError> {
        self.channel.send_until(
            &ControlMessage::LifecycleCommit(record.clone()),
            deadline_after(LIFECYCLE_ACK_TIMEOUT),
        )?;
        self.receive_matching_ack(
            LIFECYCLE_ACK_TIMEOUT,
            |message| {
                matches!(
                    message,
                    ControlMessage::LifecycleAck { request_id }
                        if *request_id == record.request_id
                )
            },
            "lifecycle acknowledgement did not match the request",
        )
    }

    /// The worker realization of root-authorized `process.exit`: publish the
    /// fixed record, require its acknowledgement, then park without returning
    /// through JavaScript or unwinding the engine frame. A missing ACK takes
    /// the reserved worker disposition; the supervisor still keys final status
    /// on whether it accepted the record.
    // @ref LLP 0025#8-exit-and-lifecycle
    pub(crate) fn commit_lifecycle_and_park(&mut self, record: LifecycleRecord) -> ! {
        if self.send_lifecycle_commit(record).is_err() {
            unsafe { libc::_exit(69) }
        }
        loop {
            unsafe {
                libc::pause();
            }
        }
    }

    pub(crate) fn mirror_exit_code(
        &mut self,
        mutation_id: u64,
        status: i32,
    ) -> Result<(), WorkerProtocolError> {
        self.channel.send_until(
            &ControlMessage::ExitCodeMirror {
                mutation_id,
                status,
            },
            deadline_after(LIFECYCLE_ACK_TIMEOUT),
        )?;
        self.receive_matching_ack(
            LIFECYCLE_ACK_TIMEOUT,
            |message| {
                matches!(
                    message,
                    ControlMessage::ExitCodeAck { mutation_id: ack } if *ack == mutation_id
                )
            },
            "exit-code mirror acknowledgement did not match",
        )
    }

    /// Display trees are never fire-and-forget: the worker cannot resolve the
    /// evaluation result until the supervisor has reported displayed,
    /// fallback, or write-failed disposition.
    pub(crate) fn send_display_and_wait_ack(
        &mut self,
        submission_id: u64,
        tree: Vec<u8>,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    ) -> Result<DisplayAckDisposition, WorkerProtocolError> {
        self.send(&ControlMessage::Display {
            submission_id,
            tree,
            stdout_cutoff,
            stderr_cutoff,
        })?;
        let mut disposition = None;
        self.receive_matching_ack(
            LIFECYCLE_ACK_TIMEOUT,
            |message| {
                if let ControlMessage::DisplayAck {
                    submission_id: ack_id,
                    disposition: ack_disposition,
                } = message
                {
                    if *ack_id == submission_id {
                        disposition = Some(*ack_disposition);
                        return true;
                    }
                }
                false
            },
            "display acknowledgement did not match the result",
        )?;
        disposition.ok_or(WorkerProtocolError::Malformed(
            "display acknowledgement carried no disposition",
        ))
    }
}

/// Application commands admitted after the authenticated bootstrap. Protocol
/// handshakes and synchronous acknowledgements are deliberately absent.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AuthenticatedWorkerCommand {
    Start {
        mode: SessionInputMode,
    },
    Submit {
        submission_id: u64,
        kind: SubmissionKind,
        source: Vec<u8>,
    },
    EndOfInput,
    ReadyCheckpoint {
        checkpoint_id: u64,
    },
    Cancel {
        request_id: u64,
        target_id: u64,
    },
    Shutdown {
        status: i32,
    },
    Resize {
        columns: u16,
        rows: u16,
    },
}

#[cfg(unix)]
impl TryFrom<ControlMessage> for AuthenticatedWorkerCommand {
    type Error = WorkerProtocolError;

    fn try_from(message: ControlMessage) -> Result<Self, Self::Error> {
        match message {
            ControlMessage::Start { mode } => Ok(Self::Start { mode }),
            ControlMessage::Submit {
                submission_id,
                kind,
                source,
            } => Ok(Self::Submit {
                submission_id,
                kind,
                source,
            }),
            ControlMessage::EndOfInput => Ok(Self::EndOfInput),
            ControlMessage::ReadyCheckpoint { checkpoint_id } => {
                Ok(Self::ReadyCheckpoint { checkpoint_id })
            }
            ControlMessage::Cancel {
                request_id,
                target_id,
            } => Ok(Self::Cancel {
                request_id,
                target_id,
            }),
            ControlMessage::Shutdown { status } => Ok(Self::Shutdown { status }),
            ControlMessage::Resize { columns, rows } => Ok(Self::Resize { columns, rows }),
            _ => Err(WorkerProtocolError::Malformed(
                "unexpected protocol record on the application command lane",
            )),
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerLoopControl {
    Continue,
    Exit(i32),
}

/// Typed seam between the authenticated worker protocol and Runtime/REPL
/// ownership. Implementations receive no raw channel key, root descriptor, or
/// bootstrap authority.
#[cfg(unix)]
pub(crate) trait AuthenticatedWorkerApplication {
    fn handle(
        &mut self,
        command: AuthenticatedWorkerCommand,
        endpoint: &mut VerifiedWorkerEndpoint,
    ) -> Result<WorkerLoopControl, WorkerProtocolError>;
}

/// Drive authenticated commands until the application chooses a disposition.
/// Ping bypasses application dispatch while the command loop is available;
/// supervisor escape and parent-death enforcement deliberately do not depend
/// on receiving a Pong from a worker stuck inside its application callback.
#[cfg(unix)]
pub(crate) fn run_authenticated_worker_loop(
    mut endpoint: VerifiedWorkerEndpoint,
    application: &mut impl AuthenticatedWorkerApplication,
) -> Result<i32, WorkerProtocolError> {
    loop {
        let command = match endpoint.receive()? {
            ControlMessage::Ping { nonce } => {
                endpoint.send(&ControlMessage::Pong { nonce })?;
                continue;
            }
            message => AuthenticatedWorkerCommand::try_from(message)?,
        };
        match application.handle(command, &mut endpoint)? {
            WorkerLoopControl::Continue => {}
            WorkerLoopControl::Exit(status) => return Ok(status),
        }
    }
}

/// Safe integration placeholder: until main supplies the Runtime-owned
/// application, authenticated traffic is refused without evaluating bytes.
#[cfg(unix)]
pub(crate) struct RefusingWorkerApplication;

#[cfg(unix)]
impl AuthenticatedWorkerApplication for RefusingWorkerApplication {
    fn handle(
        &mut self,
        _command: AuthenticatedWorkerCommand,
        endpoint: &mut VerifiedWorkerEndpoint,
    ) -> Result<WorkerLoopControl, WorkerProtocolError> {
        endpoint.emit(&ControlMessage::WorkerFault {
            stdout_cutoff: 0,
            stderr_cutoff: 0,
            detail: b"session worker application is unavailable".to_vec(),
        })?;
        Ok(WorkerLoopControl::Exit(78))
    }
}

/// Consume the fixed inherited descriptors and authenticate the supervisor.
/// This must run before clap, Host installation, or Runtime construction.
#[cfg(unix)]
pub(crate) fn inherited_worker_bootstrap() -> Result<WorkerBootstrapContext, WorkerProtocolError> {
    use std::os::fd::FromRawFd;

    validate_inherited_descriptor(CONTROL_FD, libc::S_IFSOCK)?;
    validate_inherited_descriptor(BOOTSTRAP_FD, libc::S_IFSOCK)?;
    validate_inherited_descriptor(ROOT_FD, libc::S_IFDIR)?;
    validate_inherited_descriptor(WATCHDOG_FD, libc::S_IFSOCK)?;
    // dup2 intentionally cleared CLOEXEC for the one worker exec. Restore it
    // before any Runtime code can spawn a descendant.
    for descriptor in [CONTROL_FD, ROOT_FD, WATCHDOG_FD] {
        set_close_on_exec(descriptor)?;
    }

    // SAFETY: exact bootstrap classification gives this function sole
    // ownership of the allowlisted descriptors.
    let mut bootstrap = unsafe { std::os::unix::net::UnixStream::from_raw_fd(BOOTSTRAP_FD) };
    let mut bytes = [0u8; BOOTSTRAP_RECORD_BYTES];
    read_exact_or_truncated(&mut bootstrap, &mut bytes)?;
    let mut trailing = [0u8; 1];
    loop {
        match bootstrap.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => return Err(WorkerProtocolError::UnauthorizedBootstrap),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(WorkerProtocolError::Io(error)),
        }
    }
    let record = BootstrapRecord::decode(&bytes)?;
    bytes.fill(0);
    drop(bootstrap);

    let parent_pid = unsafe { libc::getppid() };
    if parent_pid <= 1 || parent_pid as u32 != record.parent_pid {
        return Err(WorkerProtocolError::WrongParent);
    }

    // SAFETY: ROOT_FD is independently validated above and is now owned here.
    let root_file = unsafe { std::fs::File::from_raw_fd(ROOT_FD) };
    let root_object = object_identity_for_directory(&root_file)?;
    if unsafe { libc::fchdir(ROOT_FD) } != 0 {
        return Err(WorkerProtocolError::Io(io::Error::last_os_error()));
    }

    // SAFETY: WATCHDOG_FD was validated, and from_raw_fd transfers its sole
    // ownership into the stream that must then move to the watchdog thread.
    let watchdog = unsafe { std::os::unix::net::UnixStream::from_raw_fd(WATCHDOG_FD) };
    start_parent_watchdog(watchdog)?;

    // SAFETY: CONTROL_FD was validated and this endpoint owns it now.
    let control = unsafe { std::os::unix::net::UnixStream::from_raw_fd(CONTROL_FD) };
    let mut channel = AuthenticatedChannel::new(
        control,
        EndpointRole::Worker,
        ChannelKey(record.channel_key),
        record.binding.run_nonce,
        record.channel_epoch,
    );
    let (challenge, bootstrap_config) =
        match channel.receive_until(deadline_after(LIFECYCLE_ACK_TIMEOUT))? {
            ControlMessage::SupervisorHello {
                challenge,
                bootstrap_config,
            } if challenge == record.challenge => (challenge, bootstrap_config),
            _ => return Err(WorkerProtocolError::UnauthorizedBootstrap),
        };
    let proof = root_proof(&channel.key, &challenge, &root_object)?;
    channel.send_until(
        &ControlMessage::WorkerHello {
            pid: std::process::id(),
            root_proof: proof,
        },
        deadline_after(LIFECYCLE_ACK_TIMEOUT),
    )?;

    Ok(WorkerBootstrapContext {
        channel,
        expected_binding: record.binding.clone(),
        root_object,
        root_file,
        challenge,
        bootstrap_config,
    })
}

#[cfg(not(unix))]
pub(crate) struct WorkerBootstrapContext {
    _private: (),
}

#[cfg(not(unix))]
pub(crate) fn inherited_worker_bootstrap() -> Result<WorkerBootstrapContext, WorkerProtocolError> {
    Err(WorkerProtocolError::UnsupportedPlatform)
}

/// Route the private worker spelling before clap, environment-derived runtime
/// configuration, or any project/source observation. A malformed appearance
/// is a refusal, never an ordinary CLI parse error or fallback execution.
pub(crate) fn pre_clap_worker_bootstrap(
    args: &[OsString],
) -> Result<Option<WorkerBootstrapContext>, WorkerProtocolError> {
    match classify_bootstrap_invocation(args) {
        BootstrapInvocation::Ordinary => Ok(None),
        BootstrapInvocation::WorkerCandidate => inherited_worker_bootstrap().map(Some),
        BootstrapInvocation::RefusedMalformed => Err(WorkerProtocolError::UnauthorizedBootstrap),
    }
}

#[cfg(unix)]
fn validate_inherited_descriptor(
    fd: i32,
    expected_type: libc::mode_t,
) -> Result<(), WorkerProtocolError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(WorkerProtocolError::UnauthorizedBootstrap);
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != expected_type {
        return Err(WorkerProtocolError::UnauthorizedBootstrap);
    }
    Ok(())
}

#[cfg(unix)]
fn set_close_on_exec(fd: i32) -> Result<(), WorkerProtocolError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(WorkerProtocolError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(unix)]
type ParentWatchdogTask = Box<dyn FnOnce() + Send + 'static>;

#[cfg(unix)]
fn start_parent_watchdog_with(
    mut watchdog: std::os::unix::net::UnixStream,
    spawn: impl FnOnce(ParentWatchdogTask) -> io::Result<()>,
) -> Result<(), WorkerProtocolError> {
    let task: ParentWatchdogTask = Box::new(move || {
        let mut byte = [0u8; 1];
        loop {
            match watchdog.read(&mut byte) {
                Ok(0) | Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        // The worker is its own process group. This path takes no Runtime,
        // broker, allocator, or application lock.
        unsafe {
            libc::kill(0, libc::SIGKILL);
            libc::_exit(70);
        }
    });
    spawn(task).map_err(WorkerProtocolError::Io)
}

#[cfg(unix)]
fn start_parent_watchdog(
    watchdog: std::os::unix::net::UnixStream,
) -> Result<(), WorkerProtocolError> {
    start_parent_watchdog_with(watchdog, |task| {
        std::thread::Builder::new()
            .name("ibex-session-parent-watchdog".to_string())
            .spawn(task)
            .map(|_| ())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const TEST_EPOCH: u64 = 0x0102_0304_0506_0708;
    const TEST_NONCE: [u8; 16] = [0x31; 16];

    fn key() -> ChannelKey {
        ChannelKey::test([0x5a; 32])
    }

    fn binding(marker: u8) -> ArmedSessionBinding {
        ArmedSessionBinding::new([marker; 16], [marker.wrapping_add(1); 32])
    }

    fn encoded(message: &ControlMessage, epoch: u64, sequence: u64) -> Vec<u8> {
        let payload = message.encode_payload().unwrap();
        encode_authenticated_frame(
            &key(),
            TEST_NONCE,
            epoch,
            sequence,
            message.kind(),
            &payload,
        )
        .unwrap()
    }

    fn decode_one(message: &ControlMessage) -> ControlMessage {
        let role = match message.kind().direction() {
            Direction::SupervisorToWorker => EndpointRole::Worker,
            Direction::WorkerToSupervisor => EndpointRole::Supervisor,
        };
        let mut channel = AuthenticatedChannel::new(
            Cursor::new(encoded(message, TEST_EPOCH, 1)),
            role,
            key(),
            TEST_NONCE,
            TEST_EPOCH,
        );
        channel.receive().unwrap()
    }

    fn all_messages() -> Vec<ControlMessage> {
        vec![
            ControlMessage::SupervisorHello {
                challenge: [1; 32],
                bootstrap_config: b"opaque-config".to_vec(),
            },
            ControlMessage::WorkerHello {
                pid: 123,
                root_proof: [2; 32],
            },
            ControlMessage::WorkerReady {
                session_proof: [3; 32],
            },
            ControlMessage::Start {
                mode: SessionInputMode::Interactive,
            },
            ControlMessage::Submit {
                submission_id: 4,
                kind: SubmissionKind::Inline,
                source: vec![0xff, 0, b'x'],
            },
            ControlMessage::EndOfInput,
            ControlMessage::DisplayAck {
                submission_id: 4,
                disposition: DisplayAckDisposition::Fallback,
            },
            ControlMessage::Cancel {
                request_id: 5,
                target_id: 6,
            },
            ControlMessage::Shutdown { status: 130 },
            ControlMessage::Resize {
                columns: 120,
                rows: 44,
            },
            ControlMessage::LifecycleAck { request_id: 7 },
            ControlMessage::ExitCodeAck { mutation_id: 8 },
            ControlMessage::Ping { nonce: 9 },
            ControlMessage::ReadyCheckpoint { checkpoint_id: 10 },
            ControlMessage::Step {
                submission_id: 10,
                kind: 11,
                payload: b"step".to_vec(),
            },
            ControlMessage::Display {
                submission_id: 10,
                tree: b"display-tree".to_vec(),
                stdout_cutoff: 12,
                stderr_cutoff: 13,
            },
            ControlMessage::Outcome {
                submission_id: 10,
                kind: EvaluationOutcomeKind::Throw,
                status: 1,
                stdout_cutoff: 21,
                stderr_cutoff: 34,
                detail: b"throw".to_vec(),
            },
            ControlMessage::AsyncFailure {
                stdout_cutoff: 23,
                stderr_cutoff: 29,
                detail: b"rejection".to_vec(),
            },
            ControlMessage::LifecycleCommit(LifecycleRecord {
                request_id: 14,
                status: 7,
                stdout_cutoff: 15,
                stderr_cutoff: 16,
            }),
            ControlMessage::ExitCodeMirror {
                mutation_id: 17,
                status: 23,
            },
            ControlMessage::WorkUnit {
                target_id: 18,
                scheduling_id: 19,
                kind: WorkUnitKind::Callback,
                phase: WorkUnitPhase::Due,
            },
            ControlMessage::CancellationResolved {
                request_id: 20,
                target_id: 18,
                resolution: CancellationResolution::Defeated,
            },
            ControlMessage::Quiescent,
            ControlMessage::Pong { nonce: 9 },
            ControlMessage::PreReceiptLoss { count: 21 },
            ControlMessage::WorkerFault {
                stdout_cutoff: 31,
                stderr_cutoff: 37,
                detail: b"engine fault".to_vec(),
            },
            ControlMessage::ReadyCheckpointAck {
                checkpoint_id: 10,
                stdout_cutoff: 55,
                stderr_cutoff: 89,
            },
        ]
    }

    #[test]
    fn closed_codec_round_trips_every_control_record() {
        for message in all_messages() {
            assert_eq!(decode_one(&message), message);
        }
    }

    #[cfg(unix)]
    #[test]
    fn supervisor_replaces_worker_diagnostic_cutoffs_with_relay_acceptance() {
        let acceptance = SupervisorRelayAcceptance::default();
        acceptance.note_stdout(13).unwrap();
        acceptance.note_stderr(21).unwrap();
        acceptance.note_stdout(8).unwrap();

        for mut message in [
            ControlMessage::AsyncFailure {
                stdout_cutoff: u64::MAX,
                stderr_cutoff: u64::MAX,
                detail: b"async".to_vec(),
            },
            ControlMessage::WorkerFault {
                stdout_cutoff: u64::MAX,
                stderr_cutoff: u64::MAX,
                detail: b"fault".to_vec(),
            },
        ] {
            normalize_supervisor_diagnostic_cutoffs(&mut message, acceptance.snapshot());
            match message {
                ControlMessage::AsyncFailure {
                    stdout_cutoff,
                    stderr_cutoff,
                    ..
                }
                | ControlMessage::WorkerFault {
                    stdout_cutoff,
                    stderr_cutoff,
                    ..
                } => assert_eq!((stdout_cutoff, stderr_cutoff), (21, 21)),
                _ => unreachable!(),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_channel_is_bidirectional_and_sequence_exact() {
        let (supervisor_io, worker_io) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut supervisor = AuthenticatedChannel::new(
            supervisor_io,
            EndpointRole::Supervisor,
            key(),
            TEST_NONCE,
            TEST_EPOCH,
        );
        let mut worker = AuthenticatedChannel::new(
            worker_io,
            EndpointRole::Worker,
            key(),
            TEST_NONCE,
            TEST_EPOCH,
        );
        let submission = ControlMessage::Submit {
            submission_id: 41,
            kind: SubmissionKind::Inline,
            source: b"1 + 1".to_vec(),
        };
        supervisor.send(&submission).unwrap();
        assert_eq!(worker.receive().unwrap(), submission);

        let outcome = ControlMessage::Outcome {
            submission_id: 41,
            kind: EvaluationOutcomeKind::Empty,
            status: 0,
            stdout_cutoff: 0,
            stderr_cutoff: 0,
            detail: Vec::new(),
        };
        worker.send(&outcome).unwrap();
        assert_eq!(supervisor.receive().unwrap(), outcome);
    }

    #[cfg(unix)]
    #[test]
    fn absolute_receive_deadline_rejects_a_trickled_partial_frame_and_restores_mode() {
        let (mut writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let frame = encoded(
            &ControlMessage::Submit {
                submission_id: 1,
                kind: SubmissionKind::Inline,
                source: b"trickle".to_vec(),
            },
            TEST_EPOCH,
            1,
        );
        let trickle = std::thread::spawn(move || {
            for byte in frame.into_iter().take(12) {
                if writer.write_all(&[byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let mut channel =
            AuthenticatedChannel::new(reader, EndpointRole::Worker, key(), TEST_NONCE, TEST_EPOCH);
        let started = Instant::now();
        let error = channel
            .receive_until(deadline_after(Duration::from_millis(25)))
            .unwrap_err();
        assert!(matches!(
            error,
            WorkerProtocolError::Io(ref error) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_millis(200));
        assert_eq!(channel.next_receive_sequence, 1);
        assert!(!unix_stream_is_nonblocking(&channel.io).unwrap());
        trickle.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn absolute_send_deadline_rejects_a_slow_reader_without_consuming_sequence() {
        use std::os::fd::AsRawFd;

        let (writer, mut reader) = std::os::unix::net::UnixStream::pair().unwrap();
        let send_buffer: libc::c_int = 4 * 1024;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    writer.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&send_buffer as *const libc::c_int).cast(),
                    std::mem::size_of_val(&send_buffer) as libc::socklen_t,
                )
            },
            0
        );
        let slow_reader = std::thread::spawn(move || {
            let mut bytes = [0u8; 512];
            for _ in 0..12 {
                if reader.read(&mut bytes).unwrap_or(0) == 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let mut channel =
            AuthenticatedChannel::new(writer, EndpointRole::Worker, key(), TEST_NONCE, TEST_EPOCH);
        let message = ControlMessage::Display {
            submission_id: 1,
            tree: vec![0x61; 2 * 1024 * 1024],
            stdout_cutoff: 0,
            stderr_cutoff: 0,
        };
        let started = Instant::now();
        let error = channel
            .send_until(&message, deadline_after(Duration::from_millis(30)))
            .unwrap_err();
        assert!(matches!(
            error,
            WorkerProtocolError::Io(ref error) if error.kind() == io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_millis(250));
        assert_eq!(channel.next_send_sequence, 1);
        assert!(!unix_stream_is_nonblocking(&channel.io).unwrap());
        drop(channel);
        slow_reader.join().unwrap();
    }

    #[test]
    fn wrong_mac_is_rejected() {
        let message = ControlMessage::Submit {
            submission_id: 1,
            kind: SubmissionKind::Inline,
            source: b"source".to_vec(),
        };
        let mut frame = encoded(&message, TEST_EPOCH, 1);
        *frame.last_mut().unwrap() ^= 0x80;
        let mut channel = AuthenticatedChannel::new(
            Cursor::new(frame),
            EndpointRole::Worker,
            key(),
            TEST_NONCE,
            TEST_EPOCH,
        );
        assert!(matches!(
            channel.receive(),
            Err(WorkerProtocolError::BadMac)
        ));
    }

    #[test]
    fn replayed_frame_is_rejected_before_application_delivery() {
        let message = ControlMessage::Submit {
            submission_id: 1,
            kind: SubmissionKind::Inline,
            source: b"source".to_vec(),
        };
        let frame = encoded(&message, TEST_EPOCH, 1);
        let mut repeated = frame.clone();
        repeated.extend_from_slice(&frame);
        let mut channel = AuthenticatedChannel::new(
            Cursor::new(repeated),
            EndpointRole::Worker,
            key(),
            TEST_NONCE,
            TEST_EPOCH,
        );
        assert_eq!(channel.receive().unwrap(), message);
        assert!(matches!(
            channel.receive(),
            Err(WorkerProtocolError::BadSequence {
                expected: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn frame_is_bound_to_exact_run_nonce_epoch_and_direction() {
        let message = ControlMessage::Submit {
            submission_id: 1,
            kind: SubmissionKind::Inline,
            source: Vec::new(),
        };
        let frame = encoded(&message, TEST_EPOCH, 1);

        let mut wrong_nonce = AuthenticatedChannel::new(
            Cursor::new(frame.clone()),
            EndpointRole::Worker,
            key(),
            [0x32; 16],
            TEST_EPOCH,
        );
        assert!(matches!(
            wrong_nonce.receive(),
            Err(WorkerProtocolError::WrongSession)
        ));

        let mut wrong_epoch = AuthenticatedChannel::new(
            Cursor::new(frame.clone()),
            EndpointRole::Worker,
            key(),
            TEST_NONCE,
            TEST_EPOCH + 1,
        );
        assert!(matches!(
            wrong_epoch.receive(),
            Err(WorkerProtocolError::WrongEpoch)
        ));

        let mut wrong_direction = AuthenticatedChannel::new(
            Cursor::new(frame),
            EndpointRole::Supervisor,
            key(),
            TEST_NONCE,
            TEST_EPOCH,
        );
        assert!(matches!(
            wrong_direction.receive(),
            Err(WorkerProtocolError::WrongDirection)
        ));
    }

    #[test]
    fn oversized_declared_payload_is_refused_before_read_or_allocation() {
        let message = ControlMessage::Submit {
            submission_id: 1,
            kind: SubmissionKind::Inline,
            source: Vec::new(),
        };
        let mut frame = encoded(&message, TEST_EPOCH, 1);
        frame[44..48].copy_from_slice(
            &u32::try_from(MessageKind::Submit.maximum_payload() + 1)
                .unwrap()
                .to_le_bytes(),
        );
        frame.truncate(WIRE_HEADER_BYTES);
        let mut channel = AuthenticatedChannel::new(
            Cursor::new(frame),
            EndpointRole::Worker,
            key(),
            TEST_NONCE,
            TEST_EPOCH,
        );
        assert!(matches!(
            channel.receive(),
            Err(WorkerProtocolError::Oversize)
        ));
    }

    #[test]
    fn clean_eof_and_every_partial_frame_boundary_are_distinct() {
        let message = ControlMessage::Submit {
            submission_id: 1,
            kind: SubmissionKind::Inline,
            source: b"abc".to_vec(),
        };
        let frame = encoded(&message, TEST_EPOCH, 1);
        let payload_length = u32::from_le_bytes(frame[44..48].try_into().unwrap()) as usize;
        let cuts = [
            1,
            WIRE_HEADER_BYTES - 1,
            WIRE_HEADER_BYTES + payload_length - 1,
            frame.len() - 1,
        ];

        let mut empty = AuthenticatedChannel::new(
            Cursor::new(Vec::<u8>::new()),
            EndpointRole::Worker,
            key(),
            TEST_NONCE,
            TEST_EPOCH,
        );
        assert!(matches!(
            empty.receive(),
            Err(WorkerProtocolError::CleanEof)
        ));

        for cut in cuts {
            let mut channel = AuthenticatedChannel::new(
                Cursor::new(frame[..cut].to_vec()),
                EndpointRole::Worker,
                key(),
                TEST_NONCE,
                TEST_EPOCH,
            );
            assert!(matches!(
                channel.receive(),
                Err(WorkerProtocolError::Truncated)
            ));
        }
    }

    #[test]
    fn root_and_session_proofs_are_fresh_challenge_and_object_bound() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let first_file = std::fs::File::open(first.path()).unwrap();
        let second_file = std::fs::File::open(second.path()).unwrap();
        let first_root = object_identity_for_directory(&first_file).unwrap();
        let second_root = object_identity_for_directory(&second_file).unwrap();
        let challenge = [0x71; 32];
        let other_challenge = [0x72; 32];

        assert_ne!(
            root_proof(&key(), &challenge, &first_root).unwrap(),
            root_proof(&key(), &other_challenge, &first_root).unwrap()
        );
        assert_ne!(
            root_proof(&key(), &challenge, &first_root).unwrap(),
            root_proof(&key(), &challenge, &second_root).unwrap()
        );
        assert_ne!(
            session_proof(&key(), &challenge, &binding(1), &first_root).unwrap(),
            session_proof(&key(), &challenge, &binding(2), &first_root).unwrap()
        );
    }

    #[test]
    fn authenticated_root_descriptor_rejects_directory_swap() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let first_file = std::fs::File::open(first.path()).unwrap();
        let expected = object_identity_for_directory(&first_file).unwrap();
        let second_file = std::fs::File::open(second.path()).unwrap();
        assert!(matches!(
            AuthenticatedRootDescriptor::new(second_file, &expected),
            Err(WorkerProtocolError::WrongRoot)
        ));
    }

    #[test]
    fn bootstrap_record_authenticates_all_fixed_fields() {
        let record = BootstrapRecord {
            channel_key: [0xa5; 32],
            channel_epoch: 77,
            binding: binding(3),
            challenge: [0xb6; 32],
            parent_pid: 1234,
        };
        let encoded = record.encode();
        let decoded = BootstrapRecord::decode(&encoded).unwrap();
        assert_eq!(decoded.channel_epoch, 77);
        assert_eq!(decoded.binding, binding(3));
        assert_eq!(decoded.challenge, [0xb6; 32]);
        assert_eq!(decoded.parent_pid, 1234);

        let mut tampered = encoded;
        tampered[70] ^= 1;
        assert!(matches!(
            BootstrapRecord::decode(&tampered),
            Err(WorkerProtocolError::UnauthorizedBootstrap)
        ));

        let zero_epoch = BootstrapRecord {
            channel_key: [0xa5; 32],
            channel_epoch: 0,
            binding: binding(3),
            challenge: [0xb6; 32],
            parent_pid: 1234,
        }
        .encode();
        assert!(matches!(
            BootstrapRecord::decode(&zero_epoch),
            Err(WorkerProtocolError::UnauthorizedBootstrap)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn parent_watchdog_spawn_failure_refuses_worker_startup() {
        let (_supervisor, worker) = std::os::unix::net::UnixStream::pair().unwrap();
        let result = start_parent_watchdog_with(worker, |_task| {
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        });

        match result {
            Err(WorkerProtocolError::Io(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            }
            other => panic!("watchdog spawn failure did not fail closed: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn pending_supervisor_child_drop_kills_and_reaps_the_process_group() {
        use std::os::unix::process::CommandExt as _;

        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "exec sleep 30"]);
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let pending = PendingSupervisorChild::new(command.spawn().unwrap());
        let pid = pending.child().id() as libc::pid_t;
        drop(pending);

        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    #[test]
    fn hidden_bootstrap_spelling_is_exact_and_never_falls_through() {
        let program = OsString::from("ibex");
        let hidden = OsString::from(WORKER_BOOTSTRAP_ARG);
        assert_eq!(
            classify_bootstrap_invocation(std::slice::from_ref(&program)),
            BootstrapInvocation::Ordinary
        );
        assert_eq!(
            classify_bootstrap_invocation(&[program.clone(), hidden.clone()]),
            BootstrapInvocation::WorkerCandidate
        );
        assert_eq!(
            classify_bootstrap_invocation(&[program.clone(), hidden.clone(), OsString::from("x")]),
            BootstrapInvocation::RefusedMalformed
        );
        assert_eq!(
            classify_bootstrap_invocation(&[program, hidden.clone(), hidden]),
            BootstrapInvocation::RefusedMalformed
        );
    }

    #[test]
    fn lifecycle_commit_is_idempotent_and_survives_ack_loss_and_worker_death() {
        let record = LifecycleRecord {
            request_id: 9,
            status: 23,
            stdout_cutoff: 101,
            stderr_cutoff: 202,
        };
        let mut lifecycle = SupervisorLifecycleState::default();
        assert_eq!(
            lifecycle.accept_lifecycle(record.clone()).unwrap(),
            LifecycleCommitDisposition::Accepted
        );
        // Re-delivery models a lost ACK; it cannot double-apply the request.
        assert_eq!(
            lifecycle.accept_lifecycle(record.clone()).unwrap(),
            LifecycleCommitDisposition::IdempotentReplay
        );
        // The accepted record, not the worker's subsequent death, owns status.
        lifecycle.latch_engine_fault();
        assert_eq!(lifecycle.final_status(false), 23);
        assert_eq!(lifecycle.accepted_lifecycle(), Some(&record));

        let later = LifecycleRecord {
            request_id: 10,
            status: 99,
            stdout_cutoff: 303,
            stderr_cutoff: 404,
        };
        assert_eq!(
            lifecycle.accept_lifecycle(later).unwrap(),
            LifecycleCommitDisposition::LaterRequestIgnored
        );
        let conflicting = LifecycleRecord {
            status: 24,
            ..record
        };
        assert!(matches!(
            lifecycle.accept_lifecycle(conflicting),
            Err(WorkerProtocolError::ConflictingLifecycleRecord)
        ));
    }

    #[test]
    fn worker_death_without_accepted_lifecycle_is_engine_fault_70() {
        let mut lifecycle = SupervisorLifecycleState::default();
        lifecycle.latch_engine_fault();
        assert_eq!(lifecycle.cause(), Some(TerminationCause::EngineFault));
        assert_eq!(lifecycle.final_status(false), 70);
    }

    #[test]
    fn supervisor_exit_code_mirror_is_ordered_and_authoritative() {
        let mut lifecycle = SupervisorLifecycleState::default();
        lifecycle.mirror_exit_code(1, 7).unwrap();
        lifecycle.mirror_exit_code(2, 11).unwrap();
        assert!(matches!(
            lifecycle.mirror_exit_code(4, 99),
            Err(WorkerProtocolError::ExitCodeMirrorGap)
        ));
        lifecycle.latch_orderly();
        assert_eq!(lifecycle.final_status(false), 11);
    }

    #[test]
    fn cleanup_loss_only_modifies_orderly_or_cooperative_causes() {
        let mut orderly = SupervisorLifecycleState::default();
        orderly.mirror_exit_code(1, 7).unwrap();
        orderly.latch_orderly();
        assert_eq!(orderly.final_status(true), 141);

        let mut cooperative = SupervisorLifecycleState::default();
        cooperative
            .accept_lifecycle(LifecycleRecord {
                request_id: 1,
                status: 9,
                stdout_cutoff: 0,
                stderr_cutoff: 0,
            })
            .unwrap();
        assert_eq!(cooperative.final_status(true), 141);

        let mut interrupted = SupervisorLifecycleState::default();
        interrupted.latch_interrupt();
        assert_eq!(interrupted.final_status(true), 130);

        let mut faulted = SupervisorLifecycleState::default();
        faulted.latch_engine_fault();
        assert_eq!(faulted.final_status(true), 70);
    }

    #[test]
    fn supervisor_sequences_only_received_events_and_never_rewinds() {
        let sequences = SupervisorSequenceAllocator::new(5).unwrap();
        let first = sequences.assign("first").unwrap();
        let second = sequences.assign("second").unwrap();
        sequences.restart().unwrap();
        let after_restart = sequences.assign("third").unwrap();
        assert_eq!((first.epoch, first.sequence), (5, 1));
        assert_eq!((second.epoch, second.sequence), (5, 2));
        assert_eq!((after_restart.epoch, after_restart.sequence), (6, 3));
    }

    #[cfg(unix)]
    fn test_plan() -> crate::terminal_session::SessionIoPlan {
        use crate::terminal_session::{
            CapturedPresentation, NativeTerminalFacts, PresentationTopology,
            SelectedExecutionRoute, SessionIoPlan,
        };
        use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};
        SessionIoPlan {
            route: SelectedExecutionRoute {
                entry_kind: ArmedEntryKind::Repl,
                mode: ArmedExecutionMode::Transcript,
            },
            terminal_facts: NativeTerminalFacts {
                stdin_is_tty: false,
                stdout_is_tty: false,
                stderr_is_tty: false,
            },
            presentation: CapturedPresentation {
                topology: PresentationTopology::Transcript,
                session_ansi: false,
                editor_control: false,
            },
        }
    }

    #[cfg(unix)]
    #[test]
    fn typed_worker_configuration_round_trips_and_refuses_cross_route_pairing() {
        let configuration = WorkerBootstrapConfiguration::new(
            test_plan(),
            WorkerApplicationRole::Repl,
            b"application".to_vec(),
        )
        .unwrap();
        let encoded = configuration.encode().unwrap();
        assert_eq!(
            WorkerBootstrapConfiguration::decode(&encoded).unwrap(),
            configuration
        );

        assert!(matches!(
            WorkerBootstrapConfiguration::new(
                test_plan(),
                WorkerApplicationRole::Inline,
                Vec::new(),
            ),
            Err(WorkerProtocolError::Malformed(_))
        ));

        let mut reserved_bit = encoded;
        reserved_bit[11] |= 0x80;
        assert!(matches!(
            WorkerBootstrapConfiguration::decode(&reserved_bit),
            Err(WorkerProtocolError::Malformed(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn shared_worker_stdio_preserves_exact_cross_stream_write_order() {
        use crate::terminal_session::{NativeOutputDestination, OutputDestinationTopology};
        use std::io::Read as _;

        let (stdout, stderr, relays) = worker_relay_stdio(OutputDestinationTopology::Shared {
            destination: NativeOutputDestination::Stdout,
        })
        .unwrap();
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("printf 'E000' >&2; printf 'O000'; printf 'E001' >&2; printf 'O001'")
            .stdout(stdout)
            .stderr(stderr)
            .status()
            .unwrap();
        assert!(status.success());

        let WorkerRelayDescriptors::Shared { output } = relays else {
            panic!("shared topology produced split relay descriptors");
        };
        let mut bytes = Vec::new();
        std::fs::File::from(output).read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"E000O000E001O001");
    }

    #[cfg(unix)]
    struct LoopApplication;

    #[cfg(unix)]
    impl AuthenticatedWorkerApplication for LoopApplication {
        fn handle(
            &mut self,
            command: AuthenticatedWorkerCommand,
            endpoint: &mut VerifiedWorkerEndpoint,
        ) -> Result<WorkerLoopControl, WorkerProtocolError> {
            match command {
                AuthenticatedWorkerCommand::Start { .. } => Ok(WorkerLoopControl::Continue),
                AuthenticatedWorkerCommand::Submit { submission_id, .. } => {
                    endpoint.emit(&ControlMessage::Outcome {
                        submission_id,
                        kind: EvaluationOutcomeKind::Empty,
                        status: 0,
                        stdout_cutoff: 0,
                        stderr_cutoff: 0,
                        detail: Vec::new(),
                    })?;
                    Ok(WorkerLoopControl::Exit(23))
                }
                _ => Err(WorkerProtocolError::Malformed("unexpected test command")),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn generic_worker_loop_handles_ping_without_runtime_and_dispatches_typed_commands() {
        let root = tempfile::tempdir().unwrap();
        let root_file = std::fs::File::open(root.path()).unwrap();
        let (supervisor_io, worker_io) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut supervisor = AuthenticatedChannel::new(
            supervisor_io,
            EndpointRole::Supervisor,
            key(),
            TEST_NONCE,
            TEST_EPOCH,
        );
        let endpoint = VerifiedWorkerEndpoint {
            channel: AuthenticatedChannel::new(
                worker_io,
                EndpointRole::Worker,
                key(),
                TEST_NONCE,
                TEST_EPOCH,
            ),
            deferred_inbound: VecDeque::new(),
            _root_file: root_file,
            _descriptor_policy: crate::terminal_session::SessionIo::new(test_plan()),
            _native_descriptor_policy: WorkerNativeDescriptorPolicy::ProtocolOnly,
            stdio_query: None,
            _output_relay: None,
        };
        let worker = std::thread::spawn(move || {
            run_authenticated_worker_loop(endpoint, &mut LoopApplication).unwrap()
        });

        supervisor
            .send(&ControlMessage::Ping { nonce: 44 })
            .unwrap();
        assert_eq!(
            supervisor.receive().unwrap(),
            ControlMessage::Pong { nonce: 44 }
        );
        supervisor
            .send(&ControlMessage::Start {
                mode: SessionInputMode::Transcript,
            })
            .unwrap();
        supervisor
            .send(&ControlMessage::Submit {
                submission_id: 55,
                kind: SubmissionKind::Inline,
                source: b"source".to_vec(),
            })
            .unwrap();
        assert_eq!(
            supervisor.receive().unwrap(),
            ControlMessage::Outcome {
                submission_id: 55,
                kind: EvaluationOutcomeKind::Empty,
                status: 0,
                stdout_cutoff: 0,
                stderr_cutoff: 0,
                detail: Vec::new(),
            }
        );
        assert_eq!(worker.join().unwrap(), 23);
    }

    #[cfg(unix)]
    #[test]
    fn acknowledged_worker_records_defer_interleaved_control_messages_in_order() {
        let root = tempfile::tempdir().unwrap();
        let root_file = std::fs::File::open(root.path()).unwrap();
        let (supervisor_io, worker_io) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut supervisor = AuthenticatedChannel::new(
            supervisor_io,
            EndpointRole::Supervisor,
            key(),
            TEST_NONCE,
            TEST_EPOCH,
        );
        let mut endpoint = VerifiedWorkerEndpoint {
            channel: AuthenticatedChannel::new(
                worker_io,
                EndpointRole::Worker,
                key(),
                TEST_NONCE,
                TEST_EPOCH,
            ),
            deferred_inbound: VecDeque::new(),
            _root_file: root_file,
            _descriptor_policy: crate::terminal_session::SessionIo::new(test_plan()),
            _native_descriptor_policy: WorkerNativeDescriptorPolicy::ProtocolOnly,
            stdio_query: None,
            _output_relay: None,
        };

        let worker = std::thread::spawn(move || {
            endpoint.mirror_exit_code(1, 17).unwrap();
            endpoint
                .send_lifecycle_commit(LifecycleRecord {
                    request_id: 9,
                    status: 23,
                    stdout_cutoff: 31,
                    stderr_cutoff: 37,
                })
                .unwrap();
            (endpoint.receive().unwrap(), endpoint.receive().unwrap())
        });

        assert_eq!(
            supervisor.receive().unwrap(),
            ControlMessage::ExitCodeMirror {
                mutation_id: 1,
                status: 17,
            }
        );
        supervisor
            .send(&ControlMessage::Cancel {
                request_id: 5,
                target_id: 7,
            })
            .unwrap();
        supervisor
            .send(&ControlMessage::ExitCodeAck { mutation_id: 1 })
            .unwrap();
        assert!(matches!(
            supervisor.receive().unwrap(),
            ControlMessage::LifecycleCommit(LifecycleRecord {
                request_id: 9,
                status: 23,
                stdout_cutoff: 31,
                stderr_cutoff: 37,
            })
        ));
        supervisor
            .send(&ControlMessage::Resize {
                columns: 120,
                rows: 40,
            })
            .unwrap();
        supervisor
            .send(&ControlMessage::LifecycleAck { request_id: 9 })
            .unwrap();

        assert_eq!(
            worker.join().unwrap(),
            (
                ControlMessage::Cancel {
                    request_id: 5,
                    target_id: 7,
                },
                ControlMessage::Resize {
                    columns: 120,
                    rows: 40,
                },
            )
        );
    }
}
