//! Supervisor-owned terminal session core.
//!
//! This module deliberately stops at typed ports. The legacy rustyline REPL
//! cannot implement the asynchronous editor contract because its completer
//! blocks the same reader that must consume `Ctrl+C`; wiring that adapter would
//! be a false safety claim. A future PTY/ConPTY adapter can drive this core
//! without changing its interrupt policy.
//!
//! @ref LLP 0025#5-terminal-presentation-and-restoration — the supervisor owns
//! raw-mode entry and restores before any potentially blocking cleanup.
//! @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker — session
//! payloads are rendered as hostile data and all writes share receipt ordering.
//! @ref LLP 0025#4-color — session ANSI is derived only from captured facts;
//! program bytes remain byte-exact.
//! @ref LLP 0025#6-interruption-and-cancellation — interrupt selection comes
//! exclusively from the generated machine, including promise/cause precedence.
//! @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker — the
//! worker is reached only through cancellation and termination ports.
//! @ref LLP 0025#8-exit-and-lifecycle — cooperative exit is a supervisor event,
//! never a call to `process::exit` in the evaluator.

#![allow(dead_code)]

#[rustfmt::skip]
#[path = "../../../vendored-generated/interrupt_machine.generated.rs"]
mod generated;
#[path = "../../../vendored-generated/session_constants.generated.rs"]
mod session_constants;

pub use session_constants::{
    BROKER_FLUSH_BUDGET_MILLIS, BROKER_QUEUE_BOUND_BYTES, DISPLAY_PAYLOAD_SCALARS,
    DISPLAY_RENDER_BREADTH, DISPLAY_RENDER_DEPTH, DISPLAY_TREE_MAX_SERIALIZED_BYTES,
    DISPLAY_TREE_WIRE_VERSION, MAX_LIVE_RELAYS,
};

use session_constants::{
    ANSI_DISPLAY_ERROR, ANSI_DISPLAY_KEY, ANSI_DISPLAY_KEYWORD, ANSI_DISPLAY_NUMBER,
    ANSI_DISPLAY_STRING, ANSI_DISPLAY_TRUNCATION, ANSI_DISPLAY_TYPE_TAG, ANSI_RESET,
    ANSI_SESSION_ERROR, ANSI_SESSION_NOTICE, ANSI_SESSION_PROMPT, DISPLAY_FALLBACK_PREFIX,
    DISPLAY_FALLBACK_REASON_MALFORMED_OR_UNKNOWN_TREE, DISPLAY_FALLBACK_REASON_OVERSIZE_TREE,
    DISPLAY_FALLBACK_REASON_RENDERED_TOO_LARGE, DISPLAY_FALLBACK_SUFFIX, DISPLAY_NODE_TAG_BOOLEAN,
    DISPLAY_NODE_TAG_CYCLE, DISPLAY_NODE_TAG_ERROR, DISPLAY_NODE_TAG_KEY, DISPLAY_NODE_TAG_NULL,
    DISPLAY_NODE_TAG_NUMBER, DISPLAY_NODE_TAG_STRING, DISPLAY_NODE_TAG_TEXT,
    DISPLAY_NODE_TAG_TRUNCATION, DISPLAY_NODE_TAG_TYPE_TAG, DISPLAY_NODE_TAG_UNDEFINED,
    DISPLAY_TREE_CHILD_COUNT_BITS, DISPLAY_TREE_KIND_BITS, DISPLAY_TREE_LITTLE_ENDIAN,
    DISPLAY_TREE_MAGIC, DISPLAY_TREE_MAGIC_BITS, DISPLAY_TREE_PAYLOAD_LENGTH_BITS,
    DISPLAY_TREE_ROOT_DEPTH, DISPLAY_TREE_VERSION_BITS, EXIT_STATUS_BROKEN_PIPE,
    EXIT_STATUS_ENGINE_FAULT, EXIT_STATUS_INTERRUPT, NOTICE_CANCELLING_COMPLETION,
    NOTICE_CANCELLING_WORK, NOTICE_INPUT_DISCARDED, NOTICE_ORDERLY_PROMISE, NOTICE_WORK_IN_FLIGHT,
    POSIX_EXIT_STATUS_MASK, PROMPT_DEFAULT_TEXT, PROMPT_EDITOR_ERASE_BYTES, PROMPT_INTERRUPT_BYTE,
    PROMPT_TRANSCRIPT_BOUNDARY_BYTES, RENDER_CHILDREN_CLOSE, RENDER_CHILDREN_OPEN,
    RENDER_CHILDREN_SEPARATOR, RENDER_PAYLOAD_TRUNCATION_SEPARATOR, TRUNCATION_PREFIX,
    TRUNCATION_SUFFIX, UNKNOWN_DISPLAY_NODE_PREFIX, UNKNOWN_DISPLAY_NODE_SUFFIX,
};

use crate::cli::{Cli, Commands};
use capsec_semantics::arming::{ArmedEntryKind, ArmedExecutionMode};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::io::{self, IsTerminal, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const PROMPT_LIVE_BIT: u64 = 1_u64 << 63;
const PROMPT_CYCLE_MASK: u64 = !PROMPT_LIVE_BIT;
static NEXT_BROKER_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);
const _: [(); DISPLAY_TREE_MAGIC_BITS as usize] =
    [(); DISPLAY_TREE_MAGIC.len() * u8::BITS as usize];
const _: [(); DISPLAY_TREE_VERSION_BITS as usize] = [(); u16::BITS as usize];
const _: [(); DISPLAY_TREE_KIND_BITS as usize] = [(); u16::BITS as usize];
const _: [(); DISPLAY_TREE_PAYLOAD_LENGTH_BITS as usize] = [(); u32::BITS as usize];
const _: [(); DISPLAY_TREE_CHILD_COUNT_BITS as usize] = [(); u32::BITS as usize];

/// The launcher-observed entry tuple shared by CLI dispatch, immutable
/// snapshot construction, and the terminal-session adapter.
///
/// Keeping these as the CapSec arming enums avoids a second route vocabulary
/// that could disagree with the digest-bound snapshot.
/// @ref LLP 0022#3-input-modes — stdin TTY state and the
/// explicit `repl` spelling jointly select interactive, transcript, or program.
/// @ref LLP 0024#1-the-in-memory-source-api — the execution mode and entry kind
/// are authenticated session facts, not evaluator-selected source metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedExecutionRoute {
    pub entry_kind: ArmedEntryKind,
    pub mode: ArmedExecutionMode,
}

impl SelectedExecutionRoute {
    pub const fn synthetic_identity(self) -> Option<&'static str> {
        match self.entry_kind {
            ArmedEntryKind::File => None,
            ArmedEntryKind::Stdin => Some("ibex:stdin"),
            ArmedEntryKind::Repl => Some("ibex:repl"),
            ArmedEntryKind::Eval => Some("ibex:eval"),
        }
    }

    /// Session-owned stdin becomes an EOF-only view before JavaScript can
    /// perform a descriptor operation. File and eval routes retain ordinary
    /// typed stdio because their source did not consume fd 0.
    pub const fn seals_javascript_stdin(self) -> bool {
        matches!(
            self.entry_kind,
            ArmedEntryKind::Repl | ArmedEntryKind::Stdin
        )
    }

    pub const fn has_interactive_editor(self) -> bool {
        matches!(self.mode, ArmedExecutionMode::Interactive)
    }
}

/// Select the semantic execution route before runtime construction or any
/// source read. This is intentionally the only CLI-to-entry decision table.
pub fn selected_execution_route(cli: &Cli, stdin_is_tty: bool) -> Option<SelectedExecutionRoute> {
    let eval = SelectedExecutionRoute {
        entry_kind: ArmedEntryKind::Eval,
        mode: ArmedExecutionMode::OneShot,
    };
    if cli.eval_code.is_some() || cli.print_eval.is_some() {
        return Some(eval);
    }

    match cli.command.as_ref() {
        Some(Commands::Eval { .. }) => Some(eval),
        Some(Commands::Repl) => Some(SelectedExecutionRoute {
            entry_kind: ArmedEntryKind::Repl,
            mode: if stdin_is_tty {
                ArmedExecutionMode::Interactive
            } else {
                ArmedExecutionMode::Transcript
            },
        }),
        Some(Commands::Run { .. }) => Some(SelectedExecutionRoute {
            entry_kind: ArmedEntryKind::File,
            mode: ArmedExecutionMode::Program,
        }),
        None if cli.file.is_some() => Some(SelectedExecutionRoute {
            entry_kind: ArmedEntryKind::File,
            mode: ArmedExecutionMode::Program,
        }),
        None if stdin_is_tty => Some(SelectedExecutionRoute {
            entry_kind: ArmedEntryKind::Repl,
            mode: ArmedExecutionMode::Interactive,
        }),
        None => Some(SelectedExecutionRoute {
            entry_kind: ArmedEntryKind::Stdin,
            mode: ArmedExecutionMode::Program,
        }),
        Some(
            Commands::Build { .. }
            | Commands::Completions { .. }
            | Commands::Version
            | Commands::Debug { .. }
            | Commands::Policy { .. }
            | Commands::Capsec { .. }
            | Commands::SelfTest
            | Commands::Compat { .. },
        ) => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeTerminalFacts {
    pub stdin_is_tty: bool,
    pub stdout_is_tty: bool,
    pub stderr_is_tty: bool,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TerminalDimensions {
    pub(crate) columns: u16,
    pub(crate) rows: u16,
}

#[cfg(unix)]
fn terminal_dimensions_from_fd(fd: libc::c_int) -> io::Result<TerminalDimensions> {
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: `size` is writable storage for one winsize and the caller
        // supplies a retained terminal descriptor.
        if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut size) } == 0 {
            return Ok(TerminalDimensions {
                columns: size.ws_col,
                rows: size.ws_row,
            });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// Capture the current dimensions from the supervisor's real presentation
/// descriptor before fd 1/fd 2 are replaced by broker pipes.
#[cfg(unix)]
pub(crate) fn capture_standard_terminal_dimensions(
    presentation: CapturedPresentation,
) -> io::Result<Option<TerminalDimensions>> {
    let descriptor = match presentation.topology {
        PresentationTopology::StdoutTty => libc::STDOUT_FILENO,
        PresentationTopology::StderrTty => libc::STDERR_FILENO,
        PresentationTopology::Transcript => return Ok(None),
    };
    terminal_dimensions_from_fd(descriptor).map(Some)
}

impl NativeTerminalFacts {
    pub fn capture() -> Self {
        Self {
            stdin_is_tty: io::stdin().is_terminal(),
            stdout_is_tty: io::stdout().is_terminal(),
            stderr_is_tty: io::stderr().is_terminal(),
        }
    }

    pub const fn presentation_topology(self) -> PresentationTopology {
        if self.stdout_is_tty {
            PresentationTopology::StdoutTty
        } else if self.stderr_is_tty {
            PresentationTopology::StderrTty
        } else {
            PresentationTopology::Transcript
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresentationTopology {
    StdoutTty,
    StderrTty,
    Transcript,
}

/// The supervisor-selected native destination for a shared program-output
/// stream. This is a construction fact, not an identity inferred from two
/// inherited descriptors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeOutputDestination {
    Stdout,
    Stderr,
}

impl NativeOutputDestination {
    const fn relay_id(self) -> RelayId {
        match self {
            Self::Stdout => NATIVE_STDOUT_RELAY,
            Self::Stderr => NATIVE_STDERR_RELAY,
        }
    }

    #[cfg(unix)]
    const fn descriptor(self) -> libc::c_int {
        match self {
            Self::Stdout => libc::STDOUT_FILENO,
            Self::Stderr => libc::STDERR_FILENO,
        }
    }
}

/// Whether fd 1 and fd 2 are structurally joined before an armed runtime can
/// write. When both captured outputs are terminals, the supervisor deliberately
/// canonicalizes both streams to the selected session terminal (stdout wins by
/// the presentation rule); all other combinations retain independent relays.
///
/// @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker — a shared
/// destination is one open file description, one relay, and one counter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputDestinationTopology {
    Shared {
        destination: NativeOutputDestination,
    },
    Split,
}

/// Immutable presentation facts captured before the worker is armed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturedPresentation {
    pub topology: PresentationTopology,
    pub session_ansi: bool,
    pub editor_control: bool,
}

impl CapturedPresentation {
    pub const fn interactive_plain() -> Self {
        Self {
            topology: PresentationTopology::StdoutTty,
            session_ansi: false,
            editor_control: true,
        }
    }
}

const NATIVE_STDOUT_RELAY: RelayId = RelayId(1);
const NATIVE_STDERR_RELAY: RelayId = RelayId(2);

/// Immutable CLI/descriptor topology captured before an armed host is built.
/// Every execution route has broker-owned fd 1 and fd 2; only REPL and stdin
/// routes replace JavaScript's fd-0 view.
/// @ref LLP 0025#1-modes-descriptors-and-topology — semantic mode, descriptor
/// ownership, and presentation topology are selected independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionIoPlan {
    pub route: SelectedExecutionRoute,
    pub terminal_facts: NativeTerminalFacts,
    pub presentation: CapturedPresentation,
}

impl SessionIoPlan {
    /// The one production pre-arm capture: native TTY facts and color-related
    /// environment are observed once, then carried immutably with the route.
    pub fn capture_for_cli(cli: &Cli) -> Option<Self> {
        let terminal_facts = NativeTerminalFacts::capture();
        let mut plan = Self::for_cli(cli, terminal_facts, false)?;
        let color = CapturedColorFacts::capture(
            plan.route,
            terminal_facts,
            plan.presentation.editor_control,
        );
        plan.presentation.session_ansi = color.session_ansi();
        Some(plan)
    }

    pub fn for_cli(
        cli: &Cli,
        terminal_facts: NativeTerminalFacts,
        session_ansi: bool,
    ) -> Option<Self> {
        let route = selected_execution_route(cli, terminal_facts.stdin_is_tty)?;
        let topology = terminal_facts.presentation_topology();
        let editor_control =
            route.has_interactive_editor() && !matches!(topology, PresentationTopology::Transcript);
        Some(Self {
            route,
            terminal_facts,
            presentation: CapturedPresentation {
                topology,
                // Transcript presentation cannot safely carry terminal control
                // or styling. Other modes receive the already-captured color
                // decision for their selected destination.
                session_ansi: session_ansi
                    && !matches!(topology, PresentationTopology::Transcript)
                    && !matches!(route.mode, ArmedExecutionMode::Transcript),
                editor_control,
            },
        })
    }

    pub const fn output_topology(self) -> OutputDestinationTopology {
        if self.terminal_facts.stdout_is_tty && self.terminal_facts.stderr_is_tty {
            OutputDestinationTopology::Shared {
                destination: NativeOutputDestination::Stdout,
            }
        } else {
            OutputDestinationTopology::Split
        }
    }

    pub const fn broker_routes(self) -> BrokerRoutes {
        broker_routes_for_plan(self.presentation, self.output_topology())
    }

    pub fn broker_presentations(self) -> Vec<(RelayId, RelayPresentation)> {
        broker_presentations_for_topology(self.presentation, self.output_topology())
    }
}

const fn broker_routes_for_plan(
    presentation: CapturedPresentation,
    output_topology: OutputDestinationTopology,
) -> BrokerRoutes {
    let session = match presentation.topology {
        PresentationTopology::StdoutTty | PresentationTopology::Transcript => NATIVE_STDOUT_RELAY,
        PresentationTopology::StderrTty => NATIVE_STDERR_RELAY,
    };
    let control = match presentation.topology {
        PresentationTopology::StdoutTty => NATIVE_STDOUT_RELAY,
        PresentationTopology::StderrTty | PresentationTopology::Transcript => NATIVE_STDERR_RELAY,
    };
    let (program_stdout, program_stderr) = match output_topology {
        OutputDestinationTopology::Shared { destination } => {
            let relay = destination.relay_id();
            (relay, relay)
        }
        OutputDestinationTopology::Split => (NATIVE_STDOUT_RELAY, NATIVE_STDERR_RELAY),
    };
    BrokerRoutes {
        program_stdout,
        program_stderr,
        session,
        control,
    }
}

fn broker_presentations_for(
    presentation: CapturedPresentation,
) -> Vec<(RelayId, RelayPresentation)> {
    broker_presentations_for_topology(presentation, OutputDestinationTopology::Split)
}

fn broker_presentations_for_topology(
    presentation: CapturedPresentation,
    output_topology: OutputDestinationTopology,
) -> Vec<(RelayId, RelayPresentation)> {
    let stdout = (
        NATIVE_STDOUT_RELAY,
        RelayPresentation {
            session_ansi: presentation.session_ansi,
            editor_control: presentation.editor_control
                && matches!(presentation.topology, PresentationTopology::StdoutTty),
        },
    );
    let stderr = (
        NATIVE_STDERR_RELAY,
        RelayPresentation {
            session_ansi: presentation.session_ansi,
            editor_control: presentation.editor_control
                && matches!(presentation.topology, PresentationTopology::StderrTty),
        },
    );
    match output_topology {
        OutputDestinationTopology::Shared {
            destination: NativeOutputDestination::Stdout,
        } => vec![stdout],
        OutputDestinationTopology::Shared {
            destination: NativeOutputDestination::Stderr,
        } => vec![stderr],
        OutputDestinationTopology::Split => vec![stdout, stderr],
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorReadRoute {
    Eof,
    Protected,
    Native,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorWriteRoute {
    Broker(ProgramStream),
    Protected,
    Native,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorCloseRoute {
    NoOp,
    Protected,
    Native,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorAliasRoute {
    EofView,
    RefusedStandardDescriptor,
    Protected,
    Native,
}

/// Native descriptor policy installed before an armed worker receives any
/// numeric-descriptor capability. Relay, control, and watchdog handles are
/// registered here and checked before ordinary fd dispatch.
#[derive(Clone, Debug)]
pub struct SessionIo {
    plan: SessionIoPlan,
    protected_descriptors: BTreeSet<i32>,
}

impl SessionIo {
    pub fn new(plan: SessionIoPlan) -> Self {
        Self {
            plan,
            protected_descriptors: BTreeSet::new(),
        }
    }

    pub const fn plan(&self) -> SessionIoPlan {
        self.plan
    }

    pub fn protect_descriptor(&mut self, descriptor: i32) -> Result<(), &'static str> {
        if descriptor <= 2 {
            return Err("a session-internal handle cannot replace fd 0, 1, or 2");
        }
        if !self.protected_descriptors.insert(descriptor) {
            return Err("session-internal descriptor was already registered");
        }
        Ok(())
    }

    pub fn is_protected_descriptor(&self, descriptor: i32) -> bool {
        self.protected_descriptors.contains(&descriptor)
    }

    pub fn route_read(&self, descriptor: i32) -> DescriptorReadRoute {
        if self.is_protected_descriptor(descriptor) {
            DescriptorReadRoute::Protected
        } else if descriptor == 0 && self.plan.route.seals_javascript_stdin() {
            DescriptorReadRoute::Eof
        } else {
            DescriptorReadRoute::Native
        }
    }

    pub fn route_write(&self, descriptor: i32) -> DescriptorWriteRoute {
        if self.is_protected_descriptor(descriptor) {
            DescriptorWriteRoute::Protected
        } else {
            match descriptor {
                1 => DescriptorWriteRoute::Broker(ProgramStream::Stdout),
                2 => DescriptorWriteRoute::Broker(ProgramStream::Stderr),
                _ => DescriptorWriteRoute::Native,
            }
        }
    }

    pub fn route_close(&self, descriptor: i32) -> DescriptorCloseRoute {
        if self.is_protected_descriptor(descriptor) {
            DescriptorCloseRoute::Protected
        } else if matches!(descriptor, 1 | 2)
            || (descriptor == 0 && self.plan.route.seals_javascript_stdin())
        {
            DescriptorCloseRoute::NoOp
        } else {
            DescriptorCloseRoute::Native
        }
    }

    /// Classify a source descriptor before attempting dup/alias construction.
    /// A session fd-0 alias is another virtual EOF view; output descriptors
    /// cannot be aliased around the broker.
    pub fn route_alias_source(&self, descriptor: i32) -> DescriptorAliasRoute {
        if self.is_protected_descriptor(descriptor) {
            DescriptorAliasRoute::Protected
        } else if descriptor == 0 && self.plan.route.seals_javascript_stdin() {
            DescriptorAliasRoute::EofView
        } else if matches!(descriptor, 1 | 2) {
            DescriptorAliasRoute::RefusedStandardDescriptor
        } else {
            DescriptorAliasRoute::Native
        }
    }

    /// No route may replace the three standard descriptors after capture.
    pub fn route_alias_target(&self, descriptor: i32) -> DescriptorAliasRoute {
        if self.is_protected_descriptor(descriptor) {
            DescriptorAliasRoute::Protected
        } else if matches!(descriptor, 0..=2) {
            DescriptorAliasRoute::RefusedStandardDescriptor
        } else {
            DescriptorAliasRoute::Native
        }
    }

    /// fd-0 EOF is returned before `native_read` is invoked. This shape is the
    /// focused hook used by numeric fd, FileHandle, and process.stdin adapters.
    pub fn read_javascript_descriptor<F>(
        &self,
        descriptor: i32,
        bytes: &mut [u8],
        native_read: F,
    ) -> io::Result<usize>
    where
        F: FnOnce(i32, &mut [u8]) -> io::Result<usize>,
    {
        match self.route_read(descriptor) {
            DescriptorReadRoute::Eof => Ok(0),
            DescriptorReadRoute::Protected => Err(protected_descriptor_error()),
            DescriptorReadRoute::Native => native_read(descriptor, bytes),
        }
    }

    /// fd-1/fd-2 bytes enter the broker before any native descriptor write.
    pub fn write_javascript_descriptor<B, N>(
        &self,
        descriptor: i32,
        bytes: &[u8],
        broker_write: B,
        native_write: N,
    ) -> io::Result<usize>
    where
        B: FnOnce(ProgramStream, &[u8]) -> io::Result<()>,
        N: FnOnce(i32, &[u8]) -> io::Result<usize>,
    {
        match self.route_write(descriptor) {
            DescriptorWriteRoute::Broker(stream) => {
                broker_write(stream, bytes)?;
                Ok(bytes.len())
            }
            DescriptorWriteRoute::Protected => Err(protected_descriptor_error()),
            DescriptorWriteRoute::Native => native_write(descriptor, bytes),
        }
    }

    pub fn close_javascript_descriptor<F>(&self, descriptor: i32, native_close: F) -> io::Result<()>
    where
        F: FnOnce(i32) -> io::Result<()>,
    {
        match self.route_close(descriptor) {
            DescriptorCloseRoute::NoOp => Ok(()),
            DescriptorCloseRoute::Protected => Err(protected_descriptor_error()),
            DescriptorCloseRoute::Native => native_close(descriptor),
        }
    }
}

fn protected_descriptor_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "descriptor belongs to the terminal-session control plane",
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStyle {
    Plain,
    Prompt,
    Notice,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerFrameKind {
    Program,
    Display,
    Prompt,
    PromptErase,
    PromptRedraw,
    AsyncReport,
    InterruptNotice,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerFrame {
    pub epoch: u64,
    pub sequence: u64,
    pub kind: BrokerFrameKind,
    pub bytes: Vec<u8>,
}

fn escape_session_text(text: &str) -> String {
    let mut escaped = String::new();
    for ch in text.chars() {
        let code = ch as u32;
        if ch == '\x1b'
            || ch.is_control()
            || (0x80..=0x9f).contains(&code)
            || matches!(code, 0x2028 | 0x2029 | 0x202a..=0x202e | 0x2066..=0x2069)
        {
            use std::fmt::Write as _;
            let _ = write!(escaped, "\\u{{{code:04x}}}");
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

fn escape_session_bytes(bytes: &[u8]) -> Vec<u8> {
    escape_session_text(&String::from_utf8_lossy(bytes)).into_bytes()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayDisposition {
    Displayed,
    Fallback,
    WriteFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum DisplayNodeKind {
    Text = DISPLAY_NODE_TAG_TEXT,
    String = DISPLAY_NODE_TAG_STRING,
    Number = DISPLAY_NODE_TAG_NUMBER,
    Boolean = DISPLAY_NODE_TAG_BOOLEAN,
    Null = DISPLAY_NODE_TAG_NULL,
    Undefined = DISPLAY_NODE_TAG_UNDEFINED,
    Error = DISPLAY_NODE_TAG_ERROR,
    Key = DISPLAY_NODE_TAG_KEY,
    TypeTag = DISPLAY_NODE_TAG_TYPE_TAG,
    Cycle = DISPLAY_NODE_TAG_CYCLE,
    Truncation = DISPLAY_NODE_TAG_TRUNCATION,
}

impl DisplayNodeKind {
    fn from_wire(value: u16) -> Option<Self> {
        match value {
            value if value == Self::Text as u16 => Some(Self::Text),
            value if value == Self::String as u16 => Some(Self::String),
            value if value == Self::Number as u16 => Some(Self::Number),
            value if value == Self::Boolean as u16 => Some(Self::Boolean),
            value if value == Self::Null as u16 => Some(Self::Null),
            value if value == Self::Undefined as u16 => Some(Self::Undefined),
            value if value == Self::Error as u16 => Some(Self::Error),
            value if value == Self::Key as u16 => Some(Self::Key),
            value if value == Self::TypeTag as u16 => Some(Self::TypeTag),
            value if value == Self::Cycle as u16 => Some(Self::Cycle),
            value if value == Self::Truncation as u16 => Some(Self::Truncation),
            _ => None,
        }
    }
}

/// Styling derived solely from a trusted node kind. This vocabulary is
/// deliberately disjoint from `SessionStyle`, so a worker cannot render as a
/// prompt, notice, or editor-control frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DisplayStyle {
    Plain,
    String,
    Number,
    Keyword,
    Error,
    Key,
    TypeTag,
    Truncation,
}

fn display_style(kind: DisplayNodeKind) -> DisplayStyle {
    match kind {
        DisplayNodeKind::Text => DisplayStyle::Plain,
        DisplayNodeKind::String => DisplayStyle::String,
        DisplayNodeKind::Number => DisplayStyle::Number,
        DisplayNodeKind::Boolean | DisplayNodeKind::Null | DisplayNodeKind::Undefined => {
            DisplayStyle::Keyword
        }
        DisplayNodeKind::Error => DisplayStyle::Error,
        DisplayNodeKind::Key => DisplayStyle::Key,
        DisplayNodeKind::TypeTag => DisplayStyle::TypeTag,
        DisplayNodeKind::Cycle | DisplayNodeKind::Truncation => DisplayStyle::Truncation,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedDisplay {
    pub bytes: Vec<u8>,
    pub disposition: DisplayDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturedColorFacts {
    pub plain_transcript: bool,
    pub interactive_mode: bool,
    pub interactive_editor: bool,
    pub no_color: bool,
    pub clicolor_force: bool,
    pub stream_is_tty: bool,
    pub term_is_dumb: bool,
}

impl CapturedColorFacts {
    pub fn capture(
        route: SelectedExecutionRoute,
        terminal_facts: NativeTerminalFacts,
        interactive_editor: bool,
    ) -> Self {
        let stream_is_tty = match terminal_facts.presentation_topology() {
            PresentationTopology::StdoutTty => terminal_facts.stdout_is_tty,
            PresentationTopology::StderrTty => terminal_facts.stderr_is_tty,
            PresentationTopology::Transcript => false,
        };
        Self {
            plain_transcript: matches!(route.mode, ArmedExecutionMode::Transcript),
            interactive_mode: matches!(route.mode, ArmedExecutionMode::Interactive),
            interactive_editor,
            no_color: std::env::var_os("NO_COLOR").is_some(),
            clicolor_force: std::env::var_os("CLICOLOR_FORCE").is_some_and(|value| value != "0"),
            stream_is_tty,
            term_is_dumb: std::env::var_os("TERM").is_some_and(|value| value == "dumb"),
        }
    }

    /// Apply LLP 0025's ordered predicate to facts captured before arming.
    pub const fn session_ansi(self) -> bool {
        if self.plain_transcript || (self.interactive_mode && !self.interactive_editor) {
            false
        } else if self.no_color {
            false
        } else if self.clicolor_force {
            true
        } else {
            self.stream_is_tty && !self.term_is_dumb
        }
    }
}

pub struct SafeSessionRenderer;

impl SafeSessionRenderer {
    // @ref LLP 0024#8-safe-inspection — the wire object carries
    // kind, untrusted payload, and children, but no style or layout tokens.
    /// Render the versioned length-bearing wire tree owned by LLP 0024. The
    /// format is `IBDX`, little-endian u16 version, then recursively
    /// `(u16 kind, u32 payload_len, payload, u32 child_count, children...)`.
    pub fn render_tree(wire: &[u8], session_ansi: bool) -> RenderedDisplay {
        if wire.len() > DISPLAY_TREE_MAX_SERIALIZED_BYTES {
            return fallback_display(DISPLAY_FALLBACK_REASON_OVERSIZE_TREE);
        }
        let mut cursor = DisplayCursor::new(wire);
        let parsed = (|| {
            if !DISPLAY_TREE_LITTLE_ENDIAN {
                return Err(DisplayParseError);
            }
            if cursor.take(DISPLAY_TREE_MAGIC.len())? != DISPLAY_TREE_MAGIC {
                return Err(DisplayParseError);
            }
            if cursor.u16()? != DISPLAY_TREE_WIRE_VERSION {
                return Err(DisplayParseError);
            }
            let mut output = Vec::new();
            let mut bounded_fallback = false;
            render_display_node(
                &mut cursor,
                DISPLAY_TREE_ROOT_DEPTH,
                session_ansi,
                &mut output,
                &mut bounded_fallback,
            )?;
            if !cursor.is_at_end() {
                return Err(DisplayParseError);
            }
            Ok((output, bounded_fallback))
        })();
        match parsed {
            Ok((bytes, false)) => RenderedDisplay {
                bytes,
                disposition: DisplayDisposition::Displayed,
            },
            Ok((bytes, true)) => RenderedDisplay {
                bytes,
                disposition: DisplayDisposition::Fallback,
            },
            Err(_) => fallback_display(DISPLAY_FALLBACK_REASON_MALFORMED_OR_UNKNOWN_TREE),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct DisplayParseError;

struct DisplayCursor<'a> {
    wire: &'a [u8],
    position: usize,
}

impl<'a> DisplayCursor<'a> {
    fn new(wire: &'a [u8]) -> Self {
        Self { wire, position: 0 }
    }

    fn is_at_end(&self) -> bool {
        self.position == self.wire.len()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DisplayParseError> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.wire.len())
            .ok_or(DisplayParseError)?;
        let bytes = &self.wire[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, DisplayParseError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| DisplayParseError)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, DisplayParseError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| DisplayParseError)?;
        Ok(u32::from_le_bytes(bytes))
    }
}

fn render_display_node(
    cursor: &mut DisplayCursor<'_>,
    depth: usize,
    session_ansi: bool,
    output: &mut Vec<u8>,
    bounded_fallback: &mut bool,
) -> Result<(), DisplayParseError> {
    let raw_kind = cursor.u16()?;
    let payload_length = usize::try_from(cursor.u32()?).map_err(|_| DisplayParseError)?;
    let payload = cursor.take(payload_length)?;
    let child_count = cursor.u32()?;
    let Some(kind) = DisplayNodeKind::from_wire(raw_kind) else {
        *bounded_fallback = true;
        extend_render_output(
            output,
            format!("{UNKNOWN_DISPLAY_NODE_PREFIX}{raw_kind}{UNKNOWN_DISPLAY_NODE_SUFFIX}")
                .as_bytes(),
        )?;
        skip_display_nodes(cursor, u64::from(child_count))?;
        return Ok(());
    };

    render_display_payload(
        payload,
        display_style(kind),
        session_ansi,
        output,
        bounded_fallback,
    )?;
    if child_count == 0 {
        return Ok(());
    }

    if depth >= DISPLAY_RENDER_DEPTH {
        *bounded_fallback = true;
        skip_display_nodes(cursor, u64::from(child_count))?;
        render_truncation_marker(output, usize::try_from(child_count).unwrap_or(usize::MAX))?;
        return Ok(());
    }

    extend_render_output(output, RENDER_CHILDREN_OPEN)?;
    let rendered_children = usize::try_from(child_count)
        .unwrap_or(usize::MAX)
        .min(DISPLAY_RENDER_BREADTH);
    for index in 0..rendered_children {
        if index > 0 {
            extend_render_output(output, RENDER_CHILDREN_SEPARATOR)?;
        }
        render_display_node(cursor, depth + 1, session_ansi, output, bounded_fallback)?;
    }
    let skipped = usize::try_from(child_count)
        .unwrap_or(usize::MAX)
        .saturating_sub(rendered_children);
    if skipped > 0 {
        *bounded_fallback = true;
        skip_display_nodes(cursor, skipped as u64)?;
        if rendered_children > 0 {
            extend_render_output(output, RENDER_CHILDREN_SEPARATOR)?;
        }
        render_truncation_marker(output, skipped)?;
    }
    extend_render_output(output, RENDER_CHILDREN_CLOSE)?;
    Ok(())
}

fn skip_display_nodes(cursor: &mut DisplayCursor<'_>, count: u64) -> Result<(), DisplayParseError> {
    let mut remaining = count;
    while remaining > 0 {
        let _kind = cursor.u16()?;
        let payload_length = usize::try_from(cursor.u32()?).map_err(|_| DisplayParseError)?;
        cursor.take(payload_length)?;
        let children = u64::from(cursor.u32()?);
        remaining = remaining
            .checked_sub(1)
            .and_then(|remaining| remaining.checked_add(children))
            .ok_or(DisplayParseError)?;
    }
    Ok(())
}

fn render_display_payload(
    payload: &[u8],
    style: DisplayStyle,
    session_ansi: bool,
    output: &mut Vec<u8>,
    bounded_fallback: &mut bool,
) -> Result<(), DisplayParseError> {
    let decoded = String::from_utf8_lossy(payload);
    let scalar_count = decoded.chars().count();
    let displayed: String = decoded.chars().take(DISPLAY_PAYLOAD_SCALARS).collect();
    let escaped = escape_session_text(&displayed);
    let style_prefix = if session_ansi {
        match style {
            DisplayStyle::Plain => "",
            DisplayStyle::String => ANSI_DISPLAY_STRING,
            DisplayStyle::Number => ANSI_DISPLAY_NUMBER,
            DisplayStyle::Keyword => ANSI_DISPLAY_KEYWORD,
            DisplayStyle::Error => ANSI_DISPLAY_ERROR,
            DisplayStyle::Key => ANSI_DISPLAY_KEY,
            DisplayStyle::TypeTag => ANSI_DISPLAY_TYPE_TAG,
            DisplayStyle::Truncation => ANSI_DISPLAY_TRUNCATION,
        }
    } else {
        ""
    };
    extend_render_output(output, style_prefix.as_bytes())?;
    extend_render_output(output, escaped.as_bytes())?;
    if session_ansi && !style_prefix.is_empty() {
        extend_render_output(output, ANSI_RESET.as_bytes())?;
    }
    if scalar_count > DISPLAY_PAYLOAD_SCALARS {
        *bounded_fallback = true;
        extend_render_output(output, RENDER_PAYLOAD_TRUNCATION_SEPARATOR)?;
        render_truncation_marker(output, scalar_count - DISPLAY_PAYLOAD_SCALARS)?;
    }
    Ok(())
}

fn render_truncation_marker(output: &mut Vec<u8>, omitted: usize) -> Result<(), DisplayParseError> {
    extend_render_output(
        output,
        format!("{TRUNCATION_PREFIX}{omitted}{TRUNCATION_SUFFIX}").as_bytes(),
    )
}

fn extend_render_output(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DisplayParseError> {
    let next_length = output
        .len()
        .checked_add(bytes.len())
        .filter(|length| *length <= BROKER_QUEUE_BOUND_BYTES)
        .ok_or(DisplayParseError)?;
    output.reserve(next_length - output.len());
    output.extend_from_slice(bytes);
    Ok(())
}

fn fallback_display(reason: &str) -> RenderedDisplay {
    RenderedDisplay {
        bytes: format!(
            "{DISPLAY_FALLBACK_PREFIX}{}{DISPLAY_FALLBACK_SUFFIX}",
            escape_session_text(reason)
        )
        .into_bytes(),
        disposition: DisplayDisposition::Fallback,
    }
}

/// Encode one Stage-1 value as the smallest valid IBDX tree. The producer can
/// choose only a value kind and hostile payload; styling and framing remain
/// broker-owned.
pub(crate) fn encode_authenticated_display(
    display: &crate::engine::AuthenticatedDisplay,
) -> Result<Vec<u8>, &'static str> {
    use crate::engine::AuthenticatedDisplayKind as Kind;

    let tag = match display.kind {
        Kind::String => DISPLAY_NODE_TAG_STRING,
        Kind::Number | Kind::BigInt => DISPLAY_NODE_TAG_NUMBER,
        Kind::Boolean => DISPLAY_NODE_TAG_BOOLEAN,
        Kind::Null => DISPLAY_NODE_TAG_NULL,
        Kind::Undefined => DISPLAY_NODE_TAG_UNDEFINED,
        Kind::Function | Kind::Array | Kind::Object => DISPLAY_NODE_TAG_TYPE_TAG,
        Kind::Symbol | Kind::JsonData => DISPLAY_NODE_TAG_TEXT,
    };
    let payload = display.text.as_bytes();
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| "display payload is too large")?;
    let capacity = DISPLAY_TREE_MAGIC
        .len()
        .checked_add(2 + 2 + 4 + 4)
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or("display tree length overflow")?;
    let mut wire = Vec::with_capacity(capacity);
    wire.extend_from_slice(DISPLAY_TREE_MAGIC);
    wire.extend_from_slice(&DISPLAY_TREE_WIRE_VERSION.to_le_bytes());
    wire.extend_from_slice(&tag.to_le_bytes());
    wire.extend_from_slice(&payload_length.to_le_bytes());
    wire.extend_from_slice(payload);
    wire.extend_from_slice(&0_u32.to_le_bytes());
    Ok(wire)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RelayId(pub u8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgramStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum BrokerLane {
    Data,
    Control,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerAuthor {
    Program,
    Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerRoutes {
    pub program_stdout: RelayId,
    pub program_stderr: RelayId,
    pub session: RelayId,
    pub control: RelayId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayPresentation {
    pub session_ansi: bool,
    pub editor_control: bool,
}

impl RelayPresentation {
    pub const fn capture(color: CapturedColorFacts, editor_control: bool) -> Self {
        Self {
            session_ansi: color.session_ansi(),
            editor_control,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerReceipt {
    pub epoch: u64,
    pub sequence: u64,
    pub relay: RelayId,
    pub lane: BrokerLane,
    pub author: BrokerAuthor,
    pub kind: BrokerFrameKind,
    pub bytes: usize,
}

pub struct RelayWriteRequest<'a> {
    pub relay: RelayId,
    pub lane: BrokerLane,
    pub epoch: u64,
    pub sequence: u64,
    pub author: BrokerAuthor,
    pub kind: BrokerFrameKind,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayWriteOutcome {
    Written(usize),
    WouldBlock,
}

/// Concrete sinks must be nonblocking. The broker revisits `WouldBlock`
/// relays independently, so one stalled destination cannot hold another.
pub trait NonBlockingRelaySink {
    fn try_write(&mut self, request: RelayWriteRequest<'_>) -> Result<RelayWriteOutcome, String>;

    fn flush(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerEnqueueError {
    Closed,
    UnknownRelay(RelayId),
    TooManyRelays {
        attempted: usize,
    },
    Backpressure {
        relay: RelayId,
        lane: BrokerLane,
        attempted: usize,
        available: usize,
    },
    WriteFailed {
        relay: RelayId,
        message: String,
    },
    BarrierPending,
    BarrierSuperseded,
    ForeignBarrier,
    StaleBarrier,
    BarrierWriteFailed(Vec<RelayId>),
    CounterExhausted,
}

impl fmt::Display for BrokerEnqueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "output broker is closed"),
            Self::UnknownRelay(relay) => write!(f, "unknown output relay {}", relay.0),
            Self::TooManyRelays { attempted } => {
                write!(
                    f,
                    "{attempted} output relays exceeds the limit of {MAX_LIVE_RELAYS}"
                )
            }
            Self::Backpressure {
                relay,
                lane,
                attempted,
                available,
            } => write!(
                f,
                "relay {} {lane:?} queue backpressure: {attempted} bytes for {available} available",
                relay.0
            ),
            Self::WriteFailed { relay, message } => {
                write!(f, "relay {} write failed: {message}", relay.0)
            }
            Self::BarrierPending => write!(f, "output barrier is still pending"),
            Self::BarrierSuperseded => {
                write!(f, "output arrived after the supplied barrier cutoff")
            }
            Self::ForeignBarrier => write!(f, "output barrier belongs to another broker"),
            Self::StaleBarrier => write!(f, "output barrier belongs to a retired generation"),
            Self::BarrierWriteFailed(relays) => {
                write!(f, "output barrier failed on relays {relays:?}")
            }
            Self::CounterExhausted => write!(f, "output broker counter space exhausted"),
        }
    }
}

impl std::error::Error for BrokerEnqueueError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingBrokerFrame {
    receipt: BrokerReceipt,
    bytes: Vec<u8>,
    offset: usize,
}

impl PendingBrokerFrame {
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }
}

#[derive(Clone, Debug)]
struct RelayQueue {
    presentation: RelayPresentation,
    data: VecDeque<PendingBrokerFrame>,
    control: VecDeque<PendingBrokerFrame>,
    queued_data_bytes: usize,
    queued_control_bytes: usize,
    accepted_data_bytes: u64,
    written_data_bytes: u64,
    write_failure: Option<String>,
    prompt_visible: bool,
    prompt_line: Vec<u8>,
}

impl RelayQueue {
    fn new(presentation: RelayPresentation) -> Self {
        Self {
            presentation,
            data: VecDeque::new(),
            control: VecDeque::new(),
            queued_data_bytes: 0,
            queued_control_bytes: 0,
            accepted_data_bytes: 0,
            written_data_bytes: 0,
            write_failure: None,
            prompt_visible: false,
            prompt_line: Vec::new(),
        }
    }

    fn queued_bytes(&self, lane: BrokerLane) -> usize {
        match lane {
            BrokerLane::Data => self.queued_data_bytes,
            BrokerLane::Control => self.queued_control_bytes,
        }
    }
}

#[derive(Clone, Debug)]
struct PendingBatchFrame {
    relay: RelayId,
    lane: BrokerLane,
    author: BrokerAuthor,
    kind: BrokerFrameKind,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayCutoff {
    relay: RelayId,
    accepted_bytes: u64,
}

impl RelayCutoff {
    pub const fn relay(&self) -> RelayId {
        self.relay
    }

    pub const fn accepted_bytes(&self) -> u64 {
        self.accepted_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerBarrier {
    broker_instance_id: u64,
    generation: u64,
    epoch: u64,
    sequence: u64,
    cutoffs: Vec<RelayCutoff>,
}

impl BrokerBarrier {
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn cutoffs(&self) -> &[RelayCutoff] {
        &self.cutoffs
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayBarrierProgress {
    pub relay: RelayId,
    pub written_bytes: u64,
    pub cutoff_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BarrierPoll {
    Complete,
    Pending(Vec<RelayBarrierProgress>),
    WriteFailed(Vec<RelayId>),
    Invalid(BarrierInvalidity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierInvalidity {
    ForeignBroker,
    StaleGeneration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisplayTicket {
    barrier: BrokerBarrier,
    rendered_disposition: DisplayDisposition,
    receipts: Vec<BrokerReceipt>,
}

impl DisplayTicket {
    pub fn barrier(&self) -> &BrokerBarrier {
        &self.barrier
    }

    pub fn receipts(&self) -> &[BrokerReceipt] {
        &self.receipts
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisplayPoll {
    Pending,
    Complete(DisplayDisposition),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PumpSummary {
    pub progressed_relays: usize,
    pub stalled_relays: usize,
    pub failed_relays: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayLoss {
    pub relay: RelayId,
    pub program_bytes: usize,
    pub session_bytes: usize,
    pub program_frames: usize,
    pub session_frames: usize,
    pub control_frames: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerLossAccounting {
    pub forced_close_epoch: u64,
    pub forced_close_sequence: u64,
    pub relays: Vec<RelayLoss>,
}

impl BrokerLossAccounting {
    pub fn has_loss(&self) -> bool {
        self.relays.iter().any(|relay| {
            relay.program_bytes > 0
                || relay.session_bytes > 0
                || relay.program_frames > 0
                || relay.session_frames > 0
        })
    }
}

/// An in-process, receipt-sequenced broker with one bounded data queue and one
/// independently reserved control queue per physical destination.
// @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker — counters
// advance on queue acceptance, barriers carry per-relay cutoffs, and forced
// close accounts rather than silently discarding.
pub struct InProcessOutputBroker<W: NonBlockingRelaySink> {
    sink: W,
    routes: BrokerRoutes,
    relays: BTreeMap<RelayId, RelayQueue>,
    instance_id: u64,
    generation: u64,
    sequencer: crate::session_worker::SupervisorSequenceAllocator,
    queue_bound_bytes: usize,
    closed: bool,
}

impl<W: NonBlockingRelaySink> InProcessOutputBroker<W> {
    pub fn new(
        sink: W,
        routes: BrokerRoutes,
        presentations: impl IntoIterator<Item = (RelayId, RelayPresentation)>,
    ) -> Result<Self, BrokerEnqueueError> {
        Self::with_queue_bound(sink, routes, presentations, BROKER_QUEUE_BOUND_BYTES)
    }

    pub(crate) fn with_sequence_allocator(
        sink: W,
        routes: BrokerRoutes,
        presentations: impl IntoIterator<Item = (RelayId, RelayPresentation)>,
        sequencer: crate::session_worker::SupervisorSequenceAllocator,
    ) -> Result<Self, BrokerEnqueueError> {
        Self::with_queue_bound_and_sequence_allocator(
            sink,
            routes,
            presentations,
            BROKER_QUEUE_BOUND_BYTES,
            sequencer,
        )
    }

    fn with_queue_bound(
        sink: W,
        routes: BrokerRoutes,
        presentations: impl IntoIterator<Item = (RelayId, RelayPresentation)>,
        queue_bound_bytes: usize,
    ) -> Result<Self, BrokerEnqueueError> {
        let sequencer = crate::session_worker::SupervisorSequenceAllocator::new(1)
            .map_err(|_| BrokerEnqueueError::CounterExhausted)?;
        Self::with_queue_bound_and_sequence_allocator(
            sink,
            routes,
            presentations,
            queue_bound_bytes,
            sequencer,
        )
    }

    fn with_queue_bound_and_sequence_allocator(
        sink: W,
        routes: BrokerRoutes,
        presentations: impl IntoIterator<Item = (RelayId, RelayPresentation)>,
        queue_bound_bytes: usize,
        sequencer: crate::session_worker::SupervisorSequenceAllocator,
    ) -> Result<Self, BrokerEnqueueError> {
        let relays: BTreeMap<_, _> = presentations
            .into_iter()
            .map(|(id, presentation)| (id, RelayQueue::new(presentation)))
            .collect();
        if relays.len() > MAX_LIVE_RELAYS {
            return Err(BrokerEnqueueError::TooManyRelays {
                attempted: relays.len(),
            });
        }
        for relay in [
            routes.program_stdout,
            routes.program_stderr,
            routes.session,
            routes.control,
        ] {
            if !relays.contains_key(&relay) {
                return Err(BrokerEnqueueError::UnknownRelay(relay));
            }
        }
        let instance_id = NEXT_BROKER_INSTANCE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| BrokerEnqueueError::CounterExhausted)?;
        Ok(Self {
            sink,
            routes,
            relays,
            instance_id,
            generation: 1,
            sequencer,
            queue_bound_bytes,
            closed: false,
        })
    }

    #[cfg(test)]
    fn sink(&self) -> &W {
        &self.sink
    }

    #[cfg(test)]
    fn sink_mut(&mut self) -> &mut W {
        &mut self.sink
    }

    pub fn accepted_bytes(&self, relay: RelayId) -> Option<u64> {
        self.relays
            .get(&relay)
            .map(|relay| relay.accepted_data_bytes)
    }

    pub fn written_bytes(&self, relay: RelayId) -> Option<u64> {
        self.relays
            .get(&relay)
            .map(|relay| relay.written_data_bytes)
    }

    pub fn queued_bytes(&self, relay: RelayId, lane: BrokerLane) -> Option<usize> {
        self.relays
            .get(&relay)
            .map(|relay| relay.queued_bytes(lane))
    }

    pub fn publish_prompt(
        &mut self,
        prompt: &str,
        edit_buffer: &[u8],
    ) -> Result<Vec<BrokerReceipt>, BrokerEnqueueError> {
        let relay_id = self.routes.session;
        let relay = self
            .relays
            .get(&relay_id)
            .ok_or(BrokerEnqueueError::UnknownRelay(relay_id))?;
        let prompt_line = render_prompt_line(prompt, edit_buffer, relay.presentation.session_ansi);
        let mut frames = Vec::new();
        if relay.prompt_visible {
            frames.push(prompt_erase_frame(
                relay_id,
                BrokerLane::Data,
                relay.presentation,
            ));
        }
        frames.push(PendingBatchFrame {
            relay: relay_id,
            lane: BrokerLane::Data,
            author: BrokerAuthor::Session,
            kind: BrokerFrameKind::Prompt,
            bytes: prompt_line.clone(),
        });
        let receipts = self.enqueue_batch(frames)?;
        let relay = self.relays.get_mut(&relay_id).expect("route was validated");
        relay.prompt_visible = true;
        relay.prompt_line = prompt_line;
        Ok(receipts)
    }

    pub fn update_edit_buffer(&mut self, prompt: &str, edit_buffer: &[u8]) {
        if let Some(relay) = self.relays.get_mut(&self.routes.session) {
            relay.prompt_line =
                render_prompt_line(prompt, edit_buffer, relay.presentation.session_ansi);
        }
    }

    pub fn hide_prompt(&mut self) {
        if let Some(relay) = self.relays.get_mut(&self.routes.session) {
            relay.prompt_visible = false;
        }
    }

    pub fn receive_program(
        &mut self,
        stream: ProgramStream,
        bytes: &[u8],
    ) -> Result<Vec<BrokerReceipt>, BrokerEnqueueError> {
        let relay_id = match stream {
            ProgramStream::Stdout => self.routes.program_stdout,
            ProgramStream::Stderr => self.routes.program_stderr,
        };
        let relay = self
            .relays
            .get(&relay_id)
            .ok_or(BrokerEnqueueError::UnknownRelay(relay_id))?;
        let wrapper_bytes = if relay_id == self.routes.session && relay.prompt_visible {
            prompt_erase_frame(relay_id, BrokerLane::Data, relay.presentation)
                .bytes
                .len()
                .checked_add(relay.prompt_line.len())
                .ok_or(BrokerEnqueueError::CounterExhausted)?
        } else {
            0
        };
        let attempted = bytes
            .len()
            .checked_add(wrapper_bytes)
            .ok_or(BrokerEnqueueError::CounterExhausted)?;
        self.ensure_lane_capacity(relay_id, BrokerLane::Data, attempted)?;
        let mut frames = self.prompt_wrapped_frames(
            relay_id,
            BrokerLane::Data,
            BrokerAuthor::Program,
            BrokerFrameKind::Program,
            bytes.to_vec(),
        )?;
        let redraws_prompt = frames.len() > 1;
        let receipts = self.enqueue_batch(std::mem::take(&mut frames))?;
        if redraws_prompt {
            if let Some(relay) = self.relays.get_mut(&relay_id) {
                relay.prompt_visible = true;
            }
        }
        Ok(receipts)
    }

    fn ensure_lane_capacity(
        &self,
        relay_id: RelayId,
        lane: BrokerLane,
        attempted: usize,
    ) -> Result<(), BrokerEnqueueError> {
        if self.closed {
            return Err(BrokerEnqueueError::Closed);
        }
        let relay = self
            .relays
            .get(&relay_id)
            .ok_or(BrokerEnqueueError::UnknownRelay(relay_id))?;
        if let Some(message) = &relay.write_failure {
            return Err(BrokerEnqueueError::WriteFailed {
                relay: relay_id,
                message: message.clone(),
            });
        }
        let available = self
            .queue_bound_bytes
            .saturating_sub(relay.queued_bytes(lane));
        if attempted > available {
            Err(BrokerEnqueueError::Backpressure {
                relay: relay_id,
                lane,
                attempted,
                available,
            })
        } else {
            Ok(())
        }
    }

    pub fn receive_async_report(
        &mut self,
        report: &str,
    ) -> Result<Vec<BrokerReceipt>, BrokerEnqueueError> {
        let relay_id = self.routes.session;
        let presentation = self
            .relays
            .get(&relay_id)
            .ok_or(BrokerEnqueueError::UnknownRelay(relay_id))?
            .presentation;
        let payload = render_session_text(report, SessionStyle::Error, presentation.session_ansi);
        let frames = self.prompt_wrapped_frames(
            relay_id,
            BrokerLane::Data,
            BrokerAuthor::Session,
            BrokerFrameKind::AsyncReport,
            payload,
        )?;
        self.enqueue_batch(frames)
    }

    /// Render one session-owned logical line. Payload bytes are escaped as
    /// hostile data; the line boundary is a trusted annex-owned framing byte.
    pub fn receive_session_line(
        &mut self,
        text: &str,
        style: SessionStyle,
    ) -> Result<Vec<BrokerReceipt>, BrokerEnqueueError> {
        let relay_id = self.routes.session;
        let presentation = self
            .relays
            .get(&relay_id)
            .ok_or(BrokerEnqueueError::UnknownRelay(relay_id))?
            .presentation;
        let mut payload = render_session_text(text, style, presentation.session_ansi);
        payload.extend_from_slice(PROMPT_TRANSCRIPT_BOUNDARY_BYTES);
        let frames = self.prompt_wrapped_frames(
            relay_id,
            BrokerLane::Data,
            BrokerAuthor::Session,
            BrokerFrameKind::AsyncReport,
            payload,
        )?;
        self.enqueue_batch(frames)
    }

    /// Render a terminal-safe diagnostic on the reserved control destination.
    /// Non-file one-shot/program failures use this path so pipeline stdout is
    /// never polluted by evaluator diagnostics and a stalled data lane cannot
    /// hide the terminal status explanation.
    pub fn receive_control_line(
        &mut self,
        text: &str,
        style: SessionStyle,
    ) -> Result<Vec<BrokerReceipt>, BrokerEnqueueError> {
        let relay_id = self.routes.control;
        let presentation = self
            .relays
            .get(&relay_id)
            .ok_or(BrokerEnqueueError::UnknownRelay(relay_id))?
            .presentation;
        let mut payload = render_session_text(text, style, presentation.session_ansi);
        payload.extend_from_slice(PROMPT_TRANSCRIPT_BOUNDARY_BYTES);
        let frames = self.prompt_wrapped_frames(
            relay_id,
            BrokerLane::Control,
            BrokerAuthor::Session,
            BrokerFrameKind::AsyncReport,
            payload,
        )?;
        self.enqueue_batch(frames)
    }

    /// Commit the currently visible raw editor line. This is trusted editor
    /// framing, not runtime-authored payload.
    pub fn receive_prompt_boundary(&mut self) -> Result<Vec<BrokerReceipt>, BrokerEnqueueError> {
        let relay_id = self.routes.session;
        self.hide_prompt();
        self.enqueue_batch(vec![PendingBatchFrame {
            relay: relay_id,
            lane: BrokerLane::Data,
            author: BrokerAuthor::Session,
            kind: BrokerFrameKind::PromptErase,
            bytes: PROMPT_TRANSCRIPT_BOUNDARY_BYTES.to_vec(),
        }])
    }

    pub fn receive_editor_clear(&mut self) -> Result<Vec<BrokerReceipt>, BrokerEnqueueError> {
        let relay_id = self.routes.session;
        let presentation = self
            .relays
            .get(&relay_id)
            .ok_or(BrokerEnqueueError::UnknownRelay(relay_id))?
            .presentation;
        if !presentation.editor_control {
            return Ok(Vec::new());
        }
        self.enqueue_batch(vec![PendingBatchFrame {
            relay: relay_id,
            lane: BrokerLane::Control,
            author: BrokerAuthor::Session,
            kind: BrokerFrameKind::PromptErase,
            // Trusted editor-control vocabulary. Runtime-authored text never
            // enters this frame.
            bytes: b"\x1b[2J\x1b[H".to_vec(),
        }])
    }

    pub fn receive_interrupt_notice(
        &mut self,
        notice: &str,
    ) -> Result<Vec<BrokerReceipt>, BrokerEnqueueError> {
        debug_assert!(!notice.contains("^C"));
        let relay_id = self.routes.control;
        let presentation = self
            .relays
            .get(&relay_id)
            .ok_or(BrokerEnqueueError::UnknownRelay(relay_id))?
            .presentation;
        let payload = render_session_text(notice, SessionStyle::Notice, presentation.session_ansi);
        let frames = self.prompt_wrapped_frames(
            relay_id,
            BrokerLane::Control,
            BrokerAuthor::Session,
            BrokerFrameKind::InterruptNotice,
            payload,
        )?;
        self.enqueue_batch(frames)
    }

    pub fn receive_display_tree(
        &mut self,
        wire: &[u8],
    ) -> Result<DisplayTicket, BrokerEnqueueError> {
        let relay_id = self.routes.session;
        let presentation = self
            .relays
            .get(&relay_id)
            .ok_or(BrokerEnqueueError::UnknownRelay(relay_id))?
            .presentation;
        let mut rendered = SafeSessionRenderer::render_tree(wire, presentation.session_ansi);
        if rendered.bytes.len() > self.queue_bound_bytes {
            rendered = fallback_display(DISPLAY_FALLBACK_REASON_RENDERED_TOO_LARGE);
        }
        let frames = self.prompt_wrapped_frames(
            relay_id,
            BrokerLane::Data,
            BrokerAuthor::Session,
            BrokerFrameKind::Display,
            rendered.bytes,
        )?;
        let receipts = self.enqueue_batch(frames)?;
        let barrier = self.snapshot_barrier()?;
        Ok(DisplayTicket {
            barrier,
            rendered_disposition: rendered.disposition,
            receipts,
        })
    }

    /// Enqueue a result only after every relay has reached the byte cutoff
    /// captured before that result. This is the cross-destination ordering
    /// gate; merely delaying the display acknowledgement would be too late.
    pub fn receive_display_tree_after(
        &mut self,
        prerequisite: &BrokerBarrier,
        wire: &[u8],
    ) -> Result<DisplayTicket, BrokerEnqueueError> {
        match self.poll_barrier(prerequisite) {
            BarrierPoll::Complete => {
                let cutoff_is_current = prerequisite.cutoffs.iter().all(|cutoff| {
                    self.relays
                        .get(&cutoff.relay)
                        .is_some_and(|relay| relay.accepted_data_bytes == cutoff.accepted_bytes)
                });
                if !cutoff_is_current {
                    return Err(BrokerEnqueueError::BarrierSuperseded);
                }
                self.receive_display_tree(wire)
            }
            BarrierPoll::Pending(_) => Err(BrokerEnqueueError::BarrierPending),
            BarrierPoll::WriteFailed(relays) => Err(BrokerEnqueueError::BarrierWriteFailed(relays)),
            BarrierPoll::Invalid(BarrierInvalidity::ForeignBroker) => {
                Err(BrokerEnqueueError::ForeignBarrier)
            }
            BarrierPoll::Invalid(BarrierInvalidity::StaleGeneration) => {
                Err(BrokerEnqueueError::StaleBarrier)
            }
        }
    }

    fn prompt_wrapped_frames(
        &self,
        relay_id: RelayId,
        lane: BrokerLane,
        author: BrokerAuthor,
        kind: BrokerFrameKind,
        bytes: Vec<u8>,
    ) -> Result<Vec<PendingBatchFrame>, BrokerEnqueueError> {
        let relay = self
            .relays
            .get(&relay_id)
            .ok_or(BrokerEnqueueError::UnknownRelay(relay_id))?;
        let redraw = relay_id == self.routes.session && relay.prompt_visible;
        let mut frames = Vec::with_capacity(if redraw { 3 } else { 1 });
        if redraw {
            frames.push(prompt_erase_frame(relay_id, lane, relay.presentation));
        }
        frames.push(PendingBatchFrame {
            relay: relay_id,
            lane,
            author,
            kind,
            bytes,
        });
        if redraw {
            frames.push(PendingBatchFrame {
                relay: relay_id,
                lane,
                author: BrokerAuthor::Session,
                kind: BrokerFrameKind::PromptRedraw,
                bytes: relay.prompt_line.clone(),
            });
        }
        Ok(frames)
    }

    fn enqueue_batch(
        &mut self,
        frames: Vec<PendingBatchFrame>,
    ) -> Result<Vec<BrokerReceipt>, BrokerEnqueueError> {
        if self.closed {
            return Err(BrokerEnqueueError::Closed);
        }
        let mut additions: BTreeMap<(RelayId, BrokerLane), usize> = BTreeMap::new();
        for frame in &frames {
            let relay = self
                .relays
                .get(&frame.relay)
                .ok_or(BrokerEnqueueError::UnknownRelay(frame.relay))?;
            if let Some(message) = &relay.write_failure {
                return Err(BrokerEnqueueError::WriteFailed {
                    relay: frame.relay,
                    message: message.clone(),
                });
            }
            let addition = additions.entry((frame.relay, frame.lane)).or_default();
            *addition = addition
                .checked_add(frame.bytes.len())
                .ok_or(BrokerEnqueueError::CounterExhausted)?;
        }
        for ((relay_id, lane), attempted) in &additions {
            let relay = self
                .relays
                .get(relay_id)
                .expect("batch relay was validated");
            let queued = relay.queued_bytes(*lane);
            let available = self.queue_bound_bytes.saturating_sub(queued);
            if *attempted > available {
                return Err(BrokerEnqueueError::Backpressure {
                    relay: *relay_id,
                    lane: *lane,
                    attempted: *attempted,
                    available,
                });
            }
            if *lane == BrokerLane::Data {
                let attempted =
                    u64::try_from(*attempted).map_err(|_| BrokerEnqueueError::CounterExhausted)?;
                relay
                    .accepted_data_bytes
                    .checked_add(attempted)
                    .ok_or(BrokerEnqueueError::CounterExhausted)?;
            }
        }
        let frame_count =
            u64::try_from(frames.len()).map_err(|_| BrokerEnqueueError::CounterExhausted)?;
        let reservation = self
            .sequencer
            .reserve(frame_count)
            .map_err(|_| BrokerEnqueueError::CounterExhausted)?;

        let mut receipts = Vec::with_capacity(frames.len());
        for (offset, frame) in frames.into_iter().enumerate() {
            let offset = u64::try_from(offset).map_err(|_| BrokerEnqueueError::CounterExhausted)?;
            let sequence = reservation
                .first_sequence
                .checked_add(offset)
                .ok_or(BrokerEnqueueError::CounterExhausted)?;
            let receipt = BrokerReceipt {
                epoch: reservation.epoch,
                sequence,
                relay: frame.relay,
                lane: frame.lane,
                author: frame.author,
                kind: frame.kind,
                bytes: frame.bytes.len(),
            };
            let relay = self
                .relays
                .get_mut(&frame.relay)
                .expect("batch relay was validated");
            match frame.lane {
                BrokerLane::Data => {
                    relay.queued_data_bytes += frame.bytes.len();
                    relay.accepted_data_bytes += frame.bytes.len() as u64;
                    relay.data.push_back(PendingBrokerFrame {
                        receipt: receipt.clone(),
                        bytes: frame.bytes,
                        offset: 0,
                    });
                }
                BrokerLane::Control => {
                    relay.queued_control_bytes += frame.bytes.len();
                    relay.control.push_back(PendingBrokerFrame {
                        receipt: receipt.clone(),
                        bytes: frame.bytes,
                        offset: 0,
                    });
                }
            }
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    pub fn snapshot_barrier(&mut self) -> Result<BrokerBarrier, BrokerEnqueueError> {
        if self.closed {
            return Err(BrokerEnqueueError::Closed);
        }
        let reservation = self
            .sequencer
            .reserve(1)
            .map_err(|_| BrokerEnqueueError::CounterExhausted)?;
        Ok(BrokerBarrier {
            broker_instance_id: self.instance_id,
            generation: self.generation,
            epoch: reservation.epoch,
            sequence: reservation.first_sequence,
            cutoffs: self
                .relays
                .iter()
                .map(|(relay, state)| RelayCutoff {
                    relay: *relay,
                    accepted_bytes: state.accepted_data_bytes,
                })
                .collect(),
        })
    }

    pub fn poll_barrier(&self, barrier: &BrokerBarrier) -> BarrierPoll {
        if barrier.broker_instance_id != self.instance_id {
            return BarrierPoll::Invalid(BarrierInvalidity::ForeignBroker);
        }
        if barrier.generation != self.generation {
            return BarrierPoll::Invalid(BarrierInvalidity::StaleGeneration);
        }
        let mut pending = Vec::new();
        let mut failed = Vec::new();
        for cutoff in &barrier.cutoffs {
            let Some(relay) = self.relays.get(&cutoff.relay) else {
                failed.push(cutoff.relay);
                continue;
            };
            if relay.written_data_bytes < cutoff.accepted_bytes {
                if relay.write_failure.is_some() || self.closed {
                    failed.push(cutoff.relay);
                } else {
                    pending.push(RelayBarrierProgress {
                        relay: cutoff.relay,
                        written_bytes: relay.written_data_bytes,
                        cutoff_bytes: cutoff.accepted_bytes,
                    });
                }
            }
        }
        if !failed.is_empty() {
            BarrierPoll::WriteFailed(failed)
        } else if pending.is_empty() {
            BarrierPoll::Complete
        } else {
            BarrierPoll::Pending(pending)
        }
    }

    pub fn poll_display(&self, ticket: &DisplayTicket) -> DisplayPoll {
        match self.poll_barrier(&ticket.barrier) {
            BarrierPoll::Complete => DisplayPoll::Complete(ticket.rendered_disposition),
            BarrierPoll::WriteFailed(_) => DisplayPoll::Complete(DisplayDisposition::WriteFailed),
            BarrierPoll::Invalid(_) => DisplayPoll::Complete(DisplayDisposition::WriteFailed),
            BarrierPoll::Pending(_) => DisplayPoll::Pending,
        }
    }

    pub fn pump_all_once(&mut self) -> PumpSummary {
        let relay_ids: Vec<_> = self.relays.keys().copied().collect();
        let mut summary = PumpSummary::default();
        for relay_id in relay_ids {
            match self.pump_relay_once(relay_id) {
                RelayPump::Progress => summary.progressed_relays += 1,
                RelayPump::Stalled | RelayPump::Empty => summary.stalled_relays += 1,
                RelayPump::Failed => summary.failed_relays += 1,
            }
        }
        summary
    }

    pub fn pump_available(&mut self) -> PumpSummary {
        let mut total = PumpSummary::default();
        loop {
            let current = self.pump_all_once();
            total.progressed_relays += current.progressed_relays;
            total.stalled_relays += current.stalled_relays;
            total.failed_relays += current.failed_relays;
            if current.progressed_relays == 0 {
                return total;
            }
        }
    }

    pub fn drain_barrier(&mut self, barrier: &BrokerBarrier) -> BarrierPoll {
        loop {
            let status = self.poll_barrier(barrier);
            if !matches!(status, BarrierPoll::Pending(_)) {
                return status;
            }
            let pump = self.pump_all_once();
            if pump.progressed_relays == 0 {
                return self.poll_barrier(barrier);
            }
        }
    }

    /// Bounded lifecycle drain. The broker is retired on every return path;
    /// queued bytes that cannot be written within the budget are returned as
    /// explicit loss accounting rather than silently discarded.
    pub fn finish_with_budget(
        &mut self,
        budget: Duration,
    ) -> Result<BrokerLossAccounting, BrokerEnqueueError> {
        if self.closed {
            return Err(BrokerEnqueueError::Closed);
        }
        let deadline = Instant::now()
            .checked_add(budget)
            .unwrap_or_else(Instant::now);
        while self
            .relays
            .values()
            .any(|relay| relay.queued_data_bytes != 0 || relay.queued_control_bytes != 0)
            && Instant::now() < deadline
        {
            let summary = self.pump_all_once();
            if summary.failed_relays != 0 || summary.progressed_relays == 0 {
                thread::yield_now();
            }
        }
        let flush_error = self.sink.flush().err();
        let loss = self.force_close()?;
        if let Some(message) = flush_error {
            return Err(BrokerEnqueueError::WriteFailed {
                relay: self.routes.control,
                message,
            });
        }
        Ok(loss)
    }

    fn pump_relay_once(&mut self, relay_id: RelayId) -> RelayPump {
        let Self { sink, relays, .. } = self;
        let Some(relay) = relays.get_mut(&relay_id) else {
            return RelayPump::Failed;
        };
        if relay.write_failure.is_some() {
            return RelayPump::Failed;
        }
        // Reserved capacity lets control traffic enter independently; physical
        // writes on one destination still follow receipt order. A notice routed
        // to stderr can bypass a stalled stdout relay, but cannot time-travel
        // ahead of an earlier frame on the *same* relay.
        let control_sequence = relay.control.front().map(|frame| frame.receipt.sequence);
        let data_sequence = relay.data.front().map(|frame| frame.receipt.sequence);
        let lane = match (control_sequence, data_sequence) {
            (Some(control), Some(data)) if control < data => BrokerLane::Control,
            (Some(_), Some(_)) | (None, Some(_)) => BrokerLane::Data,
            (Some(_), None) => BrokerLane::Control,
            (None, None) => return RelayPump::Empty,
        };
        let queue = match lane {
            BrokerLane::Data => &mut relay.data,
            BrokerLane::Control => &mut relay.control,
        };
        let frame = queue.front_mut().expect("selected queue is non-empty");
        if frame.remaining() == 0 {
            queue.pop_front();
            return RelayPump::Progress;
        }
        let remaining = &frame.bytes[frame.offset..];
        let outcome = sink.try_write(RelayWriteRequest {
            relay: relay_id,
            lane,
            epoch: frame.receipt.epoch,
            sequence: frame.receipt.sequence,
            author: frame.receipt.author,
            kind: frame.receipt.kind,
            bytes: remaining,
        });
        match outcome {
            Ok(RelayWriteOutcome::WouldBlock) => RelayPump::Stalled,
            Ok(RelayWriteOutcome::Written(written))
                if written > 0 && written <= remaining.len() =>
            {
                frame.offset += written;
                match lane {
                    BrokerLane::Data => {
                        relay.queued_data_bytes -= written;
                        relay.written_data_bytes += written as u64;
                    }
                    BrokerLane::Control => relay.queued_control_bytes -= written,
                }
                if frame.remaining() == 0 {
                    queue.pop_front();
                }
                RelayPump::Progress
            }
            Ok(RelayWriteOutcome::Written(_)) => {
                relay.write_failure = Some("sink returned an invalid write length".to_string());
                RelayPump::Failed
            }
            Err(message) => {
                relay.write_failure = Some(message);
                RelayPump::Failed
            }
        }
    }

    pub fn force_close(&mut self) -> Result<BrokerLossAccounting, BrokerEnqueueError> {
        if self.closed {
            return Err(BrokerEnqueueError::Closed);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(BrokerEnqueueError::CounterExhausted)?;
        let reservation = self
            .sequencer
            .reserve(1)
            .map_err(|_| BrokerEnqueueError::CounterExhausted)?;
        self.generation = next_generation;
        self.closed = true;
        let mut losses = Vec::new();
        for (relay_id, relay) in &mut self.relays {
            let mut loss = RelayLoss {
                relay: *relay_id,
                program_bytes: 0,
                session_bytes: 0,
                program_frames: 0,
                session_frames: 0,
                control_frames: relay.control.len(),
            };
            for frame in relay.data.iter().chain(relay.control.iter()) {
                match frame.receipt.author {
                    BrokerAuthor::Program => {
                        loss.program_bytes += frame.remaining();
                        loss.program_frames += 1;
                    }
                    BrokerAuthor::Session => {
                        loss.session_bytes += frame.remaining();
                        loss.session_frames += 1;
                    }
                }
            }
            relay.data.clear();
            relay.control.clear();
            relay.queued_data_bytes = 0;
            relay.queued_control_bytes = 0;
            relay.prompt_visible = false;
            losses.push(loss);
        }
        Ok(BrokerLossAccounting {
            forced_close_epoch: reservation.epoch,
            forced_close_sequence: reservation.first_sequence,
            relays: losses,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelayPump {
    Progress,
    Stalled,
    Empty,
    Failed,
}

fn prompt_erase_frame(
    relay: RelayId,
    lane: BrokerLane,
    presentation: RelayPresentation,
) -> PendingBatchFrame {
    PendingBatchFrame {
        relay,
        lane,
        author: BrokerAuthor::Session,
        kind: BrokerFrameKind::PromptErase,
        bytes: if presentation.editor_control {
            PROMPT_EDITOR_ERASE_BYTES.to_vec()
        } else {
            PROMPT_TRANSCRIPT_BOUNDARY_BYTES.to_vec()
        },
    }
}

fn render_prompt_line(prompt: &str, edit_buffer: &[u8], session_ansi: bool) -> Vec<u8> {
    let mut line = render_session_text(prompt, SessionStyle::Prompt, session_ansi);
    line.extend_from_slice(&escape_session_bytes(edit_buffer));
    line
}

fn render_session_text(text: &str, style: SessionStyle, session_ansi: bool) -> Vec<u8> {
    let escaped = escape_session_text(text);
    if !session_ansi || style == SessionStyle::Plain {
        return escaped.into_bytes();
    }
    let prefix = match style {
        SessionStyle::Plain => "",
        SessionStyle::Prompt => ANSI_SESSION_PROMPT,
        SessionStyle::Notice => ANSI_SESSION_NOTICE,
        SessionStyle::Error => ANSI_SESSION_ERROR,
    };
    format!("{prefix}{escaped}{ANSI_RESET}").into_bytes()
}

pub trait TerminalLifecycle {
    /// Enter raw mode with signal-generating input disabled and retain the
    /// startup state needed by `restore_session`.
    fn enter_session(&mut self, presentation: CapturedPresentation) -> Result<(), String>;

    /// Restore cooked mode, cursor visibility, and editor-control state. This
    /// operation must precede every potentially blocking cleanup action.
    fn restore_session(&mut self) -> Result<(), String>;
}

#[cfg(unix)]
const SIGNAL_CURSOR_SHOW_BYTES: &[u8] = b"\x1b[?25h";

#[cfg(unix)]
unsafe fn write_terminal_restore_bytes(control_fd: libc::c_int) {
    let reset = ANSI_RESET.as_bytes();
    libc::write(control_fd, reset.as_ptr().cast(), reset.len());
    libc::write(
        control_fd,
        SIGNAL_CURSOR_SHOW_BYTES.as_ptr().cast(),
        SIGNAL_CURSOR_SHOW_BYTES.len(),
    );
}

#[cfg(unix)]
const SIGNAL_RESTORE_DISARMED: u8 = 0;
#[cfg(unix)]
const SIGNAL_RESTORE_PREPARING: u8 = 1;
#[cfg(unix)]
const SIGNAL_RESTORE_ARMED: u8 = 2;

/// Process-global copy used only by the async-signal-safe fallback. The normal
/// path remains the supervisor's `restore -> flush -> terminate` sequence.
#[cfg(unix)]
struct SignalRestoreState {
    state: std::sync::atomic::AtomicU8,
    input_fd: std::sync::atomic::AtomicI32,
    control_fd: std::sync::atomic::AtomicI32,
    original: std::cell::UnsafeCell<std::mem::MaybeUninit<libc::termios>>,
}

#[cfg(unix)]
// SAFETY: `original` is written only while state is PREPARING and is read only
// after an acquire load observes ARMED. Session startup admits one owner.
unsafe impl Sync for SignalRestoreState {}

#[cfg(unix)]
impl SignalRestoreState {
    const fn new() -> Self {
        Self {
            state: std::sync::atomic::AtomicU8::new(SIGNAL_RESTORE_DISARMED),
            input_fd: std::sync::atomic::AtomicI32::new(-1),
            control_fd: std::sync::atomic::AtomicI32::new(-1),
            original: std::cell::UnsafeCell::new(std::mem::MaybeUninit::uninit()),
        }
    }

    fn prepare(
        &self,
        input_fd: libc::c_int,
        control_fd: libc::c_int,
        original: libc::termios,
    ) -> Result<(), String> {
        self.state
            .compare_exchange(
                SIGNAL_RESTORE_DISARMED,
                SIGNAL_RESTORE_PREPARING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| "another terminal restoration guard is already armed".to_string())?;
        // SAFETY: PREPARING is held exclusively by this caller and signal-side
        // reads require an acquire observation of ARMED.
        unsafe {
            (*self.original.get()).write(original);
        }
        self.input_fd.store(input_fd, Ordering::Relaxed);
        self.control_fd.store(control_fd, Ordering::Relaxed);
        self.state.store(SIGNAL_RESTORE_ARMED, Ordering::Release);
        Ok(())
    }

    fn disarm_without_restore(&self) {
        self.state.store(SIGNAL_RESTORE_DISARMED, Ordering::Release);
    }

    fn disarm_after_restore(&self) {
        self.state.store(SIGNAL_RESTORE_DISARMED, Ordering::Release);
    }

    /// Uses only async-signal-safe libc calls and atomic loads. The termios
    /// storage remains immutable for the rest of the process because this path
    /// always exits immediately after returning.
    unsafe fn restore_from_signal(&self) {
        if self.state.load(Ordering::Acquire) != SIGNAL_RESTORE_ARMED {
            return;
        }
        let input_fd = self.input_fd.load(Ordering::Relaxed);
        let control_fd = self.control_fd.load(Ordering::Relaxed);
        // SAFETY: observing ARMED with acquire ordering makes the initialized
        // termios copy and descriptor stores visible.
        let original = unsafe { (*self.original.get()).assume_init_ref() };
        // SAFETY: tcsetattr and write are async-signal-safe POSIX operations;
        // all pointers and lengths refer to process-lifetime static storage.
        unsafe {
            libc::tcsetattr(input_fd, libc::TCSANOW, original);
            write_terminal_restore_bytes(control_fd);
        }
    }
}

#[cfg(unix)]
static SIGNAL_RESTORE_STATE: SignalRestoreState = SignalRestoreState::new();

#[cfg(unix)]
const TERMINAL_FATAL_SIGNALS: [libc::c_int; 9] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGABRT,
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGILL,
    libc::SIGFPE,
];

/// Installs the async-signal-safe restoration fallback only for the lifetime
/// of an editor-owned terminal. The previous dispositions are restored after
/// cooked mode is back, so non-session commands retain the embedding
/// process's signal policy.
#[cfg(unix)]
struct UnixFatalSignalGuard {
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

#[cfg(unix)]
impl UnixFatalSignalGuard {
    fn install() -> io::Result<Self> {
        let mut previous = Vec::with_capacity(TERMINAL_FATAL_SIGNALS.len());
        for signal in TERMINAL_FATAL_SIGNALS {
            // SAFETY: sigaction is a plain-old-data POSIX structure. The mask
            // is initialized before the structure is installed.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = terminal_fatal_signal_handler as *const () as usize;
            action.sa_flags = libc::SA_RESTART | libc::SA_RESETHAND;
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
                let error = io::Error::last_os_error();
                restore_signal_actions(&previous);
                return Err(error);
            }
            // SAFETY: both action pointers name initialized sigaction values.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(signal, &action, &mut old) } != 0 {
                let error = io::Error::last_os_error();
                restore_signal_actions(&previous);
                return Err(error);
            }
            previous.push((signal, old));
        }
        Ok(Self { previous })
    }
}

#[cfg(unix)]
impl Drop for UnixFatalSignalGuard {
    fn drop(&mut self) {
        restore_signal_actions(&self.previous);
    }
}

#[cfg(unix)]
const SESSION_SIGNAL_RESIZE: u8 = 1 << 0;
#[cfg(unix)]
const SESSION_SIGNAL_SUSPEND: u8 = 1 << 1;
#[cfg(unix)]
const SESSION_SIGNAL_SHUTDOWN: u8 = 1 << 2;
#[cfg(unix)]
const SESSION_SIGNAL_INTERRUPT: u8 = 1 << 3;
#[cfg(unix)]
static SESSION_SIGNAL_PENDING: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
#[cfg(unix)]
static SESSION_SIGNAL_WRITE_FD: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(-1);

#[cfg(unix)]
unsafe fn wake_session_signal_loop(bits: u8) {
    SESSION_SIGNAL_PENDING.fetch_or(bits, Ordering::AcqRel);
    let descriptor = SESSION_SIGNAL_WRITE_FD.load(Ordering::Acquire);
    if descriptor >= 0 {
        let byte = [bits];
        // SAFETY: the descriptor is a process-owned nonblocking pipe writer;
        // a full pipe is harmless because the pending bit is authoritative.
        unsafe {
            libc::write(descriptor, byte.as_ptr().cast(), byte.len());
        }
    }
}

#[cfg(unix)]
unsafe extern "C" fn terminal_session_signal_handler(signal: libc::c_int) {
    let bits = session_signal_bits(signal);
    // SAFETY: this handler calls only lock-free atomics and nonblocking write.
    unsafe { wake_session_signal_loop(bits) }
}

#[cfg(unix)]
const fn session_signal_bits(signal: libc::c_int) -> u8 {
    if signal == libc::SIGWINCH {
        SESSION_SIGNAL_RESIZE
    } else if signal == libc::SIGINT {
        SESSION_SIGNAL_INTERRUPT
    } else {
        SESSION_SIGNAL_SUSPEND
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct UnixSessionSignalHandle;

#[cfg(unix)]
impl UnixSessionSignalHandle {
    fn request_suspend(self) {
        // SAFETY: ordinary-thread callers may use the same async-signal-safe
        // wake route as the SIGTSTP handler.
        unsafe { wake_session_signal_loop(SESSION_SIGNAL_SUSPEND) }
    }

    fn request_shutdown(self) {
        // SAFETY: see request_suspend.
        unsafe { wake_session_signal_loop(SESSION_SIGNAL_SHUTDOWN) }
    }
}

/// Scoped self-pipe bridge for live SIGWINCH, external SIGTSTP, and the
/// non-editor terminate tier's SIGINT. Signal handlers never touch the worker
/// channel, terminal mutex, broker, or heap.
#[cfg(unix)]
struct UnixSessionSignalGuard {
    receiver: Option<NativeFd>,
    writer: NativeFd,
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

#[cfg(unix)]
impl UnixSessionSignalGuard {
    fn install(capture_suspend: bool, capture_interrupt: bool) -> io::Result<Self> {
        let (receiver, writer) = native_pipe()?;
        let writer_flags = descriptor_flags(writer.raw(), libc::F_GETFL)?;
        set_descriptor_flag(writer.raw(), libc::F_SETFL, writer_flags | libc::O_NONBLOCK)?;
        SESSION_SIGNAL_PENDING.store(0, Ordering::Release);
        SESSION_SIGNAL_WRITE_FD
            .compare_exchange(-1, writer.raw(), Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "another terminal signal bridge is already active",
                )
            })?;

        let signals: &[libc::c_int] = match (capture_suspend, capture_interrupt) {
            (true, true) => &[libc::SIGWINCH, libc::SIGTSTP, libc::SIGINT],
            (true, false) => &[libc::SIGWINCH, libc::SIGTSTP],
            (false, true) => &[libc::SIGWINCH, libc::SIGINT],
            (false, false) => &[libc::SIGWINCH],
        };
        let mut previous = Vec::with_capacity(signals.len());
        for signal in signals {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = terminal_session_signal_handler as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
                let error = io::Error::last_os_error();
                restore_signal_actions(&previous);
                SESSION_SIGNAL_WRITE_FD.store(-1, Ordering::Release);
                return Err(error);
            }
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(*signal, &action, &mut old) } != 0 {
                let error = io::Error::last_os_error();
                restore_signal_actions(&previous);
                SESSION_SIGNAL_WRITE_FD.store(-1, Ordering::Release);
                return Err(error);
            }
            previous.push((*signal, old));
        }
        Ok(Self {
            receiver: Some(receiver),
            writer,
            previous,
        })
    }

    fn protected_descriptors(&self) -> [i32; 2] {
        [
            self.receiver.as_ref().map_or(-1, NativeFd::raw),
            self.writer.raw(),
        ]
    }

    fn take_source(&mut self) -> io::Result<(NativeFd, UnixSessionSignalHandle)> {
        self.receiver
            .take()
            .map(|receiver| (receiver, UnixSessionSignalHandle))
            .ok_or_else(|| io::Error::other("terminal signal source was already taken"))
    }
}

#[cfg(unix)]
const fn captures_non_editor_interrupt(presentation: CapturedPresentation) -> bool {
    !presentation.editor_control
}

#[cfg(unix)]
impl Drop for UnixSessionSignalGuard {
    fn drop(&mut self) {
        restore_signal_actions(&self.previous);
        SESSION_SIGNAL_WRITE_FD.store(-1, Ordering::Release);
        SESSION_SIGNAL_PENDING.store(0, Ordering::Release);
    }
}

#[cfg(unix)]
fn restore_signal_actions(previous: &[(libc::c_int, libc::sigaction)]) {
    for (signal, action) in previous.iter().rev() {
        // SAFETY: each value was returned by a successful sigaction query.
        unsafe {
            libc::sigaction(*signal, action, std::ptr::null_mut());
        }
    }
}

#[cfg(unix)]
unsafe extern "C" fn terminal_fatal_signal_handler(signal: libc::c_int) {
    // SAFETY: the installed handler has no Rust allocation/locking path; the
    // callee performs only atomic loads and async-signal-safe POSIX calls and
    // terminates with _exit.
    unsafe { restore_terminal_and_exit_from_signal(signal) }
}

/// Concrete Unix terminal guard. Raw mode is entered only when the captured
/// topology actually has an editor, and explicitly disables `ISIG` so Ctrl-C
/// remains a byte for the dedicated editor reader.
/// @ref LLP 0025#5-terminal-presentation-and-restoration — raw mode has ISIG
/// off and restoration precedes every blocking cleanup step.
#[cfg(unix)]
pub struct UnixTerminalLifecycle {
    input_fd: libc::c_int,
    control_fd: libc::c_int,
    original: Option<libc::termios>,
    fatal_signals: Option<UnixFatalSignalGuard>,
    active: bool,
}

#[cfg(unix)]
impl UnixTerminalLifecycle {
    pub const fn new(input_fd: libc::c_int, control_fd: libc::c_int) -> Self {
        Self {
            input_fd,
            control_fd,
            original: None,
            fatal_signals: None,
            active: false,
        }
    }

    pub const fn for_standard_descriptors(topology: PresentationTopology) -> Self {
        let control_fd = match topology {
            PresentationTopology::StdoutTty => libc::STDOUT_FILENO,
            PresentationTopology::StderrTty | PresentationTopology::Transcript => {
                libc::STDERR_FILENO
            }
        };
        Self::new(libc::STDIN_FILENO, control_fd)
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    const fn control_fd(&self) -> libc::c_int {
        self.control_fd
    }
}

#[cfg(unix)]
fn reacquire_and_verify_foreground(input_fd: libc::c_int) -> io::Result<()> {
    let process_group = unsafe { libc::getpgrp() };
    if process_group <= 0 {
        return Err(io::Error::last_os_error());
    }
    let foreground = unsafe { libc::tcgetpgrp(input_fd) };
    if foreground < 0 {
        return Err(io::Error::last_os_error());
    }
    if foreground != process_group {
        // A normal job-control shell assigns the terminal before SIGCONT. The
        // explicit reacquire covers supervisors resumed by another controller;
        // SIGTTOU must not stop us midway through the transaction.
        let mut ignore: libc::sigaction = unsafe { std::mem::zeroed() };
        ignore.sa_sigaction = libc::SIG_IGN;
        if unsafe { libc::sigemptyset(&mut ignore.sa_mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(libc::SIGTTOU, &ignore, &mut previous) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let reacquire = unsafe { libc::tcsetpgrp(input_fd, process_group) };
        let error = (reacquire != 0).then(io::Error::last_os_error);
        unsafe {
            libc::sigaction(libc::SIGTTOU, &previous, std::ptr::null_mut());
        }
        if let Some(error) = error {
            return Err(error);
        }
    }
    let verified = unsafe { libc::tcgetpgrp(input_fd) };
    if verified != process_group {
        return Err(if verified < 0 {
            io::Error::last_os_error()
        } else {
            io::Error::other("supervisor did not reacquire foreground terminal ownership")
        });
    }
    Ok(())
}

#[cfg(unix)]
impl TerminalLifecycle for UnixTerminalLifecycle {
    fn enter_session(&mut self, presentation: CapturedPresentation) -> Result<(), String> {
        if !presentation.editor_control {
            return Ok(());
        }
        if self.active {
            return Err("terminal raw mode was already entered".to_string());
        }

        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: the pointer is valid for one termios value and tcgetattr
        // initializes it on success.
        if unsafe { libc::tcgetattr(self.input_fd, original.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        // SAFETY: tcgetattr succeeded above.
        let original = unsafe { original.assume_init() };
        SIGNAL_RESTORE_STATE.prepare(self.input_fd, self.control_fd, original)?;

        let fatal_signals = match UnixFatalSignalGuard::install() {
            Ok(guard) => guard,
            Err(error) => {
                SIGNAL_RESTORE_STATE.disarm_without_restore();
                return Err(format!(
                    "failed to install terminal restoration signal handlers: {error}"
                ));
            }
        };

        let mut raw = original;
        // SAFETY: raw points to a fully initialized local termios value.
        unsafe {
            libc::cfmakeraw(&mut raw);
        }
        raw.c_lflag &= !(libc::ISIG as libc::tcflag_t);
        // TCSANOW preserves pending input; flushing would silently discard
        // typeahead during the transition to the session-owned reader.
        // SAFETY: self.input_fd was successfully queried and raw is valid.
        if unsafe { libc::tcsetattr(self.input_fd, libc::TCSANOW, &raw) } != 0 {
            SIGNAL_RESTORE_STATE.disarm_without_restore();
            return Err(io::Error::last_os_error().to_string());
        }
        self.original = Some(original);
        self.fatal_signals = Some(fatal_signals);
        self.active = true;
        Ok(())
    }

    fn restore_session(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| "terminal restoration state is missing".to_string())?;
        // Keep the signal copy armed until cooked mode is known to be restored,
        // closing the signal-during-restore race.
        // SAFETY: original was captured from this descriptor and remains valid.
        if unsafe { libc::tcsetattr(self.input_fd, libc::TCSANOW, original) } != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        // Cursor visibility and SGR reset are idempotent restoration bytes.
        // SAFETY: control_fd is captured native state and the static buffer is
        // valid for the duration of the call.
        unsafe {
            write_terminal_restore_bytes(self.control_fd);
        }
        SIGNAL_RESTORE_STATE.disarm_after_restore();
        self.active = false;
        self.original = None;
        self.fatal_signals.take();
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for UnixTerminalLifecycle {
    fn drop(&mut self) {
        let _ = self.restore_session();
    }
}

/// Last-resort handler path for a process that cannot re-enter the ordinary
/// supervisor loop. Callers may install this function from their fatal signal
/// handler; it deliberately does not flush the broker.
///
/// # Safety
///
/// This must be called only from a Unix signal handler or an equivalent fatal
/// path that will not return to Rust. The process exits through `_exit`.
#[cfg(unix)]
pub unsafe extern "C" fn restore_terminal_and_exit_from_signal(signal: libc::c_int) -> ! {
    // SAFETY: this function is itself the documented handler-only entry point.
    unsafe {
        SIGNAL_RESTORE_STATE.restore_from_signal();
    }
    let status = if signal == libc::SIGINT {
        EXIT_STATUS_INTERRUPT
    } else {
        128_i32
            .saturating_add(signal)
            .clamp(1, POSIX_EXIT_STATUS_MASK)
    };
    // SAFETY: _exit is async-signal-safe and never returns.
    unsafe { libc::_exit(status) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TargetId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ScheduleId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CompletionRequestId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CancellationRequestId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationStatus {
    Pending,
    Accepted,
    Unavailable,
    Failed,
    Defeated,
}

impl CancellationStatus {
    fn is_terminal(self) -> bool {
        self != Self::Pending
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancellationRequest {
    pub request_id: CancellationRequestId,
    pub target_id: TargetId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancellationRecord {
    pub request: CancellationRequest,
    pub status: CancellationStatus,
}

/// Must address the supplied target exactly; it may not retarget a successor.
/// Implementations enqueue the request without waiting for the target to stop.
pub trait ExactCancellation {
    fn request_exact(&mut self, request: CancellationRequest) -> CancellationStatus;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminationMode {
    Begin,
    Expedite,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminationKind {
    Orderly,
    Cooperative,
    Interrupt,
    Fault,
    BrokenPipe,
    Signal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerTermination {
    pub mode: TerminationMode,
    pub kind: TerminationKind,
    pub status: i32,
}

/// A supervisor-owned, nonblocking OS termination primitive.
pub trait WorkerTerminator {
    fn terminate_worker(&mut self, request: WorkerTermination) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditorPhase {
    Idle,
    Editing,
    Continuation,
    Evaluating,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingSubmission {
    None,
    Undispatched,
    Dispatched,
    Discarded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkKind {
    Evaluation,
    Callback,
    Completion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutingUnit {
    pub id: TargetId,
    pub kind: WorkKind,
    pub completion: Option<ExecutingCompletion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutingCompletion {
    pub request_id: CompletionRequestId,
    pub input_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspendedUnit {
    pub id: TargetId,
    pub kind: WorkKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueuedCompletion {
    pub request_id: CompletionRequestId,
    pub input_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionDisposition {
    Apply,
    Abandoned,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LiveUnits {
    pub executing: Option<ExecutingUnit>,
    pub suspended: BTreeMap<TargetId, SuspendedUnit>,
    pub due: BTreeSet<ScheduleId>,
    pub completion_queued: Option<QueuedCompletion>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromiseClass {
    None,
    Orderly,
    Interrupt130,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminationCause {
    pub kind: TerminationKind,
    pub status: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PromptCycle(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StampedInputByte {
    pub byte: u8,
    pub observed_prompt: Option<PromptCycle>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionState {
    pub phase: EditorPhase,
    pub buffer: Vec<u8>,
    pub input_generation: u64,
    pub prompt_cycle: PromptCycle,
    pub prompt_live: bool,
    pub typed_ahead: Vec<StampedInputByte>,
    pub pending_submission: PendingSubmission,
    pub live_units: LiveUnits,
    pub cancellations: BTreeMap<CancellationRequestId, CancellationRecord>,
    pub escape_credit: u8,
    pub promise: PromiseClass,
    pub cause: Option<TerminationCause>,
    pub ended: bool,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            phase: EditorPhase::Idle,
            buffer: Vec::new(),
            input_generation: 0,
            prompt_cycle: PromptCycle(0),
            prompt_live: false,
            typed_ahead: Vec::new(),
            pending_submission: PendingSubmission::None,
            live_units: LiveUnits::default(),
            cancellations: BTreeMap::new(),
            escape_credit: 0,
            promise: PromiseClass::None,
            cause: None,
            ended: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditorInputEvent {
    Byte {
        byte: u8,
        observed_prompt: Option<PromptCycle>,
    },
    Interrupt,
    Eof,
    ReaderError(String),
}

fn is_generated_interrupt_byte(byte: u8) -> bool {
    byte == PROMPT_INTERRUPT_BYTE
        && matches!(
            crate::repl_surface::keybinding_for_bytes(&[byte]).map(|binding| binding.action),
            Some(crate::repl_surface::KeybindingAction::InterruptMachine)
        )
}

fn generated_counts_as_editor_input(byte: u8) -> bool {
    crate::repl_surface::keybinding_for_bytes(&[byte])
        .map(|binding| binding.counts_as_editor_input)
        .unwrap_or(byte >= 0x20 && byte != 0x7f)
}

/// Pluggable event source for an editor integration. Implementations must keep
/// producing input events while completion work is pending elsewhere.
pub trait EditorPort {
    fn try_next_event(&mut self) -> Result<Option<EditorInputEvent>, String>;
}

pub struct AsyncEditorPort {
    events: mpsc::Receiver<EditorInputEvent>,
    reader_thread: thread::JoinHandle<()>,
}

impl AsyncEditorPort {
    pub fn recv_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<EditorInputEvent, mpsc::RecvTimeoutError> {
        self.events.recv_timeout(timeout)
    }

    /// Join only after the input descriptor has reached EOF or been closed by
    /// the terminal adapter; joining a live raw reader would itself block.
    pub fn join_reader(self) -> thread::Result<()> {
        self.reader_thread.join()
    }
}

impl EditorPort for AsyncEditorPort {
    fn try_next_event(&mut self) -> Result<Option<EditorInputEvent>, String> {
        match self.events.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                Err("dedicated editor reader disconnected".to_string())
            }
        }
    }
}

/// A single atomic prompt-liveness snapshot shared with the input reader.
#[derive(Clone, Default)]
pub struct PromptWitness {
    encoded: Arc<AtomicU64>,
    snapshot: Arc<Mutex<PromptSnapshot>>,
}

#[derive(Default)]
struct PromptSnapshot {
    cycle: u64,
    live: bool,
    buffer: Vec<u8>,
}

impl PromptWitness {
    pub fn publish(&self, cycle: PromptCycle, live: bool) {
        {
            let mut snapshot = self
                .snapshot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            snapshot.cycle = cycle.0;
            snapshot.live = live;
        }
        let encoded = (cycle.0 & PROMPT_CYCLE_MASK) | if live { PROMPT_LIVE_BIT } else { 0 };
        self.encoded.store(encoded, Ordering::Release);
    }

    fn publish_prompt(
        &self,
        cycle: PromptCycle,
        buffer: &[u8],
        broker: &ReplBrokerHandle,
    ) -> Result<(), String> {
        let mut snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        snapshot.cycle = cycle.0;
        snapshot.live = true;
        snapshot.buffer.clear();
        snapshot.buffer.extend_from_slice(buffer);
        let encoded = (cycle.0 & PROMPT_CYCLE_MASK) | PROMPT_LIVE_BIT;
        self.encoded.store(encoded, Ordering::Release);
        // Keep publication and broker enqueue ordered under one small lock so
        // a concurrent resize redraw cannot publish an older edit buffer after
        // this prompt.
        broker.prompt(PROMPT_DEFAULT_TEXT, buffer)
    }

    fn redraw(&self, broker: &ReplBrokerHandle) -> Result<(), String> {
        let snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !snapshot.live {
            return Ok(());
        }
        broker.prompt(PROMPT_DEFAULT_TEXT, &snapshot.buffer)
    }

    pub fn observe(&self) -> Option<PromptCycle> {
        let encoded = self.encoded.load(Ordering::Acquire);
        if encoded & PROMPT_LIVE_BIT == 0 {
            None
        } else {
            Some(PromptCycle(encoded & PROMPT_CYCLE_MASK))
        }
    }
}

/// Spawn the raw byte reader independently of completion and worker traffic.
/// The annex-owned interrupt byte is always an event and never enters the edit buffer.
pub fn spawn_editor_reader<R>(mut reader: R, witness: PromptWitness) -> io::Result<AsyncEditorPort>
where
    R: Read + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let reader_thread = thread::Builder::new()
        .name("ibex-terminal-input".to_string())
        .spawn(move || {
            let mut byte = [0_u8; 1];
            loop {
                match reader.read(&mut byte) {
                    Ok(0) => {
                        let _ = tx.send(EditorInputEvent::Eof);
                        break;
                    }
                    Ok(_)
                        if matches!(
                            crate::repl_surface::keybinding_for_bytes(&byte)
                                .map(|binding| binding.action),
                            Some(crate::repl_surface::KeybindingAction::InterruptMachine)
                        ) =>
                    {
                        if tx.send(EditorInputEvent::Interrupt).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {
                        if tx
                            .send(EditorInputEvent::Byte {
                                byte: byte[0],
                                observed_prompt: witness.observe(),
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let _ = tx.send(EditorInputEvent::ReaderError(error.to_string()));
                        break;
                    }
                }
            }
        })?;
    Ok(AsyncEditorPort {
        events: rx,
        reader_thread,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditorAdapterGap {
    SynchronousCompletionBlocksInterruptInput,
}

pub fn legacy_rustyline_adapter_status() -> Result<(), EditorAdapterGap> {
    Err(EditorAdapterGap::SynchronousCompletionBlocksInterruptInput)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionAdapterGap {
    StructuredStdinProgramIngressUnavailable,
    SupervisorOwnedEditorUnavailable,
    StructuredTranscriptLoopUnavailable,
    StructuredOneShotEvaluationUnavailable,
    StructuredFileEvaluationUnavailable,
    ReadinessRouteMismatch,
    InvalidExecutionRoute,
}

impl fmt::Display for ExecutionAdapterGap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StructuredStdinProgramIngressUnavailable => formatter.write_str(
                "stdin program execution is waiting for structured authenticated ingress",
            ),
            Self::SupervisorOwnedEditorUnavailable => formatter.write_str(
                "interactive execution is waiting for the supervisor-owned editor adapter",
            ),
            Self::StructuredTranscriptLoopUnavailable => formatter
                .write_str("transcript execution is waiting for the structured transcript loop"),
            Self::StructuredOneShotEvaluationUnavailable => formatter
                .write_str("one-shot execution is waiting for the structured evaluation adapter"),
            Self::StructuredFileEvaluationUnavailable => formatter
                .write_str("file execution is waiting for the structured evaluation adapter"),
            Self::ReadinessRouteMismatch => formatter
                .write_str("constructed execution adapter does not match the selected route"),
            Self::InvalidExecutionRoute => {
                formatter.write_str("selected execution route is not a valid armed entry tuple")
            }
        }
    }
}

impl std::error::Error for ExecutionAdapterGap {}

/// Opaque evidence minted by an actually constructed execution adapter. There
/// is deliberately no route-enum constructor: a future adapter must live in
/// this module (or expose a module-owned constructor) and issue the token only
/// after its ingress, broker, cancellation, and lifecycle ports exist.
#[derive(Debug)]
struct ExecutionAdapterReady<'adapter> {
    route: SelectedExecutionRoute,
    _lease: std::marker::PhantomData<&'adapter mut ExecutionAdapterLease>,
}

#[derive(Debug)]
struct ExecutionAdapterLease;

fn mint_execution_adapter_ready<'adapter>(
    _lease: &'adapter mut ExecutionAdapterLease,
    route: SelectedExecutionRoute,
) -> ExecutionAdapterReady<'adapter> {
    ExecutionAdapterReady {
        route,
        _lease: std::marker::PhantomData,
    }
}

/// Public fail-closed gate for routes that do not own a complete adapter. The
/// readiness-bearing path is module-private so no caller can separate a
/// successful check from the adapter lifetime that justified it.
pub fn execution_adapter_status(plan: SessionIoPlan) -> Result<(), ExecutionAdapterGap> {
    execution_adapter_status_with_readiness(plan, None)
}

/// Fail-closed integration seam for the production REPL adapter. The secure
/// driver and authenticated evaluator can be built before a descriptor/editor
/// adapter exists, but that is not readiness evidence. The implementation that
/// replaces this gate must retain both values for the adapter lifetime and mint
/// `ExecutionAdapterReady` only after broker, cancellation, lifecycle, and
/// terminal restoration ports are live.
pub async fn run_repl_execution_adapter(
    plan: SessionIoPlan,
    session: crate::repl::ReplEvaluationSession,
    driver: crate::repl::session::ReplDriver,
    history: crate::history::HistorySession,
) -> anyhow::Result<i32> {
    #[cfg(unix)]
    {
        run_repl_unix(plan, session, driver, history, None).await
    }
    #[cfg(not(unix))]
    {
        let _closed_repl_state = (session, driver, history);
        execution_adapter_status(plan).map_err(Into::into)
    }
}

/// Production supervisor-owned REPL adapter. The child relay descriptors are
/// consumed by the same broker that renders session output; they are never
/// copied directly to the supervisor's standard descriptors.
#[cfg(unix)]
pub(crate) async fn run_worker_repl_execution_adapter(
    plan: SessionIoPlan,
    session: crate::repl::ReplEvaluationSession,
    driver: crate::repl::session::ReplDriver,
    history: crate::history::HistorySession,
    relays: crate::session_worker::WorkerRelays,
) -> anyhow::Result<i32> {
    run_repl_unix(plan, session, driver, history, Some(relays)).await
}

/// Execute program-mode stdin in the authenticated worker while this process
/// remains the sole output/session owner.
#[cfg(unix)]
pub(crate) async fn run_worker_program_execution_adapter(
    plan: SessionIoPlan,
    mut program: crate::session_worker_runtime::RemoteProgramSession,
    relays: crate::session_worker::WorkerRelays,
    source: Vec<u8>,
) -> anyhow::Result<i32> {
    use anyhow::Context as _;

    if !matches!(
        (plan.route.entry_kind, plan.route.mode),
        (ArmedEntryKind::Stdin, ArmedExecutionMode::Program)
    ) {
        return Err(ExecutionAdapterGap::ReadinessRouteMismatch.into());
    }
    let mut active = ActiveReplCapture::start(plan, Some(relays))
        .context("failed to construct the worker program output adapter")?;
    let non_editor_interrupt =
        NonEditorWorkerInterruptControl::Program(program.cancellation_port());
    let mut terminal_signals = start_worker_terminal_signal_coordinator(
        &mut active,
        Some(program.terminal_control()),
        None,
        Some(non_editor_interrupt),
    )
    .context("failed to start the worker terminal signal coordinator")?;
    let readiness = mint_execution_adapter_ready(&mut active.lease, plan.route);
    execution_adapter_status_with_readiness(plan, Some(&readiness)).map_err(anyhow::Error::from)?;
    let broker = active.broker.clone();
    let outcome = program.execute(source);
    drop(readiness);

    // Even non-editor program mode follows the universal restore-before-block
    // ordering, then drains the authenticated result cutoff before publishing
    // any supervisor-authored diagnostic.
    if let Some(signals) = terminal_signals.as_ref() {
        signals.request_shutdown();
    }
    let restore = active
        .restore_terminal()
        .context("failed to restore program terminal state");
    let signal_finish = match terminal_signals.take() {
        Some(signals) => signals
            .finish()
            .context("failed to finish the worker terminal signal coordinator"),
        None => Ok(()),
    };
    active.disarm_session_signals();
    let mut unreportable_output_loss = false;
    let settlement = match outcome {
        Ok(outcome) => {
            let (stdout_cutoff, stderr_cutoff) = outcome.cutoffs();
            if let Err(error) = broker.worker_barrier(stdout_cutoff, stderr_cutoff) {
                unreportable_output_loss |= error.is_output_loss();
                let _ =
                    broker.diagnostic(&format!("worker program output barrier failed: {error}"));
            }
            settle_remote_program_outcome(&broker, outcome)
                .unwrap_or(InlineSettlement::Fixed(EXIT_STATUS_BROKEN_PIPE))
        }
        Err(error) => {
            let _ = broker.diagnostic(&format!(
                "engine fault: authenticated worker program failed: {error:#}"
            ));
            InlineSettlement::Fixed(EXIT_STATUS_ENGINE_FAULT)
        }
    };
    // Cleanup happens after the cause is fixed. A later restoration, signal,
    // or disposal error cannot replace a fault/interrupt status; only bounded
    // output loss may modify a successful orderly/cooperative disposition.
    let _restore_error = restore.err();
    let _signal_error = signal_finish.err();
    let _dispose_error = program.dispose_preserving_lifecycle().err();
    match active.finish_report() {
        Ok(loss) => unreportable_output_loss |= loss.has_loss(),
        Err(_) => unreportable_output_loss = true,
    }
    Ok(settlement.final_status(unreportable_output_loss))
}

#[cfg(unix)]
fn settle_remote_program_outcome(
    broker: &ReplBrokerHandle,
    outcome: crate::session_worker_runtime::RemoteProgramOutcome,
) -> anyhow::Result<InlineSettlement> {
    use crate::session_worker_runtime::RemoteProgramOutcome;

    match outcome {
        RemoteProgramOutcome::Completed { status, .. }
        | RemoteProgramOutcome::Lifecycle { status, .. } => {
            Ok(InlineSettlement::Successful(status))
        }
        RemoteProgramOutcome::Cancelled { .. } => {
            Ok(InlineSettlement::Fixed(EXIT_STATUS_INTERRUPT))
        }
        RemoteProgramOutcome::Throw { detail, .. } => {
            match serde_json::from_slice::<crate::engine::AuthenticatedThrow>(&detail) {
                Ok(thrown) => render_inline_throw(broker, thrown),
                Err(_) => {
                    broker
                        .diagnostic(&String::from_utf8_lossy(&detail))
                        .map_err(anyhow::Error::msg)?;
                }
            }
            Ok(InlineSettlement::Fixed(1))
        }
        RemoteProgramOutcome::AsyncFailure { failure, .. } => {
            broker
                .diagnostic(&format!("asynchronous task failed: {failure}"))
                .map_err(anyhow::Error::msg)?;
            Ok(InlineSettlement::Fixed(1))
        }
        RemoteProgramOutcome::Refused { detail, .. } => {
            broker
                .diagnostic(&format!(
                    "evaluation refused: {}",
                    String::from_utf8_lossy(&detail)
                ))
                .map_err(anyhow::Error::msg)?;
            Ok(InlineSettlement::Fixed(1))
        }
        RemoteProgramOutcome::EngineFault { detail, .. } => {
            broker
                .diagnostic(&format!(
                    "engine fault: {}",
                    String::from_utf8_lossy(&detail)
                ))
                .map_err(anyhow::Error::msg)?;
            Ok(InlineSettlement::Fixed(EXIT_STATUS_ENGINE_FAULT))
        }
    }
}

/// Whether an authenticated one-shot result is part of the command's public
/// output (`-p`) or is intentionally discarded (`-e` and program stdin).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InlineResultPresentation {
    Suppress,
    Print,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InlineSettlement {
    /// An orderly or cooperative cause. A final, unreportable broker loss may
    /// still change this disposition to 141.
    Successful(i32),
    /// A fault, interrupt, or broker failure whose status is already fixed.
    Fixed(i32),
}

#[cfg(unix)]
impl InlineSettlement {
    const fn status(self) -> i32 {
        match self {
            Self::Successful(status) | Self::Fixed(status) => status,
        }
    }

    const fn permits_cleanup_loss_upgrade(self) -> bool {
        matches!(self, Self::Successful(_))
    }

    const fn final_status(self, unreportable_output_loss: bool) -> i32 {
        if unreportable_output_loss && self.permits_cleanup_loss_upgrade() {
            EXIT_STATUS_BROKEN_PIPE
        } else {
            self.status()
        }
    }
}

/// Execute one authenticated eval/program-stdin request while this adapter
/// exclusively owns fd 1/2. Runtime/bootstrap construction may precede this
/// call, but no project source may execute before it. The returned integer is
/// already the product status: refusal/throw 1, engine fault 70, cancellation
/// 130, broker failure 141, lifecycle request `n`, or success 0.
///
/// @ref LLP 0024#1-the-in-memory-source-api — program and one-shot routes use
/// the closed request seam and drain to full quiescence.
/// @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker — fd 1/2,
/// safe result rendering, display disposition, and bounded loss accounting are
/// one adapter lifetime.
pub(crate) async fn run_authenticated_inline_execution_adapter(
    runtime: &crate::runtime::Runtime,
    source: Vec<u8>,
    result_presentation: InlineResultPresentation,
) -> anyhow::Result<i32> {
    use anyhow::Context as _;

    let plan = runtime
        .session_io_plan()
        .ok_or_else(|| anyhow::anyhow!("inline runtime has no session-I/O plan"))?;
    let valid_route = matches!(
        (plan.route.entry_kind, plan.route.mode),
        (ArmedEntryKind::Eval, ArmedExecutionMode::OneShot)
            | (ArmedEntryKind::Stdin, ArmedExecutionMode::Program)
    );
    if !valid_route
        || (plan.route.entry_kind == ArmedEntryKind::Stdin
            && result_presentation != InlineResultPresentation::Suppress)
    {
        anyhow::bail!("authenticated inline adapter received an invalid execution route");
    }

    #[cfg(unix)]
    {
        let mut ingress = runtime.authenticated_inline_ingress()?;
        if ingress.entry_kind() != plan.route.entry_kind || ingress.mode() != plan.route.mode {
            anyhow::bail!("authenticated inline ingress changed route after arming");
        }
        let engine = runtime.engine();
        let lifecycle = runtime.session_lifecycle();
        let mut active = ActiveReplCapture::start(plan, None)
            .map_err(anyhow::Error::new)
            .context("failed to construct the inline output adapter")?;
        let readiness = mint_execution_adapter_ready(&mut active.lease, plan.route);
        execution_adapter_status_with_readiness(plan, Some(&readiness))
            .map_err(anyhow::Error::from)?;
        let broker = active.broker.clone();

        let evaluation = ingress.evaluate(engine.as_ref(), source).await;
        let settlement = settle_authenticated_inline_evaluation(
            engine.as_ref(),
            &lifecycle,
            &broker,
            evaluation,
            result_presentation,
        )
        .await;
        drop(readiness);

        let finish = active.finish_report();
        match finish {
            Ok(loss) if loss.has_loss() && settlement.permits_cleanup_loss_upgrade() => {
                Ok(EXIT_STATUS_BROKEN_PIPE)
            }
            Ok(_) => Ok(settlement.status()),
            Err(
                FileProgramAdapterError::Broker(_) | FileProgramAdapterError::RelayThreadPanicked,
            ) if settlement.permits_cleanup_loss_upgrade() => Ok(EXIT_STATUS_BROKEN_PIPE),
            Err(
                FileProgramAdapterError::Broker(_) | FileProgramAdapterError::RelayThreadPanicked,
            ) => Ok(settlement.status()),
            Err(error) => Err(anyhow::Error::new(error)),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (runtime, source, result_presentation);
        Err(ExecutionAdapterGap::StructuredOneShotEvaluationUnavailable.into())
    }
}

#[cfg(unix)]
async fn settle_authenticated_inline_evaluation(
    engine: &dyn crate::engine::Engine,
    lifecycle: &ibex_runtime::session_lifecycle::SessionLifecyclePort,
    broker: &ReplBrokerHandle,
    evaluation: std::result::Result<
        crate::engine::AuthenticatedEvaluation,
        crate::runtime::AuthenticatedEvaluationFailure,
    >,
    result_presentation: InlineResultPresentation,
) -> InlineSettlement {
    use crate::engine::AuthenticatedEvaluation;

    let (display, receipt) = match evaluation {
        Err(error) => {
            let status = if error.is_engine_fault() {
                EXIT_STATUS_ENGINE_FAULT
            } else {
                1
            };
            let label = if error.is_engine_fault() {
                "engine fault"
            } else {
                "evaluation refused"
            };
            let _ = broker.diagnostic(&format!("{label}: {error:#}"));
            return InlineSettlement::Fixed(status);
        }
        Ok(AuthenticatedEvaluation::Lifecycle(status)) => {
            let _ = lifecycle.take_pending_request();
            return finish_successful_inline(lifecycle, broker, Some(status));
        }
        Ok(AuthenticatedEvaluation::Throw(thrown)) => {
            render_inline_throw(broker, thrown);
            return InlineSettlement::Fixed(1);
        }
        Ok(AuthenticatedEvaluation::Cancelled) => {
            return InlineSettlement::Fixed(EXIT_STATUS_INTERRUPT);
        }
        Ok(AuthenticatedEvaluation::Empty) => (None, None),
        Ok(AuthenticatedEvaluation::Value { display, receipt }) => (Some(display), receipt),
    };

    // A result is not published until the program-mode keep-alive set reaches
    // quiescence. A cooperative exit raised by a timer is carried by the shared
    // lifecycle port and supersedes the pending display value.
    let drain = engine.drive_authenticated_program_to_quiescence().await;
    if let Some(request) = lifecycle.take_pending_request() {
        if let Some(receipt) = receipt {
            let _ = engine.release_undisplayed_value(receipt).await;
        }
        return finish_successful_inline(lifecycle, broker, Some(request.status));
    }
    let async_failures = match engine.take_authenticated_async_failures().await {
        Ok(failures) => failures,
        Err(error) => vec![
            crate::engine::AuthenticatedAsyncFailure::capture_unavailable(format!(
                "asynchronous failure drain failed: {error:#}"
            )),
        ],
    };
    if !async_failures.is_empty() {
        if let Some(receipt) = receipt {
            let _ = engine.release_undisplayed_value(receipt).await;
        }
        for failure in async_failures {
            let _ = broker.diagnostic(&format!("unhandled asynchronous failure: {failure}"));
        }
        return InlineSettlement::Fixed(1);
    }
    if let Err(error) = drain {
        if let Some(receipt) = receipt {
            let _ = engine.release_undisplayed_value(receipt).await;
        }
        let status = if error.is_engine_fault() {
            EXIT_STATUS_ENGINE_FAULT
        } else {
            1
        };
        let _ = broker.diagnostic(&format!("{error:#}"));
        return InlineSettlement::Fixed(status);
    }

    let Some(display) = display else {
        return finish_successful_inline(lifecycle, broker, None);
    };
    if result_presentation == InlineResultPresentation::Suppress {
        let release_status = match receipt {
            Some(receipt) => match engine.release_undisplayed_value(receipt).await {
                Ok(()) => None,
                Err(error) => {
                    let _ = broker.diagnostic(&format!(
                        "engine fault: failed to release undisplayed value: {error:#}"
                    ));
                    Some(EXIT_STATUS_ENGINE_FAULT)
                }
            },
            None => None,
        };
        return match release_status {
            Some(status) => InlineSettlement::Fixed(status),
            None => finish_successful_inline(lifecycle, broker, None),
        };
    }

    crate::host::abi::ex_host_console_flush(BROKER_FLUSH_BUDGET_MILLIS as u32);
    let (disposition, write_failed) = match encode_authenticated_display(&display) {
        Ok(wire) => match broker.display(wire, None) {
            Ok(disposition) => (disposition, disposition == DisplayDisposition::WriteFailed),
            Err(_) => (DisplayDisposition::WriteFailed, true),
        },
        Err(error) => {
            let _ = broker.diagnostic(&format!("display fallback: {error}"));
            (DisplayDisposition::Fallback, false)
        }
    };
    if let Some(receipt) = receipt {
        let engine_disposition = match disposition {
            DisplayDisposition::Displayed => crate::engine::DisplayDisposition::Displayed,
            DisplayDisposition::Fallback => crate::engine::DisplayDisposition::Fallback,
            DisplayDisposition::WriteFailed => crate::engine::DisplayDisposition::WriteFailed,
        };
        if let Err(error) = engine
            .acknowledge_display(receipt, engine_disposition)
            .await
        {
            let _ = broker.diagnostic(&format!(
                "engine fault: display acknowledgement failed: {error:#}"
            ));
            return InlineSettlement::Fixed(EXIT_STATUS_ENGINE_FAULT);
        }
    }
    if write_failed || broker.boundary().is_err() {
        InlineSettlement::Fixed(EXIT_STATUS_BROKEN_PIPE)
    } else {
        resolve_successful_inline_status(lifecycle, None)
    }
}

#[cfg(unix)]
fn finish_successful_inline(
    lifecycle: &ibex_runtime::session_lifecycle::SessionLifecyclePort,
    broker: &ReplBrokerHandle,
    cooperative_status: Option<i32>,
) -> InlineSettlement {
    if broker.boundary().is_err() {
        return InlineSettlement::Fixed(EXIT_STATUS_BROKEN_PIPE);
    }
    let settlement = resolve_successful_inline_status(lifecycle, cooperative_status);
    if settlement == InlineSettlement::Fixed(EXIT_STATUS_ENGINE_FAULT) {
        let _ = broker.diagnostic("engine fault: Root lifecycle exitCode read was denied");
    }
    settlement
}

#[cfg(unix)]
fn resolve_successful_inline_status(
    lifecycle: &ibex_runtime::session_lifecycle::SessionLifecyclePort,
    cooperative_status: Option<i32>,
) -> InlineSettlement {
    use ibex_runtime::session_lifecycle::{LifecycleGetDisposition, LifecyclePrincipal};

    // A request published while the final result/release boundary completed
    // supersedes orderly exitCode. An already-observed cooperative outcome is
    // next; only otherwise-orderly completion reads the live Root mirror.
    if let Some(request) = lifecycle.take_pending_request() {
        return InlineSettlement::Successful(request.status);
    }
    if let Some(status) = cooperative_status {
        return InlineSettlement::Successful(status);
    }
    match lifecycle.get_exit_code(LifecyclePrincipal::Root) {
        LifecycleGetDisposition::Value(status) => InlineSettlement::Successful(status),
        LifecycleGetDisposition::Denied => InlineSettlement::Fixed(EXIT_STATUS_ENGINE_FAULT),
    }
}

#[cfg(unix)]
fn render_inline_throw(broker: &ReplBrokerHandle, thrown: crate::engine::AuthenticatedThrow) {
    let _ = broker.diagnostic(&thrown.value.text);
    if let Some(message) = thrown.metadata.message() {
        let _ = broker.diagnostic(message);
    }
    if let Some(stack) = thrown.metadata.stack() {
        for line in stack.lines() {
            let _ = broker.diagnostic(line);
        }
    }
    for position in thrown.metadata.positions() {
        let _ = broker.diagnostic(&format!(
            "at {}:{}:{}",
            position.source_label, position.line, position.column
        ));
    }
}

fn execution_adapter_status_with_readiness(
    plan: SessionIoPlan,
    readiness: Option<&ExecutionAdapterReady<'_>>,
) -> Result<(), ExecutionAdapterGap> {
    if let Some(readiness) = readiness {
        if readiness.route.entry_kind == plan.route.entry_kind
            && readiness.route.mode == plan.route.mode
        {
            return Ok(());
        }
        return Err(ExecutionAdapterGap::ReadinessRouteMismatch);
    }

    match (plan.route.entry_kind, plan.route.mode) {
        (ArmedEntryKind::File, ArmedExecutionMode::Program) => {
            Err(ExecutionAdapterGap::StructuredFileEvaluationUnavailable)
        }
        (ArmedEntryKind::Eval, ArmedExecutionMode::OneShot) => {
            Err(ExecutionAdapterGap::StructuredOneShotEvaluationUnavailable)
        }
        (ArmedEntryKind::Stdin, ArmedExecutionMode::Program) => {
            Err(ExecutionAdapterGap::StructuredStdinProgramIngressUnavailable)
        }
        (ArmedEntryKind::Repl, ArmedExecutionMode::Interactive) => {
            Err(ExecutionAdapterGap::SupervisorOwnedEditorUnavailable)
        }
        (ArmedEntryKind::Repl, ArmedExecutionMode::Transcript) => {
            Err(ExecutionAdapterGap::StructuredTranscriptLoopUnavailable)
        }
        // SelectedExecutionRoute is a public transport type, so fail closed if
        // a caller ever fabricates a tuple outside the arming schema.
        _ => Err(ExecutionAdapterGap::InvalidExecutionRoute),
    }
}

#[derive(Debug)]
pub enum FileProgramAdapterError {
    Gate(ExecutionAdapterGap),
    Native(io::Error),
    Broker(String),
    RelayThreadPanicked,
}

impl fmt::Display for FileProgramAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gate(error) => write!(formatter, "file execution adapter: {error}"),
            Self::Native(error) => write!(formatter, "file execution adapter I/O: {error}"),
            Self::Broker(error) => write!(formatter, "file execution output broker: {error}"),
            Self::RelayThreadPanicked => {
                formatter.write_str("file execution output relay thread panicked")
            }
        }
    }
}

impl std::error::Error for FileProgramAdapterError {}

impl From<io::Error> for FileProgramAdapterError {
    fn from(error: io::Error) -> Self {
        Self::Native(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileProgramExecutionReport {
    receipts: Vec<BrokerReceipt>,
    loss: BrokerLossAccounting,
    unaccepted_stdout_bytes: usize,
    unaccepted_stderr_bytes: usize,
}

impl FileProgramExecutionReport {
    pub fn receipts(&self) -> &[BrokerReceipt] {
        &self.receipts
    }

    pub fn loss(&self) -> &BrokerLossAccounting {
        &self.loss
    }

    pub const fn unaccepted_stdout_bytes(&self) -> usize {
        self.unaccepted_stdout_bytes
    }

    pub const fn unaccepted_stderr_bytes(&self) -> usize {
        self.unaccepted_stderr_bytes
    }

    pub fn has_loss(&self) -> bool {
        self.loss.has_loss()
            || self.unaccepted_stdout_bytes != 0
            || self.unaccepted_stderr_bytes != 0
    }
}

/// The only production adapter currently complete enough to mint readiness.
/// Construction validates the File/Program tuple; `run` activates native
/// descriptor capture before it polls the supplied future and retains that
/// capture until restoration and bounded broker finish have completed.
// @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker — file-mode
// fd 1/fd 2 bytes enter the same bounded, receipt-sequenced broker.
// @ref LLP 0025#5-terminal-presentation-and-restoration — native descriptors
// are restored before the bounded broker finish and on unwinding Drop paths.
pub struct FileProgramExecutionAdapter {
    plan: SessionIoPlan,
}

impl FileProgramExecutionAdapter {
    pub fn new(plan: SessionIoPlan) -> Result<Self, FileProgramAdapterError> {
        if !matches!(
            (plan.route.entry_kind, plan.route.mode),
            (ArmedEntryKind::File, ArmedExecutionMode::Program)
        ) {
            return Err(FileProgramAdapterError::Gate(
                ExecutionAdapterGap::InvalidExecutionRoute,
            ));
        }
        Ok(Self { plan })
    }

    pub async fn run<F>(
        self,
        execution: F,
    ) -> Result<(F::Output, FileProgramExecutionReport), FileProgramAdapterError>
    where
        F: Future,
    {
        #[cfg(unix)]
        {
            let mut active = ActiveFileProgramCapture::start(self.plan)?;
            let readiness = mint_execution_adapter_ready(&mut active.lease, active.plan.route);
            execution_adapter_status_with_readiness(active.plan, Some(&readiness))
                .map_err(FileProgramAdapterError::Gate)?;
            let output = execution.await;
            drop(readiness);
            let report = active.finish()?;
            Ok((output, report))
        }
        #[cfg(not(unix))]
        {
            let _ = execution;
            Err(FileProgramAdapterError::Gate(
                ExecutionAdapterGap::StructuredFileEvaluationUnavailable,
            ))
        }
    }
}

#[cfg(unix)]
struct NativeFd(i32);

#[cfg(unix)]
impl NativeFd {
    fn duplicate(descriptor: i32) -> io::Result<Self> {
        Self::duplicate_at_least(descriptor, 3)
    }

    fn duplicate_high(descriptor: i32) -> io::Result<Self> {
        Self::duplicate_at_least(descriptor, 64)
    }

    fn duplicate_at_least(descriptor: i32, minimum: i32) -> io::Result<Self> {
        loop {
            // SAFETY: fcntl receives a live descriptor and returns a fresh
            // descriptor owned by this value on success.
            let duplicated = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, minimum) };
            if duplicated >= 0 {
                return Ok(Self(duplicated));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    const fn raw(&self) -> i32 {
        self.0
    }
}

#[cfg(unix)]
impl Drop for NativeFd {
    fn drop(&mut self) {
        // SAFETY: this value uniquely owns the descriptor.
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(unix)]
fn native_pipe() -> io::Result<(NativeFd, NativeFd)> {
    let mut descriptors = [-1; 2];
    // SAFETY: pipe initializes both array elements on success.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let read = NativeFd(descriptors[0]);
    let write = NativeFd(descriptors[1]);
    set_descriptor_flag(read.raw(), libc::F_SETFD, libc::FD_CLOEXEC)?;
    set_descriptor_flag(write.raw(), libc::F_SETFD, libc::FD_CLOEXEC)?;
    let read_flags = descriptor_flags(read.raw(), libc::F_GETFL)?;
    set_descriptor_flag(read.raw(), libc::F_SETFL, read_flags | libc::O_NONBLOCK)?;
    Ok((read, write))
}

#[cfg(unix)]
fn descriptor_flags(descriptor: i32, operation: i32) -> io::Result<i32> {
    loop {
        // SAFETY: fcntl performs a read-only descriptor query.
        let result = unsafe { libc::fcntl(descriptor, operation) };
        if result >= 0 {
            return Ok(result);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn set_descriptor_flag(descriptor: i32, operation: i32, value: i32) -> io::Result<()> {
    loop {
        // SAFETY: fcntl updates flags on a live descriptor.
        let result = unsafe { libc::fcntl(descriptor, operation, value) };
        if result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn duplicate_over(source: i32, target: i32) -> io::Result<()> {
    loop {
        // SAFETY: dup2 atomically replaces target with a duplicate of source.
        let result = unsafe { libc::dup2(source, target) };
        if result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn flush_process_stdio() -> io::Result<()> {
    io::stdout().lock().flush()?;
    io::stderr().lock().flush()?;
    // SAFETY: a null stream asks libc to flush every open output stream.
    if unsafe { libc::fflush(std::ptr::null_mut()) } == libc::EOF {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
enum NativeRelayCommand {
    Write(Vec<u8>),
}

#[cfg(unix)]
fn write_native_relay(descriptor: i32, bytes: &[u8]) -> Result<usize, String> {
    let mut offset = 0;
    while offset < bytes.len() {
        loop {
            // SAFETY: the worker owns descriptor and bytes remains live until
            // the complete blocking write has either succeeded or failed.
            let written = unsafe {
                libc::write(
                    descriptor,
                    bytes[offset..].as_ptr().cast(),
                    bytes.len() - offset,
                )
            };
            if written > 0 {
                offset += written as usize;
                break;
            }
            if written == 0 {
                return Err("native relay returned a zero-byte write".to_string());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.to_string());
            }
        }
    }
    Ok(offset)
}

#[cfg(unix)]
struct PendingNativeRelayWrite {
    epoch: u64,
    sequence: u64,
    lane: BrokerLane,
    length: usize,
}

#[cfg(unix)]
struct NativeRelayWorker {
    commands: Option<mpsc::SyncSender<NativeRelayCommand>>,
    acknowledgements: mpsc::Receiver<Result<usize, String>>,
    pending: Option<PendingNativeRelayWrite>,
    worker: Option<thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl NativeRelayWorker {
    fn spawn(name: &'static str, descriptor: NativeFd) -> io::Result<Self> {
        let (command_tx, command_rx) = mpsc::sync_channel(1);
        let (ack_tx, ack_rx) = mpsc::channel();
        let worker = thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                while let Ok(NativeRelayCommand::Write(bytes)) = command_rx.recv() {
                    let result = write_native_relay(descriptor.raw(), &bytes);
                    if ack_tx.send(result).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            commands: Some(command_tx),
            acknowledgements: ack_rx,
            pending: None,
            worker: Some(worker),
        })
    }

    fn try_write(&mut self, request: &RelayWriteRequest<'_>) -> Result<RelayWriteOutcome, String> {
        if let Some(pending) = &self.pending {
            if pending.epoch != request.epoch
                || pending.sequence != request.sequence
                || pending.lane != request.lane
                || pending.length != request.bytes.len()
            {
                return Err(
                    "native relay changed a write while acknowledgement was pending".into(),
                );
            }
            return match self.acknowledgements.try_recv() {
                Ok(Ok(written)) => {
                    self.pending = None;
                    Ok(RelayWriteOutcome::Written(written))
                }
                Ok(Err(error)) => {
                    self.pending = None;
                    Err(error)
                }
                Err(mpsc::TryRecvError::Empty) => Ok(RelayWriteOutcome::WouldBlock),
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    Err("native relay worker disconnected".to_string())
                }
            };
        }

        self.commands
            .as_ref()
            .ok_or_else(|| "native relay is closed".to_string())?
            .try_send(NativeRelayCommand::Write(request.bytes.to_vec()))
            .map_err(|error| format!("native relay command queue: {error}"))?;
        self.pending = Some(PendingNativeRelayWrite {
            epoch: request.epoch,
            sequence: request.sequence,
            lane: request.lane,
            length: request.bytes.len(),
        });
        Ok(RelayWriteOutcome::WouldBlock)
    }

    fn finish(&mut self) -> Result<(), String> {
        let mut acknowledgement_error = None;
        if self.pending.is_some() {
            match self.acknowledgements.try_recv() {
                Ok(Ok(_)) => self.pending = None,
                Ok(Err(error)) => {
                    self.pending = None;
                    acknowledgement_error = Some(error);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.pending = None;
                    acknowledgement_error = Some("native relay worker disconnected".to_string());
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.commands.take();
        if self.pending.is_none() {
            if let Some(worker) = self.worker.take() {
                worker
                    .join()
                    .map_err(|_| "native relay worker panicked".to_string())?;
            }
        } else {
            // A blocked destination must not defeat the broker's finite flush
            // budget. Dropping the JoinHandle detaches this one CLI-only
            // relay; the process exits after the adapter reports its frame as
            // forced-close loss.
            self.worker.take();
        }
        if let Some(error) = acknowledgement_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
impl Drop for NativeRelayWorker {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(unix)]
enum NativeRelaySink {
    Shared {
        relay: RelayId,
        worker: NativeRelayWorker,
    },
    Split {
        stdout: NativeRelayWorker,
        stderr: NativeRelayWorker,
    },
}

#[cfg(unix)]
impl NativeRelaySink {
    fn new(
        topology: OutputDestinationTopology,
        stdout: NativeFd,
        stderr: NativeFd,
    ) -> io::Result<Self> {
        match topology {
            OutputDestinationTopology::Shared { destination } => {
                let (name, descriptor) = match destination {
                    NativeOutputDestination::Stdout => ("ibex-file-shared-relay", stdout),
                    NativeOutputDestination::Stderr => ("ibex-file-shared-relay", stderr),
                };
                Ok(Self::Shared {
                    relay: destination.relay_id(),
                    worker: NativeRelayWorker::spawn(name, descriptor)?,
                })
            }
            OutputDestinationTopology::Split => Ok(Self::Split {
                stdout: NativeRelayWorker::spawn("ibex-file-stdout-relay", stdout)?,
                stderr: NativeRelayWorker::spawn("ibex-file-stderr-relay", stderr)?,
            }),
        }
    }
}

#[cfg(unix)]
impl NonBlockingRelaySink for NativeRelaySink {
    fn try_write(&mut self, request: RelayWriteRequest<'_>) -> Result<RelayWriteOutcome, String> {
        match self {
            Self::Shared { relay, worker } if request.relay == *relay => worker.try_write(&request),
            Self::Shared { .. } => Err(format!("unknown shared native relay {}", request.relay.0)),
            Self::Split { stdout, .. } if request.relay == NATIVE_STDOUT_RELAY => {
                stdout.try_write(&request)
            }
            Self::Split { stderr, .. } if request.relay == NATIVE_STDERR_RELAY => {
                stderr.try_write(&request)
            }
            Self::Split { .. } => Err(format!("unknown native relay {}", request.relay.0)),
        }
    }

    fn flush(&mut self) -> Result<(), String> {
        match self {
            Self::Shared { worker, .. } => worker.finish(),
            Self::Split { stdout, stderr } => {
                let stdout = stdout.finish();
                let stderr = stderr.finish();
                stdout.and(stderr)
            }
        }
    }
}

#[cfg(unix)]
struct CapturedInput {
    descriptor: NativeFd,
    stream: ProgramStream,
    relay_acceptance: Option<crate::session_worker::SupervisorRelayAcceptance>,
    eof: bool,
    pending: Vec<u8>,
    accepted_bytes: u64,
}

#[cfg(unix)]
impl CapturedInput {
    fn new(descriptor: NativeFd, stream: ProgramStream) -> Self {
        Self {
            descriptor,
            stream,
            relay_acceptance: None,
            eof: false,
            pending: Vec::new(),
            accepted_bytes: 0,
        }
    }

    fn with_relay_acceptance(
        descriptor: NativeFd,
        stream: ProgramStream,
        relay_acceptance: crate::session_worker::SupervisorRelayAcceptance,
    ) -> Self {
        let mut input = Self::new(descriptor, stream);
        input.relay_acceptance = Some(relay_acceptance);
        input
    }

    const fn accepted_bytes(&self) -> u64 {
        self.accepted_bytes
    }

    fn note_accepted(&mut self, amount: usize) -> Result<(), String> {
        let amount = u64::try_from(amount)
            .map_err(|_| "captured program-output byte count does not fit u64".to_string())?;
        self.accepted_bytes = self
            .accepted_bytes
            .checked_add(amount)
            .ok_or_else(|| "captured program-output byte count exhausted u64".to_string())?;
        if let Some(acceptance) = self.relay_acceptance.as_ref() {
            match self.stream {
                ProgramStream::Stdout => acceptance.note_stdout(amount),
                ProgramStream::Stderr => acceptance.note_stderr(amount),
            }
            .map_err(str::to_string)?;
        }
        Ok(())
    }

    fn ingest<W: NonBlockingRelaySink>(
        &mut self,
        broker: &mut InProcessOutputBroker<W>,
        receipts: &mut Vec<BrokerReceipt>,
    ) -> Result<bool, String> {
        if self.eof {
            return Ok(false);
        }
        if !self.pending.is_empty() {
            match broker.receive_program(self.stream, &self.pending) {
                Ok(accepted) => {
                    receipts.extend(accepted);
                    let amount = self.pending.len();
                    self.pending.clear();
                    self.note_accepted(amount)?;
                    return Ok(true);
                }
                Err(BrokerEnqueueError::Backpressure { .. }) => return Ok(false),
                Err(error) => return Err(error.to_string()),
            }
        }

        let mut bytes = vec![0_u8; 16 * 1024];
        loop {
            // SAFETY: bytes is writable for its full advertised length.
            let amount = unsafe {
                libc::read(
                    self.descriptor.raw(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                )
            };
            if amount > 0 {
                bytes.truncate(amount as usize);
                match broker.receive_program(self.stream, &bytes) {
                    Ok(accepted) => {
                        receipts.extend(accepted);
                        self.note_accepted(bytes.len())?;
                    }
                    Err(BrokerEnqueueError::Backpressure { .. }) => self.pending = bytes,
                    Err(error) => return Err(error.to_string()),
                }
                return Ok(true);
            }
            if amount == 0 {
                self.eof = true;
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Ok(false),
                _ => return Err(error.to_string()),
            }
        }
    }
}

#[cfg(unix)]
enum RelayInputDescriptors {
    Shared { output: NativeFd },
    Split { stdout: NativeFd, stderr: NativeFd },
}

#[cfg(unix)]
impl RelayInputDescriptors {
    fn raw_descriptors(&self) -> Vec<i32> {
        match self {
            Self::Shared { output } => vec![output.raw()],
            Self::Split { stdout, stderr } => vec![stdout.raw(), stderr.raw()],
        }
    }
}

#[cfg(unix)]
enum CapturedInputs {
    Shared {
        output: CapturedInput,
    },
    Split {
        stdout: CapturedInput,
        stderr: CapturedInput,
    },
}

#[cfg(unix)]
impl CapturedInputs {
    fn new(descriptors: RelayInputDescriptors) -> Self {
        match descriptors {
            RelayInputDescriptors::Shared { output } => Self::Shared {
                output: CapturedInput::new(output, ProgramStream::Stdout),
            },
            RelayInputDescriptors::Split { stdout, stderr } => Self::Split {
                stdout: CapturedInput::new(stdout, ProgramStream::Stdout),
                stderr: CapturedInput::new(stderr, ProgramStream::Stderr),
            },
        }
    }

    fn with_relay_acceptance(
        descriptors: RelayInputDescriptors,
        acceptance: crate::session_worker::SupervisorRelayAcceptance,
    ) -> Self {
        match descriptors {
            RelayInputDescriptors::Shared { output } => Self::Shared {
                output: CapturedInput::with_relay_acceptance(
                    output,
                    ProgramStream::Stdout,
                    acceptance,
                ),
            },
            RelayInputDescriptors::Split { stdout, stderr } => Self::Split {
                stdout: CapturedInput::with_relay_acceptance(
                    stdout,
                    ProgramStream::Stdout,
                    acceptance.clone(),
                ),
                stderr: CapturedInput::with_relay_acceptance(
                    stderr,
                    ProgramStream::Stderr,
                    acceptance,
                ),
            },
        }
    }

    fn ingest<W: NonBlockingRelaySink>(
        &mut self,
        broker: &mut InProcessOutputBroker<W>,
        receipts: &mut Vec<BrokerReceipt>,
    ) -> Result<bool, String> {
        match self {
            Self::Shared { output } => output.ingest(broker, receipts),
            Self::Split { stdout, stderr } => {
                let mut progressed = stdout.ingest(broker, receipts)?;
                progressed |= stderr.ingest(broker, receipts)?;
                Ok(progressed)
            }
        }
    }

    fn finished(&self) -> bool {
        match self {
            Self::Shared { output } => output.eof && output.pending.is_empty(),
            Self::Split { stdout, stderr } => {
                stdout.eof && stderr.eof && stdout.pending.is_empty() && stderr.pending.is_empty()
            }
        }
    }

    fn pending_bytes(&self) -> (usize, usize) {
        match self {
            Self::Shared { output } => (output.pending.len(), 0),
            Self::Split { stdout, stderr } => (stdout.pending.len(), stderr.pending.len()),
        }
    }

    fn accepted_bytes(&self) -> (u64, u64) {
        match self {
            Self::Shared { output } => (output.accepted_bytes(), 0),
            Self::Split { stdout, stderr } => (stdout.accepted_bytes(), stderr.accepted_bytes()),
        }
    }
}

#[cfg(unix)]
fn file_program_relay_loop(
    plan: SessionIoPlan,
    inputs: RelayInputDescriptors,
    sink: NativeRelaySink,
    shutdown: mpsc::Receiver<()>,
) -> Result<FileProgramExecutionReport, String> {
    let mut broker =
        InProcessOutputBroker::new(sink, plan.broker_routes(), plan.broker_presentations())
            .map_err(|error| error.to_string())?;
    let mut inputs = CapturedInputs::new(inputs);
    let mut receipts = Vec::new();
    let mut shutdown_deadline = None;

    loop {
        if shutdown_deadline.is_none() && shutdown.try_recv().is_ok() {
            shutdown_deadline = Some(
                Instant::now()
                    .checked_add(Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS))
                    .unwrap_or_else(Instant::now),
            );
        }
        let mut progressed = broker.pump_available().progressed_relays != 0;
        progressed |= inputs.ingest(&mut broker, &mut receipts)?;

        if shutdown_deadline.is_some() && inputs.finished() {
            break;
        }
        if shutdown_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }
        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let finish_budget = shutdown_deadline
        .map(|deadline| deadline.saturating_duration_since(Instant::now()))
        .unwrap_or_else(|| Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS));
    let loss = broker
        .finish_with_budget(finish_budget)
        .map_err(|error| error.to_string())?;
    let (unaccepted_stdout_bytes, unaccepted_stderr_bytes) = inputs.pending_bytes();
    Ok(FileProgramExecutionReport {
        receipts,
        loss,
        unaccepted_stdout_bytes,
        unaccepted_stderr_bytes,
    })
}

#[cfg(unix)]
struct ActiveFileProgramCapture {
    plan: SessionIoPlan,
    lease: ExecutionAdapterLease,
    _descriptor_policy: SessionIo,
    _close_guard: crate::host::abi::TerminalSessionOutputCloseGuard,
    restore_stdout: NativeFd,
    restore_stderr: NativeFd,
    stdout_descriptor_flags: i32,
    stderr_descriptor_flags: i32,
    shutdown: Option<mpsc::Sender<()>>,
    relay: Option<thread::JoinHandle<Result<FileProgramExecutionReport, String>>>,
    restored: bool,
    finished: bool,
}

#[cfg(unix)]
impl ActiveFileProgramCapture {
    fn start(plan: SessionIoPlan) -> Result<Self, FileProgramAdapterError> {
        let close_guard = crate::host::abi::arm_terminal_session_output_close_guard()?;
        flush_process_stdio()?;

        let stdout_descriptor_flags = descriptor_flags(libc::STDOUT_FILENO, libc::F_GETFD)?;
        let stderr_descriptor_flags = descriptor_flags(libc::STDERR_FILENO, libc::F_GETFD)?;
        let restore_stdout = NativeFd::duplicate(libc::STDOUT_FILENO)?;
        let restore_stderr = NativeFd::duplicate(libc::STDERR_FILENO)?;
        let stdout_relay = NativeFd::duplicate(libc::STDOUT_FILENO)?;
        let stderr_relay = NativeFd::duplicate(libc::STDERR_FILENO)?;
        let (inputs, stdout_write, stderr_write) = match plan.output_topology() {
            OutputDestinationTopology::Shared { .. } => {
                let (output, write) = native_pipe()?;
                (RelayInputDescriptors::Shared { output }, write, None)
            }
            OutputDestinationTopology::Split => {
                let (stdout, stdout_write) = native_pipe()?;
                let (stderr, stderr_write) = native_pipe()?;
                (
                    RelayInputDescriptors::Split { stdout, stderr },
                    stdout_write,
                    Some(stderr_write),
                )
            }
        };

        let mut descriptor_policy = SessionIo::new(plan);
        let mut protected_descriptors = vec![
            restore_stdout.raw(),
            restore_stderr.raw(),
            stdout_relay.raw(),
            stderr_relay.raw(),
            stdout_write.raw(),
        ];
        protected_descriptors.extend(inputs.raw_descriptors());
        if let Some(stderr_write) = stderr_write.as_ref() {
            protected_descriptors.push(stderr_write.raw());
        }
        for descriptor in protected_descriptors {
            descriptor_policy
                .protect_descriptor(descriptor)
                .map_err(|message| {
                    FileProgramAdapterError::Native(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        message,
                    ))
                })?;
        }

        let sink = NativeRelaySink::new(plan.output_topology(), stdout_relay, stderr_relay)?;

        if let Err(error) = duplicate_over(stdout_write.raw(), libc::STDOUT_FILENO) {
            return Err(error.into());
        }
        let stderr_write_descriptor = stderr_write
            .as_ref()
            .map_or(stdout_write.raw(), NativeFd::raw);
        if let Err(error) = duplicate_over(stderr_write_descriptor, libc::STDERR_FILENO) {
            let _ = duplicate_over(restore_stdout.raw(), libc::STDOUT_FILENO);
            return Err(error.into());
        }
        drop(stdout_write);
        drop(stderr_write);

        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let relay = match thread::Builder::new()
            .name("ibex-file-output-broker".to_string())
            .spawn(move || file_program_relay_loop(plan, inputs, sink, shutdown_rx))
        {
            Ok(relay) => relay,
            Err(error) => {
                let _ = duplicate_over(restore_stdout.raw(), libc::STDOUT_FILENO);
                let _ = duplicate_over(restore_stderr.raw(), libc::STDERR_FILENO);
                return Err(error.into());
            }
        };

        Ok(Self {
            plan,
            lease: ExecutionAdapterLease,
            _descriptor_policy: descriptor_policy,
            _close_guard: close_guard,
            restore_stdout,
            restore_stderr,
            stdout_descriptor_flags,
            stderr_descriptor_flags,
            shutdown: Some(shutdown_tx),
            relay: Some(relay),
            restored: false,
            finished: false,
        })
    }

    fn restore_descriptors(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        crate::host::abi::ex_host_console_flush(BROKER_FLUSH_BUDGET_MILLIS as u32);
        let flush_result = flush_process_stdio();
        let stdout_result = duplicate_over(self.restore_stdout.raw(), libc::STDOUT_FILENO)
            .and_then(|()| {
                set_descriptor_flag(
                    libc::STDOUT_FILENO,
                    libc::F_SETFD,
                    self.stdout_descriptor_flags,
                )
            });
        let stderr_result = duplicate_over(self.restore_stderr.raw(), libc::STDERR_FILENO)
            .and_then(|()| {
                set_descriptor_flag(
                    libc::STDERR_FILENO,
                    libc::F_SETFD,
                    self.stderr_descriptor_flags,
                )
            });
        self.restored = stdout_result.is_ok() && stderr_result.is_ok();
        flush_result.and(stdout_result).and(stderr_result)
    }

    fn finish(&mut self) -> Result<FileProgramExecutionReport, FileProgramAdapterError> {
        let restore_error = self.restore_descriptors().err();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let relay_result = self
            .relay
            .take()
            .ok_or_else(|| FileProgramAdapterError::Broker("relay already joined".into()))?
            .join()
            .map_err(|_| FileProgramAdapterError::RelayThreadPanicked)?
            .map_err(FileProgramAdapterError::Broker);
        if let Some(error) = restore_error {
            return Err(error.into());
        }
        self.finished = true;
        relay_result
    }
}

#[cfg(unix)]
impl Drop for ActiveFileProgramCapture {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.restore_descriptors();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(relay) = self.relay.take() {
            let _ = relay.join();
        }
        self.finished = true;
    }
}

#[cfg(unix)]
const WORKER_OUTPUT_IN_FLIGHT_LIMIT: usize = 64 * 1024;

#[cfg(unix)]
static WORKER_OUTPUT_RELAY_ACTIVE: AtomicBool = AtomicBool::new(false);

/// One atomic worker write-time relay cutoff vector. Split topology uses both
/// components; shared topology stores its sole counter in `stdout` and keeps
/// `stderr` zero so the existing authenticated record shape cannot double-count
/// one physical stream.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerOutputCutoffs {
    stdout: u64,
    stderr: u64,
}

#[cfg(unix)]
impl WorkerOutputCutoffs {
    pub const fn stdout(self) -> u64 {
        self.stdout
    }

    pub const fn stderr(self) -> u64 {
        self.stderr
    }
}

/// Closed failure classification for a counted worker output relay.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerOutputRelayFailureKind {
    BrokenPipe,
    ReadFailed,
    WriteFailed,
    CounterExhausted,
    ForcedClose,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerOutputRelayFailure {
    stream: ProgramStream,
    kind: WorkerOutputRelayFailureKind,
    message: String,
}

#[cfg(unix)]
impl WorkerOutputRelayFailure {
    pub const fn stream(&self) -> ProgramStream {
        self.stream
    }

    pub const fn kind(&self) -> WorkerOutputRelayFailureKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[cfg(unix)]
struct WorkerRelayAccounting {
    read_descriptor: i32,
    forwarded: u64,
    in_flight: u64,
    closed: bool,
}

#[cfg(unix)]
impl WorkerRelayAccounting {
    const fn new(read_descriptor: i32) -> Self {
        Self {
            read_descriptor,
            forwarded: 0,
            in_flight: 0,
            closed: false,
        }
    }
}

#[cfg(unix)]
struct WorkerOutputRelayState {
    stdout: WorkerRelayAccounting,
    stderr: Option<WorkerRelayAccounting>,
    failures: Vec<WorkerOutputRelayFailure>,
}

#[cfg(unix)]
impl WorkerOutputRelayState {
    fn accounting(&self, stream: ProgramStream) -> &WorkerRelayAccounting {
        match stream {
            ProgramStream::Stdout => &self.stdout,
            ProgramStream::Stderr => self
                .stderr
                .as_ref()
                .expect("split stderr accounting is installed"),
        }
    }

    fn accounting_mut(&mut self, stream: ProgramStream) -> &mut WorkerRelayAccounting {
        match stream {
            ProgramStream::Stdout => &mut self.stdout,
            ProgramStream::Stderr => self
                .stderr
                .as_mut()
                .expect("split stderr accounting is installed"),
        }
    }

    fn record_failure(
        &mut self,
        stream: ProgramStream,
        kind: WorkerOutputRelayFailureKind,
        message: impl Into<String>,
    ) {
        if self
            .failures
            .iter()
            .any(|failure| failure.stream == stream && failure.kind == kind)
        {
            return;
        }
        self.failures.push(WorkerOutputRelayFailure {
            stream,
            kind,
            message: message.into(),
        });
    }
}

/// Cloneable read-only port captured by lifecycle and display callbacks.
/// Both component cutoffs are sampled while holding one accounting lock.
#[cfg(unix)]
#[derive(Clone)]
pub struct WorkerOutputCutoffPort {
    state: Arc<Mutex<WorkerOutputRelayState>>,
}

#[cfg(unix)]
impl WorkerOutputCutoffPort {
    pub fn cutoffs(&self) -> io::Result<WorkerOutputCutoffs> {
        let state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("worker output relay accounting lock is poisoned"))?;
        Ok(WorkerOutputCutoffs {
            stdout: worker_relay_cutoff(&state.stdout)?,
            stderr: state
                .stderr
                .as_ref()
                .map(worker_relay_cutoff)
                .transpose()?
                .unwrap_or(0),
        })
    }

    pub fn failures(&self) -> io::Result<Vec<WorkerOutputRelayFailure>> {
        self.state
            .lock()
            .map(|state| state.failures.clone())
            .map_err(|_| io::Error::other("worker output relay accounting lock is poisoned"))
    }
}

#[cfg(unix)]
fn pipe_queued_bytes(descriptor: i32) -> io::Result<u64> {
    let mut queued: libc::c_int = 0;
    // SAFETY: FIONREAD writes one c_int to the supplied live pointer.
    if unsafe { libc::ioctl(descriptor, libc::FIONREAD, &mut queued) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(queued).map_err(|_| io::Error::other("pipe reported a negative byte count"))
}

#[cfg(unix)]
fn worker_relay_cutoff(accounting: &WorkerRelayAccounting) -> io::Result<u64> {
    let queued = if accounting.closed {
        0
    } else {
        pipe_queued_bytes(accounting.read_descriptor)?
    };
    accounting
        .forwarded
        .checked_add(accounting.in_flight)
        .and_then(|value| value.checked_add(queued))
        .ok_or_else(|| io::Error::other("worker output relay cutoff exhausted u64"))
}

#[cfg(unix)]
struct WorkerOutputRelayEndpoint {
    stream: ProgramStream,
    source: Option<NativeFd>,
    destination: NativeFd,
    pending: Vec<u8>,
    offset: usize,
    eof: bool,
    failed: bool,
}

#[cfg(unix)]
impl WorkerOutputRelayEndpoint {
    fn new(stream: ProgramStream, source: NativeFd, destination: NativeFd) -> Self {
        Self {
            stream,
            source: Some(source),
            destination,
            pending: Vec::new(),
            offset: 0,
            eof: false,
            failed: false,
        }
    }

    fn remaining(&self) -> usize {
        self.pending.len().saturating_sub(self.offset)
    }

    fn is_finished(&self) -> bool {
        self.failed || (self.eof && self.remaining() == 0)
    }

    fn pump(&mut self, state: &Arc<Mutex<WorkerOutputRelayState>>) -> bool {
        if self.failed {
            return false;
        }
        let mut progressed = self.forward_once(state);
        if self.failed || self.eof || self.remaining() >= WORKER_OUTPUT_IN_FLIGHT_LIMIT {
            return progressed;
        }
        progressed |= self.read_once(state);
        progressed
    }

    fn read_once(&mut self, state: &Arc<Mutex<WorkerOutputRelayState>>) -> bool {
        let Some(source_descriptor) = self.source.as_ref().map(NativeFd::raw) else {
            return false;
        };
        let mut bytes = [0_u8; 16 * 1024];
        let mut state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Holding the accounting lock across read serializes the transition
        // from FIONREAD-visible kernel bytes to the in-flight byte count.
        let amount =
            unsafe { libc::read(source_descriptor, bytes.as_mut_ptr().cast(), bytes.len()) };
        if amount > 0 {
            let amount = amount as usize;
            let accounting = state.accounting_mut(self.stream);
            let Some(in_flight) = accounting.in_flight.checked_add(amount as u64) else {
                state.record_failure(
                    self.stream,
                    WorkerOutputRelayFailureKind::CounterExhausted,
                    "worker output in-flight counter exhausted u64",
                );
                self.retire_source_locked(&mut state, false);
                self.failed = true;
                return false;
            };
            self.pending.extend_from_slice(&bytes[..amount]);
            accounting.in_flight = in_flight;
            return true;
        }
        if amount == 0 {
            self.eof = true;
            state.accounting_mut(self.stream).closed = true;
            return true;
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => false,
            _ => {
                state.record_failure(
                    self.stream,
                    WorkerOutputRelayFailureKind::ReadFailed,
                    error.to_string(),
                );
                self.retire_source_locked(&mut state, false);
                self.failed = true;
                false
            }
        }
    }

    fn forward_once(&mut self, state: &Arc<Mutex<WorkerOutputRelayState>>) -> bool {
        if self.remaining() == 0 {
            if self.offset != 0 {
                self.pending.clear();
                self.offset = 0;
            }
            return false;
        }
        let bytes = &self.pending[self.offset..];
        // SAFETY: destination is live and bytes remains valid for this call.
        let amount =
            unsafe { libc::write(self.destination.raw(), bytes.as_ptr().cast(), bytes.len()) };
        if amount > 0 {
            let amount = amount as usize;
            let mut state = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let accounting = state.accounting_mut(self.stream);
            let Some(forwarded) = accounting.forwarded.checked_add(amount as u64) else {
                state.record_failure(
                    self.stream,
                    WorkerOutputRelayFailureKind::CounterExhausted,
                    "worker output forwarded counter exhausted u64",
                );
                self.retire_source_locked(&mut state, false);
                self.failed = true;
                return false;
            };
            let Some(in_flight) = accounting.in_flight.checked_sub(amount as u64) else {
                state.record_failure(
                    self.stream,
                    WorkerOutputRelayFailureKind::CounterExhausted,
                    "worker output in-flight counter underflowed",
                );
                self.retire_source_locked(&mut state, false);
                self.failed = true;
                return false;
            };
            // The external write happens before this atomic accounting move.
            // Until the lock is acquired the bytes remain counted in-flight;
            // afterwards they are counted forwarded, so the sum is constant.
            accounting.forwarded = forwarded;
            accounting.in_flight = in_flight;
            self.offset += amount;
            if self.offset == self.pending.len() {
                self.pending.clear();
                self.offset = 0;
            } else if self.offset >= WORKER_OUTPUT_IN_FLIGHT_LIMIT {
                self.pending.drain(..self.offset);
                self.offset = 0;
            }
            return true;
        }
        if amount == 0 {
            self.fail(
                state,
                WorkerOutputRelayFailureKind::WriteFailed,
                "worker output relay returned a zero-byte write",
            );
            return false;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return true;
        }
        if error.kind() == io::ErrorKind::WouldBlock {
            return false;
        }
        let kind = if error.raw_os_error() == Some(libc::EPIPE) {
            WorkerOutputRelayFailureKind::BrokenPipe
        } else {
            WorkerOutputRelayFailureKind::WriteFailed
        };
        self.fail(state, kind, error.to_string());
        false
    }

    fn fail(
        &mut self,
        state: &Arc<Mutex<WorkerOutputRelayState>>,
        kind: WorkerOutputRelayFailureKind,
        message: impl Into<String>,
    ) {
        let mut state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.record_failure(self.stream, kind, message);
        self.retire_source_locked(&mut state, false);
        self.failed = true;
    }

    fn force_close(&mut self, state: &Arc<Mutex<WorkerOutputRelayState>>) {
        let mut state = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.retire_source_locked(&mut state, true);
        self.failed = true;
    }

    fn retire_source_locked(&mut self, state: &mut WorkerOutputRelayState, forced: bool) {
        let Some(source) = self.source.as_ref() else {
            return;
        };
        let queued = pipe_queued_bytes(source.raw()).unwrap_or(0);
        let counter_exhausted = {
            let accounting = state.accounting_mut(self.stream);
            if accounting.closed {
                false
            } else {
                let exhausted = match accounting.in_flight.checked_add(queued) {
                    Some(total) => {
                        accounting.in_flight = total;
                        false
                    }
                    None => true,
                };
                accounting.closed = true;
                exhausted
            }
        };
        if counter_exhausted {
            state.record_failure(
                self.stream,
                WorkerOutputRelayFailureKind::CounterExhausted,
                "worker output retirement counter exhausted u64",
            );
        }
        if forced && (self.remaining() != 0 || queued != 0) {
            state.record_failure(
                self.stream,
                WorkerOutputRelayFailureKind::ForcedClose,
                format!(
                    "worker output relay closed with {} in-flight and {queued} kernel-queued bytes",
                    self.remaining()
                ),
            );
        }
        self.source.take();
    }
}

#[cfg(unix)]
fn worker_output_relay_loop(
    mut stdout: WorkerOutputRelayEndpoint,
    mut stderr: Option<WorkerOutputRelayEndpoint>,
    state: Arc<Mutex<WorkerOutputRelayState>>,
    shutdown: mpsc::Receiver<()>,
) {
    let mut shutdown_deadline = None;
    loop {
        if shutdown_deadline.is_none() {
            match shutdown.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                    shutdown_deadline = Some(
                        Instant::now()
                            .checked_add(Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS))
                            .unwrap_or_else(Instant::now),
                    );
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        let mut progressed = stdout.pump(&state);
        if let Some(stderr) = stderr.as_mut() {
            progressed |= stderr.pump(&state);
        }
        if stdout.is_finished()
            && stderr
                .as_ref()
                .is_none_or(WorkerOutputRelayEndpoint::is_finished)
        {
            break;
        }
        if shutdown_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            stdout.force_close(&state);
            if let Some(stderr) = stderr.as_mut() {
                stderr.force_close(&state);
            }
            break;
        }
        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }
    if !stdout.is_finished() {
        stdout.force_close(&state);
    }
    if let Some(stderr) = stderr.as_mut() {
        if !stderr.is_finished() {
            stderr.force_close(&state);
        }
    }
}

#[cfg(unix)]
struct WorkerOutputRelayReservation {
    active: bool,
}

#[cfg(unix)]
impl WorkerOutputRelayReservation {
    fn acquire() -> io::Result<Self> {
        WORKER_OUTPUT_RELAY_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "a counted worker output relay is already active",
                )
            })?;
        Ok(Self { active: true })
    }

    fn transfer(mut self) {
        self.active = false;
    }
}

#[cfg(unix)]
impl Drop for WorkerOutputRelayReservation {
    fn drop(&mut self) {
        if self.active {
            WORKER_OUTPUT_RELAY_ACTIVE.store(false, Ordering::Release);
        }
    }
}

#[cfg(unix)]
struct SigpipeIgnoreGuard {
    previous: libc::sigaction,
}

#[cfg(unix)]
impl SigpipeIgnoreGuard {
    fn install() -> io::Result<Self> {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = libc::SIG_IGN;
        action.sa_flags = 0;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(libc::SIGPIPE, &action, &mut previous) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { previous })
    }
}

#[cfg(unix)]
impl Drop for SigpipeIgnoreGuard {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(libc::SIGPIPE, &self.previous, std::ptr::null_mut());
        }
    }
}

#[cfg(unix)]
struct WorkerDestinationStatusGuard {
    stdout: i32,
    stderr: i32,
    stdout_flags: i32,
    stderr_flags: i32,
    active: bool,
}

#[cfg(unix)]
impl WorkerDestinationStatusGuard {
    fn new(stdout: i32, stderr: i32, stdout_flags: i32, stderr_flags: i32) -> Self {
        Self {
            stdout,
            stderr,
            stdout_flags,
            stderr_flags,
            active: true,
        }
    }

    fn transfer(mut self) {
        self.active = false;
    }
}

#[cfg(unix)]
impl Drop for WorkerDestinationStatusGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let _ = set_descriptor_flag(self.stdout, libc::F_SETFL, self.stdout_flags);
        let _ = set_descriptor_flag(self.stderr, libc::F_SETFL, self.stderr_flags);
    }
}

/// Scoped worker-side fd 1/fd 2 counted relay.
///
/// Install this after the worker authenticates its inherited channel and
/// before constructing `Runtime`. The returned private descriptor list must be
/// joined to SessionIo's protected class and the native Host descriptor policy
/// before JavaScript can run. Internal descriptors are `CLOEXEC`; only the
/// same-slot fd 1/fd 2 pipe writers remain inheritable, so an intact-adapter
/// child requesting `inherit` writes into the same counted relays.
// @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker — the cutoff
// is forwarded + in-flight + kernel-queued bytes, serialized against relay
// transitions and preserving length-bearing binary payloads byte-for-byte.
#[cfg(unix)]
pub struct WorkerOutputRelayAdapter {
    cutoff_port: WorkerOutputCutoffPort,
    protected_descriptors: Box<[i32]>,
    restore_stdout: NativeFd,
    restore_stderr: NativeFd,
    stdout_descriptor_flags: i32,
    stderr_descriptor_flags: i32,
    stdout_status_flags: i32,
    stderr_status_flags: i32,
    shutdown: Option<mpsc::Sender<()>>,
    relay: Option<thread::JoinHandle<()>>,
    sigpipe: Option<SigpipeIgnoreGuard>,
    _close_guard: crate::host::abi::TerminalSessionOutputCloseGuard,
    _console_relay_guard: crate::host::abi::AuthenticatedWorkerConsoleRelayGuard,
    closed: bool,
}

#[cfg(unix)]
impl WorkerOutputRelayAdapter {
    pub fn install(output_topology: OutputDestinationTopology) -> io::Result<Self> {
        let reservation = WorkerOutputRelayReservation::acquire()?;
        let close_guard = crate::host::abi::arm_terminal_session_output_close_guard()?;
        let console_relay_guard = crate::host::abi::arm_authenticated_worker_console_relay()?;
        let sigpipe = SigpipeIgnoreGuard::install()?;
        flush_process_stdio()?;

        let stdout_descriptor_flags = descriptor_flags(libc::STDOUT_FILENO, libc::F_GETFD)?;
        let stderr_descriptor_flags = descriptor_flags(libc::STDERR_FILENO, libc::F_GETFD)?;
        let stdout_status_flags = descriptor_flags(libc::STDOUT_FILENO, libc::F_GETFL)?;
        let stderr_status_flags = descriptor_flags(libc::STDERR_FILENO, libc::F_GETFL)?;
        let restore_stdout = NativeFd::duplicate_high(libc::STDOUT_FILENO)?;
        let restore_stderr = NativeFd::duplicate_high(libc::STDERR_FILENO)?;
        let primary_destination = match output_topology {
            OutputDestinationTopology::Shared { destination } => destination.descriptor(),
            OutputDestinationTopology::Split => libc::STDOUT_FILENO,
        };
        let primary_status_flags = match primary_destination {
            libc::STDOUT_FILENO => stdout_status_flags,
            libc::STDERR_FILENO => stderr_status_flags,
            _ => unreachable!("native output destination is a standard descriptor"),
        };
        let stdout_destination = NativeFd::duplicate_high(primary_destination)?;
        let stderr_destination = match output_topology {
            OutputDestinationTopology::Shared { .. } => None,
            OutputDestinationTopology::Split => {
                Some(NativeFd::duplicate_high(libc::STDERR_FILENO)?)
            }
        };
        let destination_status = WorkerDestinationStatusGuard::new(
            restore_stdout.raw(),
            restore_stderr.raw(),
            stdout_status_flags,
            stderr_status_flags,
        );
        set_descriptor_flag(
            stdout_destination.raw(),
            libc::F_SETFL,
            primary_status_flags | libc::O_NONBLOCK,
        )?;
        if let Some(stderr_destination) = stderr_destination.as_ref() {
            set_descriptor_flag(
                stderr_destination.raw(),
                libc::F_SETFL,
                stderr_status_flags | libc::O_NONBLOCK,
            )?;
        }
        let (stdout_read, stdout_write) = native_pipe()?;
        let (stderr_read, stderr_write) = match output_topology {
            OutputDestinationTopology::Shared { .. } => (None, None),
            OutputDestinationTopology::Split => {
                let (read, write) = native_pipe()?;
                (Some(read), Some(write))
            }
        };

        let mut protected_descriptors = vec![
            restore_stdout.raw(),
            restore_stderr.raw(),
            stdout_destination.raw(),
            stdout_read.raw(),
        ];
        if let Some(stderr_destination) = stderr_destination.as_ref() {
            protected_descriptors.push(stderr_destination.raw());
        }
        if let Some(stderr_read) = stderr_read.as_ref() {
            protected_descriptors.push(stderr_read.raw());
        }
        protected_descriptors.sort_unstable();
        protected_descriptors.dedup();
        let expected_private_descriptors = match output_topology {
            OutputDestinationTopology::Shared { .. } => 4,
            OutputDestinationTopology::Split => 6,
        };
        if protected_descriptors.len() != expected_private_descriptors
            || protected_descriptors
                .iter()
                .any(|descriptor| *descriptor <= 2)
        {
            return Err(io::Error::other(format!(
                "worker output relay descriptors are not {expected_private_descriptors} distinct private descriptors"
            )));
        }

        let state = Arc::new(Mutex::new(WorkerOutputRelayState {
            stdout: WorkerRelayAccounting::new(stdout_read.raw()),
            stderr: stderr_read
                .as_ref()
                .map(|read| WorkerRelayAccounting::new(read.raw())),
            failures: Vec::new(),
        }));
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let relay_state = Arc::clone(&state);
        let relay = thread::Builder::new()
            .name("ibex-worker-output-relay".to_string())
            .spawn(move || {
                let stderr =
                    stderr_read
                        .zip(stderr_destination)
                        .map(|(stderr_read, stderr_destination)| {
                            WorkerOutputRelayEndpoint::new(
                                ProgramStream::Stderr,
                                stderr_read,
                                stderr_destination,
                            )
                        });
                worker_output_relay_loop(
                    WorkerOutputRelayEndpoint::new(
                        ProgramStream::Stdout,
                        stdout_read,
                        stdout_destination,
                    ),
                    stderr,
                    relay_state,
                    shutdown_rx,
                )
            })?;

        let stdout_result = duplicate_over(stdout_write.raw(), libc::STDOUT_FILENO);
        let stdout_replaced = stdout_result.is_ok();
        let stderr_write_descriptor = stderr_write
            .as_ref()
            .map_or(stdout_write.raw(), NativeFd::raw);
        let redirect_result = stdout_result
            .and_then(|()| duplicate_over(stderr_write_descriptor, libc::STDERR_FILENO));
        if let Err(error) = redirect_result {
            if stdout_replaced {
                let _ = duplicate_over(restore_stdout.raw(), libc::STDOUT_FILENO);
                let _ = set_descriptor_flag(
                    libc::STDOUT_FILENO,
                    libc::F_SETFD,
                    stdout_descriptor_flags,
                );
            }
            drop(stdout_write);
            drop(stderr_write);
            let _ = shutdown_tx.send(());
            let _ = relay.join();
            return Err(error);
        }
        drop(stdout_write);
        drop(stderr_write);
        destination_status.transfer();
        reservation.transfer();

        Ok(Self {
            cutoff_port: WorkerOutputCutoffPort { state },
            protected_descriptors: protected_descriptors.into_boxed_slice(),
            restore_stdout,
            restore_stderr,
            stdout_descriptor_flags,
            stderr_descriptor_flags,
            stdout_status_flags,
            stderr_status_flags,
            shutdown: Some(shutdown_tx),
            relay: Some(relay),
            sigpipe: Some(sigpipe),
            _close_guard: close_guard,
            _console_relay_guard: console_relay_guard,
            closed: false,
        })
    }

    pub fn cutoff_port(&self) -> WorkerOutputCutoffPort {
        self.cutoff_port.clone()
    }

    pub fn cutoffs(&self) -> io::Result<WorkerOutputCutoffs> {
        self.cutoff_port.cutoffs()
    }

    pub fn protected_descriptors(&self) -> &[i32] {
        &self.protected_descriptors
    }

    pub fn finish(mut self) -> io::Result<()> {
        self.restore_and_stop()
    }

    fn restore_and_stop(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        crate::host::abi::ex_host_console_flush(BROKER_FLUSH_BUDGET_MILLIS as u32);
        let stdout_result = duplicate_over(self.restore_stdout.raw(), libc::STDOUT_FILENO)
            .and_then(|()| {
                set_descriptor_flag(
                    libc::STDOUT_FILENO,
                    libc::F_SETFD,
                    self.stdout_descriptor_flags,
                )
            });
        let stderr_result = duplicate_over(self.restore_stderr.raw(), libc::STDERR_FILENO)
            .and_then(|()| {
                set_descriptor_flag(
                    libc::STDERR_FILENO,
                    libc::F_SETFD,
                    self.stderr_descriptor_flags,
                )
            });
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let relay_result = self
            .relay
            .take()
            .map(|relay| {
                relay
                    .join()
                    .map_err(|_| io::Error::other("worker output relay thread panicked"))
            })
            .transpose()
            .map(|_| ());
        let stdout_flags_result = set_descriptor_flag(
            self.restore_stdout.raw(),
            libc::F_SETFL,
            self.stdout_status_flags,
        );
        let stderr_flags_result = set_descriptor_flag(
            self.restore_stderr.raw(),
            libc::F_SETFL,
            self.stderr_status_flags,
        );
        self.sigpipe.take();
        WORKER_OUTPUT_RELAY_ACTIVE.store(false, Ordering::Release);
        self.closed = true;
        stdout_result
            .and(stderr_result)
            .and(relay_result)
            .and(stdout_flags_result)
            .and(stderr_flags_result)
    }
}

#[cfg(unix)]
impl Drop for WorkerOutputRelayAdapter {
    fn drop(&mut self) {
        let _ = self.restore_and_stop();
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkerRelayBarrier {
    stdout_cutoff: u64,
    stderr_cutoff: u64,
}

/// A bounded worker-output cutoff could not be satisfied.
///
/// The accepted/cutoff pairs remain typed through the broker handle so the
/// session owner can apply §8's status precedence without parsing text.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkerBarrierFailure {
    DeadlineExceeded {
        stdout_accepted: u64,
        stdout_cutoff: u64,
        stderr_accepted: u64,
        stderr_cutoff: u64,
    },
    EofBeforeCutoff {
        stream: ProgramStream,
        accepted_bytes: u64,
        cutoff_bytes: u64,
    },
    Unavailable {
        message: String,
    },
    Abandoned {
        stdout_accepted: u64,
        stdout_cutoff: u64,
        stderr_accepted: u64,
        stderr_cutoff: u64,
        reason: &'static str,
    },
}

#[cfg(unix)]
impl WorkerBarrierFailure {
    /// Deadline, premature EOF, and explicit abandonment all mean the worker
    /// named output that the broker could not prove accepted before disposal.
    pub(crate) const fn is_output_loss(&self) -> bool {
        !matches!(self, Self::Unavailable { .. })
    }
}

#[cfg(unix)]
impl fmt::Display for WorkerBarrierFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineExceeded {
                stdout_accepted,
                stdout_cutoff,
                stderr_accepted,
                stderr_cutoff,
            } => write!(
                f,
                "worker output cutoff timed out (stdout {stdout_accepted}/{stdout_cutoff}, stderr {stderr_accepted}/{stderr_cutoff})"
            ),
            Self::EofBeforeCutoff {
                stream,
                accepted_bytes,
                cutoff_bytes,
            } => write!(
                f,
                "worker {stream:?} relay ended at byte {accepted_bytes} before cutoff {cutoff_bytes}"
            ),
            Self::Unavailable { message } => f.write_str(message),
            Self::Abandoned {
                stdout_accepted,
                stdout_cutoff,
                stderr_accepted,
                stderr_cutoff,
                reason,
            } => write!(
                f,
                "worker output cutoff was {reason} (stdout {stdout_accepted}/{stdout_cutoff}, stderr {stderr_accepted}/{stderr_cutoff})"
            ),
        }
    }
}

#[cfg(unix)]
impl std::error::Error for WorkerBarrierFailure {}

#[cfg(unix)]
#[derive(Debug)]
enum ReplDisplayFailure {
    Broker(String),
    WorkerBarrier(WorkerBarrierFailure),
}

#[cfg(unix)]
impl fmt::Display for ReplDisplayFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Broker(message) => f.write_str(message),
            Self::WorkerBarrier(error) => error.fmt(f),
        }
    }
}

#[cfg(unix)]
impl std::error::Error for ReplDisplayFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Broker(_) => None,
            Self::WorkerBarrier(error) => Some(error),
        }
    }
}

#[cfg(unix)]
enum ReplBrokerCommand {
    Prompt {
        prompt: String,
        buffer: Vec<u8>,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    Boundary {
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    SessionLine {
        text: String,
        style: SessionStyle,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    Diagnostic {
        text: String,
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    InterruptNotice {
        text: String,
    },
    Display {
        wire: Vec<u8>,
        worker_barrier: Option<WorkerRelayBarrier>,
        reply: mpsc::SyncSender<Result<DisplayDisposition, ReplDisplayFailure>>,
    },
    WorkerBarrier {
        barrier: WorkerRelayBarrier,
        reply: mpsc::SyncSender<Result<(), WorkerBarrierFailure>>,
    },
    Clear {
        reply: mpsc::SyncSender<Result<(), String>>,
    },
    Finish {
        reply: mpsc::SyncSender<Result<BrokerLossAccounting, String>>,
    },
    ForceFinish {
        reply: mpsc::SyncSender<()>,
    },
}

#[cfg(unix)]
#[derive(Clone)]
struct ReplBrokerHandle {
    commands: mpsc::Sender<ReplBrokerCommand>,
}

#[cfg(unix)]
impl ReplBrokerHandle {
    fn request_unit(
        &self,
        build: impl FnOnce(mpsc::SyncSender<Result<(), String>>) -> ReplBrokerCommand,
    ) -> Result<(), String> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.commands
            .send(build(reply_tx))
            .map_err(|_| "REPL output broker stopped".to_string())?;
        reply_rx
            .recv()
            .map_err(|_| "REPL output broker dropped its reply".to_string())?
    }

    fn prompt(&self, prompt: &str, buffer: &[u8]) -> Result<(), String> {
        self.request_unit(|reply| ReplBrokerCommand::Prompt {
            prompt: prompt.to_owned(),
            buffer: buffer.to_vec(),
            reply,
        })
    }

    fn boundary(&self) -> Result<(), String> {
        self.request_unit(|reply| ReplBrokerCommand::Boundary { reply })
    }

    fn session_line(&self, text: &str, style: SessionStyle) -> Result<(), String> {
        self.request_unit(|reply| ReplBrokerCommand::SessionLine {
            text: text.to_owned(),
            style,
            reply,
        })
    }

    fn diagnostic(&self, text: &str) -> Result<(), String> {
        self.request_unit(|reply| ReplBrokerCommand::Diagnostic {
            text: text.to_owned(),
            reply,
        })
    }

    fn interrupt_notice(&self, text: &str) {
        let _ = self.commands.send(ReplBrokerCommand::InterruptNotice {
            text: text.to_owned(),
        });
    }

    fn display(
        &self,
        wire: Vec<u8>,
        worker_barrier: Option<WorkerRelayBarrier>,
    ) -> Result<DisplayDisposition, ReplDisplayFailure> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.commands
            .send(ReplBrokerCommand::Display {
                wire,
                worker_barrier,
                reply: reply_tx,
            })
            .map_err(|_| ReplDisplayFailure::Broker("REPL output broker stopped".to_string()))?;
        reply_rx.recv().map_err(|_| {
            ReplDisplayFailure::Broker("REPL output broker dropped its display reply".to_string())
        })?
    }

    fn worker_barrier(
        &self,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    ) -> Result<(), WorkerBarrierFailure> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.commands
            .send(ReplBrokerCommand::WorkerBarrier {
                barrier: WorkerRelayBarrier {
                    stdout_cutoff,
                    stderr_cutoff,
                },
                reply: reply_tx,
            })
            .map_err(|_| WorkerBarrierFailure::Unavailable {
                message: "REPL output broker stopped".to_string(),
            })?;
        reply_rx
            .recv()
            .map_err(|_| WorkerBarrierFailure::Unavailable {
                message: "REPL output broker dropped its worker-barrier reply".to_string(),
            })?
    }

    fn clear(&self) -> Result<(), String> {
        self.request_unit(|reply| ReplBrokerCommand::Clear { reply })
    }

    fn finish(&self) -> Result<BrokerLossAccounting, String> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.commands
            .send(ReplBrokerCommand::Finish { reply: reply_tx })
            .map_err(|_| "REPL output broker stopped".to_string())?;
        reply_rx
            .recv()
            .map_err(|_| "REPL output broker dropped its finish reply".to_string())?
    }

    /// Emergency escalation path used only after the generated machine has
    /// selected a terminal outcome while the owner thread is still wedged.
    fn force_finish(&self) {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        if self
            .commands
            .send(ReplBrokerCommand::ForceFinish { reply: reply_tx })
            .is_ok()
        {
            let _ = reply_rx.recv_timeout(Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS));
        }
    }
}

#[cfg(unix)]
fn accept_repl_broker_write<W: NonBlockingRelaySink>(
    broker: &mut InProcessOutputBroker<W>,
    write: Result<Vec<BrokerReceipt>, BrokerEnqueueError>,
) -> Result<(), String> {
    write.map_err(|error| error.to_string())?;
    broker.pump_available();
    Ok(())
}

#[cfg(unix)]
enum PendingWorkerBrokerReply {
    Display {
        wire: Vec<u8>,
        reply: mpsc::SyncSender<Result<DisplayDisposition, ReplDisplayFailure>>,
    },
    Barrier {
        reply: mpsc::SyncSender<Result<(), WorkerBarrierFailure>>,
    },
}

#[cfg(unix)]
struct PendingWorkerBrokerCommand {
    barrier: WorkerRelayBarrier,
    deadline: Instant,
    reply: PendingWorkerBrokerReply,
}

#[cfg(unix)]
impl PendingWorkerBrokerCommand {
    fn new(barrier: WorkerRelayBarrier, reply: PendingWorkerBrokerReply) -> Self {
        Self {
            barrier,
            deadline: Instant::now()
                .checked_add(Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS))
                .unwrap_or_else(Instant::now),
            reply,
        }
    }

    fn refuse(self, error: WorkerBarrierFailure) {
        match self.reply {
            PendingWorkerBrokerReply::Display { reply, .. } => {
                let _ = reply.send(Err(ReplDisplayFailure::WorkerBarrier(error)));
            }
            PendingWorkerBrokerReply::Barrier { reply } => {
                let _ = reply.send(Err(error));
            }
        }
    }
}

#[cfg(unix)]
fn worker_barrier_reached(
    inputs: Option<&CapturedInputs>,
    barrier: WorkerRelayBarrier,
) -> Result<bool, WorkerBarrierFailure> {
    let inputs = inputs.ok_or_else(|| WorkerBarrierFailure::Unavailable {
        message: "worker output relay is not attached".to_string(),
    })?;
    match inputs {
        CapturedInputs::Shared { output } => {
            if barrier.stderr_cutoff != 0 {
                return Err(WorkerBarrierFailure::Unavailable {
                    message: "shared worker relay carried a nonzero stderr cutoff".to_string(),
                });
            }
            if output.eof && output.accepted_bytes() < barrier.stdout_cutoff {
                return Err(WorkerBarrierFailure::EofBeforeCutoff {
                    stream: ProgramStream::Stdout,
                    accepted_bytes: output.accepted_bytes(),
                    cutoff_bytes: barrier.stdout_cutoff,
                });
            }
            Ok(output.accepted_bytes() >= barrier.stdout_cutoff)
        }
        CapturedInputs::Split { stdout, stderr } => {
            if stdout.eof && stdout.accepted_bytes() < barrier.stdout_cutoff {
                return Err(WorkerBarrierFailure::EofBeforeCutoff {
                    stream: ProgramStream::Stdout,
                    accepted_bytes: stdout.accepted_bytes(),
                    cutoff_bytes: barrier.stdout_cutoff,
                });
            }
            if stderr.eof && stderr.accepted_bytes() < barrier.stderr_cutoff {
                return Err(WorkerBarrierFailure::EofBeforeCutoff {
                    stream: ProgramStream::Stderr,
                    accepted_bytes: stderr.accepted_bytes(),
                    cutoff_bytes: barrier.stderr_cutoff,
                });
            }
            Ok(stdout.accepted_bytes() >= barrier.stdout_cutoff
                && stderr.accepted_bytes() >= barrier.stderr_cutoff)
        }
    }
}

#[cfg(unix)]
fn worker_barrier_deadline_failure(
    inputs: Option<&CapturedInputs>,
    barrier: WorkerRelayBarrier,
) -> WorkerBarrierFailure {
    match inputs {
        Some(inputs) => {
            let (stdout_accepted, stderr_accepted) = inputs.accepted_bytes();
            WorkerBarrierFailure::DeadlineExceeded {
                stdout_accepted,
                stdout_cutoff: barrier.stdout_cutoff,
                stderr_accepted,
                stderr_cutoff: barrier.stderr_cutoff,
            }
        }
        None => WorkerBarrierFailure::Unavailable {
            message: "worker output relays are not attached".to_string(),
        },
    }
}

#[cfg(unix)]
fn worker_barrier_abandoned_failure(
    inputs: Option<&CapturedInputs>,
    barrier: WorkerRelayBarrier,
    reason: &'static str,
) -> WorkerBarrierFailure {
    match inputs {
        Some(inputs) => {
            let (stdout_accepted, stderr_accepted) = inputs.accepted_bytes();
            WorkerBarrierFailure::Abandoned {
                stdout_accepted,
                stdout_cutoff: barrier.stdout_cutoff,
                stderr_accepted,
                stderr_cutoff: barrier.stderr_cutoff,
                reason,
            }
        }
        None => WorkerBarrierFailure::Unavailable {
            message: "worker output relays are not attached".to_string(),
        },
    }
}

#[cfg(unix)]
enum PendingReplDisplay {
    DrainLocal {
        wire: Vec<u8>,
        reply: mpsc::SyncSender<Result<DisplayDisposition, ReplDisplayFailure>>,
    },
    AwaitWrite {
        ticket: DisplayTicket,
        reply: mpsc::SyncSender<Result<DisplayDisposition, ReplDisplayFailure>>,
    },
}

#[cfg(unix)]
impl PendingReplDisplay {
    fn refuse(self, message: &'static str) {
        let reply = match self {
            Self::DrainLocal { reply, .. } | Self::AwaitWrite { reply, .. } => reply,
        };
        let _ = reply.send(Err(ReplDisplayFailure::Broker(message.to_string())));
    }
}

#[cfg(unix)]
fn begin_repl_display<W: NonBlockingRelaySink>(
    broker: &mut InProcessOutputBroker<W>,
    wire: Vec<u8>,
    reply: mpsc::SyncSender<Result<DisplayDisposition, ReplDisplayFailure>>,
) -> Option<PendingReplDisplay> {
    let ticket = match broker.receive_display_tree(&wire) {
        Ok(ticket) => ticket,
        Err(error) => {
            let _ = reply.send(Err(ReplDisplayFailure::Broker(error.to_string())));
            return None;
        }
    };
    broker.pump_available();
    match broker.poll_display(&ticket) {
        DisplayPoll::Complete(disposition) => {
            let _ = reply.send(Ok(disposition));
            None
        }
        DisplayPoll::Pending => Some(PendingReplDisplay::AwaitWrite { ticket, reply }),
    }
}

#[cfg(unix)]
fn repl_broker_loop<W: NonBlockingRelaySink>(
    plan: SessionIoPlan,
    inputs: RelayInputDescriptors,
    worker_inputs: Option<(
        RelayInputDescriptors,
        crate::session_worker::SupervisorRelayAcceptance,
    )>,
    sequence_allocator: Option<crate::session_worker::SupervisorSequenceAllocator>,
    sink: W,
    commands: mpsc::Receiver<ReplBrokerCommand>,
) -> Result<(), String> {
    let mut broker = match sequence_allocator {
        Some(sequence_allocator) => InProcessOutputBroker::with_sequence_allocator(
            sink,
            plan.broker_routes(),
            plan.broker_presentations(),
            sequence_allocator,
        ),
        None => InProcessOutputBroker::new(sink, plan.broker_routes(), plan.broker_presentations()),
    }
    .map_err(|error| error.to_string())?;
    let mut inputs = CapturedInputs::new(inputs);
    let mut worker_inputs = worker_inputs.map(|(descriptors, acceptance)| {
        CapturedInputs::with_relay_acceptance(descriptors, acceptance)
    });
    let mut pending_worker_command: Option<PendingWorkerBrokerCommand> = None;
    let mut pending_display: Option<PendingReplDisplay> = None;

    loop {
        let mut progressed = broker.pump_available().progressed_relays != 0;
        let inputs_progressed = inputs.ingest(&mut broker, &mut Vec::new())?;
        progressed |= inputs_progressed;
        if let Some(input) = worker_inputs.as_mut() {
            progressed |= input.ingest(&mut broker, &mut Vec::new())?;
        }

        if let Some(pending) = pending_worker_command.take() {
            match worker_barrier_reached(worker_inputs.as_ref(), pending.barrier) {
                Ok(true) => match pending.reply {
                    PendingWorkerBrokerReply::Display { wire, reply } => {
                        debug_assert!(pending_display.is_none());
                        pending_display = begin_repl_display(&mut broker, wire, reply);
                    }
                    PendingWorkerBrokerReply::Barrier { reply } => {
                        let _ = reply.send(Ok(()));
                    }
                },
                Ok(false) if Instant::now() >= pending.deadline => {
                    let error =
                        worker_barrier_deadline_failure(worker_inputs.as_ref(), pending.barrier);
                    pending.refuse(error);
                }
                Ok(false) => pending_worker_command = Some(pending),
                Err(error) => pending.refuse(error),
            }
        }

        // Display completion is a polled state, never a broker-thread wait.
        // This keeps interrupt/control commands and ForceFinish serviceable
        // while a display destination is backpressured.
        if let Some(display) = pending_display.take() {
            match display {
                PendingReplDisplay::DrainLocal { wire, reply }
                    if !inputs_progressed && inputs.pending_bytes() == (0, 0) =>
                {
                    pending_display = begin_repl_display(&mut broker, wire, reply);
                }
                PendingReplDisplay::DrainLocal { wire, reply } => {
                    pending_display = Some(PendingReplDisplay::DrainLocal { wire, reply });
                }
                PendingReplDisplay::AwaitWrite { ticket, reply } => {
                    match broker.poll_display(&ticket) {
                        DisplayPoll::Complete(disposition) => {
                            let _ = reply.send(Ok(disposition));
                        }
                        DisplayPoll::Pending => {
                            pending_display =
                                Some(PendingReplDisplay::AwaitWrite { ticket, reply });
                        }
                    }
                }
            }
        }

        match commands.try_recv() {
            Ok(ReplBrokerCommand::Prompt {
                prompt,
                buffer,
                reply,
            }) => {
                let write = broker.publish_prompt(&prompt, &buffer);
                let _ = reply.send(accept_repl_broker_write(&mut broker, write));
            }
            Ok(ReplBrokerCommand::Boundary { reply }) => {
                let write = broker.receive_prompt_boundary();
                let _ = reply.send(accept_repl_broker_write(&mut broker, write));
            }
            Ok(ReplBrokerCommand::SessionLine { text, style, reply }) => {
                let write = broker.receive_session_line(&text, style);
                let _ = reply.send(accept_repl_broker_write(&mut broker, write));
            }
            Ok(ReplBrokerCommand::Diagnostic { text, reply }) => {
                let write = broker.receive_control_line(&text, SessionStyle::Error);
                let _ = reply.send(accept_repl_broker_write(&mut broker, write));
            }
            Ok(ReplBrokerCommand::InterruptNotice { text }) => {
                let write = broker.receive_interrupt_notice(&text);
                let _ = accept_repl_broker_write(&mut broker, write);
            }
            Ok(ReplBrokerCommand::Display {
                wire,
                worker_barrier,
                reply,
            }) => {
                if let Some(barrier) = worker_barrier {
                    if pending_worker_command.is_some() || pending_display.is_some() {
                        let _ = reply.send(Err(ReplDisplayFailure::Broker(
                            "another display or worker output barrier is already pending"
                                .to_string(),
                        )));
                    } else {
                        pending_worker_command = Some(PendingWorkerBrokerCommand::new(
                            barrier,
                            PendingWorkerBrokerReply::Display { wire, reply },
                        ));
                    }
                    continue;
                }
                // All synchronous console writes have returned before the
                // evaluator sends this command. Drain the observable pipe
                // bytes before snapshotting the result barrier, one broker
                // turn at a time so control commands remain serviceable.
                if pending_worker_command.is_some() || pending_display.is_some() {
                    let _ = reply.send(Err(ReplDisplayFailure::Broker(
                        "another display or worker output barrier is already pending".to_string(),
                    )));
                } else {
                    pending_display = Some(PendingReplDisplay::DrainLocal { wire, reply });
                }
            }
            Ok(ReplBrokerCommand::WorkerBarrier { barrier, reply }) => {
                if pending_worker_command.is_some() || pending_display.is_some() {
                    let _ = reply.send(Err(WorkerBarrierFailure::Unavailable {
                        message: "another display or worker output barrier is already pending"
                            .to_string(),
                    }));
                } else {
                    pending_worker_command = Some(PendingWorkerBrokerCommand::new(
                        barrier,
                        PendingWorkerBrokerReply::Barrier { reply },
                    ));
                }
            }
            Ok(ReplBrokerCommand::Clear { reply }) => {
                let write = broker.receive_editor_clear();
                let _ = reply.send(accept_repl_broker_write(&mut broker, write));
            }
            Ok(ReplBrokerCommand::Finish { reply }) => {
                if let Some(pending) = pending_worker_command.take() {
                    let error = worker_barrier_abandoned_failure(
                        worker_inputs.as_ref(),
                        pending.barrier,
                        "abandoned by broker finish",
                    );
                    pending.refuse(error);
                }
                if let Some(display) = pending_display.take() {
                    display.refuse("REPL broker finished before display completion");
                }
                let deadline = Instant::now()
                    .checked_add(Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS))
                    .unwrap_or_else(Instant::now);
                while Instant::now() < deadline {
                    let mut progress = broker.pump_available().progressed_relays != 0;
                    progress |= inputs.ingest(&mut broker, &mut Vec::new())?;
                    if let Some(input) = worker_inputs.as_mut() {
                        progress |= input.ingest(&mut broker, &mut Vec::new())?;
                    }
                    let worker_finished =
                        worker_inputs.as_ref().is_none_or(CapturedInputs::finished);
                    if inputs.finished() && worker_finished {
                        break;
                    }
                    if !progress {
                        thread::sleep(Duration::from_millis(1));
                    }
                }
                let loss = broker
                    .finish_with_budget(deadline.saturating_duration_since(Instant::now()))
                    .map_err(|error| error.to_string());
                let _ = reply.send(loss);
                return Ok(());
            }
            Ok(ReplBrokerCommand::ForceFinish { reply }) => {
                if let Some(pending) = pending_worker_command.take() {
                    let error = worker_barrier_abandoned_failure(
                        worker_inputs.as_ref(),
                        pending.barrier,
                        "abandoned by broker force-finish",
                    );
                    pending.refuse(error);
                }
                if let Some(display) = pending_display.take() {
                    display.refuse("REPL broker was force-finished before display completion");
                }
                let _ =
                    broker.finish_with_budget(Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS));
                let _ = reply.send(());
                return Ok(());
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                if let Some(pending) = pending_worker_command.take() {
                    let error = worker_barrier_abandoned_failure(
                        worker_inputs.as_ref(),
                        pending.barrier,
                        "abandoned after command-lane disconnect",
                    );
                    pending.refuse(error);
                }
                if let Some(display) = pending_display.take() {
                    display.refuse("REPL broker command lane disconnected");
                }
                let _ =
                    broker.finish_with_budget(Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS));
                return Ok(());
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }

        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }
}

#[cfg(unix)]
struct ActiveReplCapture {
    plan: SessionIoPlan,
    lease: ExecutionAdapterLease,
    _descriptor_policy: SessionIo,
    _close_guard: crate::host::abi::TerminalSessionOutputCloseGuard,
    terminal: Arc<Mutex<UnixTerminalLifecycle>>,
    session_signals: Option<UnixSessionSignalGuard>,
    _control_descriptor: NativeFd,
    restore_stdout: NativeFd,
    restore_stderr: NativeFd,
    stdout_descriptor_flags: i32,
    stderr_descriptor_flags: i32,
    broker: ReplBrokerHandle,
    broker_thread: Option<thread::JoinHandle<Result<(), String>>>,
    descriptors_restored: bool,
    terminal_restored: bool,
    finished: bool,
}

#[cfg(unix)]
impl ActiveReplCapture {
    fn start(
        plan: SessionIoPlan,
        worker_relays: Option<crate::session_worker::WorkerRelays>,
    ) -> Result<Self, FileProgramAdapterError> {
        use std::os::fd::IntoRawFd as _;

        let close_guard = crate::host::abi::arm_terminal_session_output_close_guard()?;
        flush_process_stdio()?;

        let (worker_inputs, sequence_allocator) = match worker_relays {
            Some(relays) => {
                let crate::session_worker::WorkerRelays {
                    descriptors,
                    acceptance,
                    sequencer,
                } = relays;
                let descriptors = match descriptors {
                    crate::session_worker::WorkerRelayDescriptors::Shared { output } => {
                        RelayInputDescriptors::Shared {
                            output: NativeFd(output.into_raw_fd()),
                        }
                    }
                    crate::session_worker::WorkerRelayDescriptors::Split { stdout, stderr } => {
                        RelayInputDescriptors::Split {
                            stdout: NativeFd(stdout.into_raw_fd()),
                            stderr: NativeFd(stderr.into_raw_fd()),
                        }
                    }
                };
                for descriptor in descriptors.raw_descriptors() {
                    let flags = descriptor_flags(descriptor, libc::F_GETFL)?;
                    set_descriptor_flag(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK)?;
                }
                (Some((descriptors, acceptance)), Some(sequencer))
            }
            None => (None, None),
        };

        let stdout_descriptor_flags = descriptor_flags(libc::STDOUT_FILENO, libc::F_GETFD)?;
        let stderr_descriptor_flags = descriptor_flags(libc::STDERR_FILENO, libc::F_GETFD)?;
        let restore_stdout = NativeFd::duplicate(libc::STDOUT_FILENO)?;
        let restore_stderr = NativeFd::duplicate(libc::STDERR_FILENO)?;
        let stdout_relay = NativeFd::duplicate(libc::STDOUT_FILENO)?;
        let stderr_relay = NativeFd::duplicate(libc::STDERR_FILENO)?;
        let control_descriptor = NativeFd::duplicate(match plan.presentation.topology {
            PresentationTopology::StdoutTty => libc::STDOUT_FILENO,
            PresentationTopology::StderrTty | PresentationTopology::Transcript => {
                libc::STDERR_FILENO
            }
        })?;
        let session_signals = if worker_inputs.is_some() {
            Some(UnixSessionSignalGuard::install(
                true,
                captures_non_editor_interrupt(plan.presentation),
            )?)
        } else {
            None
        };
        let (inputs, stdout_write, stderr_write) = match plan.output_topology() {
            OutputDestinationTopology::Shared { .. } => {
                let (output, write) = native_pipe()?;
                (RelayInputDescriptors::Shared { output }, write, None)
            }
            OutputDestinationTopology::Split => {
                let (stdout, stdout_write) = native_pipe()?;
                let (stderr, stderr_write) = native_pipe()?;
                (
                    RelayInputDescriptors::Split { stdout, stderr },
                    stdout_write,
                    Some(stderr_write),
                )
            }
        };

        let mut descriptor_policy = SessionIo::new(plan);
        let mut protected_descriptors = vec![
            restore_stdout.raw(),
            restore_stderr.raw(),
            stdout_relay.raw(),
            stderr_relay.raw(),
            control_descriptor.raw(),
            stdout_write.raw(),
        ];
        protected_descriptors.extend(inputs.raw_descriptors());
        if let Some(stderr_write) = stderr_write.as_ref() {
            protected_descriptors.push(stderr_write.raw());
        }
        if let Some((worker_descriptors, _)) = worker_inputs.as_ref() {
            protected_descriptors.extend(worker_descriptors.raw_descriptors());
        }
        if let Some(signals) = session_signals.as_ref() {
            protected_descriptors.extend(signals.protected_descriptors());
        }
        for descriptor in protected_descriptors {
            descriptor_policy
                .protect_descriptor(descriptor)
                .map_err(|message| {
                    FileProgramAdapterError::Native(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        message,
                    ))
                })?;
        }

        let sink = NativeRelaySink::new(plan.output_topology(), stdout_relay, stderr_relay)?;
        duplicate_over(stdout_write.raw(), libc::STDOUT_FILENO)?;
        let stderr_write_descriptor = stderr_write
            .as_ref()
            .map_or(stdout_write.raw(), NativeFd::raw);
        if let Err(error) = duplicate_over(stderr_write_descriptor, libc::STDERR_FILENO) {
            let _ = duplicate_over(restore_stdout.raw(), libc::STDOUT_FILENO);
            return Err(error.into());
        }
        drop(stdout_write);
        drop(stderr_write);

        let (command_tx, command_rx) = mpsc::channel();
        let broker_thread = match thread::Builder::new()
            .name("ibex-repl-output-broker".to_string())
            .spawn(move || {
                repl_broker_loop(
                    plan,
                    inputs,
                    worker_inputs,
                    sequence_allocator,
                    sink,
                    command_rx,
                )
            }) {
            Ok(worker) => worker,
            Err(error) => {
                let _ = duplicate_over(restore_stdout.raw(), libc::STDOUT_FILENO);
                let _ = duplicate_over(restore_stderr.raw(), libc::STDERR_FILENO);
                return Err(error.into());
            }
        };

        let mut terminal = UnixTerminalLifecycle::new(libc::STDIN_FILENO, control_descriptor.raw());
        if let Err(error) = terminal.enter_session(plan.presentation) {
            let _ = duplicate_over(restore_stdout.raw(), libc::STDOUT_FILENO);
            let _ = duplicate_over(restore_stderr.raw(), libc::STDERR_FILENO);
            return Err(FileProgramAdapterError::Broker(error));
        }
        let terminal = Arc::new(Mutex::new(terminal));

        Ok(Self {
            plan,
            lease: ExecutionAdapterLease,
            _descriptor_policy: descriptor_policy,
            _close_guard: close_guard,
            terminal,
            session_signals,
            _control_descriptor: control_descriptor,
            restore_stdout,
            restore_stderr,
            stdout_descriptor_flags,
            stderr_descriptor_flags,
            broker: ReplBrokerHandle {
                commands: command_tx,
            },
            broker_thread: Some(broker_thread),
            descriptors_restored: false,
            terminal_restored: false,
            finished: false,
        })
    }

    fn restore_terminal(&mut self) -> io::Result<()> {
        if self.terminal_restored {
            return Ok(());
        }
        self.terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .restore_session()
            .map_err(io::Error::other)?;
        self.terminal_restored = true;
        Ok(())
    }

    fn take_session_signal_source(
        &mut self,
    ) -> io::Result<Option<(NativeFd, UnixSessionSignalHandle)>> {
        self.session_signals
            .as_mut()
            .map(UnixSessionSignalGuard::take_source)
            .transpose()
    }

    fn disarm_session_signals(&mut self) {
        self.session_signals.take();
    }

    fn restore_descriptors(&mut self) -> io::Result<()> {
        if self.descriptors_restored {
            return Ok(());
        }
        crate::host::abi::ex_host_console_flush(BROKER_FLUSH_BUDGET_MILLIS as u32);
        let flush_result = flush_process_stdio();
        let stdout_result = duplicate_over(self.restore_stdout.raw(), libc::STDOUT_FILENO)
            .and_then(|()| {
                set_descriptor_flag(
                    libc::STDOUT_FILENO,
                    libc::F_SETFD,
                    self.stdout_descriptor_flags,
                )
            });
        let stderr_result = duplicate_over(self.restore_stderr.raw(), libc::STDERR_FILENO)
            .and_then(|()| {
                set_descriptor_flag(
                    libc::STDERR_FILENO,
                    libc::F_SETFD,
                    self.stderr_descriptor_flags,
                )
            });
        self.descriptors_restored = stdout_result.is_ok() && stderr_result.is_ok();
        flush_result.and(stdout_result).and(stderr_result)
    }

    fn finish_report(&mut self) -> Result<BrokerLossAccounting, FileProgramAdapterError> {
        // Restoration is deliberately complete before the broker's bounded
        // finish may block on a destination.
        self.restore_terminal()?;
        self.restore_descriptors()?;
        let loss_result = self
            .broker
            .finish()
            .map_err(FileProgramAdapterError::Broker);
        let join_result = self
            .broker_thread
            .take()
            .ok_or_else(|| FileProgramAdapterError::Broker("broker already joined".into()))?
            .join()
            .map_err(|_| FileProgramAdapterError::RelayThreadPanicked)?
            .map_err(FileProgramAdapterError::Broker);
        self.finished = true;
        let loss = loss_result?;
        join_result?;
        Ok(loss)
    }

    fn finish(&mut self) -> Result<(), FileProgramAdapterError> {
        let loss = self.finish_report()?;
        if loss.has_loss() {
            return Err(FileProgramAdapterError::Broker(format!(
                "REPL output was lost during bounded shutdown: {:?}",
                loss.relays
            )));
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for ActiveReplCapture {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let _ = self.restore_terminal();
        let _ = self.restore_descriptors();
        let _ = self.broker.finish();
        if let Some(worker) = self.broker_thread.take() {
            let _ = worker.join();
        }
        self.finished = true;
    }
}

#[cfg(unix)]
trait TerminalSuspensionTransactionPort {
    fn restore_terminal(&mut self) -> Result<(), String>;
    fn stop_worker_group(&mut self) -> Result<(), String>;
    fn stop_supervisor(&mut self) -> Result<(), String>;
    fn reacquire_foreground(&mut self) -> Result<(), String>;
    fn enter_terminal(&mut self) -> Result<(), String>;
    fn continue_worker_group(&mut self) -> Result<(), String>;
    fn refresh_dimensions(&mut self) -> Result<(), String>;
    fn redraw(&mut self) -> Result<(), String>;
}

/// One suspension transaction shared by the Ctrl+Z byte path and external
/// SIGTSTP. Keeping the sequence explicit makes it testable without racing a
/// real shell or PTY.
#[cfg(unix)]
fn execute_terminal_suspension_transaction(
    port: &mut impl TerminalSuspensionTransactionPort,
) -> Result<(), String> {
    port.restore_terminal()?;
    if let Err(error) = port.stop_worker_group() {
        let _ = port.enter_terminal();
        return Err(error);
    }
    if let Err(error) = port.stop_supervisor() {
        let _ = port.enter_terminal();
        let _ = port.continue_worker_group();
        return Err(error);
    }
    if let Err(error) = port.reacquire_foreground() {
        // Foreground reacquisition failed, so raw mode must not be installed.
        // Resume the worker only as a liveness rollback; the coordinator
        // reports the terminal fault and the outer owner selects disposition.
        let _ = port.continue_worker_group();
        return Err(error);
    }
    if let Err(error) = port.enter_terminal() {
        let _ = port.continue_worker_group();
        return Err(error);
    }
    port.continue_worker_group()?;
    port.refresh_dimensions()?;
    port.redraw()
}

#[cfg(unix)]
#[derive(Clone)]
enum NonEditorWorkerInterruptControl {
    Repl(crate::repl::ReplCancellationPort),
    Program(crate::session_worker_runtime::RemoteCancellationPort),
}

#[cfg(unix)]
impl NonEditorWorkerInterruptControl {
    fn request_exact_if_executing(&self) -> Result<(), String> {
        let (target, status) = match self {
            Self::Repl(port) => {
                let Some((target, _)) = port.interrupt_work_snapshot().executing else {
                    return Ok(());
                };
                (target, port.request_exact(target))
            }
            Self::Program(port) => {
                let Some((target, _)) = port.interrupt_work_snapshot().executing else {
                    return Ok(());
                };
                (target, port.request_exact(target))
            }
        };
        match status {
            crate::engine::AuthenticatedCancellationStatus::Accepted
            | crate::engine::AuthenticatedCancellationStatus::StaleTarget => Ok(()),
            crate::engine::AuthenticatedCancellationStatus::Unavailable => Err(format!(
                "authenticated cancellation for target {target} became unavailable"
            )),
            crate::engine::AuthenticatedCancellationStatus::Failed => Err(format!(
                "authenticated cancellation for target {target} failed"
            )),
        }
    }

    fn terminate_worker(&self) -> Result<(), String> {
        match self {
            Self::Repl(port) => port.terminate_worker_for_interrupt(),
            Self::Program(port) => port.terminate_worker(),
        }
        .map_err(|error| format!("failed to terminate interrupted worker: {error:#}"))
    }
}

#[cfg(unix)]
struct UnixWorkerTerminalSignalPort {
    terminal: Arc<Mutex<UnixTerminalLifecycle>>,
    presentation: CapturedPresentation,
    worker: crate::session_worker_runtime::WorkerTerminalControl,
    non_editor_interrupt: Option<NonEditorWorkerInterruptControl>,
    broker: ReplBrokerHandle,
    prompt: Option<PromptWitness>,
}

#[cfg(unix)]
impl UnixWorkerTerminalSignalPort {
    fn refresh_live_dimensions(&self) -> Result<(), String> {
        if matches!(self.presentation.topology, PresentationTopology::Transcript) {
            return Ok(());
        }
        let descriptor = self
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .control_fd();
        let dimensions =
            terminal_dimensions_from_fd(descriptor).map_err(|error| error.to_string())?;
        self.worker
            .resize(dimensions.columns, dimensions.rows)
            .map_err(|error| format!("failed to relay authenticated terminal resize: {error:#}"))
    }
}

#[cfg(unix)]
impl TerminalSuspensionTransactionPort for UnixWorkerTerminalSignalPort {
    fn restore_terminal(&mut self) -> Result<(), String> {
        self.terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .restore_session()
    }

    fn stop_worker_group(&mut self) -> Result<(), String> {
        self.worker
            .suspend()
            .map_err(|error| format!("failed to stop worker process group: {error:#}"))
    }

    fn stop_supervisor(&mut self) -> Result<(), String> {
        // SIGSTOP is uncatchable, so it cannot recurse through our external
        // SIGTSTP bridge. It stops every supervisor thread until the shell (or
        // external controller) delivers SIGCONT.
        if unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) } != 0 {
            return Err(format!(
                "failed to stop terminal supervisor: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn reacquire_foreground(&mut self) -> Result<(), String> {
        if matches!(self.presentation.topology, PresentationTopology::Transcript) {
            return Ok(());
        }
        let descriptor = self
            .terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .control_fd();
        reacquire_and_verify_foreground(descriptor).map_err(|error| error.to_string())
    }

    fn enter_terminal(&mut self) -> Result<(), String> {
        self.terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .enter_session(self.presentation)
    }

    fn continue_worker_group(&mut self) -> Result<(), String> {
        self.worker
            .resume()
            .map_err(|error| format!("failed to continue worker process group: {error:#}"))
    }

    fn refresh_dimensions(&mut self) -> Result<(), String> {
        self.refresh_live_dimensions()
    }

    fn redraw(&mut self) -> Result<(), String> {
        self.prompt
            .as_ref()
            .map_or(Ok(()), |prompt| prompt.redraw(&self.broker))
    }
}

#[cfg(unix)]
trait NonEditorInterruptCleanupPort {
    fn request_exact_cancellation(&mut self) -> Result<(), String>;
    fn restore_for_interrupt(&mut self) -> Result<(), String>;
    fn terminate_interrupted_worker(&mut self) -> Result<(), String>;
    fn force_finish_broker(&mut self);
}

#[cfg(unix)]
impl NonEditorInterruptCleanupPort for UnixWorkerTerminalSignalPort {
    fn request_exact_cancellation(&mut self) -> Result<(), String> {
        self.non_editor_interrupt
            .as_ref()
            .ok_or_else(|| "non-editor interrupt authority is missing".to_string())?
            .request_exact_if_executing()
    }

    fn restore_for_interrupt(&mut self) -> Result<(), String> {
        self.terminal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .restore_session()
    }

    fn terminate_interrupted_worker(&mut self) -> Result<(), String> {
        self.non_editor_interrupt
            .as_ref()
            .ok_or_else(|| "non-editor interrupt authority is missing".to_string())?
            .terminate_worker()
    }

    fn force_finish_broker(&mut self) {
        self.broker.force_finish();
    }
}

/// Ordinary-thread terminate-tier cleanup for non-editor products. Every
/// operation is bounded by its underlying supervisor/control contract, and a
/// failed exact request cannot prevent the engine-independent worker escape.
/// @ref LLP 0025#1-modes-descriptors-and-topology
#[cfg(unix)]
fn execute_non_editor_interrupt_cleanup(port: &mut impl NonEditorInterruptCleanupPort) {
    let _ = port.request_exact_cancellation();
    let _ = port.restore_for_interrupt();
    let _ = port.terminate_interrupted_worker();
    port.force_finish_broker();
}

#[cfg(unix)]
struct WorkerTerminalSignalCoordinator {
    handle: UnixSessionSignalHandle,
    thread: Option<thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl WorkerTerminalSignalCoordinator {
    fn spawn(
        receiver: NativeFd,
        handle: UnixSessionSignalHandle,
        mut port: UnixWorkerTerminalSignalPort,
    ) -> io::Result<Self> {
        let signal_thread = thread::Builder::new()
            .name("ibex-terminal-signals".to_string())
            .spawn(move || loop {
                let mut poll_descriptor = libc::pollfd {
                    fd: receiver.raw(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ready = unsafe { libc::poll(&mut poll_descriptor, 1, -1) };
                if ready < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                let mut bytes = [0_u8; 64];
                loop {
                    let amount = unsafe {
                        libc::read(receiver.raw(), bytes.as_mut_ptr().cast(), bytes.len())
                    };
                    if amount > 0 {
                        continue;
                    }
                    if amount < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    break;
                }
                let mut pending = SESSION_SIGNAL_PENDING.swap(0, Ordering::AcqRel);
                if pending & SESSION_SIGNAL_SHUTDOWN != 0 {
                    break;
                }
                if pending & SESSION_SIGNAL_INTERRUPT != 0 {
                    execute_non_editor_interrupt_cleanup(&mut port);
                    // SAFETY: SIGINT was reduced to a self-pipe bit by the
                    // signal handler; this ordinary coordinator thread has
                    // now completed bounded worker and broker cleanup.
                    unsafe {
                        libc::_exit(EXIT_STATUS_INTERRUPT);
                    }
                }
                if pending & SESSION_SIGNAL_SUSPEND != 0 {
                    if let Err(error) = execute_terminal_suspension_transaction(&mut port) {
                        port.broker
                            .interrupt_notice(&format!("terminal suspension failed: {error}"));
                    }
                    // Resume refreshes dimensions after the terminal has been
                    // reacquired, so a coalesced resize needs no second query.
                    pending &= !SESSION_SIGNAL_RESIZE;
                }
                if pending & SESSION_SIGNAL_RESIZE != 0 {
                    if let Err(error) = port.refresh_live_dimensions() {
                        port.broker
                            .interrupt_notice(&format!("terminal resize failed: {error}"));
                    } else if let Err(error) = port.redraw() {
                        port.broker
                            .interrupt_notice(&format!("terminal redraw failed: {error}"));
                    }
                }
            })?;
        Ok(Self {
            handle,
            thread: Some(signal_thread),
        })
    }

    const fn handle(&self) -> UnixSessionSignalHandle {
        self.handle
    }

    fn request_shutdown(&self) {
        self.handle.request_shutdown();
    }

    fn finish(mut self) -> io::Result<()> {
        self.handle.request_shutdown();
        self.thread
            .take()
            .expect("terminal signal coordinator thread is present")
            .join()
            .map_err(|_| io::Error::other("terminal signal coordinator panicked"))
    }
}

#[cfg(unix)]
impl Drop for WorkerTerminalSignalCoordinator {
    fn drop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        self.handle.request_shutdown();
        let _ = thread.join();
    }
}

#[cfg(unix)]
fn start_worker_terminal_signal_coordinator(
    active: &mut ActiveReplCapture,
    worker: Option<crate::session_worker_runtime::WorkerTerminalControl>,
    prompt: Option<PromptWitness>,
    non_editor_interrupt: Option<NonEditorWorkerInterruptControl>,
) -> anyhow::Result<Option<WorkerTerminalSignalCoordinator>> {
    anyhow::ensure!(
        non_editor_interrupt.is_some() == !active.plan.presentation.editor_control,
        "worker non-editor interrupt authority disagrees with captured presentation"
    );
    match (active.session_signals.is_some(), worker) {
        (true, Some(worker)) => {
            let port = UnixWorkerTerminalSignalPort {
                terminal: active.terminal.clone(),
                presentation: active.plan.presentation,
                worker,
                non_editor_interrupt,
                broker: active.broker.clone(),
                prompt,
            };
            // Close the snapshot-to-handler race: the spawn path supplied an
            // initial size before descriptor capture, and this second query
            // happens after SIGWINCH is installed. Any resize concurrent with
            // this query remains pending in the self-pipe for the new thread.
            port.refresh_live_dimensions().map_err(anyhow::Error::msg)?;
            let (receiver, handle) = active
                .take_session_signal_source()?
                .expect("active worker signal guard retains its source");
            match WorkerTerminalSignalCoordinator::spawn(receiver, handle, port) {
                Ok(coordinator) => Ok(Some(coordinator)),
                Err(error) => {
                    // No coordinator owns the reader, so restore the prior
                    // dispositions before returning through adapter cleanup.
                    active.disarm_session_signals();
                    Err(error.into())
                }
            }
        }
        (false, None) => Ok(None),
        _ => anyhow::bail!(
            "worker terminal signal source and authenticated control authority disagree"
        ),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct ReplInterruptEvent {
    terminal_status: Option<i32>,
    successful_termination: bool,
    discard_buffer: bool,
    discard_submission: bool,
}

#[cfg(unix)]
#[derive(Debug)]
enum ReplInputEvent {
    Byte {
        byte: u8,
        observed_prompt: Option<PromptCycle>,
    },
    Interrupt(ReplInterruptEvent),
    Eof,
    Error(String),
}

#[cfg(unix)]
struct ReplInterruptState {
    phase: generated::EditorPhase,
    pending_submission: generated::PendingSubmission,
    escape_credit: u8,
    promise: generated::PromiseClass,
    cause: Option<generated::TerminationCause>,
    ended: bool,
}

#[cfg(unix)]
#[derive(Clone)]
struct ReplInterruptController {
    state: Arc<Mutex<ReplInterruptState>>,
    cancellation: crate::repl::ReplCancellationPort,
    lifecycle: ibex_runtime::session_lifecycle::SessionLifecyclePort,
    broker: ReplBrokerHandle,
}

#[cfg(unix)]
impl ReplInterruptController {
    fn new(
        cancellation: crate::repl::ReplCancellationPort,
        lifecycle: ibex_runtime::session_lifecycle::SessionLifecyclePort,
        broker: ReplBrokerHandle,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ReplInterruptState {
                phase: generated::EditorPhase::Idle,
                pending_submission: generated::PendingSubmission::None,
                escape_credit: 0,
                promise: generated::PromiseClass::None,
                cause: None,
                ended: false,
            })),
            cancellation,
            lifecycle,
            broker,
        }
    }

    fn set_phase(
        &self,
        phase: generated::EditorPhase,
        pending_submission: generated::PendingSubmission,
    ) {
        let mut state = self.lock();
        state.phase = phase;
        state.pending_submission = pending_submission;
    }

    fn note_fresh_editor_input(&self) {
        let mut state = self.lock();
        state.escape_credit = 0;
        state.promise = generated::PromiseClass::None;
    }

    fn latch_cause(&self, status: i32) {
        self.lock().cause = Some(generated::TerminationCause { status });
    }

    fn end(&self) {
        self.lock().ended = true;
    }

    fn terminate_worker_for_escape(&self) {
        let _ = self.cancellation.terminate_worker_for_interrupt();
    }

    fn dispatch(&self) -> Result<(ReplInterruptEvent, bool), String> {
        use ibex_runtime::session_lifecycle::{LifecycleGetDisposition, LifecyclePrincipal};

        let live_work = self.cancellation.interrupt_work_snapshot();
        let exit_code = match self.lifecycle.get_exit_code(LifecyclePrincipal::Root) {
            LifecycleGetDisposition::Value(code) => code,
            LifecycleGetDisposition::Denied => 0,
        };
        let mut state = self.lock();
        let phase_at_dispatch = state.phase;
        let executing = live_work
            .executing
            .map(|(id, kind)| generated::ExecutingUnit {
                id,
                kind: generated_interrupt_work_kind(kind),
            });
        let decision = generated::dispatch_interrupt(generated::InterruptState {
            phase: state.phase,
            pending_submission: state.pending_submission,
            executing,
            suspended_ids: &live_work.suspended_ids,
            due_schedules: &live_work.due_schedules,
            completion_queued: None,
            escape_credit: state.escape_credit,
            promise: state.promise,
            cause: state.cause,
            exit_code,
            ended: state.ended,
        })
        .map_err(|error| format!("generated interrupt dispatch failed: {error:?}"))?;

        state.escape_credit = decision.next_credit;
        if decision.promise_to_set != generated::PromiseClass::None {
            state.promise = decision.promise_to_set;
        }
        if decision.buffer == generated::BufferAction::DiscardInvalidate {
            state.phase = generated::EditorPhase::Idle;
        }
        match decision.submission {
            generated::SubmissionAction::Unchanged => {}
            generated::SubmissionAction::Discard => {
                state.pending_submission = generated::PendingSubmission::Discarded;
            }
            generated::SubmissionAction::DiscardAndIdle => {
                state.pending_submission = generated::PendingSubmission::None;
                state.phase = generated::EditorPhase::Idle;
            }
        }
        drop(state);

        if decision.notice != generated::Notice::None {
            self.broker
                .interrupt_notice(interrupt_notice(decision.notice));
        }

        if let Some(target) = decision.cancel_target {
            match self.cancellation.request_exact(target) {
                crate::engine::AuthenticatedCancellationStatus::Accepted
                | crate::engine::AuthenticatedCancellationStatus::StaleTarget => {}
                crate::engine::AuthenticatedCancellationStatus::Unavailable => {
                    return Err("authenticated evaluation cancellation became unavailable".into());
                }
                crate::engine::AuthenticatedCancellationStatus::Failed => {
                    return Err("authenticated evaluation cancellation failed".into());
                }
            }
        }

        let event = ReplInterruptEvent {
            terminal_status: decision.status,
            successful_termination: decision.status_class == Some(generated::StatusClass::Orderly),
            discard_buffer: decision.buffer == generated::BufferAction::DiscardInvalidate,
            discard_submission: !matches!(
                decision.submission,
                generated::SubmissionAction::Unchanged
            ),
        };
        // A terminal decision while an exact unit is still active must not
        // wait for that unit to cooperate. Suspended evaluations and due work
        // deliberately have no cancellation target, and an evaluation can be
        // wedged before its Begin publication, so the engine-independent path
        // is selected for every terminal decision made while work is live or
        // a submission owner is blocked awaiting settlement.
        // @ref LLP 0025#6-interruption-and-cancellation
        let force_exit =
            interrupt_requires_engine_independent_exit(&decision, phase_at_dispatch, &live_work);
        Ok((event, force_exit))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ReplInterruptState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(unix)]
fn generated_interrupt_work_kind(kind: crate::repl::ReplInterruptWorkKind) -> generated::WorkKind {
    match kind {
        crate::repl::ReplInterruptWorkKind::Evaluation => generated::WorkKind::Evaluation,
        crate::repl::ReplInterruptWorkKind::Callback => generated::WorkKind::Callback,
        crate::repl::ReplInterruptWorkKind::Completion => generated::WorkKind::Completion,
    }
}

#[cfg(unix)]
fn interrupt_requires_engine_independent_exit(
    decision: &generated::InterruptDecision,
    phase: generated::EditorPhase,
    live_work: &crate::repl::ReplInterruptWorkSnapshot,
) -> bool {
    decision.terminal && (live_work.has_live_work() || phase == generated::EditorPhase::Evaluating)
}

#[cfg(unix)]
fn spawn_repl_input_reader(
    witness: PromptWitness,
    interrupt: ReplInterruptController,
    terminal_signals: Option<UnixSessionSignalHandle>,
) -> io::Result<tokio::sync::mpsc::UnboundedReceiver<ReplInputEvent>> {
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
    thread::Builder::new()
        .name("ibex-repl-input".to_string())
        .spawn(move || {
            let mut input = io::stdin();
            let mut byte = [0_u8; 1];
            let mut paste_signals = RawBracketedPasteSignalGate::default();
            loop {
                match input.read(&mut byte) {
                    Ok(0) => {
                        let _ = events_tx.send(ReplInputEvent::Eof);
                        break;
                    }
                    Ok(_) => {
                        let pasted = paste_signals.feed(byte[0]);
                        if !pasted && is_generated_interrupt_byte(byte[0]) {
                            match interrupt.dispatch() {
                                Ok((event, force_exit)) => {
                                    let status = event.terminal_status;
                                    if events_tx.send(ReplInputEvent::Interrupt(event)).is_err() {
                                        break;
                                    }
                                    if force_exit {
                                        // SAFETY: this is the generated machine's
                                        // terminal escalation path. Restoration
                                        // must precede the broker's bounded flush
                                        // because its destination may be stalled.
                                        unsafe {
                                            SIGNAL_RESTORE_STATE.restore_from_signal();
                                        }
                                        // The input/supervisor thread owns the
                                        // engine-independent escape. Kill the exact
                                        // worker before flushing its relays; never
                                        // let `_exit` orphan a stuck evaluator.
                                        interrupt.terminate_worker_for_escape();
                                        interrupt.broker.force_finish();
                                        // SAFETY: restoration and the bounded
                                        // broker flush have completed (or timed
                                        // out), so no process cleanup remains.
                                        unsafe {
                                            libc::_exit(status.unwrap_or(EXIT_STATUS_INTERRUPT));
                                        }
                                    }
                                }
                                Err(error) => {
                                    let _ = events_tx.send(ReplInputEvent::Error(error));
                                    break;
                                }
                            }
                            continue;
                        }
                        if !pasted
                            && matches!(
                                crate::repl_surface::keybinding_for_bytes(&byte)
                                    .map(|binding| binding.action),
                                Some(crate::repl_surface::KeybindingAction::SuspendTransaction)
                            )
                            && terminal_signals.is_some()
                        {
                            terminal_signals
                                .expect("guarded terminal signal handle")
                                .request_suspend();
                            continue;
                        }
                        let _ = events_tx.send(ReplInputEvent::Byte {
                            byte: byte[0],
                            observed_prompt: witness.observe(),
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let _ = events_tx.send(ReplInputEvent::Error(error.to_string()));
                        break;
                    }
                }
            }
        })?;
    Ok(events_rx)
}

/// Mirrors only the bracketed-paste boundary needed by the input thread's
/// signal classification. The full decoder still runs on the editor thread;
/// this gate merely prevents paste payload bytes from becoming Ctrl+C/Ctrl+Z
/// control actions while an evaluation has that thread blocked.
#[cfg(unix)]
#[derive(Default)]
struct RawBracketedPasteSignalGate {
    in_paste: bool,
    escape: Vec<u8>,
}

#[cfg(unix)]
impl RawBracketedPasteSignalGate {
    /// Returns whether `byte` belongs to a bracketed-paste payload and must be
    /// delivered as inert editor data instead of classified as a signal key.
    fn feed(&mut self, byte: u8) -> bool {
        const START: &[u8] = b"\x1b[200~";
        const END: &[u8] = b"\x1b[201~";

        let was_in_paste = self.in_paste;
        if self.escape.is_empty() && byte != 0x1b {
            return was_in_paste;
        }
        self.escape.push(byte);
        let target = if self.in_paste { END } else { START };
        if target.starts_with(&self.escape) {
            if self.escape == target {
                self.in_paste = !self.in_paste;
                self.escape.clear();
            }
        } else {
            self.escape.clear();
        }
        was_in_paste
    }
}

#[cfg(unix)]
async fn run_repl_unix(
    plan: SessionIoPlan,
    mut session: crate::repl::ReplEvaluationSession,
    mut driver: crate::repl::session::ReplDriver,
    history: crate::history::HistorySession,
    worker_relays: Option<crate::session_worker::WorkerRelays>,
) -> anyhow::Result<i32> {
    use anyhow::Context as _;

    if plan.route.entry_kind != ArmedEntryKind::Repl
        || !matches!(
            plan.route.mode,
            ArmedExecutionMode::Interactive | ArmedExecutionMode::Transcript
        )
        || session.mode() != plan.route.mode
        || session.presentation() != plan.presentation
    {
        return Err(ExecutionAdapterGap::ReadinessRouteMismatch.into());
    }
    if !session.cancellation_port().is_available() {
        return Err(ExecutionAdapterGap::SupervisorOwnedEditorUnavailable.into());
    }

    let mut active = ActiveReplCapture::start(plan, worker_relays)
        .context("failed to construct the REPL terminal/output adapter")?;
    let prompt_witness = (plan.presentation.editor_control
        && plan.route.mode == ArmedExecutionMode::Interactive)
        .then(PromptWitness::default);
    let non_editor_interrupt = (!plan.presentation.editor_control)
        .then(|| NonEditorWorkerInterruptControl::Repl(session.cancellation_port()));
    let mut terminal_signals = start_worker_terminal_signal_coordinator(
        &mut active,
        session.worker_terminal_control(),
        prompt_witness.clone(),
        non_editor_interrupt,
    )
    .context("failed to start the REPL terminal signal coordinator")?;
    let terminal_signal_handle = terminal_signals
        .as_ref()
        .map(WorkerTerminalSignalCoordinator::handle);
    let readiness = mint_execution_adapter_ready(&mut active.lease, plan.route);
    execution_adapter_status_with_readiness(plan, Some(&readiness)).map_err(anyhow::Error::from)?;
    let broker = active.broker.clone();
    let result =
        if plan.presentation.editor_control && plan.route.mode == ArmedExecutionMode::Interactive {
            run_interactive_repl(
                &mut session,
                &mut driver,
                broker,
                active.terminal.clone(),
                plan.presentation,
                prompt_witness.expect("interactive REPL has a prompt witness"),
                terminal_signal_handle,
                history,
            )
            .await
        } else {
            // `HistorySession::open` is a no-I/O disabled handle whenever the
            // immutable presentation lacks an editor. Dropping it here keeps
            // transcript/program routes entirely outside history behavior.
            drop(history);
            run_plain_repl(&mut session, &mut driver, broker).await
        };
    drop(readiness);
    // Restoration is the first exit-side action. Only after cooked mode is
    // back may a lifecycle cutoff block on a stalled program destination or
    // the supervisor dispose a parked/stuck evaluator.
    if let Some(signals) = terminal_signals.as_ref() {
        signals.request_shutdown();
    }
    let restore = active
        .restore_terminal()
        .context("failed to restore the REPL terminal before worker disposal");
    let signal_finish = match terminal_signals.take() {
        Some(signals) => signals
            .finish()
            .context("failed to finish the REPL terminal signal coordinator"),
        None => Ok(()),
    };
    active.disarm_session_signals();
    let mut unreportable_output_loss = false;
    for barrier in [
        session.take_worker_outcome_barrier(),
        session.take_worker_lifecycle_barrier(),
    ] {
        if let Some((stdout_cutoff, stderr_cutoff)) = barrier {
            if let Err(error) = active.broker.worker_barrier(stdout_cutoff, stderr_cutoff) {
                unreportable_output_loss |= error.is_output_loss();
                let _ = active
                    .broker
                    .diagnostic(&format!("worker output barrier failed: {error}"));
            }
        }
    }
    let _restore_error = restore.err();
    let _signal_error = signal_finish.err();
    let _dispose_error = session.dispose_worker_preserving_lifecycle().err();
    match active.finish_report() {
        Ok(loss) => unreportable_output_loss |= loss.has_loss(),
        Err(_) => unreportable_output_loss = true,
    }
    match result {
        Ok(settlement) => Ok(settlement.final_status(unreportable_output_loss)),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TranscriptRecordRead {
    Eof,
    Record,
    Oversize,
}

#[cfg(unix)]
fn read_bounded_transcript_record(
    input: &mut impl std::io::BufRead,
    record: &mut Vec<u8>,
) -> io::Result<TranscriptRecordRead> {
    let bound = ibex_runtime::session_constants::MAX_INPUT_BYTES;
    record.clear();
    let mut oversize = false;
    let mut observed = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Ok(if !observed {
                TranscriptRecordRead::Eof
            } else if oversize {
                TranscriptRecordRead::Oversize
            } else {
                TranscriptRecordRead::Record
            });
        }
        observed = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let payload_len = newline.unwrap_or(available.len());
        if !oversize {
            let remaining = bound.saturating_sub(record.len());
            let accepted = payload_len.min(remaining);
            record.extend_from_slice(&available[..accepted]);
            oversize = payload_len > remaining;
        }
        let consumed = newline.map_or(payload_len, |index| index + 1);
        input.consume(consumed);
        if newline.is_some() {
            return Ok(if oversize {
                TranscriptRecordRead::Oversize
            } else {
                TranscriptRecordRead::Record
            });
        }
    }
}

#[cfg(unix)]
async fn run_plain_repl(
    session: &mut crate::repl::ReplEvaluationSession,
    driver: &mut crate::repl::session::ReplDriver,
    broker: ReplBrokerHandle,
) -> anyhow::Result<InlineSettlement> {
    let lifecycle = session.session_lifecycle();
    let mut input = io::BufReader::new(io::stdin());
    let mut record = Vec::with_capacity(ibex_runtime::session_constants::MAX_INPUT_BYTES);
    loop {
        match read_bounded_transcript_record(&mut input, &mut record)? {
            TranscriptRecordRead::Eof => {
                let step = driver.finish_transcript();
                if let Some(settlement) = render_repl_step(session, &broker, step).await? {
                    return Ok(settlement);
                }
                break;
            }
            TranscriptRecordRead::Oversize => {
                driver.abandon_continuation();
                broker
                    .session_line(
                        &format!(
                            "repl-input-too-large: input exceeds the {}-byte session limit",
                            ibex_runtime::session_constants::MAX_INPUT_BYTES
                        ),
                        SessionStyle::Error,
                    )
                    .map_err(anyhow::Error::msg)?;
                continue;
            }
            TranscriptRecordRead::Record => {}
        }
        if record.last() == Some(&b'\r') {
            record.pop();
        }
        let line = match std::str::from_utf8(&record) {
            Ok(line) => line,
            Err(error) => {
                broker
                    .session_line(
                        &format!("repl-invalid-utf8: input is not UTF-8: {error}"),
                        SessionStyle::Error,
                    )
                    .map_err(anyhow::Error::msg)?;
                // A newline is not an authenticated resynchronization frame:
                // after an undecodable transcript record the session cannot
                // prove where the next source submission begins. Refuse the
                // transcript instead of recovering onto attacker-shaped
                // bytes. @ref LLP 0025#8-exit-and-lifecycle
                return Ok(InlineSettlement::Fixed(1));
            }
        };
        let step = driver.submit_line(session, line).await;
        if let Some(settlement) = render_repl_step(session, &broker, step).await? {
            return Ok(settlement);
        }
        if let Some(request) = lifecycle.take_pending_request() {
            return Ok(InlineSettlement::Successful(request.status));
        }
        let failures = match session.drive_ready_tasks().await {
            Ok(failures) => failures,
            Err(error) => {
                if let Some(request) = lifecycle.take_pending_request() {
                    return Ok(InlineSettlement::Successful(request.status));
                }
                broker
                    .session_line(
                        &format!("engine fault: ready-work checkpoint failed: {error:#}"),
                        SessionStyle::Error,
                    )
                    .map_err(anyhow::Error::msg)?;
                return Ok(InlineSettlement::Fixed(EXIT_STATUS_ENGINE_FAULT));
            }
        };
        if let Some((stdout_cutoff, stderr_cutoff)) = session.take_worker_outcome_barrier() {
            broker
                .worker_barrier(stdout_cutoff, stderr_cutoff)
                .map_err(anyhow::Error::new)?;
        }
        for error in failures {
            broker
                .session_line(
                    &format!("asynchronous task failed: {error:#}"),
                    SessionStyle::Error,
                )
                .map_err(anyhow::Error::msg)?;
        }
    }
    if let Some(request) = lifecycle.take_pending_request() {
        Ok(InlineSettlement::Successful(request.status))
    } else {
        use ibex_runtime::session_lifecycle::{LifecycleGetDisposition, LifecyclePrincipal};
        Ok(InlineSettlement::Successful(
            match lifecycle.get_exit_code(LifecyclePrincipal::Root) {
                LifecycleGetDisposition::Value(status) => status,
                LifecycleGetDisposition::Denied => 0,
            },
        ))
    }
}

#[cfg(unix)]
#[derive(Default)]
struct BracketedPasteDecoder {
    in_paste: bool,
    escape: Vec<u8>,
}

#[cfg(unix)]
enum DecodedEditorByte {
    Key(u8),
    Data(Vec<u8>),
}

#[cfg(unix)]
impl BracketedPasteDecoder {
    fn feed(&mut self, byte: u8) -> Option<DecodedEditorByte> {
        const START: &[u8] = b"\x1b[200~";
        const END: &[u8] = b"\x1b[201~";
        if self.escape.is_empty() && byte != 0x1b {
            if self.in_paste {
                return Some(DecodedEditorByte::Data(vec![if byte == b'\r' {
                    b'\n'
                } else {
                    byte
                }]));
            }
            return Some(DecodedEditorByte::Key(byte));
        }
        self.escape.push(byte);
        let target = if self.in_paste { END } else { START };
        if target.starts_with(&self.escape) {
            if self.escape == target {
                self.in_paste = !self.in_paste;
                self.escape.clear();
            }
            return None;
        }
        let escaped = std::mem::take(&mut self.escape);
        if self.in_paste {
            Some(DecodedEditorByte::Data(escaped))
        } else {
            // Unknown terminal control sequences are editor input, not source.
            None
        }
    }
}

#[cfg(unix)]
async fn run_interactive_repl(
    session: &mut crate::repl::ReplEvaluationSession,
    driver: &mut crate::repl::session::ReplDriver,
    broker: ReplBrokerHandle,
    terminal: Arc<Mutex<UnixTerminalLifecycle>>,
    presentation: CapturedPresentation,
    witness: PromptWitness,
    terminal_signals: Option<UnixSessionSignalHandle>,
    mut history: crate::history::HistorySession,
) -> anyhow::Result<InlineSettlement> {
    let lifecycle = session.session_lifecycle();
    let interrupt = ReplInterruptController::new(
        session.cancellation_port(),
        lifecycle.clone(),
        broker.clone(),
    );
    let mut input = spawn_repl_input_reader(witness.clone(), interrupt.clone(), terminal_signals)?;
    let mut prompt_cycle = PromptCycle(1);
    let mut buffer = Vec::new();
    let mut paste = BracketedPasteDecoder::default();
    let mut history_search = ReverseHistorySearch::default();

    for line in [
        format!("Ibex v{} (Hermes)", env!("CARGO_PKG_VERSION")),
        "Type .help for help; Ctrl+D or .exit exits".to_string(),
    ] {
        broker
            .session_line(&line, SessionStyle::Notice)
            .map_err(anyhow::Error::msg)?;
    }
    for diagnostic in history.startup_diagnostics() {
        broker
            .session_line(&format!("history: {diagnostic}"), SessionStyle::Notice)
            .map_err(anyhow::Error::msg)?;
    }
    witness
        .publish_prompt(prompt_cycle, &buffer, &broker)
        .map_err(anyhow::Error::msg)?;

    loop {
        let event = tokio::select! {
            event = input.recv() => event,
            () = session.wait_for_pending_tasks() => {
                let failures = match session.drive_ready_tasks().await {
                    Ok(failures) => failures,
                    Err(error) => {
                        if let Some(request) = lifecycle.take_pending_request() {
                            interrupt.latch_cause(request.status);
                            return Ok(InlineSettlement::Successful(request.status));
                        }
                        broker.session_line(
                            &format!("engine fault: ready-work checkpoint failed: {error:#}"),
                            SessionStyle::Error,
                        ).map_err(anyhow::Error::msg)?;
                        interrupt.latch_cause(EXIT_STATUS_ENGINE_FAULT);
                        return Ok(InlineSettlement::Fixed(EXIT_STATUS_ENGINE_FAULT));
                    }
                };
                if let Some((stdout_cutoff, stderr_cutoff)) =
                    session.take_worker_outcome_barrier()
                {
                    broker
                        .worker_barrier(stdout_cutoff, stderr_cutoff)
                        .map_err(anyhow::Error::new)?;
                }
                for error in failures {
                    broker.session_line(
                        &format!("asynchronous task failed: {error:#}"),
                        SessionStyle::Error,
                    ).map_err(anyhow::Error::msg)?;
                }
                if let Some(request) = lifecycle.take_pending_request() {
                    interrupt.latch_cause(request.status);
                    return Ok(InlineSettlement::Successful(request.status));
                }
                continue;
            }
        };
        let Some(event) = event else {
            break;
        };
        match event {
            ReplInputEvent::Error(error) => anyhow::bail!("REPL input reader failed: {error}"),
            ReplInputEvent::Eof => {
                if buffer.is_empty() {
                    return Ok(InlineSettlement::Successful(operator_exit_status(session)?));
                }
            }
            ReplInputEvent::Interrupt(event) => {
                if event.discard_buffer {
                    buffer.clear();
                    driver.abandon_continuation();
                    prompt_cycle = PromptCycle(prompt_cycle.0.saturating_add(1));
                    witness
                        .publish_prompt(prompt_cycle, &buffer, &broker)
                        .map_err(anyhow::Error::msg)?;
                }
                if event.discard_submission {
                    // The exact native cancellation has already been issued by
                    // the reader. Its typed outcome is consumed by the in-flight
                    // submit path before another source can dispatch.
                }
                if let Some(status) = event.terminal_status {
                    interrupt.latch_cause(status);
                    return Ok(if event.successful_termination {
                        InlineSettlement::Successful(status)
                    } else {
                        InlineSettlement::Fixed(status)
                    });
                }
            }
            ReplInputEvent::Byte {
                byte,
                observed_prompt,
            } => {
                let Some(decoded) = paste.feed(byte) else {
                    continue;
                };
                match decoded {
                    DecodedEditorByte::Data(bytes) => {
                        history_search.reset();
                        if buffer.len().saturating_add(bytes.len())
                            > ibex_runtime::session_constants::MAX_INPUT_BYTES
                        {
                            broker
                                .session_line(
                                    "repl-input-too-large: input exceeds the 1 MiB session limit",
                                    SessionStyle::Error,
                                )
                                .map_err(anyhow::Error::msg)?;
                        } else {
                            buffer.extend_from_slice(&bytes);
                            witness
                                .publish_prompt(prompt_cycle, &buffer, &broker)
                                .map_err(anyhow::Error::msg)?;
                        }
                    }
                    DecodedEditorByte::Key(key) => {
                        let fresh = observed_prompt == Some(prompt_cycle);
                        if fresh && generated_counts_as_editor_input(key) {
                            interrupt.note_fresh_editor_input();
                        }
                        if matches!(key, b'\r' | b'\n') {
                            history_search.reset();
                            witness.publish(prompt_cycle, false);
                            broker.boundary().map_err(anyhow::Error::msg)?;
                            let submitted = std::mem::take(&mut buffer);
                            let line = match String::from_utf8(submitted) {
                                Ok(line) => line,
                                Err(error) => {
                                    broker
                                        .session_line(
                                            &format!(
                                                "repl-invalid-utf8: input is not UTF-8: {}",
                                                error.utf8_error()
                                            ),
                                            SessionStyle::Error,
                                        )
                                        .map_err(anyhow::Error::msg)?;
                                    prompt_cycle = PromptCycle(prompt_cycle.0.saturating_add(1));
                                    witness
                                        .publish_prompt(prompt_cycle, &buffer, &broker)
                                        .map_err(anyhow::Error::msg)?;
                                    continue;
                                }
                            };
                            interrupt.set_phase(
                                generated::EditorPhase::Evaluating,
                                generated::PendingSubmission::Dispatched,
                            );
                            let mut history_disposition = None;
                            let step = driver
                                .submit_line_with_hook(session, &line, |source| {
                                    history_disposition = Some(history.append_submission(source));
                                })
                                .await;
                            report_history_append(&broker, history_disposition)?;
                            if let Some(settlement) =
                                render_repl_step(session, &broker, step).await?
                            {
                                interrupt.latch_cause(settlement.status());
                                return Ok(settlement);
                            }
                            if let Some(request) = lifecycle.take_pending_request() {
                                interrupt.latch_cause(request.status);
                                return Ok(InlineSettlement::Successful(request.status));
                            }
                            let phase = if driver.is_continuation() {
                                generated::EditorPhase::Continuation
                            } else {
                                generated::EditorPhase::Idle
                            };
                            interrupt.set_phase(phase, generated::PendingSubmission::None);
                            prompt_cycle = PromptCycle(prompt_cycle.0.saturating_add(1));
                            witness
                                .publish_prompt(prompt_cycle, &buffer, &broker)
                                .map_err(anyhow::Error::msg)?;
                        } else if matches!(key, 0x08 | 0x7f) {
                            history_search.reset();
                            pop_last_utf8_unit(&mut buffer);
                            witness
                                .publish_prompt(prompt_cycle, &buffer, &broker)
                                .map_err(anyhow::Error::msg)?;
                        } else if let Some(binding) =
                            crate::repl_surface::keybinding_for_bytes(&[key])
                        {
                            use crate::repl_surface::KeybindingAction;
                            match binding.action {
                                KeybindingAction::BoundedAsynchronousCompletion => {
                                    history_search.reset();
                                    complete_static_input(
                                        driver,
                                        &mut buffer,
                                        &broker,
                                        &witness,
                                        prompt_cycle,
                                    )?;
                                }
                                KeybindingAction::OrderlyEofOrDeleteForward => {
                                    history_search.reset();
                                    if buffer.is_empty() {
                                        return Ok(InlineSettlement::Successful(
                                            operator_exit_status(session)?,
                                        ));
                                    }
                                }
                                KeybindingAction::ReverseHistorySearch => {
                                    reverse_history_search(
                                        &history,
                                        &mut history_search,
                                        &mut buffer,
                                        &broker,
                                        &witness,
                                        prompt_cycle,
                                    )?;
                                }
                                KeybindingAction::SuspendTransaction => {
                                    history_search.reset();
                                    if let Some(signals) = terminal_signals {
                                        signals.request_suspend();
                                    } else {
                                        suspend_repl_terminal(
                                            &terminal,
                                            presentation,
                                            &witness,
                                            &broker,
                                        )?;
                                    }
                                }
                                KeybindingAction::InterruptMachine => {
                                    unreachable!("interrupt bytes are consumed by the reader")
                                }
                            }
                        } else if key >= 0x20 {
                            history_search.reset();
                            if buffer.len() < ibex_runtime::session_constants::MAX_INPUT_BYTES {
                                buffer.push(key);
                            }
                            witness
                                .publish_prompt(prompt_cycle, &buffer, &broker)
                                .map_err(anyhow::Error::msg)?;
                        }
                    }
                }
            }
        }
    }
    interrupt.end();
    operator_exit_status(session).map(InlineSettlement::Successful)
}

#[cfg(unix)]
#[derive(Default)]
struct ReverseHistorySearch {
    query: Option<String>,
    before: Option<usize>,
}

#[cfg(unix)]
impl ReverseHistorySearch {
    fn reset(&mut self) {
        self.query = None;
        self.before = None;
    }
}

#[cfg(unix)]
fn reverse_history_search(
    history: &crate::history::HistorySession,
    search: &mut ReverseHistorySearch,
    buffer: &mut Vec<u8>,
    broker: &ReplBrokerHandle,
    witness: &PromptWitness,
    prompt_cycle: PromptCycle,
) -> anyhow::Result<()> {
    if search.query.is_none() {
        let Ok(query) = std::str::from_utf8(buffer) else {
            return Ok(());
        };
        search.query = Some(query.to_owned());
    }
    let query = search.query.as_deref().unwrap_or_default();
    if let Some((index, entry)) = history.reverse_search(query, search.before) {
        buffer.clear();
        buffer.extend_from_slice(entry.as_bytes());
        search.before = Some(index);
    } else {
        broker
            .session_line("history: no earlier match", SessionStyle::Notice)
            .map_err(anyhow::Error::msg)?;
    }
    witness
        .publish_prompt(prompt_cycle, buffer, broker)
        .map_err(anyhow::Error::msg)
}

#[cfg(unix)]
fn report_history_append(
    broker: &ReplBrokerHandle,
    disposition: Option<crate::history::HistoryAppendDisposition>,
) -> anyhow::Result<()> {
    if let Some(crate::history::HistoryAppendDisposition::Skipped(diagnostic)) = disposition {
        broker
            .session_line(&format!("history: {diagnostic}"), SessionStyle::Notice)
            .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

#[cfg(unix)]
fn pop_last_utf8_unit(buffer: &mut Vec<u8>) {
    if buffer.pop().is_none() {
        return;
    }
    while buffer
        .last()
        .is_some_and(|byte| byte & 0b1100_0000 == 0b1000_0000)
    {
        buffer.pop();
    }
}

#[cfg(unix)]
fn complete_static_input(
    driver: &crate::repl::session::ReplDriver,
    buffer: &mut Vec<u8>,
    broker: &ReplBrokerHandle,
    witness: &PromptWitness,
    prompt_cycle: PromptCycle,
) -> anyhow::Result<()> {
    let Ok(line) = std::str::from_utf8(buffer) else {
        return Ok(());
    };
    let candidates = driver.completion_candidates(line, line.len());
    if candidates.len() == 1 && candidates[0].starts_with(line) {
        buffer.extend_from_slice(&candidates[0].as_bytes()[line.len()..]);
        witness
            .publish_prompt(prompt_cycle, buffer, broker)
            .map_err(anyhow::Error::msg)?;
    } else if !candidates.is_empty() {
        for candidate in candidates {
            broker
                .session_line(&candidate, SessionStyle::Plain)
                .map_err(anyhow::Error::msg)?;
        }
        witness
            .publish_prompt(prompt_cycle, buffer, broker)
            .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

#[cfg(unix)]
fn suspend_repl_terminal(
    terminal: &Arc<Mutex<UnixTerminalLifecycle>>,
    presentation: CapturedPresentation,
    witness: &PromptWitness,
    broker: &ReplBrokerHandle,
) -> anyhow::Result<()> {
    terminal
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .restore_session()
        .map_err(anyhow::Error::msg)?;
    // SAFETY: SIGTSTP is delivered to this process after cooked-mode restore.
    let result = unsafe { libc::raise(libc::SIGTSTP) };
    if result != 0 {
        anyhow::bail!("failed to suspend the REPL: {}", io::Error::last_os_error());
    }
    terminal
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .enter_session(presentation)
        .map_err(anyhow::Error::msg)?;
    witness.redraw(broker).map_err(anyhow::Error::msg)
}

#[cfg(unix)]
fn operator_exit_status(session: &mut crate::repl::ReplEvaluationSession) -> anyhow::Result<i32> {
    use ibex_runtime::session_lifecycle::LifecycleRequestDisposition;
    match session.request_operator_exit() {
        LifecycleRequestDisposition::Accepted { request } => Ok(request.status),
        LifecycleRequestDisposition::AlreadyInProgress => session
            .session_lifecycle()
            .latched_request()
            .map(|request| request.status)
            .ok_or_else(|| anyhow::anyhow!("operator exit was sealed without a lifecycle record")),
        LifecycleRequestDisposition::Denied => {
            anyhow::bail!("operator exit was denied by the typed lifecycle route")
        }
    }
}

#[cfg(unix)]
async fn render_repl_step(
    session: &mut crate::repl::ReplEvaluationSession,
    broker: &ReplBrokerHandle,
    step: crate::repl::session::ReplStep,
) -> anyhow::Result<Option<InlineSettlement>> {
    use crate::repl::session::ReplStep;
    if let Some((stdout_cutoff, stderr_cutoff)) = session.take_worker_outcome_barrier() {
        broker
            .worker_barrier(stdout_cutoff, stderr_cutoff)
            .map_err(anyhow::Error::new)?;
    }
    match step {
        ReplStep::Idle | ReplStep::Continuation => Ok(None),
        ReplStep::Evaluation { result, .. } | ReplStep::Loaded { result } => {
            render_authenticated_evaluation(session, broker, result).await
        }
        ReplStep::TimedEvaluation {
            result, elapsed, ..
        } => {
            let status = render_authenticated_evaluation(session, broker, result).await?;
            if status.is_none() {
                broker
                    .session_line(
                        &format!("elapsed {:.3} ms", elapsed.as_secs_f64() * 1000.0),
                        SessionStyle::Notice,
                    )
                    .map_err(anyhow::Error::msg)?;
            }
            Ok(status)
        }
        ReplStep::Help(help) => {
            for line in help.lines() {
                broker
                    .session_line(line, SessionStyle::Plain)
                    .map_err(anyhow::Error::msg)?;
            }
            Ok(None)
        }
        ReplStep::Clear => {
            broker.clear().map_err(anyhow::Error::msg)?;
            Ok(None)
        }
        ReplStep::Mounts(description) => {
            broker
                .session_line(
                    &format!("cwd {}", description.virtual_cwd()),
                    SessionStyle::Plain,
                )
                .map_err(anyhow::Error::msg)?;
            for mount in description.mounts() {
                broker
                    .session_line(
                        &format!(
                            "{} -> {:?} ({:?})",
                            mount.virtual_path(),
                            mount.logical_root(),
                            mount.attributes()
                        ),
                        SessionStyle::Plain,
                    )
                    .map_err(anyhow::Error::msg)?;
            }
            Ok(None)
        }
        ReplStep::Exit => operator_exit_status(session)
            .map(InlineSettlement::Successful)
            .map(Some),
        ReplStep::Diagnostic(diagnostic) => {
            broker
                .session_line(
                    &format!("{}: {}", diagnostic.code, diagnostic.message),
                    SessionStyle::Error,
                )
                .map_err(anyhow::Error::msg)?;
            Ok(None)
        }
    }
}

#[cfg(unix)]
async fn render_authenticated_evaluation(
    session: &mut crate::repl::ReplEvaluationSession,
    broker: &ReplBrokerHandle,
    result: std::result::Result<crate::repl::ReplEvaluation, crate::runtime::ReplEvaluationFailure>,
) -> anyhow::Result<Option<InlineSettlement>> {
    use crate::repl::{ReplDisplay, ReplEvaluation};
    match result {
        Err(error) => {
            let is_engine_fault = error.is_engine_fault();
            broker
                .session_line(
                    &format!(
                        "{}: {error:#}",
                        if is_engine_fault {
                            "engine fault"
                        } else {
                            "evaluation refused"
                        }
                    ),
                    SessionStyle::Error,
                )
                .map_err(anyhow::Error::msg)?;
            Ok(is_engine_fault.then_some(InlineSettlement::Fixed(EXIT_STATUS_ENGINE_FAULT)))
        }
        Ok(ReplEvaluation::Empty | ReplEvaluation::Cancelled) => Ok(None),
        Ok(ReplEvaluation::Lifecycle(status)) => {
            if let Some((stdout_cutoff, stderr_cutoff)) = session.take_worker_lifecycle_barrier() {
                broker
                    .worker_barrier(stdout_cutoff, stderr_cutoff)
                    .map_err(anyhow::Error::new)?;
            }
            Ok(Some(InlineSettlement::Successful(status)))
        }
        Ok(ReplEvaluation::Throw(thrown)) => {
            broker
                .session_line(&thrown.value.text, SessionStyle::Error)
                .map_err(anyhow::Error::msg)?;
            if let Some(message) = thrown.metadata.message() {
                broker
                    .session_line(message, SessionStyle::Error)
                    .map_err(anyhow::Error::msg)?;
            }
            if let Some(stack) = thrown.metadata.stack() {
                for line in stack.lines() {
                    broker
                        .session_line(line, SessionStyle::Error)
                        .map_err(anyhow::Error::msg)?;
                }
            }
            for position in thrown.metadata.positions() {
                broker
                    .session_line(
                        &format!(
                            "at {}:{}:{}",
                            position.source_label, position.line, position.column
                        ),
                        SessionStyle::Error,
                    )
                    .map_err(anyhow::Error::msg)?;
            }
            Ok(None)
        }
        Ok(ReplEvaluation::Value { display, receipt }) => {
            crate::host::abi::ex_host_console_flush(BROKER_FLUSH_BUDGET_MILLIS as u32);
            let worker_barrier = match receipt.as_ref() {
                Some(crate::repl::ReplDisplayReceipt::Worker {
                    stdout_cutoff,
                    stderr_cutoff,
                    ..
                }) => Some(WorkerRelayBarrier {
                    stdout_cutoff: *stdout_cutoff,
                    stderr_cutoff: *stderr_cutoff,
                }),
                _ => None,
            };
            let encoded = match display {
                ReplDisplay::Local(display) => encode_authenticated_display(&display),
                ReplDisplay::Worker(wire) => Ok(wire),
            };
            let (local_disposition, display_error) = match encoded {
                Ok(wire) => match broker.display(wire, worker_barrier) {
                    Ok(disposition) => (disposition, None),
                    Err(error) => (DisplayDisposition::WriteFailed, Some(error)),
                },
                Err(error) => (
                    DisplayDisposition::Fallback,
                    Some(ReplDisplayFailure::Broker(error.to_string())),
                ),
            };
            if let Some(receipt) = receipt {
                let engine_disposition = match local_disposition {
                    DisplayDisposition::Displayed => crate::engine::DisplayDisposition::Displayed,
                    DisplayDisposition::Fallback => crate::engine::DisplayDisposition::Fallback,
                    DisplayDisposition::WriteFailed => {
                        crate::engine::DisplayDisposition::WriteFailed
                    }
                };
                if let Err(error) = session
                    .acknowledge_display(receipt, engine_disposition)
                    .await
                {
                    broker
                        .session_line(
                            &format!("engine fault: display acknowledgement failed: {error:#}"),
                            SessionStyle::Error,
                        )
                        .map_err(anyhow::Error::msg)?;
                    return Ok(Some(InlineSettlement::Fixed(EXIT_STATUS_ENGINE_FAULT)));
                }
                if let Some((stdout_cutoff, stderr_cutoff)) = session.take_worker_outcome_barrier()
                {
                    broker
                        .worker_barrier(stdout_cutoff, stderr_cutoff)
                        .map_err(anyhow::Error::new)?;
                }
            }
            if let Some(error) = display_error {
                broker
                    .session_line(&format!("display fallback: {error}"), SessionStyle::Error)
                    .map_err(anyhow::Error::msg)?;
            } else {
                broker.boundary().map_err(anyhow::Error::msg)?;
            }
            Ok(None)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Principal {
    Root,
    Package,
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRequestDisposition {
    Accepted { status: i32 },
    AlreadyInProgress,
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleGetDisposition {
    Value(i32),
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleSetDisposition {
    Accepted { status: i32 },
    AlreadyInProgress,
    Denied,
}

#[derive(Debug)]
struct SessionLifecycleState {
    exit_code: i32,
    sealed: bool,
}

/// Cloneable lifecycle authority shared by the supervisor-side adapters.
///
/// The cell owns the supervisor-authoritative `exitCode` mirror and seals it
/// atomically with the first accepted cooperative request or any other latched
/// termination cause. Principal checks stay on all three operations so a
/// shared handle cannot become an unchecked lifecycle backdoor.
///
/// @ref LLP 0025#8-exit-and-lifecycle — exitCode is mirrored synchronously,
/// cooperative requests are root-only and idempotent, and later mutations do
/// not change an in-flight termination.
/// @ref LLP 0025#10-registry-obligations — request, getter, and setter have
/// separate typed dispositions.
#[derive(Clone, Debug)]
pub struct SessionLifecycleCell {
    inner: Arc<Mutex<SessionLifecycleState>>,
}

impl Default for SessionLifecycleCell {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionLifecycleState {
                exit_code: 0,
                sealed: false,
            })),
        }
    }
}

impl SessionLifecycleCell {
    pub fn request_exit(&self, principal: Principal, status: i32) -> LifecycleRequestDisposition {
        if principal != Principal::Root {
            return LifecycleRequestDisposition::Denied;
        }
        let mut state = self.lock_state();
        if state.sealed {
            return LifecycleRequestDisposition::AlreadyInProgress;
        }
        let status = normalize_exit_status(status);
        state.sealed = true;
        LifecycleRequestDisposition::Accepted { status }
    }

    pub fn get_exit_code(&self, principal: Principal) -> LifecycleGetDisposition {
        if principal != Principal::Root {
            return LifecycleGetDisposition::Denied;
        }
        LifecycleGetDisposition::Value(self.lock_state().exit_code)
    }

    pub fn set_exit_code(&self, principal: Principal, status: i32) -> LifecycleSetDisposition {
        if principal != Principal::Root {
            return LifecycleSetDisposition::Denied;
        }
        let mut state = self.lock_state();
        if state.sealed {
            return LifecycleSetDisposition::AlreadyInProgress;
        }
        let status = normalize_exit_status(status);
        state.exit_code = status;
        LifecycleSetDisposition::Accepted { status }
    }

    fn current_exit_code(&self) -> i32 {
        self.lock_state().exit_code
    }

    fn seal(&self) {
        self.lock_state().sealed = true;
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, SessionLifecycleState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterruptOutcome {
    pub row: Option<String>,
    pub terminal: bool,
    pub expedited: bool,
    pub status: Option<i32>,
    pub cancellation_target: Option<TargetId>,
    pub promise: PromiseClass,
}

#[derive(Debug, Eq, PartialEq)]
pub enum SessionError {
    InvalidState(&'static str),
    GeneratedDispatch(String),
    Terminal(String),
    Broker(String),
    Worker(String),
    Editor(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidState(message) => write!(f, "invalid terminal-session state: {message}"),
            Self::GeneratedDispatch(message) => {
                write!(f, "generated interrupt dispatch: {message}")
            }
            Self::Terminal(message) => write!(f, "terminal lifecycle: {message}"),
            Self::Broker(message) => write!(f, "output broker: {message}"),
            Self::Worker(message) => write!(f, "worker termination: {message}"),
            Self::Editor(message) => write!(f, "editor input: {message}"),
        }
    }
}

impl std::error::Error for SessionError {}

pub struct TerminalSessionSupervisor<T, S, C, W>
where
    T: TerminalLifecycle,
    S: NonBlockingRelaySink,
    C: ExactCancellation,
    W: WorkerTerminator,
{
    state: SessionState,
    lifecycle: SessionLifecycleCell,
    terminal: T,
    terminal_armed: bool,
    broker: InProcessOutputBroker<S>,
    broker_finished: bool,
    broker_loss: Option<BrokerLossAccounting>,
    cancellation: C,
    worker: W,
    prompt_witness: PromptWitness,
    prompt_text: String,
    next_cancellation_request: u64,
    last_target_id: Option<TargetId>,
    last_completion_request_id: Option<CompletionRequestId>,
}

impl<T, S, C, W> TerminalSessionSupervisor<T, S, C, W>
where
    T: TerminalLifecycle,
    S: NonBlockingRelaySink,
    C: ExactCancellation,
    W: WorkerTerminator,
{
    pub fn new(
        mut terminal: T,
        sink: S,
        cancellation: C,
        worker: W,
        presentation: CapturedPresentation,
        prompt_witness: PromptWitness,
        prompt_text: impl Into<String>,
    ) -> Result<Self, SessionError> {
        let broker = InProcessOutputBroker::new(
            sink,
            broker_routes_for_plan(presentation, OutputDestinationTopology::Split),
            broker_presentations_for(presentation),
        )
        .map_err(|error| SessionError::Broker(error.to_string()))?;
        terminal
            .enter_session(presentation)
            .map_err(SessionError::Terminal)?;
        let mut supervisor = Self {
            state: SessionState::default(),
            lifecycle: SessionLifecycleCell::default(),
            terminal,
            terminal_armed: true,
            broker,
            broker_finished: false,
            broker_loss: None,
            cancellation,
            worker,
            prompt_witness,
            prompt_text: prompt_text.into(),
            next_cancellation_request: 1,
            last_target_id: None,
            last_completion_request_id: None,
        };
        if let Err(error) = supervisor.publish_prompt() {
            let _ = supervisor.restore_terminal();
            return Err(error);
        }
        Ok(supervisor)
    }

    pub fn with_default_prompt(
        terminal: T,
        sink: S,
        cancellation: C,
        worker: W,
        presentation: CapturedPresentation,
        prompt_witness: PromptWitness,
    ) -> Result<Self, SessionError> {
        Self::new(
            terminal,
            sink,
            cancellation,
            worker,
            presentation,
            prompt_witness,
            PROMPT_DEFAULT_TEXT,
        )
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn broker(&self) -> &InProcessOutputBroker<S> {
        &self.broker
    }

    pub fn broker_loss(&self) -> Option<&BrokerLossAccounting> {
        self.broker_loss.as_ref()
    }

    pub fn lifecycle_cell(&self) -> SessionLifecycleCell {
        self.lifecycle.clone()
    }

    pub fn cancellation_port(&self) -> &C {
        &self.cancellation
    }

    pub fn worker_port(&self) -> &W {
        &self.worker
    }

    pub fn terminal_port(&self) -> &T {
        &self.terminal
    }

    fn publish_prompt(&mut self) -> Result<(), SessionError> {
        let next_cycle = self
            .state
            .prompt_cycle
            .0
            .checked_add(1)
            .filter(|cycle| *cycle <= PROMPT_CYCLE_MASK)
            .ok_or(SessionError::InvalidState("prompt-cycle space exhausted"))?;
        self.state.prompt_cycle = PromptCycle(next_cycle);
        self.state.prompt_live = true;
        if self.state.phase != EditorPhase::Editing && self.state.phase != EditorPhase::Continuation
        {
            self.state.phase = EditorPhase::Idle;
        }
        self.prompt_witness
            .publish(self.state.prompt_cycle, self.state.prompt_live);
        let write = self
            .broker
            .publish_prompt(&self.prompt_text, &self.state.buffer);
        self.accept_session_write(write)?;
        Ok(())
    }

    fn retire_prompt(&mut self) {
        self.state.prompt_live = false;
        self.prompt_witness
            .publish(self.state.prompt_cycle, self.state.prompt_live);
        self.broker.hide_prompt();
    }

    fn invalidate_input_generation(&mut self) -> Result<(), SessionError> {
        self.state.input_generation =
            self.state
                .input_generation
                .checked_add(1)
                .ok_or(SessionError::InvalidState(
                    "input-generation space exhausted",
                ))?;
        Ok(())
    }

    fn ensure_new_target(&self, target_id: TargetId) -> Result<(), SessionError> {
        if target_id.0 == 0
            || self
                .last_target_id
                .is_some_and(|published| target_id <= published)
        {
            return Err(SessionError::InvalidState(
                "work target ids must be nonzero and strictly monotonic",
            ));
        }
        Ok(())
    }

    fn publish_target(&mut self, target_id: TargetId) -> Result<(), SessionError> {
        self.ensure_new_target(target_id)?;
        self.last_target_id = Some(target_id);
        Ok(())
    }

    /// Forward one native editor event directly into the supervisor. In
    /// particular, the interrupt event is never rewritten as input text or a
    /// process-global signal action.
    pub fn poll_editor_port<P: EditorPort>(
        &mut self,
        editor: &mut P,
    ) -> Result<Option<InterruptOutcome>, SessionError> {
        let Some(event) = editor.try_next_event().map_err(SessionError::Editor)? else {
            return Ok(None);
        };
        self.handle_editor_event(event)
    }

    pub fn handle_editor_event(
        &mut self,
        event: EditorInputEvent,
    ) -> Result<Option<InterruptOutcome>, SessionError> {
        if self.state.ended {
            return Err(SessionError::InvalidState("session has ended"));
        }
        let is_interrupt = matches!(&event, EditorInputEvent::Interrupt)
            || matches!(
                &event,
                EditorInputEvent::Byte { byte, .. } if is_generated_interrupt_byte(*byte)
            );
        if self.state.phase == EditorPhase::Shutdown && !is_interrupt {
            return Ok(None);
        }
        match event {
            EditorInputEvent::Interrupt => self.handle_interrupt().map(Some),
            EditorInputEvent::Byte { byte, .. } if is_generated_interrupt_byte(byte) => {
                self.handle_interrupt().map(Some)
            }
            EditorInputEvent::Byte {
                byte,
                observed_prompt,
            } => {
                let fresh_prompt = self.state.prompt_live
                    && observed_prompt == Some(self.state.prompt_cycle)
                    && matches!(
                        self.state.phase,
                        EditorPhase::Idle | EditorPhase::Editing | EditorPhase::Continuation
                    );
                if fresh_prompt {
                    if generated_counts_as_editor_input(byte) {
                        self.state.escape_credit = 0;
                        self.state.promise = PromiseClass::None;
                    }
                    if byte >= 0x20 && byte != 0x7f {
                        self.state.buffer.push(byte);
                        self.invalidate_input_generation()?;
                        self.broker
                            .update_edit_buffer(&self.prompt_text, &self.state.buffer);
                        self.state.phase = EditorPhase::Editing;
                    }
                } else {
                    self.state.typed_ahead.push(StampedInputByte {
                        byte,
                        observed_prompt,
                    });
                }
                Ok(None)
            }
            EditorInputEvent::Eof => {
                self.request_orderly_shutdown()?;
                Ok(None)
            }
            EditorInputEvent::ReaderError(error) => Err(SessionError::Editor(error)),
        }
    }

    pub fn drain_typed_ahead(&mut self) -> Result<(), SessionError> {
        if !self.state.prompt_live {
            return Err(SessionError::InvalidState(
                "typed-ahead may be drained only at a live prompt",
            ));
        }
        let mut buffer_changed = false;
        for input in self.state.typed_ahead.drain(..) {
            if input.byte >= 0x20 && input.byte != 0x7f && !is_generated_interrupt_byte(input.byte)
            {
                self.state.buffer.push(input.byte);
                self.state.phase = EditorPhase::Editing;
                buffer_changed = true;
            }
        }
        if buffer_changed {
            self.invalidate_input_generation()?;
            self.broker
                .update_edit_buffer(&self.prompt_text, &self.state.buffer);
        }
        // Provenance is intentionally retained semantically: draining does not
        // clear the promise or escape credit.
        Ok(())
    }

    pub fn submit_buffer(&mut self) -> Result<(), SessionError> {
        if !self.state.prompt_live
            || !matches!(
                self.state.phase,
                EditorPhase::Editing | EditorPhase::Continuation
            )
        {
            return Err(SessionError::InvalidState(
                "submission requires an editing prompt",
            ));
        }
        self.retire_prompt();
        self.state.phase = EditorPhase::Evaluating;
        self.state.pending_submission = PendingSubmission::Undispatched;
        self.state.buffer.clear();
        self.invalidate_input_generation()?;
        self.broker
            .update_edit_buffer(&self.prompt_text, &self.state.buffer);
        Ok(())
    }

    pub fn dispatch_submission(&mut self) -> Result<(), SessionError> {
        if self.state.phase != EditorPhase::Evaluating
            || self.state.pending_submission != PendingSubmission::Undispatched
        {
            return Err(SessionError::InvalidState(
                "only an undispatched submission may dispatch",
            ));
        }
        self.state.pending_submission = PendingSubmission::Dispatched;
        Ok(())
    }

    pub fn queue_completion(
        &mut self,
        request_id: CompletionRequestId,
    ) -> Result<(), SessionError> {
        if !self.state.prompt_live
            || !matches!(
                self.state.phase,
                EditorPhase::Idle | EditorPhase::Editing | EditorPhase::Continuation
            )
        {
            return Err(SessionError::InvalidState(
                "completion requires a live editor prompt",
            ));
        }
        if request_id.0 == 0
            || self
                .last_completion_request_id
                .is_some_and(|published| request_id <= published)
        {
            return Err(SessionError::InvalidState(
                "completion request ids must be nonzero and strictly monotonic",
            ));
        }
        if self.state.live_units.completion_queued.is_some()
            || self
                .state
                .live_units
                .executing
                .is_some_and(|unit| unit.kind == WorkKind::Completion)
        {
            return Err(SessionError::InvalidState(
                "only one completion query may be live",
            ));
        }
        self.state.live_units.completion_queued = Some(QueuedCompletion {
            request_id,
            input_generation: self.state.input_generation,
        });
        self.last_completion_request_id = Some(request_id);
        Ok(())
    }

    pub fn begin_completion(
        &mut self,
        request_id: CompletionRequestId,
        target_id: TargetId,
    ) -> Result<(), SessionError> {
        let queued = self
            .state
            .live_units
            .completion_queued
            .ok_or(SessionError::InvalidState("completion was not queued"))?;
        if queued.request_id != request_id || self.state.live_units.executing.is_some() {
            return Err(SessionError::InvalidState(
                "completion begin identity mismatch or engine already executing",
            ));
        }
        self.publish_target(target_id)?;
        self.state.live_units.completion_queued = None;
        self.state.live_units.executing = Some(ExecutingUnit {
            id: target_id,
            kind: WorkKind::Completion,
            completion: Some(ExecutingCompletion {
                request_id,
                input_generation: queued.input_generation,
            }),
        });
        Ok(())
    }

    pub fn mark_due(&mut self, schedule_id: ScheduleId) -> bool {
        self.state.live_units.due.insert(schedule_id)
    }

    pub fn mark_undue(&mut self, schedule_id: ScheduleId) -> bool {
        self.state.live_units.due.remove(&schedule_id)
    }

    pub fn begin_unit(
        &mut self,
        target_id: TargetId,
        kind: WorkKind,
        schedule_id: Option<ScheduleId>,
    ) -> Result<(), SessionError> {
        if self.state.phase == EditorPhase::Shutdown || self.state.ended {
            return Err(SessionError::InvalidState(
                "work cannot begin during shutdown",
            ));
        }
        if self.state.live_units.executing.is_some() {
            return Err(SessionError::InvalidState(
                "the single engine thread already has an executing unit",
            ));
        }
        match kind {
            WorkKind::Evaluation => {
                if self.state.pending_submission != PendingSubmission::Dispatched
                    || schedule_id.is_some()
                {
                    return Err(SessionError::InvalidState(
                        "evaluation begin requires a dispatched submission",
                    ));
                }
            }
            WorkKind::Callback => {
                let schedule_id = schedule_id.ok_or(SessionError::InvalidState(
                    "callback begin requires its due scheduling identity",
                ))?;
                if !self.state.live_units.due.contains(&schedule_id) {
                    return Err(SessionError::InvalidState(
                        "callback scheduling identity was not due",
                    ));
                }
                self.ensure_new_target(target_id)?;
                self.state.live_units.due.remove(&schedule_id);
            }
            WorkKind::Completion => {
                return Err(SessionError::InvalidState(
                    "completion units must begin through begin_completion",
                ));
            }
        }
        self.publish_target(target_id)?;
        self.state.live_units.executing = Some(ExecutingUnit {
            id: target_id,
            kind,
            completion: None,
        });
        Ok(())
    }

    pub fn end_unit(&mut self, target_id: TargetId) -> Result<(), SessionError> {
        let unit = self
            .state
            .live_units
            .executing
            .ok_or(SessionError::InvalidState("no unit is executing"))?;
        if unit.id != target_id {
            return Err(SessionError::InvalidState(
                "unit end target does not match the executing id",
            ));
        }
        if unit.kind == WorkKind::Completion {
            return Err(SessionError::InvalidState(
                "completion units must end through finish_completion",
            ));
        }
        self.state.live_units.executing = None;
        if unit.kind == WorkKind::Evaluation && self.state.cause.is_none() {
            self.state.pending_submission = PendingSubmission::None;
            self.state.phase = EditorPhase::Idle;
            self.publish_prompt()?;
        }
        Ok(())
    }

    pub fn finish_completion(
        &mut self,
        request_id: CompletionRequestId,
        target_id: TargetId,
    ) -> Result<CompletionDisposition, SessionError> {
        let unit = self
            .state
            .live_units
            .executing
            .ok_or(SessionError::InvalidState("no completion is executing"))?;
        let completion = unit.completion.ok_or(SessionError::InvalidState(
            "executing unit is not a completion",
        ))?;
        if unit.id != target_id || completion.request_id != request_id {
            return Err(SessionError::InvalidState(
                "completion end identity does not match the executing query",
            ));
        }
        self.state.live_units.executing = None;
        if self.state.cause.is_none() && completion.input_generation == self.state.input_generation
        {
            Ok(CompletionDisposition::Apply)
        } else {
            Ok(CompletionDisposition::Abandoned)
        }
    }

    pub fn suspend_unit(&mut self, target_id: TargetId) -> Result<(), SessionError> {
        let unit = self
            .state
            .live_units
            .executing
            .ok_or(SessionError::InvalidState("no unit is executing"))?;
        if unit.id != target_id || unit.kind != WorkKind::Evaluation {
            return Err(SessionError::InvalidState(
                "only the exact executing evaluation may suspend",
            ));
        }
        self.state.live_units.executing = None;
        self.state.live_units.suspended.insert(
            target_id,
            SuspendedUnit {
                id: target_id,
                kind: unit.kind,
            },
        );
        Ok(())
    }

    pub fn settle_unit(&mut self, target_id: TargetId) -> Result<(), SessionError> {
        if self.state.live_units.suspended.remove(&target_id).is_none() {
            return Err(SessionError::InvalidState("settle target is not suspended"));
        }
        if self.state.cause.is_none()
            && self.state.live_units.suspended.is_empty()
            && self.state.live_units.executing.is_none()
        {
            self.state.pending_submission = PendingSubmission::None;
            self.state.phase = EditorPhase::Idle;
            self.publish_prompt()?;
        }
        Ok(())
    }

    pub fn resolve_cancellation(
        &mut self,
        request_id: CancellationRequestId,
        status: CancellationStatus,
    ) -> Result<(), SessionError> {
        if !status.is_terminal() {
            return Err(SessionError::InvalidState(
                "a cancellation resolution must be terminal",
            ));
        }
        let record =
            self.state
                .cancellations
                .get_mut(&request_id)
                .ok_or(SessionError::InvalidState(
                    "unknown cancellation request id",
                ))?;
        if record.status != CancellationStatus::Pending {
            return Err(SessionError::InvalidState(
                "cancellation request already resolved",
            ));
        }
        record.status = status;
        if status == CancellationStatus::Failed && self.state.cause.is_none() {
            self.latch_cause(TerminationKind::Fault, EXIT_STATUS_ENGINE_FAULT);
            self.run_cleanup(TerminationMode::Begin)?;
        }
        Ok(())
    }

    pub fn get_exit_code(&self, principal: Principal) -> LifecycleGetDisposition {
        self.lifecycle.get_exit_code(principal)
    }

    pub fn set_exit_code(&mut self, principal: Principal, status: i32) -> LifecycleSetDisposition {
        self.lifecycle.set_exit_code(principal, status)
    }

    pub fn request_cooperative_exit(
        &mut self,
        principal: Principal,
        status: i32,
    ) -> Result<LifecycleRequestDisposition, SessionError> {
        let disposition = self.lifecycle.request_exit(principal, status);
        if let LifecycleRequestDisposition::Accepted { status } = disposition {
            self.latch_cause(TerminationKind::Cooperative, status);
            self.run_cleanup(TerminationMode::Begin)?;
        }
        Ok(disposition)
    }

    pub fn report_async(&mut self, report: &str) -> Result<u64, SessionError> {
        let write = self.broker.receive_async_report(report);
        self.accept_session_write(write)
    }

    pub fn emit_program_output(&mut self, bytes: &[u8]) -> Result<u64, SessionError> {
        let write = self.broker.receive_program(ProgramStream::Stdout, bytes);
        self.accept_session_write(write)
    }

    pub fn handle_interrupt(&mut self) -> Result<InterruptOutcome, SessionError> {
        let suspended_ids: Vec<u64> = self
            .state
            .live_units
            .suspended
            .keys()
            .map(|id| id.0)
            .collect();
        let due_schedules: Vec<u64> = self.state.live_units.due.iter().map(|id| id.0).collect();
        let generated_state = generated::InterruptState {
            phase: generated_phase(self.state.phase),
            pending_submission: generated_submission(self.state.pending_submission),
            executing: self
                .state
                .live_units
                .executing
                .map(|unit| generated::ExecutingUnit {
                    id: unit.id.0,
                    kind: generated_work_kind(unit.kind),
                }),
            suspended_ids: &suspended_ids,
            due_schedules: &due_schedules,
            completion_queued: self
                .state
                .live_units
                .completion_queued
                .map(|queued| queued.request_id.0),
            escape_credit: self.state.escape_credit,
            promise: generated_promise(self.state.promise),
            cause: self.state.cause.map(|cause| generated::TerminationCause {
                status: cause.status,
            }),
            exit_code: self.lifecycle.current_exit_code(),
            ended: self.state.ended,
        };
        let decision = generated::dispatch_interrupt(generated_state)
            .map_err(|error| SessionError::GeneratedDispatch(format!("{error:?}")))?;

        self.state.escape_credit = decision.next_credit;
        let mut invalidates_generation = matches!(
            decision.buffer,
            generated::BufferAction::PreserveInvalidate
                | generated::BufferAction::DiscardInvalidate
        );
        if decision.abandon_completion {
            if self.state.live_units.completion_queued.take().is_some() {
                invalidates_generation = true;
            }
            if self
                .state
                .live_units
                .executing
                .is_some_and(|unit| unit.kind == WorkKind::Completion)
            {
                invalidates_generation = true;
            }
        }
        if invalidates_generation {
            self.invalidate_input_generation()?;
        }
        if decision.buffer == generated::BufferAction::DiscardInvalidate {
            self.state.buffer.clear();
            self.state.phase = EditorPhase::Idle;
            self.publish_prompt()?;
        }
        match decision.submission {
            generated::SubmissionAction::Unchanged => {}
            generated::SubmissionAction::Discard => {
                self.state.pending_submission = PendingSubmission::Discarded;
                self.state.typed_ahead.clear();
            }
            generated::SubmissionAction::DiscardAndIdle => {
                self.state.pending_submission = PendingSubmission::None;
                self.state.typed_ahead.clear();
                self.state.phase = EditorPhase::Idle;
                self.publish_prompt()?;
            }
        }
        if decision.promise_to_set != generated::PromiseClass::None {
            self.state.promise = local_promise(decision.promise_to_set);
        }

        if decision.notice != generated::Notice::None {
            let write = self
                .broker
                .receive_interrupt_notice(interrupt_notice(decision.notice));
            self.accept_session_write(write)?;
        }

        let cancellation_target = decision.cancel_target.map(TargetId);
        let cancellation_fault = if let Some(target_id) = cancellation_target {
            self.issue_cancellation(target_id)?
        } else {
            false
        };

        if decision.terminal {
            let status = decision.status.ok_or(SessionError::InvalidState(
                "terminal generated decision omitted status",
            ))?;
            if self.state.cause.is_none() {
                let kind = match decision.status_class {
                    Some(generated::StatusClass::Orderly) => TerminationKind::Orderly,
                    Some(generated::StatusClass::Interrupt130)
                        if status == EXIT_STATUS_INTERRUPT =>
                    {
                        TerminationKind::Interrupt
                    }
                    Some(generated::StatusClass::Interrupt130) => {
                        return Err(SessionError::InvalidState(
                            "generated interrupt status disagrees with the session constants annex",
                        ));
                    }
                    Some(generated::StatusClass::Cause) | None => {
                        return Err(SessionError::InvalidState(
                            "generated terminal status class has no cause",
                        ));
                    }
                };
                self.latch_cause(kind, status);
            }
            self.run_cleanup(if decision.expedited {
                TerminationMode::Expedite
            } else {
                TerminationMode::Begin
            })?;
        }

        Ok(InterruptOutcome {
            row: decision.row.map(|row| format!("{row:?}")),
            terminal: decision.terminal || cancellation_fault,
            expedited: decision.expedited,
            status: if cancellation_fault {
                self.state.cause.map(|cause| cause.status)
            } else {
                decision.status
            },
            cancellation_target,
            promise: self.state.promise,
        })
    }

    fn issue_cancellation(&mut self, target_id: TargetId) -> Result<bool, SessionError> {
        let next_request =
            self.next_cancellation_request
                .checked_add(1)
                .ok_or(SessionError::InvalidState(
                    "cancellation request-id space exhausted",
                ))?;
        let request = CancellationRequest {
            request_id: CancellationRequestId(self.next_cancellation_request),
            target_id,
        };
        self.next_cancellation_request = next_request;
        let status = self.cancellation.request_exact(request);
        let replaced = self
            .state
            .cancellations
            .insert(request.request_id, CancellationRecord { request, status });
        debug_assert!(replaced.is_none());
        if status == CancellationStatus::Failed {
            if self.state.cause.is_none() {
                self.latch_cause(TerminationKind::Fault, EXIT_STATUS_ENGINE_FAULT);
                self.run_cleanup(TerminationMode::Begin)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn accept_session_write(
        &mut self,
        write: Result<Vec<BrokerReceipt>, BrokerEnqueueError>,
    ) -> Result<u64, SessionError> {
        match write {
            Ok(receipts) => {
                self.broker.pump_available();
                receipts
                    .iter()
                    .find(|receipt| {
                        !matches!(
                            receipt.kind,
                            BrokerFrameKind::PromptErase | BrokerFrameKind::PromptRedraw
                        )
                    })
                    .or_else(|| receipts.first())
                    .map(|receipt| receipt.sequence)
                    .ok_or(SessionError::InvalidState(
                        "broker accepted an empty event batch",
                    ))
            }
            Err(error) => {
                if self.state.cause.is_none() {
                    self.latch_cause(TerminationKind::BrokenPipe, EXIT_STATUS_BROKEN_PIPE);
                    let _ = self.run_cleanup(TerminationMode::Begin);
                }
                Err(SessionError::Broker(error.to_string()))
            }
        }
    }

    fn request_orderly_shutdown(&mut self) -> Result<(), SessionError> {
        if self.state.cause.is_none() {
            self.latch_cause(TerminationKind::Orderly, self.lifecycle.current_exit_code());
            self.run_cleanup(TerminationMode::Begin)?;
        }
        Ok(())
    }

    fn latch_cause(&mut self, kind: TerminationKind, status: i32) {
        if self.state.cause.is_some() {
            return;
        }
        self.lifecycle.seal();
        self.state.cause = Some(TerminationCause { kind, status });
        self.state.phase = EditorPhase::Shutdown;
        self.state.pending_submission = PendingSubmission::None;
        self.retire_prompt();
    }

    fn restore_terminal(&mut self) -> Result<(), SessionError> {
        if !self.terminal_armed {
            return Ok(());
        }
        // Flip before calling the port so Drop cannot invoke a possibly failing
        // restore twice after the first process-controlled attempt.
        self.terminal_armed = false;
        self.terminal
            .restore_session()
            .map_err(SessionError::Terminal)
    }

    fn run_cleanup(&mut self, mode: TerminationMode) -> Result<(), SessionError> {
        let cause = self
            .state
            .cause
            .ok_or(SessionError::InvalidState("cleanup requires a cause"))?;
        let mut first_error = self.restore_terminal().err();
        if !self.broker_finished {
            self.broker_finished = true;
            match self
                .broker
                .finish_with_budget(Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS))
                .map_err(|error| SessionError::Broker(error.to_string()))
            {
                Ok(loss) => self.broker_loss = Some(loss),
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        if let Err(error) = self
            .worker
            .terminate_worker(WorkerTermination {
                mode,
                kind: cause.kind,
                status: cause.status,
            })
            .map_err(SessionError::Worker)
        {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(())
        }
    }

    pub fn mark_session_ended(&mut self) {
        self.state.ended = true;
        self.state.promise = PromiseClass::None;
        self.state.escape_credit = 0;
        self.retire_prompt();
    }
}

impl<T, S, C, W> Drop for TerminalSessionSupervisor<T, S, C, W>
where
    T: TerminalLifecycle,
    S: NonBlockingRelaySink,
    C: ExactCancellation,
    W: WorkerTerminator,
{
    fn drop(&mut self) {
        if self.terminal_armed {
            self.terminal_armed = false;
            let _ = self.terminal.restore_session();
        }
    }
}

fn normalize_exit_status(status: i32) -> i32 {
    #[cfg(unix)]
    {
        status & POSIX_EXIT_STATUS_MASK
    }
    #[cfg(not(unix))]
    {
        status
    }
}

fn generated_phase(phase: EditorPhase) -> generated::EditorPhase {
    match phase {
        EditorPhase::Idle => generated::EditorPhase::Idle,
        EditorPhase::Editing => generated::EditorPhase::Editing,
        EditorPhase::Continuation => generated::EditorPhase::Continuation,
        EditorPhase::Evaluating => generated::EditorPhase::Evaluating,
        EditorPhase::Shutdown => generated::EditorPhase::Shutdown,
    }
}

fn generated_submission(submission: PendingSubmission) -> generated::PendingSubmission {
    match submission {
        PendingSubmission::None => generated::PendingSubmission::None,
        PendingSubmission::Undispatched => generated::PendingSubmission::Undispatched,
        PendingSubmission::Dispatched => generated::PendingSubmission::Dispatched,
        PendingSubmission::Discarded => generated::PendingSubmission::Discarded,
    }
}

fn generated_work_kind(kind: WorkKind) -> generated::WorkKind {
    match kind {
        WorkKind::Evaluation => generated::WorkKind::Evaluation,
        WorkKind::Callback => generated::WorkKind::Callback,
        WorkKind::Completion => generated::WorkKind::Completion,
    }
}

fn generated_promise(promise: PromiseClass) -> generated::PromiseClass {
    match promise {
        PromiseClass::None => generated::PromiseClass::None,
        PromiseClass::Orderly => generated::PromiseClass::Orderly,
        PromiseClass::Interrupt130 => generated::PromiseClass::Interrupt130,
    }
}

fn local_promise(promise: generated::PromiseClass) -> PromiseClass {
    match promise {
        generated::PromiseClass::None => PromiseClass::None,
        generated::PromiseClass::Orderly => PromiseClass::Orderly,
        generated::PromiseClass::Interrupt130 => PromiseClass::Interrupt130,
    }
}

fn interrupt_notice(notice: generated::Notice) -> &'static str {
    match notice {
        generated::Notice::None => "",
        generated::Notice::OrderlyPromise => NOTICE_ORDERLY_PROMISE,
        generated::Notice::CancellingWork => NOTICE_CANCELLING_WORK,
        generated::Notice::WorkInFlight => NOTICE_WORK_IN_FLIGHT,
        generated::Notice::CancellingCompletion => NOTICE_CANCELLING_COMPLETION,
        generated::Notice::InputDiscarded => NOTICE_INPUT_DISCARDED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[cfg(unix)]
    struct SuspensionTransactionHarness {
        events: Vec<&'static str>,
        fail_at: Option<&'static str>,
    }

    #[cfg(unix)]
    impl SuspensionTransactionHarness {
        fn new(fail_at: Option<&'static str>) -> Self {
            Self {
                events: Vec::new(),
                fail_at,
            }
        }

        fn record(&mut self, event: &'static str) -> Result<(), String> {
            self.events.push(event);
            if self.fail_at == Some(event) {
                Err(format!("{event} failed"))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(unix)]
    impl TerminalSuspensionTransactionPort for SuspensionTransactionHarness {
        fn restore_terminal(&mut self) -> Result<(), String> {
            self.record("restore")
        }

        fn stop_worker_group(&mut self) -> Result<(), String> {
            self.record("stop-worker")
        }

        fn stop_supervisor(&mut self) -> Result<(), String> {
            self.record("stop-supervisor")
        }

        fn reacquire_foreground(&mut self) -> Result<(), String> {
            self.record("foreground")
        }

        fn enter_terminal(&mut self) -> Result<(), String> {
            self.record("raw")
        }

        fn continue_worker_group(&mut self) -> Result<(), String> {
            self.record("continue-worker")
        }

        fn refresh_dimensions(&mut self) -> Result<(), String> {
            self.record("resize")
        }

        fn redraw(&mut self) -> Result<(), String> {
            self.record("redraw")
        }
    }

    // @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker
    #[cfg(unix)]
    #[test]
    fn terminal_suspension_transaction_has_one_strict_restore_stop_resume_order() {
        let mut port = SuspensionTransactionHarness::new(None);

        execute_terminal_suspension_transaction(&mut port).unwrap();

        assert_eq!(
            port.events,
            [
                "restore",
                "stop-worker",
                "stop-supervisor",
                "foreground",
                "raw",
                "continue-worker",
                "resize",
                "redraw",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminal_suspension_never_reenters_raw_without_foreground_ownership() {
        let mut port = SuspensionTransactionHarness::new(Some("foreground"));

        assert_eq!(
            execute_terminal_suspension_transaction(&mut port),
            Err("foreground failed".to_string())
        );
        assert_eq!(
            port.events,
            [
                "restore",
                "stop-worker",
                "stop-supervisor",
                "foreground",
                "continue-worker",
            ]
        );
        assert!(!port.events.contains(&"raw"));
    }

    #[cfg(unix)]
    #[test]
    fn bracketed_paste_keeps_interrupt_and_suspend_bytes_inert() {
        let mut gate = RawBracketedPasteSignalGate::default();
        for byte in b"\x1b[200~" {
            assert!(!gate.feed(*byte));
        }
        assert!(gate.feed(PROMPT_INTERRUPT_BYTE));
        assert!(gate.feed(0x1a));
        for byte in b"\x1b[201~" {
            assert!(gate.feed(*byte));
        }
        assert!(!gate.feed(PROMPT_INTERRUPT_BYTE));
        assert!(!gate.feed(0x1a));
    }

    #[cfg(unix)]
    #[test]
    fn transcript_reader_bounds_allocation_and_resynchronizes_at_newline() {
        let bound = ibex_runtime::session_constants::MAX_INPUT_BYTES;
        let mut bytes = vec![b'x'; bound + 17];
        bytes.extend_from_slice(b"\nnext\r\n");
        let mut input = io::BufReader::with_capacity(257, io::Cursor::new(bytes));
        let mut record = Vec::with_capacity(bound);

        assert_eq!(
            read_bounded_transcript_record(&mut input, &mut record).unwrap(),
            TranscriptRecordRead::Oversize
        );
        assert_eq!(record.len(), bound);
        assert!(record.capacity() <= bound);
        assert_eq!(
            read_bounded_transcript_record(&mut input, &mut record).unwrap(),
            TranscriptRecordRead::Record
        );
        assert_eq!(record, b"next\r");
        assert_eq!(
            read_bounded_transcript_record(&mut input, &mut record).unwrap(),
            TranscriptRecordRead::Eof
        );
    }

    #[cfg(unix)]
    struct CountedRelayHarness {
        port: WorkerOutputCutoffPort,
        stdout_write: Option<NativeFd>,
        stderr_write: Option<NativeFd>,
        stdout_output: Option<NativeFd>,
        stderr_output: Option<NativeFd>,
        shutdown: Option<mpsc::Sender<()>>,
        relay: Option<thread::JoinHandle<()>>,
    }

    #[cfg(unix)]
    impl CountedRelayHarness {
        fn new() -> Self {
            let (stdout_read, stdout_write) = native_pipe().unwrap();
            let (stderr_read, stderr_write) = native_pipe().unwrap();
            let (stdout_output, stdout_destination) = native_pipe().unwrap();
            let (stderr_output, stderr_destination) = native_pipe().unwrap();
            for destination in [&stdout_destination, &stderr_destination] {
                let flags = descriptor_flags(destination.raw(), libc::F_GETFL).unwrap();
                set_descriptor_flag(destination.raw(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                    .unwrap();
            }
            let state = Arc::new(Mutex::new(WorkerOutputRelayState {
                stdout: WorkerRelayAccounting::new(stdout_read.raw()),
                stderr: Some(WorkerRelayAccounting::new(stderr_read.raw())),
                failures: Vec::new(),
            }));
            let port = WorkerOutputCutoffPort {
                state: Arc::clone(&state),
            };
            let (shutdown_tx, shutdown_rx) = mpsc::channel();
            let relay = thread::spawn(move || {
                worker_output_relay_loop(
                    WorkerOutputRelayEndpoint::new(
                        ProgramStream::Stdout,
                        stdout_read,
                        stdout_destination,
                    ),
                    Some(WorkerOutputRelayEndpoint::new(
                        ProgramStream::Stderr,
                        stderr_read,
                        stderr_destination,
                    )),
                    state,
                    shutdown_rx,
                )
            });
            Self {
                port,
                stdout_write: Some(stdout_write),
                stderr_write: Some(stderr_write),
                stdout_output: Some(stdout_output),
                stderr_output: Some(stderr_output),
                shutdown: Some(shutdown_tx),
                relay: Some(relay),
            }
        }

        fn close_inputs(&mut self) {
            self.stdout_write.take();
            self.stderr_write.take();
        }

        fn join(&mut self) {
            if let Some(relay) = self.relay.take() {
                relay.join().unwrap();
            }
            self.shutdown.take();
        }
    }

    #[cfg(unix)]
    impl Drop for CountedRelayHarness {
        fn drop(&mut self) {
            self.close_inputs();
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            if let Some(relay) = self.relay.take() {
                let _ = relay.join();
            }
        }
    }

    #[cfg(unix)]
    fn read_native_to_end(descriptor: NativeFd) -> Vec<u8> {
        let mut result = Vec::new();
        let mut bytes = [0_u8; 16 * 1024];
        loop {
            let amount =
                unsafe { libc::read(descriptor.raw(), bytes.as_mut_ptr().cast(), bytes.len()) };
            if amount > 0 {
                result.extend_from_slice(&bytes[..amount as usize]);
                continue;
            }
            if amount == 0 {
                return result;
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(1)),
                _ => panic!("relay output read failed: {error}"),
            }
        }
    }

    #[cfg(unix)]
    fn wait_for_cutoffs(
        port: &WorkerOutputCutoffPort,
        expected: WorkerOutputCutoffs,
    ) -> WorkerOutputCutoffs {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let observed = port.cutoffs().unwrap();
            if observed == expected {
                return observed;
            }
            assert!(
                observed.stdout() <= expected.stdout() && observed.stderr() <= expected.stderr(),
                "worker relay cutoff exceeded issued bytes: {observed:?} > {expected:?}"
            );
            assert!(
                Instant::now() < deadline,
                "worker relay cutoff did not settle"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    #[cfg(unix)]
    #[test]
    fn worker_cutoff_counts_kernel_queued_nul_and_binary_bytes_exactly() {
        let mut harness = CountedRelayHarness::new();
        let payload = b"before\0after\xff\x80";

        // Freeze the relay's kernel->in-flight transition while issuing the
        // write so this assertion exercises the FIONREAD term directly.
        let state = harness.port.state.lock().unwrap();
        assert_eq!(
            write_native_relay(harness.stdout_write.as_ref().unwrap().raw(), payload),
            Ok(payload.len())
        );
        assert_eq!(state.stdout.forwarded, 0);
        assert_eq!(state.stdout.in_flight, 0);
        assert_eq!(
            pipe_queued_bytes(state.stdout.read_descriptor).unwrap(),
            payload.len() as u64
        );
        assert_eq!(
            worker_relay_cutoff(&state.stdout).unwrap(),
            payload.len() as u64
        );
        drop(state);

        let output = harness.stdout_output.take().unwrap();
        let reader = thread::spawn(move || read_native_to_end(output));
        wait_for_cutoffs(
            &harness.port,
            WorkerOutputCutoffs {
                stdout: payload.len() as u64,
                stderr: 0,
            },
        );
        harness.close_inputs();
        harness.join();
        assert_eq!(reader.join().unwrap(), payload);
        assert!(harness.port.failures().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn worker_cutoff_pair_is_monotonic_under_concurrent_writers() {
        use std::sync::atomic::AtomicUsize;

        const WRITERS_PER_STREAM: usize = 4;
        const CHUNKS: usize = 96;
        const CHUNK_BYTES: usize = 257;
        let expected_per_stream = (WRITERS_PER_STREAM * CHUNKS * CHUNK_BYTES) as u64;
        let mut harness = CountedRelayHarness::new();
        let stdout_output = harness.stdout_output.take().unwrap();
        let stderr_output = harness.stderr_output.take().unwrap();
        let stdout_reader = thread::spawn(move || read_native_to_end(stdout_output));
        let stderr_reader = thread::spawn(move || read_native_to_end(stderr_output));

        let running = Arc::new(AtomicUsize::new(WRITERS_PER_STREAM * 2));
        let mut writers = Vec::new();
        for (stream, base) in [
            (
                ProgramStream::Stdout,
                harness.stdout_write.as_ref().unwrap(),
            ),
            (
                ProgramStream::Stderr,
                harness.stderr_write.as_ref().unwrap(),
            ),
        ] {
            for writer_id in 0..WRITERS_PER_STREAM {
                let descriptor = NativeFd::duplicate(base.raw()).unwrap();
                let running = Arc::clone(&running);
                writers.push(thread::spawn(move || {
                    let mut chunk = vec![(writer_id + 1) as u8; CHUNK_BYTES];
                    chunk[0] = match stream {
                        ProgramStream::Stdout => b'O',
                        ProgramStream::Stderr => b'E',
                    };
                    for _ in 0..CHUNKS {
                        write_native_relay(descriptor.raw(), &chunk).unwrap();
                    }
                    running.fetch_sub(1, Ordering::Release);
                }));
            }
        }

        let mut previous = WorkerOutputCutoffs {
            stdout: 0,
            stderr: 0,
        };
        while running.load(Ordering::Acquire) != 0 {
            let current = harness.port.cutoffs().unwrap();
            assert!(current.stdout() >= previous.stdout());
            assert!(current.stderr() >= previous.stderr());
            previous = current;
            thread::sleep(Duration::from_micros(100));
        }
        for writer in writers {
            writer.join().unwrap();
        }
        let final_cutoffs = wait_for_cutoffs(
            &harness.port,
            WorkerOutputCutoffs {
                stdout: expected_per_stream,
                stderr: expected_per_stream,
            },
        );
        assert!(final_cutoffs.stdout() >= previous.stdout());
        assert!(final_cutoffs.stderr() >= previous.stderr());

        harness.close_inputs();
        harness.join();
        assert_eq!(
            stdout_reader.join().unwrap().len() as u64,
            expected_per_stream
        );
        assert_eq!(
            stderr_reader.join().unwrap().len() as u64,
            expected_per_stream
        );
        assert_eq!(harness.port.cutoffs().unwrap(), final_cutoffs);
        assert!(harness.port.failures().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn worker_output_relay_reports_broken_pipe_without_sigpipe_termination() {
        const SENTINEL: &str = "IBEX_TEST_WORKER_OUTPUT_BROKEN_PIPE_CHILD";
        if std::env::var_os(SENTINEL).is_some() {
            let _sigpipe = SigpipeIgnoreGuard::install().unwrap();
            let mut harness = CountedRelayHarness::new();
            drop(harness.stdout_output.take());
            let payload = b"typed-broken-pipe";
            write_native_relay(harness.stdout_write.as_ref().unwrap().raw(), payload).unwrap();

            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let failures = harness.port.failures().unwrap();
                if failures.iter().any(|failure| {
                    failure.stream() == ProgramStream::Stdout
                        && failure.kind() == WorkerOutputRelayFailureKind::BrokenPipe
                }) {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "worker relay did not report a typed broken-pipe failure"
                );
                thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(
                harness.port.cutoffs().unwrap(),
                WorkerOutputCutoffs {
                    stdout: payload.len() as u64,
                    stderr: 0,
                }
            );
            harness.close_inputs();
            harness.join();
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("terminal_session::tests::worker_output_relay_reports_broken_pipe_without_sigpipe_termination")
            .env(SENTINEL, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "broken-pipe child terminated: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn worker_adapter_counts_same_slot_child_writes_and_protects_private_fds() {
        const SENTINEL: &str = "IBEX_TEST_WORKER_OUTPUT_RELAY_CHILD";
        const STDOUT_PAYLOAD: &[u8] = b"child\0stdout";
        const STDERR_PAYLOAD: &[u8] = b"child\0stderr";
        if let Some(record_path) = std::env::var_os(SENTINEL) {
            let adapter =
                WorkerOutputRelayAdapter::install(OutputDestinationTopology::Split).unwrap();
            assert_eq!(adapter.protected_descriptors().len(), 6);
            for descriptor in adapter.protected_descriptors() {
                assert!(*descriptor > 2);
                assert_ne!(
                    descriptor_flags(*descriptor, libc::F_GETFD).unwrap() & libc::FD_CLOEXEC,
                    0
                );
            }
            let status = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg("printf 'child\\000stdout'; printf 'child\\000stderr' >&2")
                .status()
                .unwrap();
            assert!(status.success());
            let cutoffs = wait_for_cutoffs(
                &adapter.cutoff_port(),
                WorkerOutputCutoffs {
                    stdout: STDOUT_PAYLOAD.len() as u64,
                    stderr: STDERR_PAYLOAD.len() as u64,
                },
            );
            std::fs::write(
                record_path,
                format!("{} {}", cutoffs.stdout(), cutoffs.stderr()),
            )
            .unwrap();
            adapter.finish().unwrap();
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let record_path = directory.path().join("cutoffs");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("terminal_session::tests::worker_adapter_counts_same_slot_child_writes_and_protects_private_fds")
            .env(SENTINEL, &record_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output
            .stdout
            .windows(STDOUT_PAYLOAD.len())
            .any(|window| window == STDOUT_PAYLOAD));
        assert!(output
            .stderr
            .windows(STDERR_PAYLOAD.len())
            .any(|window| window == STDERR_PAYLOAD));
        assert_eq!(
            std::fs::read_to_string(record_path).unwrap(),
            format!("{} {}", STDOUT_PAYLOAD.len(), STDERR_PAYLOAD.len())
        );
    }

    #[cfg(unix)]
    #[test]
    fn shared_worker_adapter_has_one_ofd_counter_and_exact_cross_stream_order() {
        const SENTINEL: &str = "IBEX_TEST_SHARED_WORKER_OUTPUT_RELAY_CHILD";
        const BEGIN: &[u8] = b"\0ibex-shared-begin\0";
        const END: &[u8] = b"\0ibex-shared-end\0";

        if let Some(record_path) = std::env::var_os(SENTINEL) {
            let adapter = WorkerOutputRelayAdapter::install(OutputDestinationTopology::Shared {
                destination: NativeOutputDestination::Stdout,
            })
            .unwrap();
            assert_eq!(adapter.protected_descriptors().len(), 4);

            let stdout_flags = descriptor_flags(libc::STDOUT_FILENO, libc::F_GETFL).unwrap();
            set_descriptor_flag(
                libc::STDOUT_FILENO,
                libc::F_SETFL,
                stdout_flags | libc::O_NONBLOCK,
            )
            .unwrap();
            assert_ne!(
                descriptor_flags(libc::STDERR_FILENO, libc::F_GETFL).unwrap() & libc::O_NONBLOCK,
                0,
                "fd 1 and fd 2 do not share file-status flags"
            );
            set_descriptor_flag(libc::STDOUT_FILENO, libc::F_SETFL, stdout_flags).unwrap();

            let mut expected = BEGIN.to_vec();
            write_native_relay(libc::STDOUT_FILENO, BEGIN).unwrap();
            for index in 0..256_u16 {
                let stderr = format!("E{index:04};");
                let stdout = format!("O{index:04};");
                write_native_relay(libc::STDERR_FILENO, stderr.as_bytes()).unwrap();
                write_native_relay(libc::STDOUT_FILENO, stdout.as_bytes()).unwrap();
                expected.extend_from_slice(stderr.as_bytes());
                expected.extend_from_slice(stdout.as_bytes());
            }
            write_native_relay(libc::STDERR_FILENO, END).unwrap();
            expected.extend_from_slice(END);

            let cutoffs = wait_for_cutoffs(
                &adapter.cutoff_port(),
                WorkerOutputCutoffs {
                    stdout: expected.len() as u64,
                    stderr: 0,
                },
            );
            std::fs::write(
                record_path,
                format!("{} {}", cutoffs.stdout(), cutoffs.stderr()),
            )
            .unwrap();
            adapter.finish().unwrap();
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let record_path = directory.path().join("shared-cutoff");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("terminal_session::tests::shared_worker_adapter_has_one_ofd_counter_and_exact_cross_stream_order")
            .env(SENTINEL, &record_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "shared relay child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let mut expected = BEGIN.to_vec();
        for index in 0..256_u16 {
            expected.extend_from_slice(format!("E{index:04};O{index:04};").as_bytes());
        }
        expected.extend_from_slice(END);
        assert_eq!(
            output
                .stdout
                .windows(expected.len())
                .filter(|window| *window == expected)
                .count(),
            1,
            "shared relay changed cross-stream byte order"
        );
        assert!(!output
            .stderr
            .windows(BEGIN.len())
            .any(|window| window == BEGIN));
        assert_eq!(
            std::fs::read_to_string(record_path).unwrap(),
            format!("{} 0", expected.len())
        );
    }

    #[derive(Clone)]
    struct RecordingTerminal {
        log: Arc<Mutex<Vec<String>>>,
    }

    impl TerminalLifecycle for RecordingTerminal {
        fn enter_session(&mut self, _: CapturedPresentation) -> Result<(), String> {
            self.log.lock().unwrap().push("terminal-enter".into());
            Ok(())
        }

        fn restore_session(&mut self) -> Result<(), String> {
            self.log.lock().unwrap().push("terminal-restore".into());
            Ok(())
        }
    }

    #[derive(Clone)]
    struct RecordingSink {
        frames: Arc<Mutex<Vec<BrokerFrame>>>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl NonBlockingRelaySink for RecordingSink {
        fn try_write(
            &mut self,
            request: RelayWriteRequest<'_>,
        ) -> Result<RelayWriteOutcome, String> {
            self.frames.lock().unwrap().push(BrokerFrame {
                epoch: request.epoch,
                sequence: request.sequence,
                kind: request.kind,
                bytes: request.bytes.to_vec(),
            });
            self.log
                .lock()
                .unwrap()
                .push(format!("broker-write-{:?}", request.kind));
            Ok(RelayWriteOutcome::Written(request.bytes.len()))
        }

        fn flush(&mut self) -> Result<(), String> {
            self.log.lock().unwrap().push("broker-flush".into());
            Ok(())
        }
    }

    struct RecordingCancellation {
        responses: VecDeque<CancellationStatus>,
        requests: Arc<Mutex<Vec<CancellationRequest>>>,
    }

    impl ExactCancellation for RecordingCancellation {
        fn request_exact(&mut self, request: CancellationRequest) -> CancellationStatus {
            self.requests.lock().unwrap().push(request);
            self.responses
                .pop_front()
                .unwrap_or(CancellationStatus::Pending)
        }
    }

    #[derive(Clone)]
    struct RecordingWorker {
        commands: Arc<Mutex<Vec<WorkerTermination>>>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl WorkerTerminator for RecordingWorker {
        fn terminate_worker(&mut self, request: WorkerTermination) -> Result<(), String> {
            self.commands.lock().unwrap().push(request);
            self.log
                .lock()
                .unwrap()
                .push(format!("worker-{:?}-{}", request.mode, request.status));
            Ok(())
        }
    }

    type TestSupervisor = TerminalSessionSupervisor<
        RecordingTerminal,
        RecordingSink,
        RecordingCancellation,
        RecordingWorker,
    >;

    struct Harness {
        supervisor: TestSupervisor,
        log: Arc<Mutex<Vec<String>>>,
        frames: Arc<Mutex<Vec<BrokerFrame>>>,
        requests: Arc<Mutex<Vec<CancellationRequest>>>,
        commands: Arc<Mutex<Vec<WorkerTermination>>>,
    }

    fn harness(responses: impl IntoIterator<Item = CancellationStatus>) -> Harness {
        let log = Arc::new(Mutex::new(Vec::new()));
        let frames = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let commands = Arc::new(Mutex::new(Vec::new()));
        let terminal = RecordingTerminal { log: log.clone() };
        let sink = RecordingSink {
            frames: frames.clone(),
            log: log.clone(),
        };
        let cancellation = RecordingCancellation {
            responses: responses.into_iter().collect(),
            requests: requests.clone(),
        };
        let worker = RecordingWorker {
            commands: commands.clone(),
            log: log.clone(),
        };
        let supervisor = TerminalSessionSupervisor::with_default_prompt(
            terminal,
            sink,
            cancellation,
            worker,
            CapturedPresentation::interactive_plain(),
            PromptWitness::default(),
        )
        .unwrap();
        Harness {
            supervisor,
            log,
            frames,
            requests,
            commands,
        }
    }

    fn type_byte(supervisor: &mut TestSupervisor, byte: u8) {
        let cycle = supervisor.state().prompt_cycle;
        supervisor
            .handle_editor_event(EditorInputEvent::Byte {
                byte,
                observed_prompt: Some(cycle),
            })
            .unwrap();
    }

    fn begin_evaluation(supervisor: &mut TestSupervisor, target: TargetId) {
        type_byte(supervisor, b'x');
        supervisor.submit_buffer().unwrap();
        supervisor.dispatch_submission().unwrap();
        supervisor
            .begin_unit(target, WorkKind::Evaluation, None)
            .unwrap();
    }

    fn callback(supervisor: &mut TestSupervisor, schedule: ScheduleId, target: TargetId) {
        assert!(supervisor.mark_due(schedule));
        supervisor
            .begin_unit(target, WorkKind::Callback, Some(schedule))
            .unwrap();
    }

    fn last_command(harness: &Harness) -> WorkerTermination {
        *harness.commands.lock().unwrap().last().unwrap()
    }

    #[test]
    fn default_prompt_is_the_llp_0022_annex_token() {
        let harness = harness([]);
        let frames = harness.frames.lock().unwrap();
        let prompt = frames
            .iter()
            .find(|frame| frame.kind == BrokerFrameKind::Prompt)
            .expect("startup publishes the default prompt");
        assert_eq!(prompt.bytes, "➤ ".as_bytes());
    }

    fn parsed_cli(args: &[&str]) -> Cli {
        Cli::parse_from(args)
    }

    fn terminal_facts(stdin: bool, stdout: bool, stderr: bool) -> NativeTerminalFacts {
        NativeTerminalFacts {
            stdin_is_tty: stdin,
            stdout_is_tty: stdout,
            stderr_is_tty: stderr,
        }
    }

    fn route(args: &[&str], stdin_is_tty: bool) -> SelectedExecutionRoute {
        selected_execution_route(&parsed_cli(args), stdin_is_tty)
            .expect("test invocation is an execution route")
    }

    #[test]
    fn cli_route_selector_distinguishes_stdin_repl_eval_and_file() {
        assert_eq!(
            route(&["ibex"], true),
            SelectedExecutionRoute {
                entry_kind: ArmedEntryKind::Repl,
                mode: ArmedExecutionMode::Interactive,
            }
        );
        assert_eq!(
            route(&["ibex"], false),
            SelectedExecutionRoute {
                entry_kind: ArmedEntryKind::Stdin,
                mode: ArmedExecutionMode::Program,
            }
        );
        assert_eq!(
            route(&["ibex", "repl"], false),
            SelectedExecutionRoute {
                entry_kind: ArmedEntryKind::Repl,
                mode: ArmedExecutionMode::Transcript,
            }
        );
        for args in [
            &["ibex", "-e", "1 + 1"][..],
            &["ibex", "-p", "1 + 1"][..],
            &["ibex", "eval", "1 + 1"][..],
        ] {
            assert_eq!(
                route(args, false),
                SelectedExecutionRoute {
                    entry_kind: ArmedEntryKind::Eval,
                    mode: ArmedExecutionMode::OneShot,
                }
            );
        }
        for args in [&["ibex", "app.ts"][..], &["ibex", "run", "app.ts"][..]] {
            assert_eq!(
                route(args, false),
                SelectedExecutionRoute {
                    entry_kind: ArmedEntryKind::File,
                    mode: ArmedExecutionMode::Program,
                }
            );
        }
        assert_eq!(
            selected_execution_route(&parsed_cli(&["ibex", "version"]), true),
            None
        );
    }

    #[test]
    fn production_adapter_gate_never_authorizes_the_legacy_repl() {
        let plan = |args: &[&str], stdin_is_tty| {
            SessionIoPlan::for_cli(
                &parsed_cli(args),
                terminal_facts(stdin_is_tty, true, true),
                false,
            )
            .unwrap()
        };
        assert_eq!(
            execution_adapter_status(plan(&["ibex"], false)),
            Err(ExecutionAdapterGap::StructuredStdinProgramIngressUnavailable)
        );
        assert_eq!(
            execution_adapter_status(plan(&["ibex"], true)),
            Err(ExecutionAdapterGap::SupervisorOwnedEditorUnavailable)
        );
        assert_eq!(
            execution_adapter_status(plan(&["ibex", "repl"], false)),
            Err(ExecutionAdapterGap::StructuredTranscriptLoopUnavailable)
        );
        assert_eq!(
            execution_adapter_status(plan(&["ibex", "repl"], true)),
            Err(ExecutionAdapterGap::SupervisorOwnedEditorUnavailable)
        );
        assert_eq!(
            execution_adapter_status(plan(&["ibex", "-e", "1"], false)),
            Err(ExecutionAdapterGap::StructuredOneShotEvaluationUnavailable)
        );
        let file = plan(&["ibex", "app.ts"], false);
        assert_eq!(
            execution_adapter_status(file),
            Err(ExecutionAdapterGap::StructuredFileEvaluationUnavailable)
        );
        assert_eq!(
            legacy_rustyline_adapter_status(),
            Err(EditorAdapterGap::SynchronousCompletionBlocksInterruptInput)
        );
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_inline_success_reads_the_live_root_exit_code() {
        use ibex_runtime::session_lifecycle::{
            LifecyclePrincipal, LifecycleSetDisposition, SessionLifecyclePort,
        };

        let lifecycle = SessionLifecyclePort::default();
        assert_eq!(
            lifecycle.set_exit_code(LifecyclePrincipal::Root, 7),
            LifecycleSetDisposition::Accepted { status: 7 }
        );
        assert_eq!(
            resolve_successful_inline_status(&lifecycle, None),
            InlineSettlement::Successful(7)
        );
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_inline_requested_exit_supersedes_orderly_exit_code() {
        use ibex_runtime::session_lifecycle::{
            LifecyclePrincipal, LifecycleRequestDisposition, LifecycleSetDisposition,
            SessionLifecyclePort,
        };

        let lifecycle = SessionLifecyclePort::default();
        assert_eq!(
            lifecycle.set_exit_code(LifecyclePrincipal::Root, 7),
            LifecycleSetDisposition::Accepted { status: 7 }
        );
        assert!(matches!(
            lifecycle.request_exit(LifecyclePrincipal::Root, 23),
            LifecycleRequestDisposition::Accepted { .. }
        ));
        assert_eq!(
            resolve_successful_inline_status(&lifecycle, None),
            InlineSettlement::Successful(23)
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_loss_changes_only_successful_causes_regardless_numeric_status() {
        for status in [0, 7, EXIT_STATUS_ENGINE_FAULT, EXIT_STATUS_INTERRUPT] {
            assert_eq!(
                InlineSettlement::Successful(status).final_status(true),
                EXIT_STATUS_BROKEN_PIPE
            );
            assert_eq!(InlineSettlement::Fixed(status).final_status(true), status);
            assert_eq!(
                InlineSettlement::Successful(status).final_status(false),
                status
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_program_adapter_captures_both_streams_and_scopes_native_close_guard() {
        const CHILD_ENV: &str = "IBEX_TEST_FILE_PROGRAM_ADAPTER_CHILD";
        const STDOUT_MARKER: &[u8] = b"\0file-stdout\x1b[31m";
        const STDERR_MARKER: &[u8] = b"\0file-stderr\x1b[32m";

        if std::env::var_os(CHILD_ENV).is_some() {
            let plan = SessionIoPlan::for_cli(
                &parsed_cli(&["ibex", "app.ts"]),
                terminal_facts(false, false, false),
                false,
            )
            .unwrap();
            assert_eq!(
                SessionIo::new(plan).route_read(0),
                DescriptorReadRoute::Native
            );
            let stdout_flags_before = descriptor_flags(libc::STDOUT_FILENO, libc::F_GETFL).unwrap();
            let stderr_flags_before = descriptor_flags(libc::STDERR_FILENO, libc::F_GETFL).unwrap();
            let stdout_descriptor_flags_before =
                descriptor_flags(libc::STDOUT_FILENO, libc::F_GETFD).unwrap();
            let stderr_descriptor_flags_before =
                descriptor_flags(libc::STDERR_FILENO, libc::F_GETFD).unwrap();
            let adapter = FileProgramExecutionAdapter::new(plan).unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let ((), report) = runtime
                .block_on(adapter.run(async {
                    assert_eq!(
                        crate::host::abi::ex_host_terminal_session_close_is_noop(0),
                        0
                    );
                    assert_eq!(
                        crate::host::abi::ex_host_terminal_session_close_is_noop(1),
                        1
                    );
                    assert_eq!(
                        crate::host::abi::ex_host_terminal_session_close_is_noop(2),
                        1
                    );
                    // SAFETY: fd 1/fd 2 are live adapter-owned pipe writers.
                    assert_eq!(
                        unsafe {
                            libc::write(
                                libc::STDOUT_FILENO,
                                STDOUT_MARKER.as_ptr().cast(),
                                STDOUT_MARKER.len(),
                            )
                        },
                        STDOUT_MARKER.len() as isize
                    );
                    // SAFETY: fd 1/fd 2 are live adapter-owned pipe writers.
                    assert_eq!(
                        unsafe {
                            libc::write(
                                libc::STDERR_FILENO,
                                STDERR_MARKER.as_ptr().cast(),
                                STDERR_MARKER.len(),
                            )
                        },
                        STDERR_MARKER.len() as isize
                    );
                }))
                .unwrap();
            assert!(!report.has_loss(), "unexpected loss: {report:?}");
            assert!(report
                .receipts()
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence));
            assert!(
                report
                    .receipts()
                    .iter()
                    .filter(|receipt| receipt.relay == NATIVE_STDOUT_RELAY)
                    .map(|receipt| receipt.bytes)
                    .sum::<usize>()
                    >= STDOUT_MARKER.len()
            );
            assert!(
                report
                    .receipts()
                    .iter()
                    .filter(|receipt| receipt.relay == NATIVE_STDERR_RELAY)
                    .map(|receipt| receipt.bytes)
                    .sum::<usize>()
                    >= STDERR_MARKER.len()
            );
            assert_eq!(
                crate::host::abi::ex_host_terminal_session_close_is_noop(1),
                0
            );
            // Darwin may add kernel-private F_GETFL bits to a pipe after its
            // first write. Assert the portable access/append/nonblocking
            // contract that the adapter can actually preserve.
            let portable_status_flags = libc::O_ACCMODE | libc::O_APPEND | libc::O_NONBLOCK;
            assert_eq!(
                descriptor_flags(libc::STDOUT_FILENO, libc::F_GETFL).unwrap()
                    & portable_status_flags,
                stdout_flags_before & portable_status_flags
            );
            assert_eq!(
                descriptor_flags(libc::STDERR_FILENO, libc::F_GETFL).unwrap()
                    & portable_status_flags,
                stderr_flags_before & portable_status_flags
            );
            assert_eq!(
                descriptor_flags(libc::STDOUT_FILENO, libc::F_GETFD).unwrap(),
                stdout_descriptor_flags_before
            );
            assert_eq!(
                descriptor_flags(libc::STDERR_FILENO, libc::F_GETFD).unwrap(),
                stderr_descriptor_flags_before
            );
            return;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "terminal_session::tests::file_program_adapter_captures_both_streams_and_scopes_native_close_guard",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed\nstdout: {:?}\nstderr: {:?}",
            output.stdout,
            output.stderr
        );
        assert_eq!(
            output
                .stdout
                .windows(STDOUT_MARKER.len())
                .filter(|window| *window == STDOUT_MARKER)
                .count(),
            1
        );
        assert_eq!(
            output
                .stderr
                .windows(STDERR_MARKER.len())
                .filter(|window| *window == STDERR_MARKER)
                .count(),
            1
        );
    }

    #[test]
    fn presentation_selection_is_stdout_then_stderr_then_no_editor() {
        let cli = parsed_cli(&["ibex"]);
        let stdout = SessionIoPlan::for_cli(&cli, terminal_facts(true, true, true), true).unwrap();
        assert_eq!(
            stdout.presentation.topology,
            PresentationTopology::StdoutTty
        );
        assert!(stdout.presentation.editor_control);

        let stderr = SessionIoPlan::for_cli(&cli, terminal_facts(true, false, true), true).unwrap();
        assert_eq!(
            stderr.presentation.topology,
            PresentationTopology::StderrTty
        );
        assert!(stderr.presentation.editor_control);

        let none = SessionIoPlan::for_cli(&cli, terminal_facts(true, false, false), true).unwrap();
        assert_eq!(none.presentation.topology, PresentationTopology::Transcript);
        assert!(!none.presentation.editor_control);
        assert!(!none.presentation.session_ansi);
        assert_eq!(none.route.mode, ArmedExecutionMode::Interactive);

        let transcript = SessionIoPlan::for_cli(
            &parsed_cli(&["ibex", "repl"]),
            terminal_facts(false, false, true),
            true,
        )
        .unwrap();
        assert_eq!(transcript.route.mode, ArmedExecutionMode::Transcript);
        assert!(!transcript.presentation.editor_control);
        assert!(!transcript.presentation.session_ansi);
    }

    #[test]
    fn output_topology_is_constructed_from_both_tty_facts_only() {
        let cli = parsed_cli(&["ibex"]);
        let shared = SessionIoPlan::for_cli(&cli, terminal_facts(true, true, true), false).unwrap();
        assert_eq!(
            shared.output_topology(),
            OutputDestinationTopology::Shared {
                destination: NativeOutputDestination::Stdout,
            }
        );
        assert_eq!(
            shared.broker_routes().program_stdout,
            shared.broker_routes().program_stderr
        );
        assert_eq!(shared.broker_routes().program_stdout, NATIVE_STDOUT_RELAY);
        assert_eq!(shared.broker_presentations().len(), 1);

        for facts in [
            terminal_facts(true, true, false),
            terminal_facts(true, false, true),
            terminal_facts(true, false, false),
        ] {
            let split = SessionIoPlan::for_cli(&cli, facts, false).unwrap();
            assert_eq!(split.output_topology(), OutputDestinationTopology::Split);
            assert_ne!(
                split.broker_routes().program_stdout,
                split.broker_routes().program_stderr
            );
            assert_eq!(split.broker_presentations().len(), 2);
        }
    }

    #[test]
    fn every_armed_cli_route_brokers_fd_one_and_two() {
        for (args, stdin_is_tty) in [
            (&["ibex"][..], true),
            (&["ibex"][..], false),
            (&["ibex", "repl"][..], false),
            (&["ibex", "-e", "1"][..], false),
            (&["ibex", "app.ts"][..], false),
        ] {
            let plan = SessionIoPlan::for_cli(
                &parsed_cli(args),
                terminal_facts(stdin_is_tty, false, false),
                false,
            )
            .unwrap();
            let io = SessionIo::new(plan);
            assert_eq!(
                io.route_write(1),
                DescriptorWriteRoute::Broker(ProgramStream::Stdout)
            );
            assert_eq!(
                io.route_write(2),
                DescriptorWriteRoute::Broker(ProgramStream::Stderr)
            );
            assert_eq!(plan.broker_routes().program_stdout, NATIVE_STDOUT_RELAY);
            assert_eq!(plan.broker_routes().program_stderr, NATIVE_STDERR_RELAY);
        }
    }

    #[test]
    fn session_fd_zero_returns_eof_before_native_descriptor_touch() {
        for args in [&["ibex"][..], &["ibex", "repl"][..]] {
            let plan = SessionIoPlan::for_cli(
                &parsed_cli(args),
                terminal_facts(false, false, false),
                false,
            )
            .unwrap();
            let io = SessionIo::new(plan);
            let touched = Cell::new(false);
            let mut bytes = [0_u8; 8];
            let read = io
                .read_javascript_descriptor(0, &mut bytes, |_, _| {
                    touched.set(true);
                    Ok(8)
                })
                .unwrap();
            assert_eq!(read, 0);
            assert!(!touched.get());
            assert_eq!(io.route_alias_source(0), DescriptorAliasRoute::EofView);

            io.close_javascript_descriptor(0, |_| {
                touched.set(true);
                Ok(())
            })
            .unwrap();
            assert!(!touched.get());
        }

        let file = SessionIoPlan::for_cli(
            &parsed_cli(&["ibex", "app.ts"]),
            terminal_facts(false, false, false),
            false,
        )
        .unwrap();
        let io = SessionIo::new(file);
        let touched = Cell::new(false);
        let mut bytes = [0_u8; 8];
        assert_eq!(
            io.read_javascript_descriptor(0, &mut bytes, |_, _| {
                touched.set(true);
                Ok(3)
            })
            .unwrap(),
            3
        );
        assert!(touched.get());
    }

    #[test]
    fn output_hooks_and_protected_handles_never_touch_native_fds() {
        let plan = SessionIoPlan::for_cli(
            &parsed_cli(&["ibex", "-e", "1"]),
            terminal_facts(false, false, false),
            false,
        )
        .unwrap();
        let mut io = SessionIo::new(plan);
        io.protect_descriptor(41).unwrap();
        let brokered = Cell::new(None);
        let native_touched = Cell::new(false);
        assert_eq!(
            io.write_javascript_descriptor(
                2,
                b"program bytes",
                |stream, _| {
                    brokered.set(Some(stream));
                    Ok(())
                },
                |_, _| {
                    native_touched.set(true);
                    Ok(0)
                },
            )
            .unwrap(),
            b"program bytes".len()
        );
        assert_eq!(brokered.get(), Some(ProgramStream::Stderr));
        assert!(!native_touched.get());

        let mut bytes = [0_u8; 1];
        let error = io
            .read_javascript_descriptor(41, &mut bytes, |_, _| {
                native_touched.set(true);
                Ok(1)
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!native_touched.get());
        assert_eq!(io.route_alias_source(41), DescriptorAliasRoute::Protected);
        assert_eq!(io.route_alias_target(41), DescriptorAliasRoute::Protected);
        assert_eq!(
            io.route_alias_target(1),
            DescriptorAliasRoute::RefusedStandardDescriptor
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_pty_raw_mode_disables_isig_and_restores_exact_flags() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        let mut master = -1;
        let mut slave = -1;
        // SAFETY: openpty initializes both descriptors on success; ownership is
        // transferred immediately to OwnedFd below.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: openpty returned two fresh owned descriptors.
        let _master = unsafe { OwnedFd::from_raw_fd(master) };
        // SAFETY: openpty returned two fresh owned descriptors.
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };

        let read_termios = |fd| {
            let mut value = std::mem::MaybeUninit::<libc::termios>::uninit();
            // SAFETY: value has space for termios and the PTY fd is live.
            assert_eq!(unsafe { libc::tcgetattr(fd, value.as_mut_ptr()) }, 0);
            // SAFETY: tcgetattr succeeded.
            unsafe { value.assume_init() }
        };
        let before = read_termios(slave.as_raw_fd());
        let mut terminal = UnixTerminalLifecycle::new(slave.as_raw_fd(), slave.as_raw_fd());
        terminal
            .enter_session(CapturedPresentation::interactive_plain())
            .unwrap();
        assert!(terminal.is_active());
        let raw = read_termios(slave.as_raw_fd());
        let editor_flags = (libc::ICANON | libc::ECHO | libc::ISIG) as libc::tcflag_t;
        assert_eq!(raw.c_lflag & editor_flags, 0);

        terminal.restore_session().unwrap();
        assert!(!terminal.is_active());
        let restored = read_termios(slave.as_raw_fd());
        assert_eq!(
            restored.c_lflag & editor_flags,
            before.c_lflag & editor_flags
        );
        assert_eq!(
            SIGNAL_RESTORE_STATE.state.load(Ordering::Acquire),
            SIGNAL_RESTORE_DISARMED
        );
    }

    const STDOUT_RELAY: RelayId = RelayId(1);
    const STDERR_RELAY: RelayId = RelayId(2);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FakeWriteMode {
        Ready(usize),
        Paused,
        Fail,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FakePhysicalWrite {
        relay: RelayId,
        lane: BrokerLane,
        sequence: u64,
        author: BrokerAuthor,
        kind: BrokerFrameKind,
        bytes: Vec<u8>,
    }

    #[derive(Default)]
    struct FakeRelaySink {
        modes: BTreeMap<RelayId, FakeWriteMode>,
        writes: Vec<FakePhysicalWrite>,
    }

    impl FakeRelaySink {
        fn set_mode(&mut self, relay: RelayId, mode: FakeWriteMode) {
            self.modes.insert(relay, mode);
        }

        fn bytes_for(&self, relay: RelayId) -> Vec<u8> {
            self.writes
                .iter()
                .filter(|write| write.relay == relay)
                .flat_map(|write| write.bytes.iter().copied())
                .collect()
        }
    }

    impl NonBlockingRelaySink for FakeRelaySink {
        fn try_write(
            &mut self,
            request: RelayWriteRequest<'_>,
        ) -> Result<RelayWriteOutcome, String> {
            let mode = self
                .modes
                .get(&request.relay)
                .copied()
                .unwrap_or(FakeWriteMode::Ready(usize::MAX));
            match mode {
                FakeWriteMode::Paused => Ok(RelayWriteOutcome::WouldBlock),
                FakeWriteMode::Fail => Err("deliberate sink failure".to_string()),
                FakeWriteMode::Ready(maximum) => {
                    let written = maximum.min(request.bytes.len());
                    self.writes.push(FakePhysicalWrite {
                        relay: request.relay,
                        lane: request.lane,
                        sequence: request.sequence,
                        author: request.author,
                        kind: request.kind,
                        bytes: request.bytes[..written].to_vec(),
                    });
                    Ok(RelayWriteOutcome::Written(written))
                }
            }
        }
    }

    #[cfg(unix)]
    #[derive(Clone, Default)]
    struct ConcurrentSinkControl {
        modes: Arc<Mutex<BTreeMap<RelayId, FakeWriteMode>>>,
        writes: Arc<Mutex<Vec<FakePhysicalWrite>>>,
    }

    #[cfg(unix)]
    impl ConcurrentSinkControl {
        fn set_mode(&self, relay: RelayId, mode: FakeWriteMode) {
            self.modes.lock().unwrap().insert(relay, mode);
        }

        fn writes(&self) -> Vec<FakePhysicalWrite> {
            self.writes.lock().unwrap().clone()
        }
    }

    #[cfg(unix)]
    struct ConcurrentFakeRelaySink {
        control: ConcurrentSinkControl,
    }

    #[cfg(unix)]
    impl NonBlockingRelaySink for ConcurrentFakeRelaySink {
        fn try_write(
            &mut self,
            request: RelayWriteRequest<'_>,
        ) -> Result<RelayWriteOutcome, String> {
            let mode = self
                .control
                .modes
                .lock()
                .unwrap()
                .get(&request.relay)
                .copied()
                .unwrap_or(FakeWriteMode::Ready(usize::MAX));
            match mode {
                FakeWriteMode::Paused => Ok(RelayWriteOutcome::WouldBlock),
                FakeWriteMode::Fail => Err("deliberate concurrent sink failure".to_string()),
                FakeWriteMode::Ready(maximum) => {
                    let written = maximum.min(request.bytes.len());
                    self.control.writes.lock().unwrap().push(FakePhysicalWrite {
                        relay: request.relay,
                        lane: request.lane,
                        sequence: request.sequence,
                        author: request.author,
                        kind: request.kind,
                        bytes: request.bytes[..written].to_vec(),
                    });
                    Ok(RelayWriteOutcome::Written(written))
                }
            }
        }
    }

    #[cfg(unix)]
    struct ReplBrokerLoopHarness {
        broker: ReplBrokerHandle,
        local_stdout_write: Option<NativeFd>,
        local_stderr_write: Option<NativeFd>,
        worker_stdout_write: Option<NativeFd>,
        worker_stderr_write: Option<NativeFd>,
        worker_acceptance: crate::session_worker::SupervisorRelayAcceptance,
        sink: ConcurrentSinkControl,
        broker_thread: Option<thread::JoinHandle<Result<(), String>>>,
    }

    #[cfg(unix)]
    impl ReplBrokerLoopHarness {
        fn transcript() -> Self {
            let plan = SessionIoPlan::for_cli(
                &parsed_cli(&["ibex", "repl"]),
                terminal_facts(false, false, false),
                false,
            )
            .unwrap();
            let (local_stdout_read, local_stdout_write) = native_pipe().unwrap();
            let (local_stderr_read, local_stderr_write) = native_pipe().unwrap();
            let (worker_stdout_read, worker_stdout_write) = native_pipe().unwrap();
            let (worker_stderr_read, worker_stderr_write) = native_pipe().unwrap();
            let sink = ConcurrentSinkControl::default();
            let broker_sink = ConcurrentFakeRelaySink {
                control: sink.clone(),
            };
            let worker_acceptance = crate::session_worker::SupervisorRelayAcceptance::default();
            let broker_acceptance = worker_acceptance.clone();
            let (command_tx, command_rx) = mpsc::channel();
            let broker_thread = thread::spawn(move || {
                repl_broker_loop(
                    plan,
                    RelayInputDescriptors::Split {
                        stdout: local_stdout_read,
                        stderr: local_stderr_read,
                    },
                    Some((
                        RelayInputDescriptors::Split {
                            stdout: worker_stdout_read,
                            stderr: worker_stderr_read,
                        },
                        broker_acceptance,
                    )),
                    None,
                    broker_sink,
                    command_rx,
                )
            });
            Self {
                broker: ReplBrokerHandle {
                    commands: command_tx,
                },
                local_stdout_write: Some(local_stdout_write),
                local_stderr_write: Some(local_stderr_write),
                worker_stdout_write: Some(worker_stdout_write),
                worker_stderr_write: Some(worker_stderr_write),
                worker_acceptance,
                sink,
                broker_thread: Some(broker_thread),
            }
        }

        fn shared_terminal() -> Self {
            let plan = SessionIoPlan::for_cli(
                &parsed_cli(&["ibex"]),
                terminal_facts(true, true, true),
                false,
            )
            .unwrap();
            let (local_output, local_stdout_write) = native_pipe().unwrap();
            let local_stderr_write = NativeFd::duplicate(local_stdout_write.raw()).unwrap();
            let (worker_output, worker_stdout_write) = native_pipe().unwrap();
            let worker_stderr_write = NativeFd::duplicate(worker_stdout_write.raw()).unwrap();
            let sink = ConcurrentSinkControl::default();
            let broker_sink = ConcurrentFakeRelaySink {
                control: sink.clone(),
            };
            let worker_acceptance = crate::session_worker::SupervisorRelayAcceptance::default();
            let broker_acceptance = worker_acceptance.clone();
            let (command_tx, command_rx) = mpsc::channel();
            let broker_thread = thread::spawn(move || {
                repl_broker_loop(
                    plan,
                    RelayInputDescriptors::Shared {
                        output: local_output,
                    },
                    Some((
                        RelayInputDescriptors::Shared {
                            output: worker_output,
                        },
                        broker_acceptance,
                    )),
                    None,
                    broker_sink,
                    command_rx,
                )
            });
            Self {
                broker: ReplBrokerHandle {
                    commands: command_tx,
                },
                local_stdout_write: Some(local_stdout_write),
                local_stderr_write: Some(local_stderr_write),
                worker_stdout_write: Some(worker_stdout_write),
                worker_stderr_write: Some(worker_stderr_write),
                worker_acceptance,
                sink,
                broker_thread: Some(broker_thread),
            }
        }

        fn close_inputs(&mut self) {
            self.local_stdout_write.take();
            self.local_stderr_write.take();
            self.worker_stdout_write.take();
            self.worker_stderr_write.take();
        }

        fn join(&mut self) {
            if let Some(thread) = self.broker_thread.take() {
                thread.join().unwrap().unwrap();
            }
        }

        fn force_finish(&mut self) {
            self.broker.force_finish();
            self.join();
        }
    }

    #[cfg(unix)]
    impl Drop for ReplBrokerLoopHarness {
        fn drop(&mut self) {
            if self.broker_thread.is_some() {
                self.broker.force_finish();
                self.join();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn repl_worker_barrier_accepts_each_exact_cutoff() {
        let mut harness = ReplBrokerLoopHarness::transcript();
        let stdout = b"abcdef";
        let stderr = b"XYZ";
        write_native_relay(harness.worker_stdout_write.as_ref().unwrap().raw(), stdout).unwrap();
        write_native_relay(harness.worker_stderr_write.as_ref().unwrap().raw(), stderr).unwrap();

        harness
            .broker
            .worker_barrier(stdout.len() as u64, stderr.len() as u64)
            .unwrap();
        harness.force_finish();
    }

    #[cfg(unix)]
    #[test]
    fn repl_shared_worker_relay_preserves_exact_cross_stream_order() {
        let mut harness = ReplBrokerLoopHarness::shared_terminal();
        let mut expected = Vec::new();
        for index in 0..256_u16 {
            let stderr = format!("E{index:04};");
            let stdout = format!("O{index:04};");
            write_native_relay(
                harness.worker_stderr_write.as_ref().unwrap().raw(),
                stderr.as_bytes(),
            )
            .unwrap();
            write_native_relay(
                harness.worker_stdout_write.as_ref().unwrap().raw(),
                stdout.as_bytes(),
            )
            .unwrap();
            expected.extend_from_slice(stderr.as_bytes());
            expected.extend_from_slice(stdout.as_bytes());
        }

        harness
            .broker
            .worker_barrier(expected.len() as u64, 0)
            .unwrap();
        assert_eq!(
            harness.worker_acceptance.snapshot(),
            (expected.len() as u64, 0)
        );
        harness.close_inputs();
        assert!(!harness.broker.finish().unwrap().has_loss());
        harness.join();

        let writes = harness.sink.writes();
        assert!(writes
            .windows(2)
            .all(|pair| pair[0].sequence <= pair[1].sequence));
        let actual: Vec<u8> = writes
            .iter()
            .filter(|write| {
                write.relay == NATIVE_STDOUT_RELAY
                    && write.author == BrokerAuthor::Program
                    && write.kind == BrokerFrameKind::Program
            })
            .flat_map(|write| write.bytes.iter().copied())
            .collect();
        assert_eq!(actual, expected);
    }

    #[cfg(unix)]
    #[test]
    fn repl_worker_barrier_reports_eof_before_cutoff_with_progress() {
        let mut harness = ReplBrokerLoopHarness::transcript();
        write_native_relay(harness.worker_stdout_write.as_ref().unwrap().raw(), b"ab").unwrap();
        harness.worker_stdout_write.take();

        let error = harness.broker.worker_barrier(3, 0).unwrap_err();
        assert_eq!(
            error,
            WorkerBarrierFailure::EofBeforeCutoff {
                stream: ProgramStream::Stdout,
                accepted_bytes: 2,
                cutoff_bytes: 3,
            }
        );
        assert!(error.is_output_loss());
        harness.force_finish();
    }

    #[cfg(unix)]
    #[test]
    fn repl_worker_barrier_times_out_with_both_stream_progress_counts() {
        let mut harness = ReplBrokerLoopHarness::transcript();
        let started = Instant::now();
        let error = harness.broker.worker_barrier(7, 11).unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(
            error,
            WorkerBarrierFailure::DeadlineExceeded {
                stdout_accepted: 0,
                stdout_cutoff: 7,
                stderr_accepted: 0,
                stderr_cutoff: 11,
            }
        );
        assert!(error.is_output_loss());
        assert!(
            elapsed >= Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS.saturating_sub(50)),
            "cutoff timed out too early: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "cutoff remained unbounded"
        );
        harness.force_finish();
    }

    #[cfg(unix)]
    #[test]
    fn repl_force_finish_preempts_a_pending_worker_cutoff_within_budget() {
        let mut harness = ReplBrokerLoopHarness::transcript();
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        harness
            .broker
            .commands
            .send(ReplBrokerCommand::WorkerBarrier {
                barrier: WorkerRelayBarrier {
                    stdout_cutoff: 13,
                    stderr_cutoff: 17,
                },
                reply: reply_tx,
            })
            .unwrap();

        let started = Instant::now();
        harness.force_finish();
        assert!(
            started.elapsed()
                < Duration::from_millis(BROKER_FLUSH_BUDGET_MILLIS.saturating_add(250)),
            "force-finish did not preempt the cutoff wait"
        );
        assert_eq!(
            reply_rx.recv().unwrap(),
            Err(WorkerBarrierFailure::Abandoned {
                stdout_accepted: 0,
                stdout_cutoff: 13,
                stderr_accepted: 0,
                stderr_cutoff: 17,
                reason: "abandoned by broker force-finish",
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn repl_pending_display_keeps_the_distinct_control_relay_responsive() {
        let mut harness = ReplBrokerLoopHarness::transcript();
        harness.sink.set_mode(STDOUT_RELAY, FakeWriteMode::Paused);
        let wire = encode_display_tree(
            DISPLAY_TREE_WIRE_VERSION,
            &display_node(DisplayNodeKind::Number, b"42".to_vec()),
        );
        let (display_tx, display_rx) = mpsc::sync_channel(1);
        harness
            .broker
            .commands
            .send(ReplBrokerCommand::Display {
                wire,
                worker_barrier: None,
                reply: display_tx,
            })
            .unwrap();
        harness.broker.interrupt_notice("control-still-live");

        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            if harness.sink.writes().iter().any(|write| {
                write.relay == STDERR_RELAY
                    && write.lane == BrokerLane::Control
                    && write.kind == BrokerFrameKind::InterruptNotice
                    && String::from_utf8_lossy(&write.bytes).contains("control-still-live")
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "pending display blocked the reserved control relay"
            );
            thread::sleep(Duration::from_millis(1));
        }
        assert!(matches!(
            display_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        harness.force_finish();
        assert!(matches!(
            display_rx.recv().unwrap(),
            Err(ReplDisplayFailure::Broker(message))
                if message.contains("force-finished before display completion")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn repl_finish_drains_worker_streams_before_retiring_the_broker() {
        let mut harness = ReplBrokerLoopHarness::transcript();
        let stdout = b"worker-finish-stdout\0";
        let stderr = b"worker-finish-stderr\0";
        write_native_relay(harness.worker_stdout_write.as_ref().unwrap().raw(), stdout).unwrap();
        write_native_relay(harness.worker_stderr_write.as_ref().unwrap().raw(), stderr).unwrap();
        harness.close_inputs();

        let loss = harness.broker.finish().unwrap();
        assert!(!loss.has_loss(), "unexpected bounded-finish loss: {loss:?}");
        harness.join();
        let writes = harness.sink.writes();
        assert_eq!(
            writes
                .iter()
                .filter(|write| write.relay == STDOUT_RELAY)
                .flat_map(|write| write.bytes.iter().copied())
                .collect::<Vec<_>>(),
            stdout
        );
        assert_eq!(
            writes
                .iter()
                .filter(|write| write.relay == STDERR_RELAY)
                .flat_map(|write| write.bytes.iter().copied())
                .collect::<Vec<_>>(),
            stderr
        );
    }

    type ConcreteBroker = InProcessOutputBroker<FakeRelaySink>;

    fn concrete_broker(queue_bound: usize) -> ConcreteBroker {
        InProcessOutputBroker::with_queue_bound(
            FakeRelaySink::default(),
            BrokerRoutes {
                program_stdout: STDOUT_RELAY,
                program_stderr: STDERR_RELAY,
                session: STDERR_RELAY,
                control: STDERR_RELAY,
            },
            [
                (
                    STDOUT_RELAY,
                    RelayPresentation {
                        session_ansi: false,
                        editor_control: false,
                    },
                ),
                (
                    STDERR_RELAY,
                    RelayPresentation {
                        session_ansi: false,
                        editor_control: true,
                    },
                ),
            ],
            queue_bound,
        )
        .unwrap()
    }

    #[test]
    fn worker_events_and_broker_receipts_share_one_epoch_and_sequence_domain() {
        let sequencer = crate::session_worker::SupervisorSequenceAllocator::new(7).unwrap();
        let worker_before = sequencer.assign("worker-before-output").unwrap();
        let mut broker = InProcessOutputBroker::with_sequence_allocator(
            FakeRelaySink::default(),
            BrokerRoutes {
                program_stdout: STDOUT_RELAY,
                program_stderr: STDERR_RELAY,
                session: STDERR_RELAY,
                control: STDERR_RELAY,
            },
            [
                (
                    STDOUT_RELAY,
                    RelayPresentation {
                        session_ansi: false,
                        editor_control: false,
                    },
                ),
                (
                    STDERR_RELAY,
                    RelayPresentation {
                        session_ansi: false,
                        editor_control: true,
                    },
                ),
            ],
            sequencer.clone(),
        )
        .unwrap();
        let output = broker
            .receive_program(ProgramStream::Stdout, b"output")
            .unwrap();
        let barrier = broker.snapshot_barrier().unwrap();
        let worker_after = sequencer.assign("worker-after-output").unwrap();

        assert_eq!((worker_before.epoch, worker_before.sequence), (7, 1));
        assert_eq!((output[0].epoch, output[0].sequence), (7, 2));
        assert_eq!((barrier.epoch(), barrier.sequence()), (7, 3));
        assert_eq!((worker_after.epoch, worker_after.sequence), (7, 4));

        sequencer.restart().unwrap();
        let after_restart = broker
            .receive_program(ProgramStream::Stderr, b"new epoch")
            .unwrap();
        assert_eq!((after_restart[0].epoch, after_restart[0].sequence), (8, 5));
    }

    #[derive(Clone)]
    struct TestDisplayNode {
        kind: u16,
        payload: Vec<u8>,
        children: Vec<TestDisplayNode>,
    }

    fn display_node(kind: DisplayNodeKind, payload: impl Into<Vec<u8>>) -> TestDisplayNode {
        TestDisplayNode {
            kind: kind as u16,
            payload: payload.into(),
            children: Vec::new(),
        }
    }

    fn encode_display_tree(version: u16, root: &TestDisplayNode) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(DISPLAY_TREE_MAGIC);
        wire.extend_from_slice(&version.to_le_bytes());
        encode_display_node(root, &mut wire);
        wire
    }

    fn encode_display_node(node: &TestDisplayNode, wire: &mut Vec<u8>) {
        wire.extend_from_slice(&node.kind.to_le_bytes());
        wire.extend_from_slice(&(node.payload.len() as u32).to_le_bytes());
        wire.extend_from_slice(&node.payload);
        wire.extend_from_slice(&(node.children.len() as u32).to_le_bytes());
        for child in &node.children {
            encode_display_node(child, wire);
        }
    }

    fn pump_until_stalled(broker: &mut ConcreteBroker) {
        loop {
            if broker.pump_all_once().progressed_relays == 0 {
                break;
            }
        }
    }

    // @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker — a
    // full destination applies backpressure without accepting or dropping.
    #[test]
    fn concrete_broker_backpressures_at_the_byte_bound_without_sequence_loss() {
        let mut broker = concrete_broker(4);
        let first = broker
            .receive_program(ProgramStream::Stdout, b"abcd")
            .unwrap();
        assert_eq!(first[0].sequence, 1);
        assert_eq!(broker.accepted_bytes(STDOUT_RELAY), Some(4));
        assert_eq!(
            broker.receive_program(ProgramStream::Stdout, b"e"),
            Err(BrokerEnqueueError::Backpressure {
                relay: STDOUT_RELAY,
                lane: BrokerLane::Data,
                attempted: 1,
                available: 0,
            })
        );
        assert_eq!(broker.accepted_bytes(STDOUT_RELAY), Some(4));
        pump_until_stalled(&mut broker);
        let retried = broker.receive_program(ProgramStream::Stdout, b"e").unwrap();
        assert_eq!(retried[0].sequence, 2);
        pump_until_stalled(&mut broker);
        assert_eq!(broker.sink().bytes_for(STDOUT_RELAY), b"abcde");
    }

    #[test]
    fn control_lane_reaches_stderr_tty_while_stdout_is_stalled() {
        let mut broker = concrete_broker(1024);
        broker.publish_prompt("> ", b"foo.").unwrap();
        pump_until_stalled(&mut broker);
        let prompt_bytes = broker.sink().bytes_for(STDERR_RELAY).len();

        broker
            .sink_mut()
            .set_mode(STDOUT_RELAY, FakeWriteMode::Paused);
        broker
            .receive_program(ProgramStream::Stdout, b"blocked")
            .unwrap();
        broker
            .receive_interrupt_notice("cancelling work — press Ctrl+C again")
            .unwrap();
        pump_until_stalled(&mut broker);

        assert!(broker.sink().bytes_for(STDOUT_RELAY).is_empty());
        let stderr = broker.sink().bytes_for(STDERR_RELAY);
        assert!(stderr.len() > prompt_bytes);
        assert!(String::from_utf8_lossy(&stderr).contains("cancelling work"));
        assert!(stderr.ends_with(b"> foo."));
        assert!(broker
            .sink()
            .writes
            .iter()
            .any(|write| write.lane == BrokerLane::Control));
    }

    #[test]
    fn concrete_async_output_erases_and_redraws_the_escaped_prompt() {
        let mut broker = concrete_broker(1024);
        broker.publish_prompt("\x1b> ", b"foo.").unwrap();
        pump_until_stalled(&mut broker);
        let receipts = broker.receive_async_report("bad\x1b\u{202e}").unwrap();
        assert_eq!(
            receipts
                .iter()
                .map(|receipt| receipt.kind)
                .collect::<Vec<_>>(),
            vec![
                BrokerFrameKind::PromptErase,
                BrokerFrameKind::AsyncReport,
                BrokerFrameKind::PromptRedraw,
            ]
        );
        pump_until_stalled(&mut broker);
        let writes = &broker.sink().writes;
        let report = writes
            .iter()
            .position(|write| write.kind == BrokerFrameKind::AsyncReport)
            .unwrap();
        assert_eq!(writes[report - 1].kind, BrokerFrameKind::PromptErase);
        assert_eq!(writes[report + 1].kind, BrokerFrameKind::PromptRedraw);
        assert!(!writes[report].bytes.contains(&0x1b));
        assert!(String::from_utf8_lossy(&writes[report].bytes).contains("\\u{202e}"));
        assert!(writes[report + 1].bytes.ends_with(b"> foo."));
        assert!(!writes[report + 1].bytes.contains(&0x1b));
    }

    fn assert_single_prompt_wrap(
        broker: &mut ConcreteBroker,
        receipts: &[BrokerReceipt],
        payload_kind: BrokerFrameKind,
        payload: &[u8],
    ) {
        assert_eq!(
            receipts
                .iter()
                .map(|receipt| (receipt.sequence, receipt.kind))
                .collect::<Vec<_>>(),
            vec![
                (2, BrokerFrameKind::PromptErase),
                (3, payload_kind),
                (4, BrokerFrameKind::PromptRedraw),
            ]
        );
        pump_until_stalled(broker);
        let writes = &broker.sink().writes;
        assert_eq!(
            writes.iter().map(|write| write.kind).collect::<Vec<_>>(),
            vec![
                BrokerFrameKind::PromptErase,
                payload_kind,
                BrokerFrameKind::PromptRedraw,
            ]
        );
        let bytes = writes
            .iter()
            .flat_map(|write| write.bytes.iter().copied())
            .collect::<Vec<_>>();
        let mut expected = PROMPT_EDITOR_ERASE_BYTES.to_vec();
        expected.extend_from_slice(payload);
        expected.extend_from_slice(b"> foo.");
        assert_eq!(bytes, expected);
    }

    fn prompted_broker() -> ConcreteBroker {
        let mut broker = concrete_broker(1024);
        broker.publish_prompt("> ", b"foo.").unwrap();
        pump_until_stalled(&mut broker);
        broker.sink_mut().writes.clear();
        broker
    }

    #[test]
    fn every_prompt_wrapped_event_has_one_erase_payload_and_redraw() {
        let mut program = prompted_broker();
        let program_bytes = b"raw\0\x1b";
        let receipts = program
            .receive_program(ProgramStream::Stderr, program_bytes)
            .unwrap();
        assert_single_prompt_wrap(
            &mut program,
            &receipts,
            BrokerFrameKind::Program,
            program_bytes,
        );

        let mut report = prompted_broker();
        let receipts = report.receive_async_report("bad").unwrap();
        assert_single_prompt_wrap(&mut report, &receipts, BrokerFrameKind::AsyncReport, b"bad");

        let mut interrupt = prompted_broker();
        let receipts = interrupt.receive_interrupt_notice("stop").unwrap();
        assert_single_prompt_wrap(
            &mut interrupt,
            &receipts,
            BrokerFrameKind::InterruptNotice,
            b"stop",
        );

        let mut display = prompted_broker();
        let wire = encode_display_tree(
            DISPLAY_TREE_WIRE_VERSION,
            &display_node(DisplayNodeKind::Number, b"42".to_vec()),
        );
        let ticket = display.receive_display_tree(&wire).unwrap();
        assert_eq!(ticket.barrier().sequence(), 5);
        let receipts = ticket.receipts().to_vec();
        assert_single_prompt_wrap(&mut display, &receipts, BrokerFrameKind::Display, b"42");
    }

    #[test]
    fn barriers_wait_for_each_unequal_relay_cutoff() {
        let mut broker = concrete_broker(1024);
        broker
            .sink_mut()
            .set_mode(STDOUT_RELAY, FakeWriteMode::Ready(2));
        let stdout = broker
            .receive_program(ProgramStream::Stdout, b"abcdef")
            .unwrap();
        let stderr = broker
            .receive_program(ProgramStream::Stderr, b"XYZ")
            .unwrap();
        let barrier = broker.snapshot_barrier().unwrap();
        assert_eq!(
            (stdout[0].sequence, stderr[0].sequence, barrier.sequence(),),
            (1, 2, 3)
        );
        assert_eq!(
            barrier
                .cutoffs()
                .iter()
                .map(|cutoff| (cutoff.relay(), cutoff.accepted_bytes()))
                .collect::<Vec<_>>(),
            vec![(STDOUT_RELAY, 6), (STDERR_RELAY, 3)]
        );

        broker.pump_all_once();
        assert_eq!(
            broker.poll_barrier(&barrier),
            BarrierPoll::Pending(vec![RelayBarrierProgress {
                relay: STDOUT_RELAY,
                written_bytes: 2,
                cutoff_bytes: 6,
            }])
        );
        assert_eq!(broker.drain_barrier(&barrier), BarrierPoll::Complete);
        assert_eq!(broker.sink().bytes_for(STDOUT_RELAY), b"abcdef");
        assert_eq!(broker.sink().bytes_for(STDERR_RELAY), b"XYZ");
    }

    #[test]
    fn result_is_not_written_before_its_cross_relay_barrier() {
        let mut broker = concrete_broker(1024);
        broker
            .sink_mut()
            .set_mode(STDOUT_RELAY, FakeWriteMode::Paused);
        broker
            .receive_program(ProgramStream::Stdout, b"program first")
            .unwrap();
        let prerequisite = broker.snapshot_barrier().unwrap();
        let result = encode_display_tree(
            DISPLAY_TREE_WIRE_VERSION,
            &display_node(DisplayNodeKind::Number, b"42".to_vec()),
        );
        assert_eq!(
            broker.receive_display_tree_after(&prerequisite, &result),
            Err(BrokerEnqueueError::BarrierPending)
        );
        assert!(!broker
            .sink()
            .writes
            .iter()
            .any(|write| write.kind == BrokerFrameKind::Display));

        broker
            .sink_mut()
            .set_mode(STDOUT_RELAY, FakeWriteMode::Ready(usize::MAX));
        assert_eq!(broker.drain_barrier(&prerequisite), BarrierPoll::Complete);
        broker
            .receive_program(ProgramStream::Stderr, b"interleaved")
            .unwrap();
        assert_eq!(
            broker.receive_display_tree_after(&prerequisite, &result),
            Err(BrokerEnqueueError::BarrierSuperseded)
        );
        let current = broker.snapshot_barrier().unwrap();
        assert_eq!(broker.drain_barrier(&current), BarrierPoll::Complete);
        let ticket = broker
            .receive_display_tree_after(&current, &result)
            .unwrap();
        assert_eq!(broker.poll_display(&ticket), DisplayPoll::Pending);
        broker.drain_barrier(&ticket.barrier);
        assert_eq!(
            broker.poll_display(&ticket),
            DisplayPoll::Complete(DisplayDisposition::Displayed)
        );
    }

    #[test]
    fn barriers_reject_foreign_forged_stale_and_superseded_proofs() {
        let result = encode_display_tree(
            DISPLAY_TREE_WIRE_VERSION,
            &display_node(DisplayNodeKind::Number, b"42".to_vec()),
        );
        let mut first = concrete_broker(1024);
        first
            .receive_program(ProgramStream::Stdout, b"prior")
            .unwrap();
        let barrier = first.snapshot_barrier().unwrap();

        let mut foreign_broker = concrete_broker(1024);
        assert_eq!(
            foreign_broker.poll_barrier(&barrier),
            BarrierPoll::Invalid(BarrierInvalidity::ForeignBroker)
        );
        assert_eq!(
            foreign_broker.receive_display_tree_after(&barrier, &result),
            Err(BrokerEnqueueError::ForeignBarrier)
        );

        // This mutation is possible only inside this module's test; external
        // callers see opaque cutoffs. Even a forged zero cutoff cannot bypass
        // the current-cutoff equality check.
        let mut forged = barrier.clone();
        for cutoff in &mut forged.cutoffs {
            cutoff.accepted_bytes = 0;
        }
        assert_eq!(first.drain_barrier(&forged), BarrierPoll::Complete);
        assert_eq!(
            first.receive_display_tree_after(&forged, &result),
            Err(BrokerEnqueueError::BarrierSuperseded)
        );

        first.drain_barrier(&barrier);
        first
            .receive_program(ProgramStream::Stderr, b"later")
            .unwrap();
        assert_eq!(
            first.receive_display_tree_after(&barrier, &result),
            Err(BrokerEnqueueError::BarrierSuperseded)
        );

        let stale = first.snapshot_barrier().unwrap();
        first.force_close().unwrap();
        assert_eq!(
            first.poll_barrier(&stale),
            BarrierPoll::Invalid(BarrierInvalidity::StaleGeneration)
        );
        assert_eq!(
            first.receive_display_tree_after(&stale, &result),
            Err(BrokerEnqueueError::StaleBarrier)
        );
    }

    #[test]
    fn acceptance_counter_covers_a_writer_paused_after_enqueue() {
        let mut broker = concrete_broker(1024);
        broker
            .sink_mut()
            .set_mode(STDOUT_RELAY, FakeWriteMode::Paused);
        let program_bytes = b"bye\0\x1b[31m";
        broker
            .receive_program(ProgramStream::Stdout, program_bytes)
            .unwrap();
        let barrier = broker.snapshot_barrier().unwrap();
        assert_eq!(
            broker.accepted_bytes(STDOUT_RELAY),
            Some(program_bytes.len() as u64)
        );
        assert_eq!(broker.written_bytes(STDOUT_RELAY), Some(0));
        assert!(matches!(
            broker.drain_barrier(&barrier),
            BarrierPoll::Pending(_)
        ));

        broker
            .sink_mut()
            .set_mode(STDOUT_RELAY, FakeWriteMode::Ready(usize::MAX));
        assert_eq!(broker.drain_barrier(&barrier), BarrierPoll::Complete);
        assert_eq!(broker.sink().bytes_for(STDOUT_RELAY), program_bytes);
    }

    #[test]
    fn renderer_escapes_hostile_payload_and_uses_only_kind_derived_style() {
        let payload = b"x\x1b[31m\x1b]0;owned\x07\x1b_payload\x1b\\\x1bPq\x90\x9b\xc2\x9b\xe2\x80\xae\xe2\x80\xa8"
            .to_vec();
        let wire = encode_display_tree(
            DISPLAY_TREE_WIRE_VERSION,
            &display_node(DisplayNodeKind::String, payload),
        );
        let plain = SafeSessionRenderer::render_tree(&wire, false);
        assert_eq!(plain.disposition, DisplayDisposition::Displayed);
        assert!(!plain.bytes.contains(&0x1b));
        assert!(!plain.bytes.contains(&0x9b));
        let plain_text = String::from_utf8_lossy(&plain.bytes);
        assert!(plain_text.contains("\\u{001b}"));
        assert!(plain_text.contains("\\u{009b}"));
        assert!(plain_text.contains("\\u{202e}"));
        assert!(plain_text.contains("\\u{2028}"));

        let styled = SafeSessionRenderer::render_tree(&wire, true);
        assert_eq!(styled.disposition, DisplayDisposition::Displayed);
        assert!(styled.bytes.starts_with(b"\x1b[32m"));
        assert!(styled.bytes.ends_with(b"\x1b[0m"));
        assert!(!String::from_utf8_lossy(&styled.bytes).contains("\x1b[31m"));
    }

    #[test]
    fn malformed_unknown_and_over_limit_trees_are_fallbacks() {
        let malformed = SafeSessionRenderer::render_tree(b"IBDX\x01", false);
        assert_eq!(malformed.disposition, DisplayDisposition::Fallback);

        let unknown_version = encode_display_tree(
            DISPLAY_TREE_WIRE_VERSION + 1,
            &display_node(DisplayNodeKind::Text, b"ignored".to_vec()),
        );
        assert_eq!(
            SafeSessionRenderer::render_tree(&unknown_version, false).disposition,
            DisplayDisposition::Fallback
        );

        let unknown_kind = encode_display_tree(
            DISPLAY_TREE_WIRE_VERSION,
            &TestDisplayNode {
                kind: u16::MAX,
                payload: b"\x1b[31mhostile".to_vec(),
                children: Vec::new(),
            },
        );
        let unknown = SafeSessionRenderer::render_tree(&unknown_kind, false);
        assert_eq!(unknown.disposition, DisplayDisposition::Fallback);
        assert!(!unknown.bytes.contains(&0x1b));

        let payload_limit = encode_display_tree(
            DISPLAY_TREE_WIRE_VERSION,
            &display_node(
                DisplayNodeKind::Text,
                vec![b'x'; DISPLAY_PAYLOAD_SCALARS + 7],
            ),
        );
        let truncated = SafeSessionRenderer::render_tree(&payload_limit, false);
        assert_eq!(truncated.disposition, DisplayDisposition::Fallback);
        assert!(truncated.bytes.ends_with("… +7 more".as_bytes()));

        let over_size = vec![0_u8; DISPLAY_TREE_MAX_SERIALIZED_BYTES + 1];
        assert_eq!(
            SafeSessionRenderer::render_tree(&over_size, false).disposition,
            DisplayDisposition::Fallback
        );
    }

    #[test]
    fn depth_and_breadth_limits_skip_hostile_subtrees_without_raw_output() {
        let mut deep = display_node(DisplayNodeKind::Text, b"leaf".to_vec());
        for _ in 0..DISPLAY_RENDER_DEPTH {
            deep = TestDisplayNode {
                kind: DisplayNodeKind::Text as u16,
                payload: b"level".to_vec(),
                children: vec![deep],
            };
        }
        let deep_render = SafeSessionRenderer::render_tree(
            &encode_display_tree(DISPLAY_TREE_WIRE_VERSION, &deep),
            false,
        );
        assert_eq!(deep_render.disposition, DisplayDisposition::Fallback);
        assert!(String::from_utf8_lossy(&deep_render.bytes).contains("+1 more"));

        let broad = TestDisplayNode {
            kind: DisplayNodeKind::Text as u16,
            payload: b"root".to_vec(),
            children: (0..=DISPLAY_RENDER_BREADTH)
                .map(|_| display_node(DisplayNodeKind::Text, b"child".to_vec()))
                .collect(),
        };
        let broad_render = SafeSessionRenderer::render_tree(
            &encode_display_tree(DISPLAY_TREE_WIRE_VERSION, &broad),
            false,
        );
        assert_eq!(broad_render.disposition, DisplayDisposition::Fallback);
        assert!(String::from_utf8_lossy(&broad_render.bytes).contains("+1 more"));
    }

    #[test]
    fn display_ack_waits_for_write_and_preserves_fallback_or_failure() {
        let valid = encode_display_tree(
            DISPLAY_TREE_WIRE_VERSION,
            &display_node(DisplayNodeKind::Number, b"42".to_vec()),
        );
        let mut broker = concrete_broker(1024);
        let displayed = broker.receive_display_tree(&valid).unwrap();
        assert_eq!(broker.poll_display(&displayed), DisplayPoll::Pending);
        assert_eq!(
            broker.drain_barrier(&displayed.barrier),
            BarrierPoll::Complete
        );
        assert_eq!(
            broker.poll_display(&displayed),
            DisplayPoll::Complete(DisplayDisposition::Displayed)
        );

        let fallback_wire = encode_display_tree(
            DISPLAY_TREE_WIRE_VERSION + 1,
            &display_node(DisplayNodeKind::Number, b"42".to_vec()),
        );
        let fallback = broker.receive_display_tree(&fallback_wire).unwrap();
        broker.drain_barrier(&fallback.barrier);
        assert_eq!(
            broker.poll_display(&fallback),
            DisplayPoll::Complete(DisplayDisposition::Fallback)
        );

        let mut failed = concrete_broker(1024);
        let failure_ticket = failed.receive_display_tree(&valid).unwrap();
        failed
            .sink_mut()
            .set_mode(STDERR_RELAY, FakeWriteMode::Fail);
        failed.pump_all_once();
        assert_eq!(
            failed.poll_display(&failure_ticket),
            DisplayPoll::Complete(DisplayDisposition::WriteFailed)
        );
    }

    #[test]
    fn forced_close_accounts_remaining_program_and_session_output() {
        let mut broker = concrete_broker(1024);
        broker
            .sink_mut()
            .set_mode(STDOUT_RELAY, FakeWriteMode::Ready(2));
        broker
            .sink_mut()
            .set_mode(STDERR_RELAY, FakeWriteMode::Paused);
        broker
            .receive_program(ProgramStream::Stdout, b"abcdef")
            .unwrap();
        broker.receive_async_report("oops").unwrap();
        broker.receive_interrupt_notice("stop").unwrap();
        broker.pump_all_once();
        let loss = broker.force_close().unwrap();
        assert!(loss.has_loss());
        assert_eq!(loss.forced_close_sequence, 4);
        let stdout = loss
            .relays
            .iter()
            .find(|loss| loss.relay == STDOUT_RELAY)
            .unwrap();
        assert_eq!((stdout.program_bytes, stdout.program_frames), (4, 1));
        let stderr = loss
            .relays
            .iter()
            .find(|loss| loss.relay == STDERR_RELAY)
            .unwrap();
        assert_eq!(stderr.session_frames, 2);
        assert_eq!(stderr.control_frames, 1);
        assert!(stderr.session_bytes >= b"oopsstop".len());
        assert!(matches!(
            broker.receive_program(ProgramStream::Stdout, b"later"),
            Err(BrokerEnqueueError::Closed)
        ));
    }

    #[test]
    fn captured_color_predicate_has_the_specified_precedence() {
        let base = CapturedColorFacts {
            plain_transcript: false,
            interactive_mode: true,
            interactive_editor: true,
            no_color: false,
            clicolor_force: false,
            stream_is_tty: true,
            term_is_dumb: false,
        };
        assert!(base.session_ansi());
        assert!(!CapturedColorFacts {
            plain_transcript: true,
            clicolor_force: true,
            ..base
        }
        .session_ansi());
        assert!(!CapturedColorFacts {
            no_color: true,
            clicolor_force: true,
            ..base
        }
        .session_ansi());
        assert!(CapturedColorFacts {
            clicolor_force: true,
            stream_is_tty: false,
            term_is_dumb: true,
            ..base
        }
        .session_ansi());
        assert!(!CapturedColorFacts {
            stream_is_tty: false,
            ..base
        }
        .session_ansi());
        assert!(CapturedColorFacts {
            interactive_mode: false,
            interactive_editor: false,
            ..base
        }
        .session_ansi());
    }

    #[cfg(unix)]
    fn dispatch_idle_worker_interrupt(
        work: &crate::repl::ReplInterruptWorkSnapshot,
        escape_credit: u8,
        promise: generated::PromiseClass,
    ) -> generated::InterruptDecision {
        generated::dispatch_interrupt(generated::InterruptState {
            phase: generated::EditorPhase::Idle,
            pending_submission: generated::PendingSubmission::None,
            executing: work.executing.map(|(id, kind)| generated::ExecutingUnit {
                id,
                kind: generated_interrupt_work_kind(kind),
            }),
            suspended_ids: &work.suspended_ids,
            due_schedules: &work.due_schedules,
            completion_queued: None,
            escape_credit,
            promise,
            cause: None,
            exit_code: 0,
            ended: false,
        })
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn production_suspended_only_interrupt_uses_work_promise_and_force_escape() {
        let work = crate::repl::ReplInterruptWorkSnapshot {
            executing: None,
            suspended_ids: vec![41],
            due_schedules: Vec::new(),
        };
        let first = dispatch_idle_worker_interrupt(&work, 0, generated::PromiseClass::None);
        assert_eq!(
            first.row,
            Some(generated::InterruptRow::IdleNonexecutingWork)
        );
        assert_eq!(first.notice, generated::Notice::WorkInFlight);
        assert_eq!(first.promise_to_set, generated::PromiseClass::Interrupt130);
        assert_eq!(first.cancel_target, None);

        let second = dispatch_idle_worker_interrupt(&work, first.next_credit, first.promise_to_set);
        assert!(second.terminal);
        assert_eq!(second.status, Some(EXIT_STATUS_INTERRUPT));
        assert!(interrupt_requires_engine_independent_exit(
            &second,
            generated::EditorPhase::Idle,
            &work,
        ));
    }

    #[cfg(unix)]
    #[test]
    fn production_due_only_interrupt_uses_work_promise_and_force_escape() {
        let work = crate::repl::ReplInterruptWorkSnapshot {
            executing: None,
            suspended_ids: Vec::new(),
            due_schedules: vec![73],
        };
        let first = dispatch_idle_worker_interrupt(&work, 0, generated::PromiseClass::None);
        assert_eq!(
            first.row,
            Some(generated::InterruptRow::IdleNonexecutingWork)
        );
        assert_eq!(first.notice, generated::Notice::WorkInFlight);
        assert_eq!(first.promise_to_set, generated::PromiseClass::Interrupt130);
        assert_eq!(first.cancel_target, None);

        let second = dispatch_idle_worker_interrupt(&work, first.next_credit, first.promise_to_set);
        assert!(second.terminal);
        assert_eq!(second.status, Some(EXIT_STATUS_INTERRUPT));
        assert!(interrupt_requires_engine_independent_exit(
            &second,
            generated::EditorPhase::Idle,
            &work,
        ));
    }

    #[cfg(unix)]
    #[test]
    fn production_non_editor_routes_capture_sigint_for_the_ordinary_cleanup_lane() {
        let transcript = CapturedPresentation {
            topology: PresentationTopology::Transcript,
            session_ansi: false,
            editor_control: false,
        };
        assert!(captures_non_editor_interrupt(transcript));
        assert!(!captures_non_editor_interrupt(
            CapturedPresentation::interactive_plain()
        ));
        assert_eq!(session_signal_bits(libc::SIGINT), SESSION_SIGNAL_INTERRUPT);
        assert_eq!(session_signal_bits(libc::SIGTSTP), SESSION_SIGNAL_SUSPEND);
        assert_eq!(session_signal_bits(libc::SIGWINCH), SESSION_SIGNAL_RESIZE);
    }

    #[cfg(unix)]
    #[test]
    fn production_non_editor_interrupt_orders_exact_cancel_restore_kill_and_flush() {
        #[derive(Default)]
        struct CleanupProbe {
            calls: Vec<&'static str>,
        }

        impl NonEditorInterruptCleanupPort for CleanupProbe {
            fn request_exact_cancellation(&mut self) -> Result<(), String> {
                self.calls.push("cancel");
                Ok(())
            }

            fn restore_for_interrupt(&mut self) -> Result<(), String> {
                self.calls.push("restore");
                Ok(())
            }

            fn terminate_interrupted_worker(&mut self) -> Result<(), String> {
                self.calls.push("terminate");
                Ok(())
            }

            fn force_finish_broker(&mut self) {
                self.calls.push("flush");
            }
        }

        let mut probe = CleanupProbe::default();
        execute_non_editor_interrupt_cleanup(&mut probe);
        assert_eq!(probe.calls, ["cancel", "restore", "terminate", "flush"]);

        struct FailedCancelProbe(CleanupProbe);
        impl NonEditorInterruptCleanupPort for FailedCancelProbe {
            fn request_exact_cancellation(&mut self) -> Result<(), String> {
                self.0.calls.push("cancel");
                Err("stale target".to_string())
            }

            fn restore_for_interrupt(&mut self) -> Result<(), String> {
                self.0.calls.push("restore");
                Ok(())
            }

            fn terminate_interrupted_worker(&mut self) -> Result<(), String> {
                self.0.calls.push("terminate");
                Ok(())
            }

            fn force_finish_broker(&mut self) {
                self.0.calls.push("flush");
            }
        }

        let mut failed = FailedCancelProbe(CleanupProbe::default());
        execute_non_editor_interrupt_cleanup(&mut failed);
        assert_eq!(
            failed.0.calls,
            ["cancel", "restore", "terminate", "flush"],
            "a failed exact request must not defeat the bounded escape"
        );
    }

    // @ref LLP 0025#acceptance-criteria — schedule (a), tight callback
    // turnover, must preserve the first running-work promise.
    #[test]
    fn schedule_a_tight_turnover_terminates_in_two() {
        let mut harness = harness([CancellationStatus::Pending]);
        callback(&mut harness.supervisor, ScheduleId(1), TargetId(11));
        let first = harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(first.cancellation_target, Some(TargetId(11)));
        harness.supervisor.end_unit(TargetId(11)).unwrap();
        callback(&mut harness.supervisor, ScheduleId(1), TargetId(12));
        let second = harness.supervisor.handle_interrupt().unwrap();
        assert!(second.terminal);
        assert_eq!(second.status, Some(130));
        assert_eq!(last_command(&harness).status, 130);
    }

    // @ref LLP 0025#acceptance-criteria — schedule (b), a target-class gap,
    // cannot invalidate the promise printed by the first press.
    #[test]
    fn schedule_b_gappy_turnover_terminates_in_two() {
        let mut harness = harness([CancellationStatus::Pending]);
        callback(&mut harness.supervisor, ScheduleId(1), TargetId(11));
        harness.supervisor.handle_interrupt().unwrap();
        harness.supervisor.end_unit(TargetId(11)).unwrap();
        let second = harness.supervisor.handle_interrupt().unwrap();
        assert!(second.terminal);
        assert_eq!(second.status, Some(130));
    }

    // @ref LLP 0025#acceptance-criteria — schedule (c), typed-ahead does not
    // become editor input merely because it is eventually drained.
    #[test]
    fn schedule_c_typed_ahead_does_not_reset() {
        let mut harness = harness([CancellationStatus::Pending]);
        begin_evaluation(&mut harness.supervisor, TargetId(21));
        harness.supervisor.handle_interrupt().unwrap();
        harness
            .supervisor
            .handle_editor_event(EditorInputEvent::Byte {
                byte: b'z',
                observed_prompt: None,
            })
            .unwrap();
        assert_eq!(harness.supervisor.state().escape_credit, 1);
        assert_eq!(
            harness.supervisor.state().promise,
            PromiseClass::Interrupt130
        );
        let second = harness.supervisor.handle_interrupt().unwrap();
        assert!(second.terminal);
        assert_eq!(second.status, Some(130));
    }

    // @ref LLP 0025#acceptance-criteria — schedule (d), completion end and
    // background readiness between presses cannot break the promise.
    #[test]
    fn schedule_d_completion_end_between_presses_preserves_buffer() {
        let mut harness = harness([CancellationStatus::Pending]);
        for byte in b"foo." {
            type_byte(&mut harness.supervisor, *byte);
        }
        harness
            .supervisor
            .queue_completion(CompletionRequestId(1))
            .unwrap();
        harness
            .supervisor
            .begin_completion(CompletionRequestId(1), TargetId(31))
            .unwrap();
        harness.supervisor.mark_due(ScheduleId(1));
        harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(harness.supervisor.state().buffer, b"foo.");
        let redraw = harness
            .frames
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|frame| frame.kind == BrokerFrameKind::PromptRedraw)
            .unwrap()
            .clone();
        assert!(redraw.bytes.ends_with(b"foo."));
        assert_eq!(
            harness
                .supervisor
                .finish_completion(CompletionRequestId(1), TargetId(31))
                .unwrap(),
            CompletionDisposition::Abandoned
        );
        let second = harness.supervisor.handle_interrupt().unwrap();
        assert!(second.terminal);
        assert_eq!(second.status, Some(130));
    }

    // @ref LLP 0025#acceptance-criteria — schedule (e), promise status wins
    // over the target selected on the credit-three press, in both directions.
    #[test]
    fn schedule_e_promise_class_survives_target_flip() {
        let mut orderly = harness([]);
        type_byte(&mut orderly.supervisor, b'x');
        orderly.supervisor.handle_interrupt().unwrap();
        orderly.supervisor.handle_interrupt().unwrap();
        orderly.supervisor.mark_due(ScheduleId(1));
        let third = orderly.supervisor.handle_interrupt().unwrap();
        assert!(third.terminal);
        assert_eq!(third.status, Some(0));
        assert_eq!(last_command(&orderly).kind, TerminationKind::Orderly);

        let mut interrupted = harness([CancellationStatus::Pending]);
        begin_evaluation(&mut interrupted.supervisor, TargetId(41));
        interrupted.supervisor.handle_interrupt().unwrap();
        interrupted.supervisor.end_unit(TargetId(41)).unwrap();
        let second = interrupted.supervisor.handle_interrupt().unwrap();
        assert_eq!(second.status, Some(130));
        assert_eq!(last_command(&interrupted).kind, TerminationKind::Interrupt);
    }

    // @ref LLP 0025#acceptance-criteria — schedule (f), late delivery keeps
    // the byte's no-prompt provenance.
    #[test]
    fn schedule_f_drained_typed_ahead_keeps_promise() {
        let mut harness = harness([CancellationStatus::Pending]);
        begin_evaluation(&mut harness.supervisor, TargetId(51));
        harness.supervisor.handle_interrupt().unwrap();
        harness
            .supervisor
            .handle_editor_event(EditorInputEvent::Byte {
                byte: b'z',
                observed_prompt: None,
            })
            .unwrap();
        harness.supervisor.end_unit(TargetId(51)).unwrap();
        harness.supervisor.drain_typed_ahead().unwrap();
        assert_eq!(harness.supervisor.state().buffer, b"z");
        assert_eq!(
            harness.supervisor.state().promise,
            PromiseClass::Interrupt130
        );
        assert_eq!(harness.supervisor.state().escape_credit, 1);
        let second = harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(second.status, Some(130));
    }

    // @ref LLP 0025#acceptance-criteria — schedule (g), a later interrupt
    // expedites an already-latched orderly cause without changing its status.
    #[test]
    fn schedule_g_idle_third_press_expedites_orderly() {
        let mut harness = harness([]);
        harness.supervisor.handle_interrupt().unwrap();
        let second = harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(second.status, Some(0));
        let third = harness.supervisor.handle_interrupt().unwrap();
        assert!(third.expedited);
        assert_eq!(third.status, Some(0));
        let commands = harness.commands.lock().unwrap();
        assert_eq!(commands[0].mode, TerminationMode::Begin);
        assert_eq!(commands[1].mode, TerminationMode::Expedite);
        assert!(commands.iter().all(|command| command.status == 0));
    }

    // @ref LLP 0025#acceptance-criteria — schedule (h), a cooperative cause
    // latched after the promise owns status while preserving next-press exit.
    #[test]
    fn schedule_h_cooperative_cause_supersedes_promise_status() {
        let mut harness = harness([CancellationStatus::Pending]);
        begin_evaluation(&mut harness.supervisor, TargetId(61));
        harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(
            harness
                .supervisor
                .request_cooperative_exit(Principal::Root, 7)
                .unwrap(),
            LifecycleRequestDisposition::Accepted { status: 7 }
        );
        let next = harness.supervisor.handle_interrupt().unwrap();
        assert!(next.terminal && next.expedited);
        assert_eq!(next.status, Some(7));
        assert_eq!(last_command(&harness).status, 7);
    }

    // @ref LLP 0025#acceptance-criteria — schedule (i), Executing{id} wins
    // over a simultaneously suspended evaluation.
    #[test]
    fn schedule_i_executing_unit_wins_over_suspended() {
        let mut harness = harness([CancellationStatus::Pending]);
        begin_evaluation(&mut harness.supervisor, TargetId(71));
        harness.supervisor.suspend_unit(TargetId(71)).unwrap();
        callback(&mut harness.supervisor, ScheduleId(1), TargetId(72));
        let outcome = harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(outcome.cancellation_target, Some(TargetId(72)));
        assert_eq!(harness.requests.lock().unwrap()[0].target_id, TargetId(72));
    }

    // @ref LLP 0025#acceptance-criteria — schedule (j), an undispatched
    // submission is one of exactly two no-promise rows and takes three presses.
    #[test]
    fn schedule_j_undispatched_submission_takes_three() {
        let mut harness = harness([]);
        type_byte(&mut harness.supervisor, b'x');
        harness.supervisor.submit_buffer().unwrap();
        let first = harness.supervisor.handle_interrupt().unwrap();
        assert!(!first.terminal);
        assert_eq!(harness.supervisor.state().promise, PromiseClass::None);
        let second = harness.supervisor.handle_interrupt().unwrap();
        assert!(!second.terminal);
        assert_eq!(harness.supervisor.state().promise, PromiseClass::Orderly);
        let third = harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(third.status, Some(0));
    }

    // @ref LLP 0025#acceptance-criteria — schedule (k), queued work has only a
    // request id while Executing work has the exact cancellation target id.
    #[test]
    fn schedule_k_queued_and_executing_completion_are_distinct() {
        let mut queued = harness([]);
        type_byte(&mut queued.supervisor, b'f');
        queued
            .supervisor
            .queue_completion(CompletionRequestId(1))
            .unwrap();
        let queued_outcome = queued.supervisor.handle_interrupt().unwrap();
        assert_eq!(queued_outcome.cancellation_target, None);
        assert!(queued.requests.lock().unwrap().is_empty());
        assert!(queued
            .supervisor
            .state()
            .live_units
            .completion_queued
            .is_none());

        let mut executing = harness([CancellationStatus::Pending]);
        type_byte(&mut executing.supervisor, b'f');
        executing
            .supervisor
            .queue_completion(CompletionRequestId(1))
            .unwrap();
        executing
            .supervisor
            .begin_completion(CompletionRequestId(1), TargetId(81))
            .unwrap();
        let executing_outcome = executing.supervisor.handle_interrupt().unwrap();
        assert_eq!(executing_outcome.cancellation_target, Some(TargetId(81)));
        assert_eq!(
            executing.requests.lock().unwrap()[0].target_id,
            TargetId(81)
        );
    }

    #[test]
    fn completion_results_are_adopted_only_for_their_buffer_generation() {
        let mut current = harness([]);
        type_byte(&mut current.supervisor, b'f');
        current
            .supervisor
            .queue_completion(CompletionRequestId(1))
            .unwrap();
        current
            .supervisor
            .begin_completion(CompletionRequestId(1), TargetId(82))
            .unwrap();
        assert_eq!(
            current
                .supervisor
                .finish_completion(CompletionRequestId(1), TargetId(82))
                .unwrap(),
            CompletionDisposition::Apply
        );

        let mut stale = harness([]);
        type_byte(&mut stale.supervisor, b'f');
        stale
            .supervisor
            .queue_completion(CompletionRequestId(1))
            .unwrap();
        type_byte(&mut stale.supervisor, b'o');
        stale
            .supervisor
            .begin_completion(CompletionRequestId(1), TargetId(83))
            .unwrap();
        assert_eq!(
            stale
                .supervisor
                .finish_completion(CompletionRequestId(1), TargetId(83))
                .unwrap(),
            CompletionDisposition::Abandoned
        );
    }

    // @ref LLP 0025#acceptance-criteria — schedule (l), Orderly is a class and
    // resolves the supervisor-authoritative exitCode at termination time.
    #[test]
    fn schedule_l_orderly_reads_live_exit_code() {
        let mut harness = harness([]);
        type_byte(&mut harness.supervisor, b'x');
        harness.supervisor.handle_interrupt().unwrap();
        harness.supervisor.handle_interrupt().unwrap();
        let shared_lifecycle = harness.supervisor.lifecycle_cell();
        assert_eq!(
            shared_lifecycle.set_exit_code(Principal::Root, 7),
            LifecycleSetDisposition::Accepted { status: 7 }
        );
        assert_eq!(
            harness.supervisor.get_exit_code(Principal::Root),
            LifecycleGetDisposition::Value(7)
        );
        assert_eq!(
            harness.supervisor.get_exit_code(Principal::Package),
            LifecycleGetDisposition::Denied
        );
        harness.supervisor.mark_due(ScheduleId(1));
        let third = harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(third.status, Some(7));
        assert_eq!(last_command(&harness).kind, TerminationKind::Orderly);
    }

    // @ref LLP 0025#acceptance-criteria — schedule (m), a lone queued global
    // completion is abandoned before selecting the idle-prompt row.
    #[test]
    fn schedule_m_idle_queued_completion_is_orderly() {
        let mut harness = harness([]);
        harness
            .supervisor
            .queue_completion(CompletionRequestId(1))
            .unwrap();
        let first = harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(first.promise, PromiseClass::Orderly);
        assert_eq!(first.cancellation_target, None);
        assert!(harness
            .supervisor
            .state()
            .live_units
            .completion_queued
            .is_none());
        let second = harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(second.status, Some(0));
    }

    // @ref LLP 0025#acceptance-criteria — schedule (n), beginning one due timer
    // consumes only its own `sched`; another due member remains observable.
    #[test]
    fn schedule_n_due_scheduling_identities_remain_distinct() {
        let mut harness = harness([]);
        assert!(harness.supervisor.mark_due(ScheduleId(1)));
        assert!(harness.supervisor.mark_due(ScheduleId(2)));
        harness
            .supervisor
            .begin_unit(TargetId(91), WorkKind::Callback, Some(ScheduleId(1)))
            .unwrap();
        assert_eq!(
            harness.supervisor.state().live_units.due,
            BTreeSet::from([ScheduleId(2)])
        );
        harness.supervisor.end_unit(TargetId(91)).unwrap();
        let first = harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(first.promise, PromiseClass::Interrupt130);
        assert_eq!(first.cancellation_target, None);
        assert_eq!(
            harness.supervisor.state().live_units.due,
            BTreeSet::from([ScheduleId(2)])
        );
    }

    #[test]
    fn stuck_worker_escalates_without_waiting_for_cancellation() {
        let mut harness = harness([CancellationStatus::Pending]);
        begin_evaluation(&mut harness.supervisor, TargetId(101));
        let first = harness.supervisor.handle_interrupt().unwrap();
        assert!(!first.terminal);
        let record = harness
            .supervisor
            .state()
            .cancellations
            .values()
            .next()
            .unwrap();
        assert_eq!(record.status, CancellationStatus::Pending);

        let second = harness.supervisor.handle_interrupt().unwrap();
        assert!(second.terminal);
        assert_eq!(second.status, Some(130));
        assert_eq!(last_command(&harness).status, 130);

        let log = harness.log.lock().unwrap();
        let restore = log
            .iter()
            .position(|entry| entry == "terminal-restore")
            .unwrap();
        let flush = log
            .iter()
            .position(|entry| entry == "broker-flush")
            .unwrap();
        let terminate = log
            .iter()
            .position(|entry| entry == "worker-Begin-130")
            .unwrap();
        assert!(restore < flush && flush < terminate);
    }

    #[test]
    fn failed_cancellation_is_a_fault_not_an_optimistic_success() {
        let mut harness = harness([CancellationStatus::Pending]);
        begin_evaluation(&mut harness.supervisor, TargetId(111));
        harness.supervisor.handle_interrupt().unwrap();
        let request_id = *harness
            .supervisor
            .state()
            .cancellations
            .keys()
            .next()
            .unwrap();
        harness
            .supervisor
            .resolve_cancellation(request_id, CancellationStatus::Failed)
            .unwrap();
        assert_eq!(
            harness.supervisor.state().cause,
            Some(TerminationCause {
                kind: TerminationKind::Fault,
                status: 70,
            })
        );
        assert_eq!(last_command(&harness).status, 70);
    }

    #[test]
    fn cancellation_status_algebra_is_preserved_without_guessing() {
        for status in [
            CancellationStatus::Accepted,
            CancellationStatus::Unavailable,
            CancellationStatus::Defeated,
        ] {
            let mut harness = harness([status]);
            begin_evaluation(&mut harness.supervisor, TargetId(112));
            let outcome = harness.supervisor.handle_interrupt().unwrap();
            assert!(!outcome.terminal);
            assert_eq!(
                harness
                    .supervisor
                    .state()
                    .cancellations
                    .values()
                    .next()
                    .unwrap()
                    .status,
                status
            );
            assert_eq!(harness.supervisor.state().cause, None);
        }

        let mut failed = harness([CancellationStatus::Failed]);
        begin_evaluation(&mut failed.supervisor, TargetId(113));
        let outcome = failed.supervisor.handle_interrupt().unwrap();
        assert!(outcome.terminal);
        assert_eq!(outcome.status, Some(70));
        assert_eq!(last_command(&failed).kind, TerminationKind::Fault);
    }

    #[test]
    fn cancellation_request_never_retargets_a_successor() {
        let mut harness = harness([CancellationStatus::Pending]);
        callback(&mut harness.supervisor, ScheduleId(1), TargetId(121));
        harness.supervisor.handle_interrupt().unwrap();
        harness.supervisor.end_unit(TargetId(121)).unwrap();
        let cycle = harness.supervisor.state().prompt_cycle;
        harness
            .supervisor
            .handle_editor_event(EditorInputEvent::Byte {
                byte: b'x',
                observed_prompt: Some(cycle),
            })
            .unwrap();
        callback(&mut harness.supervisor, ScheduleId(2), TargetId(122));
        let request = harness.requests.lock().unwrap()[0];
        assert_eq!(request.target_id, TargetId(121));
        assert_eq!(
            harness.supervisor.state().live_units.executing.unwrap().id,
            TargetId(122)
        );
    }

    #[test]
    fn ctrl_c_is_an_event_and_never_literal_caret_c_output() {
        let mut harness = harness([]);
        let cycle = harness.supervisor.state().prompt_cycle;
        harness
            .supervisor
            .handle_editor_event(EditorInputEvent::Byte {
                byte: 0x03,
                observed_prompt: Some(cycle),
            })
            .unwrap();
        assert!(harness.supervisor.state().buffer.is_empty());
        let frames = harness.frames.lock().unwrap();
        assert!(frames
            .iter()
            .all(|frame| !String::from_utf8_lossy(&frame.bytes).contains("^C")));
    }

    struct OneEditorEvent(Option<EditorInputEvent>);

    impl EditorPort for OneEditorEvent {
        fn try_next_event(&mut self) -> Result<Option<EditorInputEvent>, String> {
            Ok(self.0.take())
        }
    }

    #[test]
    fn native_interrupt_event_reaches_the_supervisor_exact_cancellation_path() {
        let mut harness = harness([CancellationStatus::Pending]);
        begin_evaluation(&mut harness.supervisor, TargetId(131));
        let mut editor = OneEditorEvent(Some(EditorInputEvent::Interrupt));
        let outcome = harness
            .supervisor
            .poll_editor_port(&mut editor)
            .unwrap()
            .expect("interrupt produces a supervisor outcome");
        assert_eq!(outcome.cancellation_target, Some(TargetId(131)));
        assert_eq!(
            harness.requests.lock().unwrap().as_slice(),
            &[CancellationRequest {
                request_id: CancellationRequestId(1),
                target_id: TargetId(131),
            }]
        );
        assert!(harness.supervisor.state().buffer.is_empty());
    }

    struct ChannelReader {
        bytes: mpsc::Receiver<Option<u8>>,
    }

    impl Read for ChannelReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            match self.bytes.recv() {
                Ok(Some(byte)) => {
                    output[0] = byte;
                    Ok(1)
                }
                Ok(None) | Err(_) => Ok(0),
            }
        }
    }

    #[test]
    fn editor_reader_delivers_interrupt_while_completion_is_blocked_elsewhere() {
        let witness = PromptWitness::default();
        witness.publish(PromptCycle(1), true);
        let (byte_tx, byte_rx) = mpsc::channel();
        let editor = spawn_editor_reader(ChannelReader { bytes: byte_rx }, witness).unwrap();

        let (completion_release_tx, completion_release_rx) = mpsc::channel();
        let (completion_started_tx, completion_started_rx) = mpsc::channel();
        let completion = thread::spawn(move || {
            completion_started_tx.send(()).unwrap();
            completion_release_rx.recv().unwrap();
        });
        completion_started_rx.recv().unwrap();

        byte_tx.send(Some(0x03)).unwrap();
        assert_eq!(
            editor.recv_timeout(Duration::from_secs(1)).unwrap(),
            EditorInputEvent::Interrupt
        );
        completion_release_tx.send(()).unwrap();
        byte_tx.send(None).unwrap();
        completion.join().unwrap();
        editor.join_reader().unwrap();
        assert_eq!(
            legacy_rustyline_adapter_status(),
            Err(EditorAdapterGap::SynchronousCompletionBlocksInterruptInput)
        );
    }

    #[test]
    fn broker_serializes_async_redraw_and_gates_session_ansi() {
        let mut harness = harness([]);
        harness
            .supervisor
            .report_async("bad\n\x1b[31m\u{007f}\u{009b}\u{202e}")
            .unwrap();
        harness
            .supervisor
            .emit_program_output(b"\x1b[31mprogram\x1b[0m")
            .unwrap();
        let frames = harness.frames.lock().unwrap();
        let kinds: Vec<_> = frames.iter().map(|frame| frame.kind).collect();
        let report = kinds
            .iter()
            .position(|kind| *kind == BrokerFrameKind::AsyncReport)
            .unwrap();
        assert_eq!(kinds[report - 1], BrokerFrameKind::PromptErase);
        assert_eq!(kinds[report + 1], BrokerFrameKind::PromptRedraw);
        let report_bytes = &frames[report].bytes;
        assert!(!report_bytes.contains(&0x1b));
        assert!(!report_bytes.contains(&b'\n'));
        assert!(!report_bytes.contains(&0x7f));
        assert!(String::from_utf8_lossy(report_bytes).contains("\\u{001b}"));
        let program = frames
            .iter()
            .position(|frame| frame.kind == BrokerFrameKind::Program)
            .unwrap();
        assert_eq!(frames[program - 1].kind, BrokerFrameKind::PromptErase);
        assert_eq!(frames[program + 1].kind, BrokerFrameKind::PromptRedraw);
        assert_eq!(frames[program].bytes, b"\x1b[31mprogram\x1b[0m");
    }

    #[test]
    fn cooperative_exit_is_a_supervisor_lifecycle_event() {
        let mut harness = harness([]);
        assert_eq!(
            harness
                .supervisor
                .request_cooperative_exit(Principal::Package, 7)
                .unwrap(),
            LifecycleRequestDisposition::Denied
        );
        assert!(harness.commands.lock().unwrap().is_empty());
        assert_eq!(
            harness
                .supervisor
                .request_cooperative_exit(Principal::Root, 7)
                .unwrap(),
            LifecycleRequestDisposition::Accepted { status: 7 }
        );
        assert_eq!(last_command(&harness).kind, TerminationKind::Cooperative);
        assert_eq!(last_command(&harness).status, 7);
    }

    #[test]
    fn lifecycle_cell_checks_request_get_and_set_across_clones() {
        let cell = SessionLifecycleCell::default();
        let shared = cell.clone();

        assert_eq!(
            cell.get_exit_code(Principal::Root),
            LifecycleGetDisposition::Value(0)
        );
        assert_eq!(
            cell.get_exit_code(Principal::Package),
            LifecycleGetDisposition::Denied
        );
        assert_eq!(
            cell.get_exit_code(Principal::Missing),
            LifecycleGetDisposition::Denied
        );
        assert_eq!(
            cell.set_exit_code(Principal::Package, 7),
            LifecycleSetDisposition::Denied
        );
        assert_eq!(
            cell.set_exit_code(Principal::Missing, 7),
            LifecycleSetDisposition::Denied
        );

        let mirrored = normalize_exit_status(263);
        assert_eq!(
            cell.set_exit_code(Principal::Root, 263),
            LifecycleSetDisposition::Accepted { status: mirrored }
        );
        assert_eq!(
            shared.get_exit_code(Principal::Root),
            LifecycleGetDisposition::Value(mirrored)
        );

        assert_eq!(
            shared.request_exit(Principal::Package, 256),
            LifecycleRequestDisposition::Denied
        );
        assert_eq!(
            shared.request_exit(Principal::Missing, 256),
            LifecycleRequestDisposition::Denied
        );
        let requested = normalize_exit_status(256);
        assert_eq!(
            shared.request_exit(Principal::Root, 256),
            LifecycleRequestDisposition::Accepted { status: requested }
        );
        assert_eq!(
            cell.request_exit(Principal::Root, 9),
            LifecycleRequestDisposition::AlreadyInProgress
        );
        assert_eq!(
            cell.set_exit_code(Principal::Root, 9),
            LifecycleSetDisposition::AlreadyInProgress
        );
        assert_eq!(
            cell.get_exit_code(Principal::Root),
            LifecycleGetDisposition::Value(mirrored)
        );
    }

    #[test]
    fn supervisor_lifecycle_cell_seals_with_noncooperative_cause() {
        let mut harness = harness([]);
        harness.supervisor.handle_interrupt().unwrap();
        harness.supervisor.handle_interrupt().unwrap();
        assert_eq!(
            harness.supervisor.set_exit_code(Principal::Root, 9),
            LifecycleSetDisposition::AlreadyInProgress
        );
        assert_eq!(
            harness
                .supervisor
                .request_cooperative_exit(Principal::Root, 9)
                .unwrap(),
            LifecycleRequestDisposition::AlreadyInProgress
        );
    }
}
