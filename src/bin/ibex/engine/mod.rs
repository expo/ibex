//! JavaScript engine abstraction layer
//!
//! This module provides a unified interface for different JS engines.
//! Hermes is the only shipped engine; the `Engine` trait and factory are
//! the seam for future engines, which require their own Accepted LLP and a
//! feature-gated build before any value re-enters the public surface.
//! @ref LLP 0010#runtime-command-surface — public engine choices must be true.

pub mod hermes;
pub use ibex_runtime::engine::sourcemap;

use anyhow::Result;
use ibex_runtime::engine::evaluation::{ArmedSessionToken, SourceRequest};
use ibex_runtime::engine::hermes_structured::Stage1DisplayReceipt;
use std::sync::Arc;

/// Result of preparing an advertised direct-file source after its structured
/// submission has been admitted. Native graphs continue through the linked
/// module evaluator; an explicitly unsupported graph uses the bounded legacy
/// evaluator without consuming a second submission ordinal.
#[cfg(feature = "module-runner")]
pub enum AuthenticatedModuleGraphPreparation {
    Native(crate::module_loader::runner_pipeline::SourceModuleGraphV1),
    LegacyRequired,
}

/// Owner-thread preparation callback for an advertised native module source.
/// The engine invokes it only after native admission, so parser/lowering
/// failures are submitted source refusals rather than pre-admission faults.
#[cfg(feature = "module-runner")]
pub type AuthenticatedModuleGraphPreparer<'a> =
    Box<dyn FnOnce(&SourceRequest) -> Result<AuthenticatedModuleGraphPreparation> + 'a>;

/// Closed display categories. `text` below is always hostile terminal text;
/// this tag lets the broker choose escaping/styling without guessing from it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatedDisplayKind {
    Undefined,
    Null,
    Boolean,
    Number,
    String,
    Symbol,
    BigInt,
    Function,
    Array,
    Object,
    JsonData,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedDisplay {
    pub kind: AuthenticatedDisplayKind,
    pub text: String,
    /// The native primitive was clipped at the fixed safe-text byte bound.
    /// Terminal rendering represents this as a separate trusted truncation
    /// node; it is never inferred from hostile payload text.
    pub truncated: bool,
}

impl AuthenticatedDisplay {
    pub(crate) fn diagnostic_text(&self) -> std::borrow::Cow<'_, str> {
        if self.truncated {
            std::borrow::Cow::Owned(format!(
                "{} {}",
                self.text,
                ibex_runtime::engine::hermes_structured::SAFE_TEXT_TRUNCATION_MARKER
            ))
        } else {
            std::borrow::Cow::Borrowed(&self.text)
        }
    }

    pub(crate) fn validate_wire(&self) -> Result<()> {
        use ibex_runtime::engine::hermes_structured::SAFE_TEXT_MAX_BYTES;

        if self.kind == AuthenticatedDisplayKind::JsonData {
            anyhow::ensure!(!self.truncated, "JSON display cannot be Stage-1 truncated");
            return Ok(());
        }
        // A JSON-quoted Stage-1 string can expand each admitted input byte to a
        // six-byte escape plus the two trusted quotes. Other primitive forms
        // are smaller, so this is one conservative hostile-wire ceiling.
        const MAX_FORMATTED_STAGE1_BYTES: usize = SAFE_TEXT_MAX_BYTES * 6 + 2;
        anyhow::ensure!(
            self.text.len() <= MAX_FORMATTED_STAGE1_BYTES,
            "Stage-1 display exceeded its formatted byte bound"
        );
        if self.truncated {
            anyhow::ensure!(
                matches!(
                    self.kind,
                    AuthenticatedDisplayKind::String
                        | AuthenticatedDisplayKind::Symbol
                        | AuthenticatedDisplayKind::BigInt
                ),
                "non-textual Stage-1 display carried a truncation signal"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedThrow {
    pub value: AuthenticatedDisplay,
    pub metadata: AuthenticatedThrowMetadata,
}

/// Serializable projection of the evaluator stratum needed to capture a
/// thrown value's metadata. Keeping this explicit across the worker boundary
/// distinguishes an engine which cannot safely capture metadata from a value
/// which merely has no message or stack.
/// @ref LLP 0024#6-evaluation-outcomes-and-the-abi
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatedCapabilityStratum {
    Base,
    SafeThrow,
    SourcePositions,
    RichInspection,
}

/// Serializable projection of the engine's trap-free direct-prototype Error
/// classification. `Unclassified` never falls back to stack or message text.
/// @ref LLP 0024#8-safe-inspection
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatedErrorClass {
    Unclassified,
    Error,
    AggregateError,
    EvalError,
    RangeError,
    ReferenceError,
    SyntaxError,
    TypeError,
    UriError,
    TimeoutError,
    QuitError,
}

impl AuthenticatedErrorClass {
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Self::Unclassified => None,
            Self::Error => Some("Error"),
            Self::AggregateError => Some("AggregateError"),
            Self::EvalError => Some("EvalError"),
            Self::RangeError => Some("RangeError"),
            Self::ReferenceError => Some("ReferenceError"),
            Self::SyntaxError => Some("SyntaxError"),
            Self::TypeError => Some("TypeError"),
            Self::UriError => Some("URIError"),
            Self::TimeoutError => Some("TimeoutError"),
            Self::QuitError => Some("QuitError"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedSourcePosition {
    pub source_label: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "status",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AuthenticatedThrowMetadata {
    Unavailable {
        required_stratum: AuthenticatedCapabilityStratum,
    },
    Captured {
        error_class: AuthenticatedErrorClass,
        message: Option<String>,
        message_truncated: bool,
        stack: Option<String>,
        stack_truncated: bool,
        positions: Vec<AuthenticatedSourcePosition>,
    },
}

impl AuthenticatedThrowMetadata {
    #[cfg(test)]
    pub fn error_class(&self) -> Option<AuthenticatedErrorClass> {
        match self {
            Self::Captured { error_class, .. } => Some(*error_class),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Captured { message, .. } => message.as_deref(),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn stack(&self) -> Option<&str> {
        match self {
            Self::Captured { stack, .. } => stack.as_deref(),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn positions(&self) -> &[AuthenticatedSourcePosition] {
        match self {
            Self::Captured { positions, .. } => positions,
            Self::Unavailable { .. } => &[],
        }
    }

    // These accessors mirror the independently authenticated wire
    // discriminants even though current renderers validate the fields in one
    // pass. Keep the projection API explicit for non-text consumers.
    #[allow(dead_code)]
    pub fn message_truncated(&self) -> bool {
        matches!(
            self,
            Self::Captured {
                message_truncated: true,
                ..
            }
        )
    }

    #[allow(dead_code)]
    pub fn stack_truncated(&self) -> bool {
        matches!(
            self,
            Self::Captured {
                stack_truncated: true,
                ..
            }
        )
    }

    fn validate_wire(&self) -> Result<()> {
        use ibex_runtime::engine::hermes_structured::{
            SAFE_TEXT_MAX_BYTES, SAFE_TEXT_TRUNCATION_MARKER,
        };

        let Self::Captured {
            message,
            message_truncated,
            stack,
            stack_truncated,
            ..
        } = self
        else {
            return Ok(());
        };
        for (name, text, truncated) in [
            ("message", message.as_deref(), *message_truncated),
            ("stack", stack.as_deref(), *stack_truncated),
        ] {
            if let Some(text) = text {
                anyhow::ensure!(
                    text.len() <= SAFE_TEXT_MAX_BYTES,
                    "throw {name} exceeded its safe-text byte bound"
                );
                anyhow::ensure!(
                    !truncated || text.ends_with(SAFE_TEXT_TRUNCATION_MARKER),
                    "truncated throw {name} omitted its trusted marker"
                );
            } else {
                anyhow::ensure!(
                    !truncated,
                    "throw {name} truncation signal was present without text"
                );
            }
        }
        Ok(())
    }
}

impl AuthenticatedThrow {
    pub(crate) fn validate_wire(&self) -> Result<()> {
        self.value.validate_wire()?;
        self.metadata.validate_wire()
    }
}

pub(crate) fn decode_authenticated_throw(detail: &[u8]) -> Result<AuthenticatedThrow> {
    let thrown: AuthenticatedThrow = serde_json::from_slice(detail)
        .map_err(|error| anyhow::anyhow!("throw envelope is malformed: {error}"))?;
    thrown.validate_wire().map_err(|error| {
        anyhow::anyhow!("throw envelope violated safe-text invariants: {error}")
    })?;
    Ok(thrown)
}

/// Closed schedule-time attribution carried by an asynchronous failure. An
/// unavailable or ambiguous owner is data, never permission to guess root.
/// @ref LLP 0024#9-asynchronous-failures
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AuthenticatedAsyncFailureOwner {
    Authenticated {
        principal: capsec_semantics::model::Principal,
    },
    Unavailable,
    Ambiguous,
}

/// Worker-to-supervisor asynchronous failure envelope. The captured arm owns
/// only a safe Stage-1 tree representation: the original native value handle
/// was materialized and released on the worker's runtime thread before this
/// serializable envelope crossed the process boundary. `CaptureUnavailable`
/// remains the explicit loss/fault arm and must never be mistaken for a throw.
/// @ref LLP 0024#9-asynchronous-failures
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "captureStatus",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AuthenticatedAsyncFailure {
    Captured {
        thrown: AuthenticatedThrow,
        owning_principal: AuthenticatedAsyncFailureOwner,
        event_identity: String,
        associated_evaluation: Option<u64>,
    },
    CaptureUnavailable {
        summary: String,
    },
    PreReceiptLoss {
        count: u64,
    },
    /// Supervisor-local report: authenticated events were received and
    /// sequenced, but their closed payloads exceeded the bounded delivery
    /// lane. `validate_wire` rejects this arm from a worker envelope.
    PostReceiptLoss {
        count: u64,
        highest_dropped_sequence: u64,
    },
}

impl AuthenticatedAsyncFailure {
    pub fn capture_unavailable(summary: impl Into<String>) -> Self {
        Self::CaptureUnavailable {
            summary: summary.into(),
        }
    }

    pub(crate) fn validate_wire(&self) -> Result<()> {
        match self {
            Self::Captured { thrown, .. } => thrown.validate_wire()?,
            Self::PreReceiptLoss { count: 0 } => {
                anyhow::bail!("pre-receipt loss count must be nonzero")
            }
            Self::PostReceiptLoss { .. } => {
                anyhow::bail!("post-receipt loss is supervisor-local")
            }
            _ => {}
        }
        Ok(())
    }
}

impl std::fmt::Display for AuthenticatedAsyncFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Captured {
                thrown,
                owning_principal,
                event_identity,
                associated_evaluation,
            } => {
                write!(
                    formatter,
                    "{} (owner {owning_principal:?}, event {event_identity}",
                    thrown.value.diagnostic_text()
                )?;
                if let Some(evaluation) = associated_evaluation {
                    write!(formatter, ", evaluation {evaluation}")?;
                }
                formatter.write_str(")")?;
                if let Some(message) = thrown.metadata.message() {
                    write!(formatter, ": {message}")?;
                }
                if let Some(stack) = thrown.metadata.stack() {
                    write!(formatter, "\n{stack}")?;
                }
                for position in thrown.metadata.positions() {
                    write!(
                        formatter,
                        "\nat {}:{}:{}",
                        position.source_label, position.line, position.column
                    )?;
                }
                Ok(())
            }
            Self::CaptureUnavailable { summary } => {
                write!(formatter, "metadata unavailable: {summary}")
            }
            Self::PreReceiptLoss { count } => {
                write!(
                    formatter,
                    "lost {count} asynchronous failure event(s) before receipt"
                )
            }
            Self::PostReceiptLoss {
                count,
                highest_dropped_sequence,
            } => write!(
                formatter,
                "lost {count} asynchronous failure event(s) after receipt through sequence {highest_dropped_sequence}"
            ),
        }
    }
}

impl std::error::Error for AuthenticatedAsyncFailure {}

/// Closed Stage-1 result returned by authenticated session evaluation.
#[derive(Debug, Eq, PartialEq)]
pub enum AuthenticatedEvaluation {
    Empty,
    Value {
        display: AuthenticatedDisplay,
        receipt: Option<Stage1DisplayReceipt>,
    },
    Throw(AuthenticatedThrow),
    Cancelled,
    Lifecycle(i32),
}

/// One native-authenticated, single-original generated CommonJS form.
///
/// Construction stays inside the runtime's digest-bound bundle/HBC verifier.
/// The engine receives owned bytes so cache-path replacement after verification
/// cannot change what Hermes executes. `bytecode` is reserved for an HBC form
/// whose evaluated value is proven to be exactly one private initializer;
/// engines must refuse it until that closed wrapper format is implemented.
/// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
pub(crate) struct AuthenticatedGeneratedEntry {
    pub(crate) source: Vec<u8>,
    pub(crate) record: Vec<u8>,
    pub(crate) bytecode: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayDisposition {
    Displayed,
    Fallback,
    WriteFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthenticatedProgramDrainFailure {
    #[error("unhandled asynchronous program failure: {0:#}")]
    Unhandled(anyhow::Error),
    #[error("engine fault while draining authenticated program work: {0:#}")]
    EngineFault(anyhow::Error),
}

impl AuthenticatedProgramDrainFailure {
    pub const fn is_engine_fault(&self) -> bool {
        matches!(self, Self::EngineFault(_))
    }
}

/// Exact, nonblocking cancellation result for an authenticated work target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedCancellationStatus {
    /// The exact request was delivered to the native runtime. This is not the
    /// terminal `Accepted` resolution; terminal state is published separately
    /// after the target returns.
    Accepted,
    Unavailable,
    StaleTarget,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedCancellationResolution {
    Accepted,
    Failed,
    Defeated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedCancellationEvent {
    pub target_id: u64,
    pub resolution: AuthenticatedCancellationResolution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedWorkUnitKind {
    Evaluation,
    Callback,
    Timer,
    MicrotaskDrain,
    CompletionQuery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedWorkUnitPhase {
    Due,
    Undue,
    Begin,
    Suspended,
    End,
}

/// One transition from the native, owner-thread work-unit publisher. A Due or
/// Undue timer has `target_id == 0` and is named only by `scheduling_id`; every
/// executing unit has a nonzero target id suitable for exact cancellation.
/// @ref LLP 0025#6-interruption-and-cancellation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedWorkUnitEvent {
    pub target_id: u64,
    pub scheduling_id: u64,
    pub kind: AuthenticatedWorkUnitKind,
    pub phase: AuthenticatedWorkUnitPhase,
}

/// The JavaScript engine interface
///
/// This trait defines the operations that all engines must support.
/// It's designed to be engine-agnostic while allowing engine-specific
/// features through downcast patterns.
#[async_trait::async_trait]
#[allow(dead_code)]
pub trait Engine: Send + Sync {
    /// Get the engine name
    fn name(&self) -> &str;

    /// Get the engine version
    fn version(&self) -> Result<String>;

    /// Load the Ibex runtime bundle into the engine
    async fn load_runtime(&self) -> Result<()>;

    /// Irreversibly close any trusted bootstrap-only code ingress before
    /// project source is admitted. Engines without such a phase leave this a
    /// no-op; Hermes seals its armed bare evaluator here.
    async fn finish_bootstrap(&self) -> Result<()> {
        Ok(())
    }

    /// Evaluate JavaScript code and return the result
    async fn eval(&self, code: &str) -> Result<Option<String>>;

    /// Evaluate JavaScript code without driving the event loop afterwards.
    /// Use this for setup code that should not trigger timer-based side effects.
    async fn eval_immediate(&self, code: &str) -> Result<Option<String>> {
        self.eval(code).await
    }

    /// Consume one closed authenticated source request. Implementations must
    /// not fall back to `eval`/`eval_immediate` or a user-reachable helper.
    async fn evaluate_authenticated(
        &self,
        _session: &ArmedSessionToken,
        _request: SourceRequest,
    ) -> Result<AuthenticatedEvaluation> {
        anyhow::bail!(
            "{} does not implement authenticated evaluation",
            self.name()
        )
    }

    /// Consume an authenticated raw file request through a verified generated
    /// representation of that *same* single original. Implementations must
    /// retain the request's SourceId, defining principal, compartment, label,
    /// referrer, argv, and module-cache transaction. No JS-reachable evaluator
    /// or generated-module registry may be introduced by this path.
    async fn evaluate_authenticated_generated(
        &self,
        _session: &ArmedSessionToken,
        _request: SourceRequest,
        _entry: AuthenticatedGeneratedEntry,
    ) -> Result<AuthenticatedEvaluation> {
        anyhow::bail!(
            "{} does not implement authenticated generated evaluation",
            self.name()
        )
    }

    /// Settle an exact display receipt after the broker has selected its final
    /// disposition. Only `Displayed` may update `$_`.
    async fn acknowledge_display(
        &self,
        _receipt: Stage1DisplayReceipt,
        _disposition: DisplayDisposition,
    ) -> Result<()> {
        anyhow::bail!("{} does not implement display acknowledgement", self.name())
    }

    /// Release a linear Stage-1 value that this route intentionally does not
    /// present (`-e` and program stdin). This is not a write failure or a
    /// fallback display, and it must never update `$_`.
    async fn release_undisplayed_value(&self, _receipt: Stage1DisplayReceipt) -> Result<()> {
        anyhow::bail!(
            "{} does not implement undisplayed-value release",
            self.name()
        )
    }

    /// Read-only metadata for the LLP 0024 executable conformance harness.
    /// This method does not exist in production builds and deliberately omits
    /// live values, source ingress, and every mutating operation.
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    async fn session_conformance_metadata(
        &self,
        _requested_own_names: &[&str],
    ) -> Result<serde_json::Value> {
        anyhow::bail!("{} has no session conformance observer", self.name())
    }

    /// Return the native-issued work target currently owned by an
    /// authenticated submission. This must be callable from the terminal
    /// reader while the engine owner thread is evaluating.
    fn active_authenticated_target(&self) -> Option<u64> {
        None
    }

    fn authenticated_cancellation_available(&self) -> bool {
        false
    }

    /// Take one native-published work-unit transition without blocking. This
    /// is any-thread so a worker controller can observe a callback even while
    /// the owner thread is wedged inside it.
    fn next_authenticated_work_unit(&self) -> Result<Option<AuthenticatedWorkUnitEvent>> {
        Ok(None)
    }

    /// Take one terminal cancellation result without blocking. Unlike request
    /// delivery, `Accepted` here proves the exact target returned because of
    /// the request and the runtime passed its native consistency check.
    fn next_authenticated_cancellation(&self) -> Result<Option<AuthenticatedCancellationEvent>> {
        Ok(None)
    }

    /// Materialize every queued background throw on the runtime owner thread.
    /// Implementations must release each worker-local value handle whether
    /// rendering succeeds or fails; only the serializable safe representation
    /// may leave the engine process.
    async fn take_authenticated_async_failures(&self) -> Result<Vec<AuthenticatedAsyncFailure>> {
        Ok(Vec::new())
    }

    /// Cancel exactly `target_id`; implementations must refuse a stale id
    /// rather than interrupting whichever unit happens to run next.
    fn cancel_authenticated_target(&self, _target_id: u64) -> AuthenticatedCancellationStatus {
        AuthenticatedCancellationStatus::Unavailable
    }

    /// Execute all currently-ready event-loop work (due timers, drained
    /// microtasks/callbacks, pending debugger interrupts) without blocking on
    /// future timers. The caller is an external liveness reference for this
    /// ready-only turn: already-due unreferenced timers may run, but remain
    /// excluded from ordinary program quiescence. The keep-alive/debug loop
    /// calls this on its own cadence to keep the runtime responsive to DevTools.
    /// Engines without an event loop leave this a no-op. (ENG-22958)
    async fn drive_ready_tasks(&self) -> Result<()> {
        Ok(())
    }

    /// Drive the event loop to quiescence — like `eval` does after running code,
    /// but without evaluating anything. The REPL calls this once its input
    /// stream ends (EOF) so pending timers/async callbacks scheduled during the
    /// session finish before the process exits, matching Node's REPL and
    /// `ibex <file>`. Unlike `drive_ready_tasks` this blocks until no work
    /// remains, so it is only safe after the prompt is gone. Engines without an
    /// event loop leave this a no-op. (ENG-23001)
    async fn drain_event_loop(&self) -> Result<()> {
        Ok(())
    }

    /// Drive an authenticated program/one-shot route until its Node-style
    /// keep-alive set is empty. This is deliberately distinct from the bounded
    /// ready-only REPL EOF drain above: a future timer or live native handle
    /// keeps program execution alive.
    /// @ref LLP 0024#1-the-in-memory-source-api — program and one-shot inputs
    /// settle at full event-loop quiescence; interactive sessions do not.
    async fn drive_authenticated_program_to_quiescence(
        &self,
    ) -> std::result::Result<(), AuthenticatedProgramDrainFailure> {
        self.drain_event_loop()
            .await
            .map_err(AuthenticatedProgramDrainFailure::EngineFault)
    }

    /// Park until the next scheduled event-loop wakeup (the soonest due timer) or
    /// a background callback, so the idle REPL prompt can stop polling at a fixed
    /// 20 Hz cadence. Engines without an event loop just sleep a short interval.
    /// (ENG-23030 #5)
    async fn wait_for_pending_tasks(&self) {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    /// Run a JavaScript file
    async fn run_file(&self, path: &str) -> Result<Option<String>>;

    /// Evaluate an already-read bytecode buffer. Generated-code caches use
    /// this path so the exact bytes whose digest was verified are the bytes
    /// executed; reopening a cache pathname after verification is a TOCTOU.
    async fn run_bytecode_bytes(&self, _bytes: &[u8], _source_url: &str) -> Result<Option<String>> {
        anyhow::bail!(
            "{} does not support in-memory bytecode execution",
            self.name()
        )
    }

    /// Admit one authenticated file request, then prepare and evaluate its
    /// source graph through the native module runner. Preparation is a callback
    /// specifically so native admission precedes graph parsing and lowering.
    /// A bounded compatibility fallback continues the same admission; it must
    /// never consume a second ordinal or fall back to bare file/eval APIs.
    /// @ref LLP 0024#6-evaluation-outcomes-and-the-abi
    /// @ref LLP 0026#phase-5-default-switch-and-retirement
    #[cfg(feature = "module-runner")]
    fn evaluate_authenticated_module_graph<'a>(
        &'a self,
        _session: &'a ArmedSessionToken,
        _request: SourceRequest,
        _prepare: AuthenticatedModuleGraphPreparer<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<AuthenticatedEvaluation>> + 'a>>
    {
        Box::pin(async move {
            anyhow::bail!("{} has no authenticated native module runner", self.name())
        })
    }

    /// Run a JavaScript file WITHOUT driving the event loop to quiescence, so a
    /// long-lived server/timer started by the file returns control to the caller.
    /// The REPL's `.load` uses this and lets its idle pump drive background work,
    /// instead of wedging the prompt on `drive_event_loop`. Defaults to
    /// `run_file`. (ENG-23030 #2)
    async fn run_file_immediate(&self, path: &str) -> Result<Option<String>> {
        self.run_file(path).await
    }

    /// Start the Chrome DevTools Protocol inspector
    async fn start_inspector(&self, host: &str, port: u16) -> Result<()>;

    /// Stop the inspector
    async fn stop_inspector(&self) -> Result<()>;

    /// Request a debugger pause through the engine control plane without
    /// evaluating source in the inspected runtime.
    async fn pause_inspector(&self) -> Result<()> {
        anyhow::bail!("{} does not support debugger pause", self.name())
    }

    /// Wait for a debugger client to attach (optional)
    async fn wait_for_inspector(&self) -> Result<()> {
        Ok(())
    }

    /// Wait for the Debugger domain to be enabled (optional)
    async fn wait_for_debugger(&self) -> Result<()> {
        Ok(())
    }

    /// Check if the engine supports a specific feature
    fn supports_feature(&self, feature: EngineFeature) -> bool;
}

/// Features that may or may not be supported by different engines
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EngineFeature {
    /// Hermes bytecode compilation
    BytecodeCompilation,
    /// Chrome DevTools Protocol debugging
    CdpDebugging,
    /// Source maps
    SourceMaps,
    /// Top-level await
    TopLevelAwait,
    /// ESM modules
    EsmModules,
    /// CommonJS modules
    CommonJsModules,
}

/// Create an engine instance by name
///
/// The CLI's clap value list rejects non-Hermes names before this runs; the
/// unknown-engine arm guards internal callers.
pub fn create_engine(name: &str, armed_snapshot_digest: Option<&str>) -> Result<Arc<dyn Engine>> {
    match name {
        "hermes" => Ok(Arc::new(hermes::HermesEngine::new_with_armed_snapshot(
            armed_snapshot_digest,
        )?)),
        other => anyhow::bail!("Unknown engine: {other}. Ibex currently supports Hermes only."),
    }
}

// Re-export async_trait for the trait definition
pub use async_trait::async_trait;
