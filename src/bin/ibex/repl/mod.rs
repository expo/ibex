//! Secure Ibex REPL orchestration.
//!
//! Operator source enters only through `ReplEvaluationSession`; presentation,
//! descriptor capture, cancellation, and lifecycle are owned by
//! `terminal_session`. The removed legacy implementation deliberately has no
//! fallback here: it evaluated completion expressions, bypassed the VFS for
//! `.load`, exposed `.env`, and rendered values by running JavaScript.
//! @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
//! @ref LLP 0022#8-commands
//! @ref LLP 0024#8-safe-inspection
//! @ref LLP 0025#3-rendering-terminal-safety-and-the-output-broker

pub(crate) mod session;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::engine::{
    AuthenticatedCancellationStatus, AuthenticatedDisplay, AuthenticatedEvaluation,
    AuthenticatedThrow, DisplayDisposition, Engine,
};
use crate::runtime::{ReplEvaluationFailure, ReplSessionIngress, Runtime};
use ibex_runtime::engine::hermes_structured::Stage1DisplayReceipt;

/// The REPL's only production evaluator. Keeping the engine and its closed
/// ingress together prevents a command handler from falling back to a bare
/// string evaluator or cross-pairing a request with another runtime.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ReplEvaluationSession {
    #[allow(dead_code)]
    Local {
        engine: Arc<dyn Engine>,
        ingress: ReplSessionIngress,
    },
    #[cfg(unix)]
    Worker(crate::session_worker_runtime::RemoteReplSession),
}

#[derive(Debug)]
pub(crate) enum ReplDisplay {
    Local(AuthenticatedDisplay),
    Worker(Vec<u8>),
}

#[derive(Debug)]
pub(crate) enum ReplDisplayReceipt {
    Local(Stage1DisplayReceipt),
    #[cfg(unix)]
    Worker {
        submission_id: u64,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
}

#[derive(Debug)]
pub(crate) enum ReplEvaluation {
    Empty,
    Value {
        display: ReplDisplay,
        receipt: Option<ReplDisplayReceipt>,
    },
    Throw(AuthenticatedThrow),
    Cancelled,
    Lifecycle(i32),
}

impl From<AuthenticatedEvaluation> for ReplEvaluation {
    fn from(evaluation: AuthenticatedEvaluation) -> Self {
        match evaluation {
            AuthenticatedEvaluation::Empty => Self::Empty,
            AuthenticatedEvaluation::Value { display, receipt } => Self::Value {
                display: ReplDisplay::Local(display),
                receipt: receipt.map(ReplDisplayReceipt::Local),
            },
            AuthenticatedEvaluation::Throw(thrown) => Self::Throw(thrown),
            AuthenticatedEvaluation::Cancelled => Self::Cancelled,
            AuthenticatedEvaluation::Lifecycle(status) => Self::Lifecycle(status),
        }
    }
}

/// Cloneable terminal-only cancellation authority. It exposes neither the
/// engine nor an evaluator; target ids can only be observed from and returned
/// to the exact authenticated native work slot.
#[derive(Clone)]
pub(crate) struct ReplCancellationPort {
    backend: ReplCancellationBackend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplInterruptWorkKind {
    Evaluation,
    Callback,
    Completion,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ReplInterruptWorkSnapshot {
    pub(crate) executing: Option<(u64, ReplInterruptWorkKind)>,
    pub(crate) suspended_ids: Vec<u64>,
    pub(crate) due_schedules: Vec<u64>,
}

impl ReplInterruptWorkSnapshot {
    pub(crate) fn has_live_work(&self) -> bool {
        self.executing.is_some() || !self.suspended_ids.is_empty() || !self.due_schedules.is_empty()
    }
}

#[derive(Clone)]
enum ReplCancellationBackend {
    Local(Arc<dyn Engine>),
    #[cfg(unix)]
    Worker(crate::session_worker_runtime::RemoteCancellationPort),
}

impl ReplCancellationPort {
    pub(crate) fn is_available(&self) -> bool {
        match &self.backend {
            ReplCancellationBackend::Local(engine) => engine.authenticated_cancellation_available(),
            #[cfg(unix)]
            ReplCancellationBackend::Worker(port) => port.is_available(),
        }
    }

    pub(crate) fn interrupt_work_snapshot(&self) -> ReplInterruptWorkSnapshot {
        match &self.backend {
            ReplCancellationBackend::Local(engine) => ReplInterruptWorkSnapshot {
                executing: engine
                    .active_authenticated_target()
                    .map(|target_id| (target_id, ReplInterruptWorkKind::Evaluation)),
                ..ReplInterruptWorkSnapshot::default()
            },
            #[cfg(unix)]
            ReplCancellationBackend::Worker(port) => {
                let snapshot = port.interrupt_work_snapshot();
                ReplInterruptWorkSnapshot {
                    executing: snapshot
                        .executing
                        .map(|(target_id, kind)| (target_id, repl_interrupt_work_kind(kind))),
                    suspended_ids: snapshot.suspended_ids,
                    due_schedules: snapshot.due_schedules,
                }
            }
        }
    }

    pub(crate) fn request_exact(&self, target_id: u64) -> AuthenticatedCancellationStatus {
        match &self.backend {
            ReplCancellationBackend::Local(engine) => engine.cancel_authenticated_target(target_id),
            #[cfg(unix)]
            ReplCancellationBackend::Worker(port) => port.request_exact(target_id),
        }
    }

    #[cfg(unix)]
    pub(crate) fn terminate_worker_for_interrupt(&self) -> Result<()> {
        match &self.backend {
            ReplCancellationBackend::Local(_) => Ok(()),
            ReplCancellationBackend::Worker(port) => port.terminate_worker(),
        }
    }
}

#[cfg(unix)]
fn repl_interrupt_work_kind(kind: crate::session_worker::WorkUnitKind) -> ReplInterruptWorkKind {
    match kind {
        crate::session_worker::WorkUnitKind::Evaluation => ReplInterruptWorkKind::Evaluation,
        crate::session_worker::WorkUnitKind::CompletionQuery => ReplInterruptWorkKind::Completion,
        crate::session_worker::WorkUnitKind::Callback
        | crate::session_worker::WorkUnitKind::Timer
        | crate::session_worker::WorkUnitKind::MicrotaskDrain => ReplInterruptWorkKind::Callback,
    }
}

impl ReplEvaluationSession {
    #[allow(dead_code)]
    fn from_runtime(runtime: &Runtime) -> Result<Self> {
        Ok(Self::Local {
            engine: runtime.engine(),
            ingress: runtime.repl_session_ingress()?,
        })
    }

    #[cfg(unix)]
    pub(crate) fn from_worker(worker: crate::session_worker_runtime::RemoteReplSession) -> Self {
        Self::Worker(worker)
    }

    pub(crate) fn mode(&self) -> capsec_semantics::arming::ArmedExecutionMode {
        match self {
            Self::Local { ingress, .. } => ingress.mode(),
            #[cfg(unix)]
            Self::Worker(worker) => worker.mode(),
        }
    }

    pub(crate) fn presentation(&self) -> crate::terminal_session::CapturedPresentation {
        match self {
            Self::Local { ingress, .. } => ingress.presentation(),
            #[cfg(unix)]
            Self::Worker(worker) => worker.presentation(),
        }
    }

    pub(crate) fn session_lifecycle(
        &self,
    ) -> ibex_runtime::session_lifecycle::SessionLifecyclePort {
        match self {
            Self::Local { ingress, .. } => ingress.session_lifecycle(),
            #[cfg(unix)]
            Self::Worker(worker) => worker.session_lifecycle(),
        }
    }

    pub(crate) fn cancellation_port(&self) -> ReplCancellationPort {
        let backend = match self {
            Self::Local { engine, .. } => ReplCancellationBackend::Local(engine.clone()),
            #[cfg(unix)]
            Self::Worker(worker) => ReplCancellationBackend::Worker(worker.cancellation_port()),
        };
        ReplCancellationPort { backend }
    }

    #[cfg(unix)]
    pub(crate) fn worker_terminal_control(
        &self,
    ) -> Option<crate::session_worker_runtime::WorkerTerminalControl> {
        match self {
            Self::Local { .. } => None,
            Self::Worker(worker) => Some(worker.terminal_control()),
        }
    }

    #[cfg(unix)]
    pub(crate) fn worker_runtime_control(
        &self,
    ) -> Option<crate::session_worker_runtime::SupervisorRuntimeControl> {
        match self {
            Self::Local { .. } => None,
            Self::Worker(worker) => Some(worker.runtime_control()),
        }
    }

    pub(crate) fn request_operator_exit(
        &mut self,
    ) -> ibex_runtime::session_lifecycle::LifecycleRequestDisposition {
        match self {
            Self::Local { ingress, .. } => ingress.request_operator_exit(),
            #[cfg(unix)]
            Self::Worker(worker) => worker.request_operator_exit(),
        }
    }

    pub(crate) async fn acknowledge_display(
        &mut self,
        receipt: ReplDisplayReceipt,
        disposition: DisplayDisposition,
    ) -> Result<()> {
        match (self, receipt) {
            (Self::Local { engine, .. }, ReplDisplayReceipt::Local(receipt)) => {
                engine.acknowledge_display(receipt, disposition).await
            }
            #[cfg(unix)]
            (
                Self::Worker(worker),
                ReplDisplayReceipt::Worker {
                    submission_id,
                    stdout_cutoff,
                    stderr_cutoff,
                },
            ) => {
                worker
                    .acknowledge_display(submission_id, stdout_cutoff, stderr_cutoff, disposition)
                    .await
            }
            _ => anyhow::bail!("display receipt belongs to a different REPL backend"),
        }
    }

    pub(crate) async fn drive_ready_tasks(
        &mut self,
    ) -> Result<Vec<crate::engine::AuthenticatedAsyncFailure>> {
        match self {
            Self::Local { engine, .. } => {
                let drive = engine.drive_ready_tasks().await;
                let mut failures = match engine.take_authenticated_async_failures().await {
                    Ok(failures) => failures,
                    Err(error) => vec![
                        crate::engine::AuthenticatedAsyncFailure::capture_unavailable(format!(
                            "asynchronous failure drain failed: {error:#}"
                        )),
                    ],
                };
                if let Err(error) = drive {
                    failures.push(
                        crate::engine::AuthenticatedAsyncFailure::capture_unavailable(format!(
                            "{error:#}"
                        )),
                    );
                }
                Ok(failures)
            }
            #[cfg(unix)]
            Self::Worker(worker) => worker.drive_ready_tasks().await,
        }
    }

    pub(crate) async fn wait_for_pending_tasks(&mut self) {
        match self {
            Self::Local { engine, .. } => engine.wait_for_pending_tasks().await,
            #[cfg(unix)]
            Self::Worker(worker) => worker.wait_for_pending_tasks().await,
        }
    }

    #[cfg(unix)]
    pub(crate) fn dispose_worker_preserving_lifecycle(&self) -> Result<()> {
        match self {
            Self::Local { .. } => Ok(()),
            Self::Worker(worker) => worker.dispose_preserving_lifecycle(),
        }
    }

    #[cfg(unix)]
    pub(crate) fn quiesce_worker_preserving_lifecycle(&self) -> Result<()> {
        match self {
            Self::Local { .. } => Ok(()),
            Self::Worker(worker) => worker.quiesce_preserving_lifecycle(),
        }
    }

    #[cfg(unix)]
    pub(crate) fn take_worker_lifecycle_barrier(&mut self) -> Option<(u64, u64)> {
        match self {
            Self::Local { .. } => None,
            Self::Worker(worker) => worker.take_lifecycle_barrier(),
        }
    }

    #[cfg(unix)]
    pub(crate) fn take_worker_outcome_barrier(&mut self) -> Option<(u64, u64)> {
        match self {
            Self::Local { .. } => None,
            Self::Worker(worker) => worker.take_outcome_barrier(),
        }
    }

    pub(crate) async fn mounts_description(
        &mut self,
    ) -> Result<crate::runtime::ReplMountsDescription> {
        match self {
            Self::Local { ingress, .. } => Ok(ingress.mounts_description()),
            #[cfg(unix)]
            Self::Worker(worker) => worker.mounts_description().await,
        }
    }
}

/// Submit ordinary prompt/transcript input through the authenticated session
/// sequence. This function is also the exact path `.time` delegates to.
async fn evaluate_repl_submission(
    session: &mut ReplEvaluationSession,
    input: &str,
) -> std::result::Result<ReplEvaluation, ReplEvaluationFailure> {
    match session {
        ReplEvaluationSession::Local { engine, ingress } => ingress
            .evaluate_inline(engine.as_ref(), input.as_bytes().to_vec())
            .await
            .map(Into::into),
        #[cfg(unix)]
        ReplEvaluationSession::Worker(worker) => {
            worker.evaluate_inline(input.as_bytes().to_vec()).await
        }
    }
}

/// Submit a `.load` argument verbatim. The closed ingress performs VFS
/// resolution, typed read, immutable byte binding, and authenticated
/// evaluation.
async fn evaluate_loaded_submission(
    session: &mut ReplEvaluationSession,
    virtual_path: &str,
) -> std::result::Result<ReplEvaluation, ReplEvaluationFailure> {
    match session {
        ReplEvaluationSession::Local { engine, ingress } => ingress
            .evaluate_load(engine.as_ref(), virtual_path)
            .await
            .map(Into::into),
        #[cfg(unix)]
        ReplEvaluationSession::Worker(worker) => worker.evaluate_load(virtual_path).await,
    }
}

async fn evaluate_timed_submission(
    session: &mut ReplEvaluationSession,
    input: &str,
) -> (
    std::result::Result<ReplEvaluation, ReplEvaluationFailure>,
    Duration,
) {
    let started = std::time::Instant::now();
    let outcome = evaluate_repl_submission(session, input).await;
    (outcome, started.elapsed())
}

/// Start the armed REPL through the production session adapter.
#[allow(dead_code)]
pub async fn start(runtime: &Runtime) -> Result<i32> {
    let plan = runtime
        .session_io_plan()
        .context("REPL runtime is missing its pre-arming session-I/O plan")?;
    let history = crate::history::HistorySession::open(runtime.history_startup());
    let session = ReplEvaluationSession::from_runtime(runtime)?;
    let driver = session::ReplDriver::new(plan.route.mode)?;
    crate::terminal_session::run_repl_execution_adapter(plan, session, driver, history).await
}

/// Start a production REPL with the terminal/history owner in this process and
/// the armed Hermes runtime in its authenticated worker. No Runtime is
/// constructed in the supervisor, and the worker receives neither operator
/// stdin nor history authority.
/// @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker
#[cfg(unix)]
pub async fn start_worker(
    cli: &crate::cli::Cli,
    plan: crate::terminal_session::SessionIoPlan,
) -> Result<i32> {
    let spawned = crate::session_worker_runtime::spawn_session_worker(cli, plan)?;
    let (worker, relays, history_startup) = spawned.into_remote_repl(plan);
    let history = crate::history::HistorySession::open(history_startup);
    let session = ReplEvaluationSession::from_worker(worker);
    let driver = session::ReplDriver::new(plan.route.mode)?;
    crate::terminal_session::run_worker_repl_execution_adapter(
        plan, session, driver, history, relays,
    )
    .await
}
