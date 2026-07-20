//! Runtime-bearing half of the authenticated terminal worker.
//!
//! The protocol and bootstrap live in `session_worker`; this module is the
//! only place that pairs that authority with a production `Runtime`. Hermes is
//! constructed and used on one owner thread. The control loop stays on the
//! bootstrap thread, so cancellation, lifecycle acknowledgements, and the
//! parent watchdog remain serviceable while JavaScript is stuck.
//! @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker

use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::engine::{
    AuthenticatedAsyncFailure, AuthenticatedCancellationEvent, AuthenticatedCancellationResolution,
    AuthenticatedCancellationStatus, AuthenticatedEvaluation, AuthenticatedProgramDrainFailure,
    AuthenticatedWorkUnitEvent, AuthenticatedWorkUnitKind, AuthenticatedWorkUnitPhase,
    DisplayDisposition, Engine,
};
use crate::runtime::{AuthenticatedEvaluationFailure, Runtime};
use crate::session_worker::{
    authenticated_frame_charge,
    bounded_lane::{
        self, BoundedLaneReceiver, BoundedLaneSender, ControllerFaultReason, LaneDelivery,
        LaneLimits, PostReceiptLoss, PushErrorKind, SequencedLaneDelivery, SequencedLaneLease,
        SequencedLaneReceiver, SequencedLaneSender, SequencedReceiveTimeoutError, TryReceiveError,
    },
    AuthenticatedWorkerCommand, CancellationResolution, ControlMessage, DisplayAckDisposition,
    EvaluationOutcomeKind, ProtectedWorkerBootstrap, SessionInputMode, SubmissionKind,
    VerifiedWorkerEndpoint, WorkUnitKind, WorkUnitPhase, WorkerApplicationRole,
    WorkerBootstrapConfiguration, WorkerProtocolError,
};

const CONTROL_POLL: Duration = Duration::from_millis(5);
// No authenticated worker frame or controller acknowledgement may sit ahead
// of the engine-independent terminate/dispose path without a fixed bound.
// @ref LLP 0025#6-interruption-and-cancellation
const SUPERVISOR_CONTROL_ACK: Duration = Duration::from_millis(250);
// Bounds only supervisor->worker control-record delivery. Once delivered, a
// target has no terminal timeout and may remain Pending until teardown.
// @ref LLP 0024#6-evaluation-outcomes-and-the-abi
const SUPERVISOR_CONTROL_WRITE: Duration = Duration::from_millis(100);
const CANCELLATION_DELIVERY_ACK: Duration = Duration::from_millis(250);
const CONTROL_DELIVERY_PENDING: u8 = 0;
const CONTROL_DELIVERY_TIMED_OUT: u8 = 1;
const CONTROL_DELIVERY_ACKNOWLEDGED: u8 = 2;
const IDLE_PUMP: Duration = Duration::from_millis(10);
const STEP_MOUNTS: u8 = 1;
const WORKER_EVENT_DRAIN_BUDGET: usize = 1;
const WORKER_NATIVE_DRAIN_BUDGET: usize = 1;
const SUPERVISOR_COMMAND_DRAIN_BUDGET: usize = 64;

enum EvaluationCommand {
    Start(SessionInputMode),
    Submit {
        submission_id: u64,
        kind: SubmissionKind,
        source: Vec<u8>,
    },
    EndOfInput,
    ReadyCheckpoint(u64),
    Shutdown(i32),
}

enum EvaluationEvent {
    Message(ControlMessage),
    Outcome {
        submission_id: u64,
        kind: EvaluationOutcomeKind,
        status: i32,
        detail: Vec<u8>,
    },
    AsyncFailure {
        submission_id: Option<u64>,
        detail: Vec<u8>,
    },
    Display {
        submission_id: u64,
        tree: Vec<u8>,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
        reply: mpsc::SyncSender<DisplayAckDisposition>,
    },
    ExitCodeMirror {
        status: i32,
        reply: mpsc::SyncSender<crate::host::abi::WorkerLifecycleAcknowledgement>,
    },
    LifecycleCommit {
        request_id: u64,
        status: i32,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
        reply: mpsc::SyncSender<crate::host::abi::WorkerLifecycleAcknowledgement>,
    },
    ReadyCheckpoint {
        checkpoint_id: u64,
    },
    Stopped(i32),
}

type EvaluationEventSender = BoundedLaneSender<EvaluationEvent, u64>;
type EvaluationEventReceiver = BoundedLaneReceiver<EvaluationEvent, u64>;
type SupervisorEventSender = SequencedLaneSender<crate::session_worker::SupervisorEventPayload>;
type SupervisorEventReceiver = SequencedLaneReceiver<crate::session_worker::SupervisorEventPayload>;

fn evaluation_lane_limits() -> LaneLimits {
    LaneLimits {
        lossy_bytes: ibex_runtime::session_constants::BROKER_QUEUE_BOUND_BYTES,
        // One maximum display tree plus a full event-sized reserve leaves
        // lifecycle, outcome, and terminal records independent of async load.
        required_bytes: ibex_runtime::session_constants::DISPLAY_TREE_MAX_SERIALIZED_BYTES
            .checked_add(ibex_runtime::session_constants::BROKER_QUEUE_BOUND_BYTES)
            .expect("session event lane constants fit usize"),
        loss_records: ibex_runtime::session_constants::BROKER_QUEUE_BOUND_BYTES
            / std::mem::size_of::<EvaluationEvent>().max(1),
    }
}

fn supervisor_event_lane_limits() -> LaneLimits {
    LaneLimits {
        lossy_bytes: ibex_runtime::session_constants::BROKER_QUEUE_BOUND_BYTES,
        required_bytes: ibex_runtime::session_constants::DISPLAY_TREE_MAX_SERIALIZED_BYTES
            .checked_add(ibex_runtime::session_constants::BROKER_QUEUE_BOUND_BYTES)
            .expect("supervisor event lane constants fit usize"),
        loss_records: ibex_runtime::session_constants::BROKER_QUEUE_BOUND_BYTES
            / std::mem::size_of::<crate::session_worker::SupervisorEventPayload>().max(1),
    }
}

fn supervisor_post_receipt_loss(
    loss: PostReceiptLoss,
) -> crate::session_worker::SupervisorEventPayload {
    crate::session_worker::SupervisorEventPayload::PostReceiptLoss {
        count: loss.count,
        highest_dropped_sequence: loss.highest_dropped_sequence,
    }
}

fn supervisor_controller_fault(
    reason: ControllerFaultReason,
) -> crate::session_worker::SupervisorEventPayload {
    crate::session_worker::SupervisorEventPayload::ControllerFault(reason)
}

fn supervisor_event_charge(
    event: &crate::session_worker::SupervisorEventPayload,
) -> std::result::Result<usize, WorkerProtocolError> {
    let payload = match event {
        crate::session_worker::SupervisorEventPayload::Worker(message) => {
            return message
                .encoded_frame_size()?
                .checked_add(std::mem::size_of::<
                    crate::session_worker::SupervisorEventPayload,
                >())
                .ok_or(WorkerProtocolError::Oversize)
        }
        crate::session_worker::SupervisorEventPayload::WorkerDied(_)
        | crate::session_worker::SupervisorEventPayload::PostReceiptLoss { .. }
        | crate::session_worker::SupervisorEventPayload::ControllerFault(_) => 32,
    };
    authenticated_frame_charge(payload)?
        .checked_add(std::mem::size_of::<
            crate::session_worker::SupervisorEventPayload,
        >())
        .ok_or(WorkerProtocolError::Oversize)
}

fn supervisor_event_is_lossy(
    event: &crate::session_worker::SupervisorEventPayload,
    allow_lossy_async: bool,
) -> bool {
    allow_lossy_async
        && matches!(
            event,
            crate::session_worker::SupervisorEventPayload::Worker(
                ControlMessage::AsyncFailure { detail, .. }
            ) if encoded_async_failure_is_ordinary(detail)
        )
}

fn publish_supervisor_event(
    events: &SupervisorEventSender,
    event: crate::session_worker::SupervisorEventPayload,
    allow_lossy_async: bool,
) -> std::result::Result<(), PushErrorKind> {
    let charge =
        supervisor_event_charge(&event).map_err(|_| PushErrorKind::RequiredCapacityExceeded)?;
    let result = if supervisor_event_is_lossy(&event, allow_lossy_async) {
        events.try_push_lossy(event, charge)
    } else {
        events.try_push_required(event, charge)
    };
    result.map(|_| ()).map_err(|error| error.kind)
}

fn evaluation_event_charge(
    event: &EvaluationEvent,
) -> std::result::Result<usize, WorkerProtocolError> {
    let payload_bytes = match event {
        EvaluationEvent::Message(message) => {
            return message
                .encoded_frame_size()?
                .checked_add(std::mem::size_of::<EvaluationEvent>())
                .ok_or(WorkerProtocolError::Oversize)
        }
        EvaluationEvent::Outcome { detail, .. } => 33usize.checked_add(detail.len()),
        EvaluationEvent::AsyncFailure { detail, .. } => 20usize.checked_add(detail.len()),
        EvaluationEvent::Display { tree, .. } => 28usize.checked_add(tree.len()),
        EvaluationEvent::ExitCodeMirror { .. } => Some(12),
        EvaluationEvent::LifecycleCommit { .. } => Some(28),
        EvaluationEvent::ReadyCheckpoint { .. } => Some(24),
        EvaluationEvent::Stopped(_) => Some(4),
    }
    .ok_or(WorkerProtocolError::Oversize)?;
    authenticated_frame_charge(payload_bytes)?
        .checked_add(std::mem::size_of::<EvaluationEvent>())
        .ok_or(WorkerProtocolError::Oversize)
}

fn encoded_async_failure_is_ordinary(detail: &[u8]) -> bool {
    matches!(
        decode_async_failure(detail),
        Ok(AuthenticatedAsyncFailure::Captured { .. }
            | AuthenticatedAsyncFailure::CaptureUnavailable { .. })
    )
}

fn evaluation_event_is_lossy(event: &EvaluationEvent) -> bool {
    matches!(
        event,
        EvaluationEvent::Message(ControlMessage::AsyncFailure { detail, .. })
            if encoded_async_failure_is_ordinary(detail)
    )
}

fn evaluation_lane_fault_detail(kind: PushErrorKind) -> &'static [u8] {
    match kind {
        PushErrorKind::Closed => b"bounded evaluator event lane closed",
        PushErrorKind::RequiredCapacityExceeded => {
            b"bounded evaluator event lane exhausted its required reserve"
        }
        PushErrorKind::PrioritySlotOccupied => {
            b"bounded evaluator event lane lifecycle slot was already occupied"
        }
        PushErrorKind::LossAccountingExhausted => {
            b"bounded evaluator event lane exhausted loss accounting"
        }
        PushErrorKind::LossCounterOverflow => {
            b"bounded evaluator event lane loss counter overflowed"
        }
        PushErrorKind::SequenceExhausted => b"bounded evaluator event lane sequence exhausted",
    }
}

fn latch_evaluation_lane_fault(events: &EvaluationEventSender, kind: PushErrorKind) {
    let _ = events.latch_terminal(EvaluationEvent::Message(ControlMessage::WorkerFault {
        stdout_cutoff: 0,
        stderr_cutoff: 0,
        detail: evaluation_lane_fault_detail(kind).to_vec(),
    }));
}

fn publish_evaluation_event(
    events: &EvaluationEventSender,
    event: EvaluationEvent,
) -> std::result::Result<(), WorkerProtocolError> {
    let charge = match evaluation_event_charge(&event) {
        Ok(charge) => charge,
        Err(error) => {
            latch_evaluation_lane_fault(events, PushErrorKind::RequiredCapacityExceeded);
            return Err(error);
        }
    };
    let result = if matches!(event, EvaluationEvent::LifecycleCommit { .. }) {
        events.try_push_priority(event)
    } else if evaluation_event_is_lossy(&event) {
        events
            .try_push_lossy(event, charge, 1u64, |count, next| {
                *count = count.checked_add(next).ok_or(())?;
                Ok(())
            })
            .map(|_| ())
    } else {
        events.try_push_required(event, charge)
    };
    result.map_err(|error| {
        latch_evaluation_lane_fault(events, error.kind);
        match error.kind {
            PushErrorKind::Closed => WorkerProtocolError::WorkerDied,
            PushErrorKind::RequiredCapacityExceeded | PushErrorKind::PrioritySlotOccupied => {
                WorkerProtocolError::Backpressure
            }
            PushErrorKind::LossAccountingExhausted | PushErrorKind::LossCounterOverflow => {
                WorkerProtocolError::Malformed("evaluator event loss accounting failed closed")
            }
            PushErrorKind::SequenceExhausted => {
                WorkerProtocolError::Malformed("evaluator event sequence exhausted")
            }
        }
    })
}

struct WorkerStartup {
    binding: crate::session_worker::ArmedSessionBinding,
    root: capsec_semantics::model::ObjectIdentity,
    engine: Arc<dyn Engine>,
}

enum WorkerIngress {
    Repl(Box<crate::runtime::ReplSessionIngress>),
    Inline(Box<crate::runtime::AuthenticatedInlineIngress>),
}

struct EvaluationSettlementPorts<'a> {
    events: &'a EvaluationEventSender,
    output_cutoffs: &'a crate::terminal_session::WorkerOutputCutoffPort,
}

/// Construct Runtime on its permanent owner thread, complete both bootstrap
/// equality proofs, and then keep the authenticated control lane responsive
/// independently of evaluation.
pub(crate) fn run_authenticated_runtime_worker(protected: ProtectedWorkerBootstrap) -> Result<i32> {
    let configuration = protected.configuration().clone();
    let output_cutoffs = protected.output_cutoff_port();
    let (commands_tx, commands_rx) = mpsc::channel();
    let (events_tx, events_rx) = bounded_lane::channel(evaluation_lane_limits());
    let (startup_tx, startup_rx) = mpsc::sync_channel(1);
    let lifecycle_events = events_tx.clone();
    let mirror_events = events_tx.clone();
    let lifecycle_output_cutoffs = output_cutoffs.clone();
    let acknowledgement_timeout =
        Duration::from_millis(ibex_runtime::session_constants::LIFECYCLE_COMMIT_ACK_MILLIS);
    let lifecycle_port = crate::host::abi::AuthenticatedWorkerLifecyclePort::new(
        move |mutation| {
            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            if publish_evaluation_event(
                &mirror_events,
                EvaluationEvent::ExitCodeMirror {
                    status: mutation.status(),
                    reply: reply_tx,
                },
            )
            .is_err()
            {
                return crate::host::abi::WorkerLifecycleAcknowledgement::Unacknowledged;
            }
            reply_rx
                .recv_timeout(acknowledgement_timeout)
                .unwrap_or(crate::host::abi::WorkerLifecycleAcknowledgement::Unacknowledged)
        },
        move |commit| {
            let cutoffs = match lifecycle_output_cutoffs.cutoffs() {
                Ok(cutoffs) => cutoffs,
                Err(_) => {
                    return crate::host::abi::WorkerLifecycleAcknowledgement::Unacknowledged;
                }
            };
            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            if publish_evaluation_event(
                &lifecycle_events,
                EvaluationEvent::LifecycleCommit {
                    request_id: commit.request_id(),
                    status: commit.status(),
                    stdout_cutoff: cutoffs.stdout(),
                    stderr_cutoff: cutoffs.stderr(),
                    reply: reply_tx,
                },
            )
            .is_err()
            {
                return crate::host::abi::WorkerLifecycleAcknowledgement::Unacknowledged;
            }
            reply_rx
                .recv_timeout(acknowledgement_timeout)
                .unwrap_or(crate::host::abi::WorkerLifecycleAcknowledgement::Unacknowledged)
        },
    );
    let _lifecycle_guard =
        crate::host::abi::install_authenticated_worker_lifecycle_port(lifecycle_port)
            .context("failed to install the authenticated worker lifecycle port")?;
    let evaluator_configuration = configuration.clone();
    let evaluator_output_cutoffs = output_cutoffs.clone();
    let evaluator_fault_events = events_tx.clone();
    let evaluator = std::thread::Builder::new()
        .name("ibex-authenticated-session-engine".to_owned())
        .spawn(move || {
            run_evaluator_owner_guarded(evaluator_fault_events, move || {
                run_evaluator_owner(
                    evaluator_configuration,
                    commands_rx,
                    events_tx,
                    startup_tx,
                    evaluator_output_cutoffs,
                )
            });
        })
        .context("failed to start the authenticated engine owner thread")?;

    let startup = startup_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("session engine stopped before authenticated startup"))??;
    let endpoint = protected
        .authenticate(&startup.binding, &startup.root)
        .context("session engine failed the worker equality proof")?;
    let result = run_control_loop(
        endpoint,
        configuration,
        startup.engine,
        commands_tx,
        events_rx,
        output_cutoffs,
    );
    // A cooperative lifecycle callback may deliberately leave the evaluator
    // parked. The supervisor disposes the worker process; never join a live
    // parked owner thread on that path.
    if evaluator.is_finished() {
        let _ = evaluator.join();
    }
    result.map_err(anyhow::Error::new)
}

/// Convert every abnormal evaluator-owner return into the authenticated event
/// lane before the thread disappears. The control owner deliberately remains a
/// separate thread so it can relay this fault even when the runtime owner
/// unwinds; the supervisor can then quiesce the worker before releasing its
/// output capture.
/// @ref LLP 0025#7-architecture-the-session-layer-must-survive-its-worker
fn run_evaluator_owner_guarded(events: EvaluationEventSender, run: impl FnOnce() -> Result<()>) {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(Ok(())) => {}
        Ok(Err(error)) => emit_fault(
            &events,
            &format!("authenticated evaluator owner failed: {error:#}"),
        ),
        Err(_) => emit_fault(&events, "authenticated evaluator owner panicked"),
    }
    // Lifecycle callbacks retain sender clones for the process lifetime, so
    // clone disconnection cannot prove that the sole Runtime owner survived.
    // The owner closes admission explicitly after its final required record.
    events.close();
}

fn run_evaluator_owner(
    configuration: WorkerBootstrapConfiguration,
    commands: mpsc::Receiver<EvaluationCommand>,
    events: EvaluationEventSender,
    startup: mpsc::SyncSender<Result<WorkerStartup>>,
    output_cutoffs: crate::terminal_session::WorkerOutputCutoffPort,
) -> Result<()> {
    let tokio = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to construct the session engine async owner")?;
    tokio.block_on(async move {
        let runtime = match Runtime::from_session_worker_material(
            &configuration.application,
            configuration.session_io,
        )
        .and_then(|runtime| {
            let binding = runtime.authenticated_worker_binding()?;
            let root = runtime.authenticated_worker_root_object()?;
            Ok((runtime, binding, root))
        }) {
            Ok(value) => value,
            Err(error) => {
                let _ = startup.send(Err(error));
                return Ok(());
            }
        };
        let (runtime, binding, root) = runtime;
        if let Err(error) = async {
            crate::suppress_runtime_banner(&runtime).await?;
            runtime.load_runtime().await
        }
        .await
        {
            let _ = startup.send(Err(error));
            return Ok(());
        }
        let engine = runtime.engine();
        if startup
            .send(Ok(WorkerStartup {
                binding,
                root,
                engine: engine.clone(),
            }))
            .is_err()
        {
            return Ok(());
        }

        let mut ingress: Option<WorkerIngress> = None;
        let mut started = false;
        loop {
            match commands.try_recv() {
                Ok(EvaluationCommand::Start(mode)) => {
                    if started || !mode_matches_configuration(mode, &configuration) {
                        emit_fault(&events, "worker Start disagrees with authenticated mode");
                        break;
                    }
                    ingress = Some(match configuration.role {
                        WorkerApplicationRole::Repl => {
                            WorkerIngress::Repl(Box::new(runtime.repl_session_ingress()?))
                        }
                        WorkerApplicationRole::Inline => {
                            WorkerIngress::Inline(Box::new(runtime.authenticated_inline_ingress()?))
                        }
                        WorkerApplicationRole::File => {
                            emit_fault(&events, "file execution is not a session-worker role");
                            break;
                        }
                    });
                    started = true;
                }
                Ok(EvaluationCommand::Submit {
                    submission_id,
                    kind,
                    source,
                }) => {
                    let Some(ingress) = ingress.as_mut() else {
                        emit_fault(&events, "worker received Submit before Start");
                        break;
                    };
                    evaluate_submission(
                        &runtime,
                        engine.as_ref(),
                        ingress,
                        submission_id,
                        kind,
                        source,
                        EvaluationSettlementPorts {
                            events: &events,
                            output_cutoffs: &output_cutoffs,
                        },
                    )
                    .await;
                }
                Ok(EvaluationCommand::EndOfInput) => {
                    if !started {
                        emit_fault(&events, "worker received EndOfInput before Start");
                        break;
                    }
                    drive_ready_and_emit_async_failures(engine.as_ref(), &events).await;
                    let _ = publish_evaluation_event(
                        &events,
                        EvaluationEvent::Message(ControlMessage::Quiescent),
                    );
                }
                Ok(EvaluationCommand::ReadyCheckpoint(checkpoint_id)) => {
                    if !started || !matches!(ingress, Some(WorkerIngress::Repl(_))) {
                        emit_fault(&events, "ready checkpoint is valid only for a live REPL");
                        break;
                    }
                    drive_ready_and_emit_async_failures(engine.as_ref(), &events).await;
                    // Lane order makes every retained report or explicit loss
                    // marker precede this required acknowledgement.
                    let _ = publish_evaluation_event(
                        &events,
                        EvaluationEvent::ReadyCheckpoint { checkpoint_id },
                    );
                }
                Ok(EvaluationCommand::Shutdown(status)) => {
                    let _ = publish_evaluation_event(&events, EvaluationEvent::Stopped(status));
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    if started && matches!(ingress, Some(WorkerIngress::Repl(_))) {
                        drive_ready_and_emit_async_failures(engine.as_ref(), &events).await;
                    }
                    tokio::time::sleep(IDLE_PUMP).await;
                }
                Err(mpsc::TryRecvError::Disconnected) => break,
            }
        }
        Ok(())
    })
}

async fn drive_ready_and_emit_async_failures(engine: &dyn Engine, events: &EvaluationEventSender) {
    let drive_error = engine.drive_ready_tasks().await.err();
    let mut failures = collect_engine_async_failures(engine).await;
    if let Some(error) = drive_error {
        failures.push(AuthenticatedAsyncFailure::capture_unavailable(format!(
            "{error:#}"
        )));
    }
    for failure in failures {
        let _ = publish_evaluation_event(
            events,
            EvaluationEvent::Message(ControlMessage::AsyncFailure {
                stdout_cutoff: 0,
                stderr_cutoff: 0,
                detail: encode_async_failure(&failure),
            }),
        );
    }
}

async fn collect_engine_async_failures(engine: &dyn Engine) -> Vec<AuthenticatedAsyncFailure> {
    match engine.take_authenticated_async_failures().await {
        Ok(failures) => failures,
        Err(error) => vec![AuthenticatedAsyncFailure::capture_unavailable(format!(
            "asynchronous failure drain failed: {error:#}"
        ))],
    }
}

fn mode_matches_configuration(
    mode: SessionInputMode,
    configuration: &WorkerBootstrapConfiguration,
) -> bool {
    use capsec_semantics::arming::ArmedExecutionMode;

    matches!(
        (mode, configuration.session_io.route.mode),
        (
            SessionInputMode::Interactive,
            ArmedExecutionMode::Interactive
        ) | (SessionInputMode::Transcript, ArmedExecutionMode::Transcript)
            | (SessionInputMode::Program, ArmedExecutionMode::Program)
    )
}

async fn evaluate_submission(
    runtime: &Runtime,
    engine: &dyn Engine,
    ingress: &mut WorkerIngress,
    submission_id: u64,
    kind: SubmissionKind,
    source: Vec<u8>,
    settlement: EvaluationSettlementPorts<'_>,
) {
    let EvaluationSettlementPorts {
        events,
        output_cutoffs,
    } = settlement;
    match (ingress, kind) {
        (WorkerIngress::Repl(ingress), SubmissionKind::Inline) => {
            let evaluation = ingress.evaluate_inline(engine, source).await;
            settle_repl_evaluation(engine, submission_id, evaluation, events, output_cutoffs).await;
        }
        (WorkerIngress::Repl(ingress), SubmissionKind::Load) => {
            let path = match String::from_utf8(source) {
                Ok(path) => path,
                Err(_) => {
                    send_outcome(
                        events,
                        submission_id,
                        EvaluationOutcomeKind::Refused,
                        1,
                        b"load path is not UTF-8".to_vec(),
                    );
                    return;
                }
            };
            let evaluation = ingress.evaluate_load(engine, &path).await;
            settle_repl_evaluation(engine, submission_id, evaluation, events, output_cutoffs).await;
        }
        (WorkerIngress::Repl(ingress), SubmissionKind::Mounts) if source.is_empty() => {
            let description = match ingress.mounts_description(engine).await {
                Ok(description) => description,
                Err(error) => {
                    send_outcome(
                        events,
                        submission_id,
                        EvaluationOutcomeKind::EngineFault,
                        70,
                        format!("{error:#}").into_bytes(),
                    );
                    return;
                }
            };
            let payload = serde_json::json!({
                "virtualCwd": description.virtual_cwd(),
                "mounts": description.mounts().iter().map(|mount| serde_json::json!({
                    "virtualPath": mount.virtual_path(),
                    "logicalRoot": mount.logical_root(),
                    "attributes": mount.attributes(),
                })).collect::<Vec<_>>(),
            });
            match capsec_semantics::canonical::to_jcs_bytes(&payload) {
                Ok(payload) => {
                    let _ = publish_evaluation_event(
                        events,
                        EvaluationEvent::Message(ControlMessage::Step {
                            submission_id,
                            kind: STEP_MOUNTS,
                            payload,
                        }),
                    );
                    send_outcome(
                        events,
                        submission_id,
                        EvaluationOutcomeKind::Empty,
                        0,
                        Vec::new(),
                    );
                }
                Err(error) => send_outcome(
                    events,
                    submission_id,
                    EvaluationOutcomeKind::EngineFault,
                    70,
                    format!("{error:#}").into_bytes(),
                ),
            }
        }
        (WorkerIngress::Repl(_), SubmissionKind::OperatorExit) if source.is_empty() => {
            use ibex_runtime::session_lifecycle::LifecycleRequestDisposition;
            match runtime.request_operator_exit() {
                LifecycleRequestDisposition::Accepted { request } => send_outcome(
                    events,
                    submission_id,
                    EvaluationOutcomeKind::Lifecycle,
                    request.status,
                    Vec::new(),
                ),
                LifecycleRequestDisposition::AlreadyInProgress => {
                    let status = runtime
                        .session_lifecycle()
                        .latched_request()
                        .map_or(0, |request| request.status);
                    send_outcome(
                        events,
                        submission_id,
                        EvaluationOutcomeKind::Lifecycle,
                        status,
                        Vec::new(),
                    );
                }
                LifecycleRequestDisposition::Denied => send_outcome(
                    events,
                    submission_id,
                    EvaluationOutcomeKind::EngineFault,
                    70,
                    b"operator lifecycle request was denied".to_vec(),
                ),
            }
        }
        (WorkerIngress::Inline(ingress), SubmissionKind::Inline) => {
            let evaluation = ingress.evaluate(engine, source).await;
            settle_program_evaluation(runtime, engine, submission_id, evaluation, events).await;
        }
        _ => send_outcome(
            events,
            submission_id,
            EvaluationOutcomeKind::Refused,
            1,
            b"submission kind is invalid for the authenticated worker role".to_vec(),
        ),
    }
}

async fn settle_repl_evaluation(
    engine: &dyn Engine,
    submission_id: u64,
    evaluation: std::result::Result<AuthenticatedEvaluation, crate::runtime::ReplEvaluationFailure>,
    events: &EvaluationEventSender,
    output_cutoffs: &crate::terminal_session::WorkerOutputCutoffPort,
) {
    for failure in collect_engine_async_failures(engine).await {
        let _ = publish_evaluation_event(
            events,
            EvaluationEvent::Message(ControlMessage::AsyncFailure {
                stdout_cutoff: 0,
                stderr_cutoff: 0,
                detail: encode_async_failure(&failure),
            }),
        );
    }
    match evaluation {
        Err(error) => send_failure(events, submission_id, error),
        Ok(AuthenticatedEvaluation::Empty) => send_outcome(
            events,
            submission_id,
            EvaluationOutcomeKind::Empty,
            0,
            Vec::new(),
        ),
        Ok(AuthenticatedEvaluation::Cancelled) => send_outcome(
            events,
            submission_id,
            EvaluationOutcomeKind::Cancelled,
            130,
            Vec::new(),
        ),
        Ok(AuthenticatedEvaluation::Lifecycle(status)) => send_outcome(
            events,
            submission_id,
            EvaluationOutcomeKind::Lifecycle,
            status,
            Vec::new(),
        ),
        Ok(AuthenticatedEvaluation::Throw(thrown)) => {
            let detail = serde_json::to_vec(&thrown)
                .unwrap_or_else(|error| format!("throw encoding failed: {error}").into_bytes());
            send_outcome(
                events,
                submission_id,
                EvaluationOutcomeKind::Throw,
                1,
                detail,
            );
        }
        Ok(AuthenticatedEvaluation::Value { display, receipt }) => {
            let tree = match crate::terminal_session::encode_authenticated_display(&display) {
                Ok(tree) => tree,
                Err(error) => {
                    if let Some(receipt) = receipt {
                        let _ = engine.release_undisplayed_value(receipt).await;
                    }
                    send_outcome(
                        events,
                        submission_id,
                        EvaluationOutcomeKind::EngineFault,
                        70,
                        error.as_bytes().to_vec(),
                    );
                    return;
                }
            };
            let cutoffs = match output_cutoffs.cutoffs() {
                Ok(cutoffs) => cutoffs,
                Err(error) => {
                    if let Some(receipt) = receipt {
                        let _ = engine.release_undisplayed_value(receipt).await;
                    }
                    send_outcome(
                        events,
                        submission_id,
                        EvaluationOutcomeKind::EngineFault,
                        70,
                        format!("worker output cutoff failed: {error}").into_bytes(),
                    );
                    return;
                }
            };
            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            if publish_evaluation_event(
                events,
                EvaluationEvent::Display {
                    submission_id,
                    tree,
                    stdout_cutoff: cutoffs.stdout(),
                    stderr_cutoff: cutoffs.stderr(),
                    reply: reply_tx,
                },
            )
            .is_err()
            {
                if let Some(receipt) = receipt {
                    let _ = engine.release_undisplayed_value(receipt).await;
                }
                return;
            }
            let disposition = match reply_rx.recv() {
                Ok(DisplayAckDisposition::Displayed) => DisplayDisposition::Displayed,
                Ok(DisplayAckDisposition::Fallback) => DisplayDisposition::Fallback,
                Ok(DisplayAckDisposition::WriteFailed) | Err(_) => DisplayDisposition::WriteFailed,
            };
            if let Some(receipt) = receipt {
                if let Err(error) = engine.acknowledge_display(receipt, disposition).await {
                    send_outcome(
                        events,
                        submission_id,
                        EvaluationOutcomeKind::EngineFault,
                        70,
                        format!("display acknowledgement failed: {error:#}").into_bytes(),
                    );
                    return;
                }
            }
            send_outcome(
                events,
                submission_id,
                EvaluationOutcomeKind::Empty,
                0,
                Vec::new(),
            );
        }
    }
}

async fn settle_program_evaluation(
    runtime: &Runtime,
    engine: &dyn Engine,
    submission_id: u64,
    evaluation: std::result::Result<AuthenticatedEvaluation, AuthenticatedEvaluationFailure>,
    events: &EvaluationEventSender,
) {
    let async_failures = collect_engine_async_failures(engine).await;
    if !async_failures.is_empty() {
        if let Ok(AuthenticatedEvaluation::Value {
            receipt: Some(receipt),
            ..
        }) = evaluation
        {
            let _ = engine.release_undisplayed_value(receipt).await;
        }
        for (index, failure) in async_failures.into_iter().enumerate() {
            let _ = publish_evaluation_event(
                events,
                EvaluationEvent::AsyncFailure {
                    submission_id: (index == 0).then_some(submission_id),
                    detail: encode_async_failure(&failure),
                },
            );
        }
        return;
    }
    let receipt = match evaluation {
        Err(error) => {
            send_failure(events, submission_id, error);
            return;
        }
        Ok(AuthenticatedEvaluation::Throw(thrown)) => {
            let detail = serde_json::to_vec(&thrown).unwrap_or_default();
            send_outcome(
                events,
                submission_id,
                EvaluationOutcomeKind::Throw,
                1,
                detail,
            );
            return;
        }
        Ok(AuthenticatedEvaluation::Cancelled) => {
            send_outcome(
                events,
                submission_id,
                EvaluationOutcomeKind::Cancelled,
                130,
                Vec::new(),
            );
            return;
        }
        Ok(AuthenticatedEvaluation::Lifecycle(status)) => {
            send_outcome(
                events,
                submission_id,
                EvaluationOutcomeKind::Lifecycle,
                status,
                Vec::new(),
            );
            return;
        }
        Ok(AuthenticatedEvaluation::Empty) => None,
        Ok(AuthenticatedEvaluation::Value { receipt, .. }) => receipt,
    };
    if let Some(receipt) = receipt {
        if let Err(error) = engine.release_undisplayed_value(receipt).await {
            send_outcome(
                events,
                submission_id,
                EvaluationOutcomeKind::EngineFault,
                70,
                format!("failed to release suppressed result: {error:#}").into_bytes(),
            );
            return;
        }
    }
    if let Some(request) = runtime.session_lifecycle().take_pending_request() {
        send_outcome(
            events,
            submission_id,
            EvaluationOutcomeKind::Lifecycle,
            request.status,
            Vec::new(),
        );
        return;
    }
    let program_drain = engine.drive_authenticated_program_to_quiescence().await;
    let async_failures = collect_engine_async_failures(engine).await;
    if !async_failures.is_empty() {
        for (index, failure) in async_failures.into_iter().enumerate() {
            let _ = publish_evaluation_event(
                events,
                EvaluationEvent::AsyncFailure {
                    submission_id: (index == 0).then_some(submission_id),
                    detail: encode_async_failure(&failure),
                },
            );
        }
        return;
    }
    match program_drain {
        Ok(()) => {
            if let Some(request) = runtime.session_lifecycle().take_pending_request() {
                send_outcome(
                    events,
                    submission_id,
                    EvaluationOutcomeKind::Lifecycle,
                    request.status,
                    Vec::new(),
                );
            } else {
                send_outcome(
                    events,
                    submission_id,
                    EvaluationOutcomeKind::Empty,
                    runtime.lifecycle_exit_code(),
                    Vec::new(),
                );
            }
        }
        Err(AuthenticatedProgramDrainFailure::Unhandled(error)) => {
            let _ = publish_evaluation_event(
                events,
                EvaluationEvent::AsyncFailure {
                    submission_id: Some(submission_id),
                    detail: unavailable_async_failure(format!("{error:#}")),
                },
            );
        }
        Err(AuthenticatedProgramDrainFailure::EngineFault(error)) => send_outcome(
            events,
            submission_id,
            EvaluationOutcomeKind::EngineFault,
            70,
            format!("{error:#}").into_bytes(),
        ),
    }
}

fn send_failure(
    events: &EvaluationEventSender,
    submission_id: u64,
    error: AuthenticatedEvaluationFailure,
) {
    let engine_fault = error.is_engine_fault();
    send_outcome(
        events,
        submission_id,
        if engine_fault {
            EvaluationOutcomeKind::EngineFault
        } else {
            EvaluationOutcomeKind::Refused
        },
        if engine_fault { 70 } else { 1 },
        format!("{error:#}").into_bytes(),
    );
}

fn send_outcome(
    events: &EvaluationEventSender,
    submission_id: u64,
    kind: EvaluationOutcomeKind,
    status: i32,
    detail: Vec<u8>,
) {
    const MAX_WORKER_EVENT_DETAIL_BYTES: usize = 1024 * 1024;
    let (kind, status, detail) = if detail.len() <= MAX_WORKER_EVENT_DETAIL_BYTES {
        (kind, status, detail)
    } else {
        (
            EvaluationOutcomeKind::EngineFault,
            70,
            b"worker outcome exceeded the bounded control-envelope payload".to_vec(),
        )
    };
    let _ = publish_evaluation_event(
        events,
        EvaluationEvent::Outcome {
            submission_id,
            kind,
            status,
            detail,
        },
    );
}

fn encode_async_failure(failure: &AuthenticatedAsyncFailure) -> Vec<u8> {
    const MAX_WORKER_EVENT_DETAIL_BYTES: usize = 1024 * 1024;
    // Both arms contain only ordinary strings/closed data, so serialization
    // cannot encounter a user-defined hook. Keep a deterministic explicit
    // fallback instead of replacing a background report with silence.
    let encoded = serde_json::to_vec(failure).unwrap_or_else(|error| {
        serde_json::to_vec(&AuthenticatedAsyncFailure::capture_unavailable(format!(
            "asynchronous failure envelope encoding failed: {error}"
        )))
        .expect("static asynchronous failure fallback is serializable")
    });
    if encoded.len() <= MAX_WORKER_EVENT_DETAIL_BYTES {
        encoded
    } else {
        serde_json::to_vec(&AuthenticatedAsyncFailure::capture_unavailable(
            "asynchronous failure exceeded the bounded control-envelope payload",
        ))
        .expect("static asynchronous failure size fallback is serializable")
    }
}

fn unavailable_async_failure(error: impl std::fmt::Display) -> Vec<u8> {
    encode_async_failure(&AuthenticatedAsyncFailure::capture_unavailable(
        error.to_string(),
    ))
}

fn decode_async_failure(detail: &[u8]) -> Result<AuthenticatedAsyncFailure> {
    let failure: AuthenticatedAsyncFailure = serde_json::from_slice(detail)
        .context("worker asynchronous failure envelope is malformed")?;
    failure
        .validate_wire()
        .context("worker asynchronous failure envelope violated safe-text invariants")?;
    Ok(failure)
}

fn emit_fault(events: &EvaluationEventSender, detail: &str) {
    let _ = publish_evaluation_event(
        events,
        EvaluationEvent::Message(ControlMessage::WorkerFault {
            stdout_cutoff: 0,
            stderr_cutoff: 0,
            detail: detail.as_bytes().to_vec(),
        }),
    );
}

fn stamp_worker_diagnostic_cutoffs(
    message: &mut ControlMessage,
    output_cutoffs: &crate::terminal_session::WorkerOutputCutoffPort,
) -> std::result::Result<(), WorkerProtocolError> {
    if let ControlMessage::AsyncFailure {
        stdout_cutoff,
        stderr_cutoff,
        ..
    }
    | ControlMessage::WorkerFault {
        stdout_cutoff,
        stderr_cutoff,
        ..
    } = message
    {
        let cutoffs = output_cutoffs.cutoffs()?;
        *stdout_cutoff = cutoffs.stdout();
        *stderr_cutoff = cutoffs.stderr();
    }
    Ok(())
}

fn work_unit_control_message(
    event: AuthenticatedWorkUnitEvent,
) -> std::result::Result<ControlMessage, WorkerProtocolError> {
    let kind = match event.kind {
        AuthenticatedWorkUnitKind::Evaluation => WorkUnitKind::Evaluation,
        AuthenticatedWorkUnitKind::Callback => WorkUnitKind::Callback,
        AuthenticatedWorkUnitKind::Timer => WorkUnitKind::Timer,
        AuthenticatedWorkUnitKind::MicrotaskDrain => WorkUnitKind::MicrotaskDrain,
        AuthenticatedWorkUnitKind::CompletionQuery => WorkUnitKind::CompletionQuery,
    };
    let phase = match event.phase {
        AuthenticatedWorkUnitPhase::Due => WorkUnitPhase::Due,
        AuthenticatedWorkUnitPhase::Undue => WorkUnitPhase::Undue,
        AuthenticatedWorkUnitPhase::Begin => WorkUnitPhase::Begin,
        AuthenticatedWorkUnitPhase::Suspended => WorkUnitPhase::Suspended,
        AuthenticatedWorkUnitPhase::End => WorkUnitPhase::End,
    };
    if matches!(phase, WorkUnitPhase::Due | WorkUnitPhase::Undue) {
        if kind != WorkUnitKind::Timer || event.target_id != 0 || event.scheduling_id == 0 {
            return Err(WorkerProtocolError::Malformed(
                "native timer transition has invalid identities",
            ));
        }
    } else if event.target_id == 0 {
        return Err(WorkerProtocolError::Malformed(
            "native work-unit transition omitted its target",
        ));
    }
    Ok(ControlMessage::WorkUnit {
        target_id: event.target_id,
        scheduling_id: event.scheduling_id,
        kind,
        phase,
    })
}

#[derive(Default)]
struct PendingWorkerCancellations {
    by_request: std::collections::BTreeMap<u64, u64>,
    last_request_id: u64,
}

impl PendingWorkerCancellations {
    fn dispatched(
        &mut self,
        request_id: u64,
        target_id: u64,
        status: AuthenticatedCancellationStatus,
    ) -> std::result::Result<Option<ControlMessage>, WorkerProtocolError> {
        if request_id == 0 || target_id == 0 || request_id <= self.last_request_id {
            return Err(WorkerProtocolError::Malformed(
                "worker received an invalid or duplicate cancellation request",
            ));
        }
        // The authenticated lane is ordered and the supervisor allocates
        // monotonically. A high-watermark rejects replay without retaining an
        // unbounded set of every historical request id.
        self.last_request_id = request_id;
        let resolution = match status {
            AuthenticatedCancellationStatus::Accepted => {
                self.by_request.insert(request_id, target_id);
                return Ok(None);
            }
            AuthenticatedCancellationStatus::Unavailable
            | AuthenticatedCancellationStatus::StaleTarget => CancellationResolution::Unavailable,
            AuthenticatedCancellationStatus::Failed => CancellationResolution::Failed,
        };
        Ok(Some(ControlMessage::CancellationResolved {
            request_id,
            target_id,
            resolution,
        }))
    }

    fn resolve_native(
        &mut self,
        event: AuthenticatedCancellationEvent,
    ) -> std::result::Result<Vec<ControlMessage>, WorkerProtocolError> {
        if event.target_id == 0 {
            return Err(WorkerProtocolError::Malformed(
                "native terminal cancellation omitted its target",
            ));
        }
        let resolution = match event.resolution {
            AuthenticatedCancellationResolution::Accepted => CancellationResolution::Accepted,
            AuthenticatedCancellationResolution::Failed => CancellationResolution::Failed,
            AuthenticatedCancellationResolution::Defeated => CancellationResolution::Defeated,
        };
        let request_ids = self
            .by_request
            .iter()
            .filter_map(|(request_id, target_id)| {
                (*target_id == event.target_id).then_some(*request_id)
            })
            .collect::<Vec<_>>();
        if request_ids.is_empty() {
            return Err(WorkerProtocolError::Malformed(
                "native resolved an unknown cancellation target",
            ));
        }
        Ok(request_ids
            .into_iter()
            .map(|request_id| {
                self.by_request.remove(&request_id);
                ControlMessage::CancellationResolved {
                    request_id,
                    target_id: event.target_id,
                    resolution,
                }
            })
            .collect())
    }

    fn fail_all(&mut self) -> Vec<ControlMessage> {
        std::mem::take(&mut self.by_request)
            .into_iter()
            .map(
                |(request_id, target_id)| ControlMessage::CancellationResolved {
                    request_id,
                    target_id,
                    resolution: CancellationResolution::Failed,
                },
            )
            .collect()
    }

    #[cfg(test)]
    fn is_pending(&self, request_id: u64) -> bool {
        self.by_request.contains_key(&request_id)
    }
}

fn emit_cancellation_messages(
    endpoint: &mut VerifiedWorkerEndpoint,
    messages: impl IntoIterator<Item = ControlMessage>,
) -> std::result::Result<(), WorkerProtocolError> {
    for message in messages {
        endpoint.emit(&message)?;
    }
    Ok(())
}

fn drain_native_publications(
    endpoint: &mut VerifiedWorkerEndpoint,
    engine: &Arc<dyn Engine>,
    cancellations: &mut PendingWorkerCancellations,
) -> std::result::Result<(), WorkerProtocolError> {
    // A finite per-turn drain keeps Ping/Cancel/Shutdown serviceable under an
    // adversarial callback storm. The native queue has its own hard bound and
    // reports overflow explicitly, so this does not turn backpressure into
    // silent loss.
    for _ in 0..WORKER_NATIVE_DRAIN_BUDGET {
        let event = engine
            .next_authenticated_work_unit()
            .map_err(|_| WorkerProtocolError::Malformed("native work-unit publication failed"))?;
        let Some(event) = event else {
            break;
        };
        endpoint.emit(&work_unit_control_message(event)?)?;
    }
    for _ in 0..WORKER_NATIVE_DRAIN_BUDGET {
        let event = engine.next_authenticated_cancellation().map_err(|_| {
            WorkerProtocolError::Malformed("native terminal-cancellation publication failed")
        })?;
        let Some(event) = event else {
            break;
        };
        let messages = cancellations.resolve_native(event)?;
        emit_cancellation_messages(endpoint, messages)?;
    }
    Ok(())
}

fn run_control_loop(
    mut endpoint: VerifiedWorkerEndpoint,
    configuration: WorkerBootstrapConfiguration,
    engine: Arc<dyn Engine>,
    commands: mpsc::Sender<EvaluationCommand>,
    events: EvaluationEventReceiver,
    output_cutoffs: crate::terminal_session::WorkerOutputCutoffPort,
) -> std::result::Result<i32, WorkerProtocolError> {
    let mut started = false;
    let mut active_submission = None;
    let mut pending_display: Option<(u64, mpsc::SyncSender<DisplayAckDisposition>)> = None;
    let mut pending_cancellations = PendingWorkerCancellations::default();
    let mut next_exit_code_mutation_id = 1_u64;

    loop {
        // Native publication is independent of the application submission
        // channel: an idle timer/callback can wedge while `active_submission`
        // is None, and still must become an exact cancellation target.
        // @ref LLP 0025#6-interruption-and-cancellation
        drain_native_publications(&mut endpoint, &engine, &mut pending_cancellations)?;
        for _ in 0..WORKER_EVENT_DRAIN_BUDGET {
            let Some(event) = next_evaluation_event(&events)? else {
                break;
            };
            // The owner publishes a native End before it sends an application
            // outcome. Close that cross-channel race by draining again after
            // receipt and before forwarding the application event.
            drain_native_publications(&mut endpoint, &engine, &mut pending_cancellations)?;
            match event {
                EvaluationEvent::Message(mut message) => {
                    stamp_worker_diagnostic_cutoffs(&mut message, &output_cutoffs)?;
                    endpoint.emit(&message)?;
                }
                EvaluationEvent::AsyncFailure {
                    submission_id,
                    detail,
                } => {
                    if let Some(submission_id) = submission_id {
                        if active_submission != Some(submission_id) {
                            return Err(WorkerProtocolError::Malformed(
                                "worker asynchronous failure did not match the active submission",
                            ));
                        }
                        active_submission = None;
                    }
                    let cutoffs = output_cutoffs.cutoffs()?;
                    endpoint.emit(&ControlMessage::AsyncFailure {
                        stdout_cutoff: cutoffs.stdout(),
                        stderr_cutoff: cutoffs.stderr(),
                        detail,
                    })?;
                }
                EvaluationEvent::Outcome {
                    submission_id,
                    kind,
                    status,
                    detail,
                } => {
                    if active_submission == Some(submission_id) {
                        active_submission = None;
                    }
                    let cutoffs = output_cutoffs.cutoffs()?;
                    endpoint.emit(&ControlMessage::Outcome {
                        submission_id,
                        kind,
                        status,
                        stdout_cutoff: cutoffs.stdout(),
                        stderr_cutoff: cutoffs.stderr(),
                        detail,
                    })?;
                }
                EvaluationEvent::Display {
                    submission_id,
                    tree,
                    stdout_cutoff,
                    stderr_cutoff,
                    reply,
                } => {
                    if pending_display.is_some() || active_submission != Some(submission_id) {
                        return Err(WorkerProtocolError::Malformed(
                            "worker produced an out-of-order display",
                        ));
                    }
                    endpoint.send(&ControlMessage::Display {
                        submission_id,
                        tree,
                        stdout_cutoff,
                        stderr_cutoff,
                    })?;
                    pending_display = Some((submission_id, reply));
                }
                EvaluationEvent::ExitCodeMirror { status, reply } => {
                    let mutation_id = next_exit_code_mutation_id;
                    let acknowledgement = match endpoint.mirror_exit_code(mutation_id, status) {
                        Ok(()) => {
                            next_exit_code_mutation_id = next_exit_code_mutation_id
                                .checked_add(1)
                                .ok_or(WorkerProtocolError::ExitCodeMirrorGap)?;
                            crate::host::abi::WorkerLifecycleAcknowledgement::Acknowledged
                        }
                        Err(_) => crate::host::abi::WorkerLifecycleAcknowledgement::Unacknowledged,
                    };
                    let _ = reply.send(acknowledgement);
                }
                EvaluationEvent::LifecycleCommit {
                    request_id,
                    status,
                    stdout_cutoff,
                    stderr_cutoff,
                    reply,
                } => {
                    let record = crate::session_worker::LifecycleRecord {
                        request_id,
                        status,
                        stdout_cutoff,
                        stderr_cutoff,
                    };
                    let acknowledgement = if endpoint.send_lifecycle_commit(record).is_ok() {
                        crate::host::abi::WorkerLifecycleAcknowledgement::Acknowledged
                    } else {
                        crate::host::abi::WorkerLifecycleAcknowledgement::Unacknowledged
                    };
                    let _ = reply.send(acknowledgement);
                }
                EvaluationEvent::ReadyCheckpoint { checkpoint_id } => {
                    let cutoffs = output_cutoffs.cutoffs()?;
                    endpoint.emit(&ControlMessage::ReadyCheckpointAck {
                        checkpoint_id,
                        stdout_cutoff: cutoffs.stdout(),
                        stderr_cutoff: cutoffs.stderr(),
                    })?;
                }
                EvaluationEvent::Stopped(status) => {
                    let failed = pending_cancellations.fail_all();
                    emit_cancellation_messages(&mut endpoint, failed)?;
                    return Ok(status);
                }
            }
        }

        let Some(message) = endpoint.receive_timeout(CONTROL_POLL)? else {
            continue;
        };
        match message {
            ControlMessage::Ping { nonce } => endpoint.send(&ControlMessage::Pong { nonce })?,
            ControlMessage::Start { mode } => {
                if started || !mode_matches_configuration(mode, &configuration) {
                    return Err(WorkerProtocolError::Malformed(
                        "worker Start disagrees with authenticated bootstrap",
                    ));
                }
                commands
                    .send(EvaluationCommand::Start(mode))
                    .map_err(|_| WorkerProtocolError::WorkerDied)?;
                started = true;
            }
            ControlMessage::Submit {
                submission_id,
                kind,
                source,
            } => {
                if !started || active_submission.is_some() || submission_id == 0 {
                    return Err(WorkerProtocolError::Malformed(
                        "worker received an invalid or overlapping submission",
                    ));
                }
                commands
                    .send(EvaluationCommand::Submit {
                        submission_id,
                        kind,
                        source,
                    })
                    .map_err(|_| WorkerProtocolError::WorkerDied)?;
                active_submission = Some(submission_id);
            }
            ControlMessage::DisplayAck {
                submission_id,
                disposition,
            } => {
                let Some((expected, reply)) = pending_display.take() else {
                    return Err(WorkerProtocolError::Malformed(
                        "worker received an unsolicited display acknowledgement",
                    ));
                };
                if expected != submission_id || reply.send(disposition).is_err() {
                    return Err(WorkerProtocolError::Malformed(
                        "worker display acknowledgement did not match",
                    ));
                }
            }
            ControlMessage::Cancel {
                request_id,
                target_id,
            } => {
                let status = engine.cancel_authenticated_target(target_id);
                if let Some(message) =
                    pending_cancellations.dispatched(request_id, target_id, status)?
                {
                    endpoint.emit(&message)?;
                }
            }
            ControlMessage::EndOfInput => commands
                .send(EvaluationCommand::EndOfInput)
                .map_err(|_| WorkerProtocolError::WorkerDied)?,
            ControlMessage::ReadyCheckpoint { checkpoint_id } => {
                if !started || active_submission.is_some() || checkpoint_id == 0 {
                    return Err(WorkerProtocolError::Malformed(
                        "worker received an invalid ready-work checkpoint",
                    ));
                }
                commands
                    .send(EvaluationCommand::ReadyCheckpoint(checkpoint_id))
                    .map_err(|_| WorkerProtocolError::WorkerDied)?;
            }
            ControlMessage::Shutdown { status } => {
                let _ = commands.send(EvaluationCommand::Shutdown(status));
                if active_submission.is_none() {
                    let failed = pending_cancellations.fail_all();
                    emit_cancellation_messages(&mut endpoint, failed)?;
                    return Ok(status);
                }
            }
            ControlMessage::Resize { columns, rows } => {
                // Topology is immutable, but dimensions are live session
                // state. This atomic typed-query update takes no Runtime lock,
                // so it remains effective while the engine owner is executing.
                endpoint.update_terminal_dimensions(columns, rows)?;
            }
            other => {
                let _ = AuthenticatedWorkerCommand::try_from(other)?;
                return Err(WorkerProtocolError::Malformed(
                    "unexpected supervisor record in runtime worker loop",
                ));
            }
        }
    }
}

/// A disconnected evaluator event lane is terminal, not equivalent to an idle
/// lane. Treating both as `try_recv`'s empty case leaves the authenticated
/// control process responsive while the supervisor waits forever for an
/// outcome that no owner can produce.
fn next_evaluation_event(
    events: &EvaluationEventReceiver,
) -> std::result::Result<Option<EvaluationEvent>, WorkerProtocolError> {
    match events.try_recv() {
        Ok(LaneDelivery::Event(event) | LaneDelivery::Terminal(event)) => Ok(Some(event)),
        Ok(LaneDelivery::Loss(count)) => Ok(Some(EvaluationEvent::Message(
            ControlMessage::PreReceiptLoss { count },
        ))),
        Err(TryReceiveError::Empty) => Ok(None),
        Err(TryReceiveError::Disconnected) => Err(WorkerProtocolError::WorkerDied),
    }
}

enum SupervisorCommand {
    Send {
        message: ControlMessage,
        deadline: std::time::Instant,
        state: Arc<std::sync::atomic::AtomicU8>,
        reply: mpsc::SyncSender<std::result::Result<(), WorkerProtocolError>>,
    },
    CancelDelivery {
        request_id: u64,
        target_id: u64,
        deadline: std::time::Instant,
        state: Arc<std::sync::atomic::AtomicU8>,
        reply: mpsc::SyncSender<std::result::Result<(), WorkerProtocolError>>,
    },
    TerminateInterrupt {
        reply: mpsc::SyncSender<std::result::Result<(), WorkerProtocolError>>,
    },
    SuspendTerminal {
        deadline: std::time::Instant,
        state: Arc<std::sync::atomic::AtomicU8>,
        reply: mpsc::SyncSender<std::result::Result<(), WorkerProtocolError>>,
    },
    ContinueTerminal {
        deadline: std::time::Instant,
        state: Arc<std::sync::atomic::AtomicU8>,
        reply: mpsc::SyncSender<std::result::Result<(), WorkerProtocolError>>,
    },
    Quiesce {
        reply: mpsc::SyncSender<std::result::Result<(), WorkerProtocolError>>,
    },
    Dispose {
        reply: mpsc::SyncSender<std::result::Result<(), WorkerProtocolError>>,
    },
}

/// Cloneable, evaluator-independent control authority retained by the terminal
/// supervisor. It can request exact cancellation even while the foreground
/// caller is waiting for a submission result.
#[derive(Clone)]
pub(crate) struct SupervisorRuntimeControl {
    commands: mpsc::Sender<SupervisorCommand>,
    lifecycle: Arc<Mutex<crate::session_worker::SupervisorLifecycleState>>,
}

impl SupervisorRuntimeControl {
    fn send(&self, message: ControlMessage) -> Result<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let state = Arc::new(std::sync::atomic::AtomicU8::new(CONTROL_DELIVERY_PENDING));
        self.commands
            .send(SupervisorCommand::Send {
                message,
                deadline: std::time::Instant::now() + SUPERVISOR_CONTROL_ACK,
                state: state.clone(),
                reply: reply_tx,
            })
            .context("session worker controller stopped")?;
        await_control_delivery(
            reply_rx,
            &state,
            SUPERVISOR_CONTROL_ACK,
            "session worker controller did not acknowledge its bounded send",
        )
    }

    pub(crate) fn cancel(&self, request_id: u64, target_id: u64) -> Result<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let state = Arc::new(std::sync::atomic::AtomicU8::new(CONTROL_DELIVERY_PENDING));
        self.commands
            .send(SupervisorCommand::CancelDelivery {
                request_id,
                target_id,
                deadline: std::time::Instant::now() + CANCELLATION_DELIVERY_ACK,
                state: state.clone(),
                reply: reply_tx,
            })
            .context("session worker controller stopped")?;
        await_control_delivery(
            reply_rx,
            &state,
            CANCELLATION_DELIVERY_ACK,
            "session worker cancellation delivery acknowledgement timed out",
        )
    }

    pub(crate) fn submit(
        &self,
        submission_id: u64,
        kind: SubmissionKind,
        source: Vec<u8>,
    ) -> Result<()> {
        self.send(ControlMessage::Submit {
            submission_id,
            kind,
            source,
        })
    }

    pub(crate) fn display_ack(
        &self,
        submission_id: u64,
        disposition: DisplayAckDisposition,
    ) -> Result<()> {
        self.send(ControlMessage::DisplayAck {
            submission_id,
            disposition,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn end_of_input(&self) -> Result<()> {
        self.send(ControlMessage::EndOfInput)
    }

    pub(crate) fn ready_checkpoint(&self, checkpoint_id: u64) -> Result<()> {
        self.send(ControlMessage::ReadyCheckpoint { checkpoint_id })
    }

    #[allow(dead_code)]
    pub(crate) fn shutdown(&self, status: i32) -> Result<()> {
        self.send(ControlMessage::Shutdown { status })
    }

    pub(crate) fn resize(&self, columns: u16, rows: u16) -> Result<()> {
        self.send(ControlMessage::Resize { columns, rows })
    }

    pub(crate) fn lifecycle(&self) -> Result<crate::session_worker::SupervisorLifecycleState> {
        Ok(self
            .lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone())
    }

    pub(crate) fn terminate_for_interrupt(&self) -> Result<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.commands
            .send(SupervisorCommand::TerminateInterrupt { reply: reply_tx })
            .context("session worker controller stopped")?;
        reply_rx
            .recv_timeout(SUPERVISOR_CONTROL_ACK)
            .context("session worker controller did not acknowledge bounded termination")??;
        Ok(())
    }

    pub(crate) fn suspend_for_terminal(&self) -> Result<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let state = Arc::new(std::sync::atomic::AtomicU8::new(CONTROL_DELIVERY_PENDING));
        self.commands
            .send(SupervisorCommand::SuspendTerminal {
                deadline: std::time::Instant::now() + SUPERVISOR_CONTROL_ACK,
                state: state.clone(),
                reply: reply_tx,
            })
            .context("session worker controller stopped")?;
        await_control_delivery(
            reply_rx,
            &state,
            SUPERVISOR_CONTROL_ACK,
            "session worker controller did not acknowledge bounded suspension",
        )
    }

    pub(crate) fn continue_after_terminal(&self) -> Result<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let state = Arc::new(std::sync::atomic::AtomicU8::new(CONTROL_DELIVERY_PENDING));
        self.commands
            .send(SupervisorCommand::ContinueTerminal {
                deadline: std::time::Instant::now() + SUPERVISOR_CONTROL_ACK,
                state: state.clone(),
                reply: reply_tx,
            })
            .context("session worker controller stopped")?;
        await_control_delivery(
            reply_rx,
            &state,
            SUPERVISOR_CONTROL_ACK,
            "session worker controller did not acknowledge bounded continuation",
        )
    }

    pub(crate) fn dispose_preserving_lifecycle(&self) -> Result<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.commands
            .send(SupervisorCommand::Dispose { reply: reply_tx })
            .context("session worker controller stopped")?;
        reply_rx
            .recv_timeout(SUPERVISOR_CONTROL_ACK)
            .context("session worker controller did not acknowledge bounded disposal")??;
        Ok(())
    }

    pub(crate) fn quiesce_preserving_lifecycle(&self) -> Result<()> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.commands
            .send(SupervisorCommand::Quiesce { reply: reply_tx })
            .context("session worker controller stopped")?;
        reply_rx
            .recv_timeout(SUPERVISOR_CONTROL_ACK)
            .context("session worker controller did not acknowledge bounded quiescence")??;
        Ok(())
    }
}

/// Narrow terminal-owner authority. It cannot submit source, acknowledge a
/// display, mutate lifecycle state, or terminate the worker; it only projects
/// the three §7 live terminal operations from the supervisor controller.
#[derive(Clone)]
pub(crate) struct WorkerTerminalControl {
    control: SupervisorRuntimeControl,
}

impl WorkerTerminalControl {
    pub(crate) fn resize(&self, columns: u16, rows: u16) -> Result<()> {
        self.control.resize(columns, rows)
    }

    pub(crate) fn suspend(&self) -> Result<()> {
        self.control.suspend_for_terminal()
    }

    pub(crate) fn resume(&self) -> Result<()> {
        self.control.continue_after_terminal()
    }
}

/// A fully authenticated child plus the two raw program relays. The relays
/// are intentionally handed to the terminal broker rather than copied to the
/// supervisor's stdout/stderr directly.
pub(crate) struct SpawnedSessionWorker {
    pub(crate) control: SupervisorRuntimeControl,
    pub(crate) events: SupervisorEventReceiver,
    pub(crate) relays: crate::session_worker::WorkerRelays,
    pub(crate) history_startup: crate::history::HistoryStartupCapture,
    _controller: std::thread::JoinHandle<()>,
}

impl SpawnedSessionWorker {
    #[allow(dead_code)]
    pub(crate) fn next_event(
        &self,
        timeout: Duration,
    ) -> Result<
        Option<crate::session_worker::Sequenced<crate::session_worker::SupervisorEventPayload>>,
    > {
        match self.events.recv_timeout(timeout) {
            Ok(event) => Ok(Some(event)),
            Err(SequencedReceiveTimeoutError::Timeout) => Ok(None),
            Err(
                SequencedReceiveTimeoutError::Disconnected
                | SequencedReceiveTimeoutError::SequenceExhausted,
            ) => {
                anyhow::bail!("session worker event controller stopped")
            }
        }
    }

    pub(crate) fn into_remote_repl(
        self,
        plan: crate::terminal_session::SessionIoPlan,
    ) -> (
        RemoteReplSession,
        crate::session_worker::WorkerRelays,
        crate::history::HistoryStartupCapture,
    ) {
        let lifecycle = ibex_runtime::session_lifecycle::SessionLifecyclePort::default();
        let active_target = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cancellations = Arc::new(Mutex::new(RemoteCancellationLedger::default()));
        let cancellation_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancellation_request_gate = Arc::new(Mutex::new(()));
        let next_cancellation = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let cancellation = RemoteCancellationPort {
            control: self.control.clone(),
            active_target: active_target.clone(),
            cancellations: cancellations.clone(),
            closed: cancellation_closed.clone(),
            request_gate: cancellation_request_gate,
            next_request: next_cancellation.clone(),
        };
        (
            RemoteReplSession {
                control: self.control,
                events: self.events,
                plan,
                lifecycle,
                active_target,
                cancellations,
                cancellation_closed,
                next_submission: 1,
                next_checkpoint: 1,
                pending_display: None,
                pending_outcome_barrier: None,
                pending_lifecycle_barrier: None,
                pending_mounts: None,
                async_failures: BoundedRemoteAsyncBuffer::default(),
                cancellation,
                _controller: self._controller,
            },
            self.relays,
            self.history_startup,
        )
    }

    pub(crate) fn into_remote_program(
        self,
    ) -> (RemoteProgramSession, crate::session_worker::WorkerRelays) {
        let active_target = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cancellations = Arc::new(Mutex::new(RemoteCancellationLedger::default()));
        let cancellation_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancellation = RemoteCancellationPort {
            control: self.control.clone(),
            active_target: active_target.clone(),
            cancellations: cancellations.clone(),
            closed: cancellation_closed.clone(),
            request_gate: Arc::new(Mutex::new(())),
            next_request: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        };
        (
            RemoteProgramSession {
                control: self.control,
                events: self.events,
                lifecycle: ibex_runtime::session_lifecycle::SessionLifecyclePort::default(),
                active_target,
                cancellations,
                cancellation_closed,
                cancellation,
                _controller: self._controller,
            },
            self.relays,
        )
    }
}

#[derive(Debug)]
pub(crate) enum RemoteProgramOutcome {
    Completed {
        status: i32,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
    Throw {
        detail: Vec<u8>,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
    AsyncFailure {
        failure: AuthenticatedAsyncFailure,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
    Cancelled {
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
    Refused {
        detail: Vec<u8>,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
    EngineFault {
        detail: Vec<u8>,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
    Lifecycle {
        status: i32,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
}

impl RemoteProgramOutcome {
    pub(crate) const fn cutoffs(&self) -> (u64, u64) {
        match self {
            Self::Completed {
                stdout_cutoff,
                stderr_cutoff,
                ..
            }
            | Self::Throw {
                stdout_cutoff,
                stderr_cutoff,
                ..
            }
            | Self::AsyncFailure {
                stdout_cutoff,
                stderr_cutoff,
                ..
            }
            | Self::Cancelled {
                stdout_cutoff,
                stderr_cutoff,
            }
            | Self::Refused {
                stdout_cutoff,
                stderr_cutoff,
                ..
            }
            | Self::EngineFault {
                stdout_cutoff,
                stderr_cutoff,
                ..
            }
            | Self::Lifecycle {
                stdout_cutoff,
                stderr_cutoff,
                ..
            } => (*stdout_cutoff, *stderr_cutoff),
        }
    }
}

pub(crate) struct RemoteProgramSession {
    control: SupervisorRuntimeControl,
    events: SupervisorEventReceiver,
    lifecycle: ibex_runtime::session_lifecycle::SessionLifecyclePort,
    active_target: Arc<std::sync::atomic::AtomicU64>,
    cancellations: SharedRemoteCancellationLedger,
    cancellation_closed: Arc<std::sync::atomic::AtomicBool>,
    cancellation: RemoteCancellationPort,
    _controller: std::thread::JoinHandle<()>,
}

impl RemoteProgramSession {
    fn close_cancellation_state(&self) {
        close_remote_cancellation_state(
            &self.active_target,
            &self.cancellation_closed,
            &self.cancellations,
        );
    }

    pub(crate) fn terminal_control(&self) -> WorkerTerminalControl {
        WorkerTerminalControl {
            control: self.control.clone(),
        }
    }

    /// Retain only the supervisor-side authority needed to stop the worker
    /// while the owning session remains alive. Teardown guards use this clone
    /// during unwinding so a producer cannot outlive the output capture that
    /// drains its authenticated relays.
    pub(crate) fn runtime_control(&self) -> SupervisorRuntimeControl {
        self.control.clone()
    }

    pub(crate) fn cancellation_port(&self) -> RemoteCancellationPort {
        self.cancellation.clone()
    }

    pub(crate) fn execute(&mut self, source: Vec<u8>) -> Result<RemoteProgramOutcome> {
        let result = self.execute_inner(source);
        self.close_cancellation_state();
        result
    }

    fn execute_inner(&mut self, source: Vec<u8>) -> Result<RemoteProgramOutcome> {
        use ibex_runtime::session_lifecycle::{LifecyclePrincipal, LifecycleSetDisposition};

        const SUBMISSION_ID: u64 = 1;
        self.control
            .submit(SUBMISSION_ID, SubmissionKind::Inline, source)?;
        loop {
            let event = match self.events.recv() {
                Ok(event) => event,
                Err(_) => {
                    if let Some(outcome) = self.accepted_lifecycle_outcome()? {
                        return Ok(outcome);
                    }
                    anyhow::bail!("session worker stopped before program settlement");
                }
            };
            let event_sequence = event.sequence;
            let message = match event.payload {
                crate::session_worker::SupervisorEventPayload::Worker(message) => message,
                crate::session_worker::SupervisorEventPayload::WorkerDied(death) => {
                    if let Some(outcome) = self.accepted_lifecycle_outcome()? {
                        return Ok(outcome);
                    }
                    anyhow::bail!(
                        "session worker died during program execution (status {:?}, signal {:?})",
                        death.status,
                        death.signal
                    );
                }
                crate::session_worker::SupervisorEventPayload::PostReceiptLoss {
                    count,
                    highest_dropped_sequence,
                } => {
                    anyhow::ensure!(
                        count > 0
                            && highest_dropped_sequence > 0
                            && highest_dropped_sequence < event_sequence,
                        "supervisor produced an invalid post-receipt loss window"
                    );
                    return Ok(RemoteProgramOutcome::AsyncFailure {
                        failure: AuthenticatedAsyncFailure::PostReceiptLoss {
                            count,
                            highest_dropped_sequence,
                        },
                        stdout_cutoff: 0,
                        stderr_cutoff: 0,
                    });
                }
                crate::session_worker::SupervisorEventPayload::ControllerFault(reason) => {
                    if let Some(outcome) = self.accepted_lifecycle_outcome()? {
                        return Ok(outcome);
                    }
                    return Ok(RemoteProgramOutcome::EngineFault {
                        detail: format!("session worker controller fault: {reason:?}").into_bytes(),
                        stdout_cutoff: 0,
                        stderr_cutoff: 0,
                    });
                }
            };
            match message {
                ControlMessage::Outcome {
                    submission_id: SUBMISSION_ID,
                    kind,
                    status,
                    stdout_cutoff,
                    stderr_cutoff,
                    detail,
                } => {
                    return Ok(match kind {
                        EvaluationOutcomeKind::Empty => RemoteProgramOutcome::Completed {
                            status,
                            stdout_cutoff,
                            stderr_cutoff,
                        },
                        EvaluationOutcomeKind::Throw => RemoteProgramOutcome::Throw {
                            detail,
                            stdout_cutoff,
                            stderr_cutoff,
                        },
                        EvaluationOutcomeKind::Cancelled => RemoteProgramOutcome::Cancelled {
                            stdout_cutoff,
                            stderr_cutoff,
                        },
                        EvaluationOutcomeKind::Lifecycle => RemoteProgramOutcome::Lifecycle {
                            status,
                            stdout_cutoff,
                            stderr_cutoff,
                        },
                        EvaluationOutcomeKind::Refused => RemoteProgramOutcome::Refused {
                            detail,
                            stdout_cutoff,
                            stderr_cutoff,
                        },
                        EvaluationOutcomeKind::EngineFault => RemoteProgramOutcome::EngineFault {
                            detail,
                            stdout_cutoff,
                            stderr_cutoff,
                        },
                    });
                }
                ControlMessage::ExitCodeMirror { status, .. } => {
                    let disposition = self
                        .lifecycle
                        .set_exit_code(LifecyclePrincipal::Root, status);
                    anyhow::ensure!(
                        matches!(disposition, LifecycleSetDisposition::Accepted { .. }),
                        "supervisor could not apply the worker exitCode mirror"
                    );
                }
                ControlMessage::LifecycleCommit(record) => {
                    let _ = self
                        .lifecycle
                        .request_exit(LifecyclePrincipal::Root, record.status);
                    return Ok(RemoteProgramOutcome::Lifecycle {
                        status: record.status,
                        stdout_cutoff: record.stdout_cutoff,
                        stderr_cutoff: record.stderr_cutoff,
                    });
                }
                ControlMessage::WorkUnit {
                    target_id,
                    scheduling_id,
                    kind,
                    phase,
                } => {
                    let active_target = self
                        .cancellations
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .apply_work_unit(target_id, scheduling_id, kind, phase)?
                        .unwrap_or(0);
                    self.active_target
                        .store(active_target, std::sync::atomic::Ordering::Release);
                }
                ControlMessage::CancellationResolved {
                    request_id,
                    target_id,
                    resolution,
                } => {
                    self.cancellations
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .resolve(request_id, target_id, resolution)?;
                    if resolution == CancellationResolution::Failed {
                        anyhow::bail!(
                            "authenticated program cancellation {request_id} failed its runtime consistency check"
                        );
                    }
                }
                ControlMessage::Quiescent | ControlMessage::Pong { .. } => {}
                ControlMessage::AsyncFailure {
                    stdout_cutoff,
                    stderr_cutoff,
                    detail,
                } => {
                    let failure = decode_async_failure(&detail)?;
                    if matches!(failure, AuthenticatedAsyncFailure::PreReceiptLoss { .. }) {
                        if let Some(outcome) = self.accepted_lifecycle_outcome()? {
                            return Ok(outcome);
                        }
                        return Ok(RemoteProgramOutcome::EngineFault {
                            detail: failure.to_string().into_bytes(),
                            stdout_cutoff,
                            stderr_cutoff,
                        });
                    }
                    return Ok(RemoteProgramOutcome::AsyncFailure {
                        failure,
                        stdout_cutoff,
                        stderr_cutoff,
                    });
                }
                ControlMessage::WorkerFault {
                    stdout_cutoff,
                    stderr_cutoff,
                    detail,
                } => {
                    if let Some(outcome) = self.accepted_lifecycle_outcome()? {
                        return Ok(outcome);
                    }
                    return Ok(RemoteProgramOutcome::EngineFault {
                        detail,
                        stdout_cutoff,
                        stderr_cutoff,
                    });
                }
                ControlMessage::PreReceiptLoss { count } => {
                    if let Some(outcome) = self.accepted_lifecycle_outcome()? {
                        return Ok(outcome);
                    }
                    return Ok(RemoteProgramOutcome::EngineFault {
                        detail: format!(
                            "session worker lost {count} asynchronous failure event(s) before supervisor receipt"
                        )
                        .into_bytes(),
                        stdout_cutoff: 0,
                        stderr_cutoff: 0,
                    });
                }
                other => anyhow::bail!(
                    "unexpected authenticated event during program execution: {other:?}"
                ),
            }
        }
    }

    fn accepted_lifecycle_outcome(&self) -> Result<Option<RemoteProgramOutcome>> {
        let state = self.control.lifecycle()?;
        Ok(state
            .accepted_lifecycle()
            .map(|record| RemoteProgramOutcome::Lifecycle {
                status: record.status,
                stdout_cutoff: record.stdout_cutoff,
                stderr_cutoff: record.stderr_cutoff,
            }))
    }

    pub(crate) fn dispose_preserving_lifecycle(&self) -> Result<()> {
        self.close_cancellation_state();
        self.control.dispose_preserving_lifecycle()
    }

    pub(crate) fn quiesce_preserving_lifecycle(&self) -> Result<()> {
        self.close_cancellation_state();
        self.control.quiesce_preserving_lifecycle()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteCancellationState {
    Pending,
    #[cfg_attr(not(test), allow(dead_code))]
    Resolved(CancellationResolution),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RemoteCancellationRecord {
    target_id: u64,
    state: RemoteCancellationState,
}

#[derive(Default)]
struct RemoteCancellationLedger {
    records: std::collections::BTreeMap<u64, RemoteCancellationRecord>,
    last_request_id: u64,
    live_work: RemoteLiveWorkState,
    #[cfg(test)]
    resolved_records: std::collections::BTreeMap<u64, RemoteCancellationRecord>,
}

/// Supervisor-side projection of authenticated native unit publications.
/// Suspended targets and due scheduling identities are live work even though
/// neither is an exact cancellation target; discarding them would make the
/// generated terminal selector choose the idle-prompt row.
/// @ref LLP 0025#6-interruption-and-cancellation
#[derive(Default)]
struct RemoteLiveWorkState {
    executing: Vec<(u64, WorkUnitKind)>,
    suspended: std::collections::BTreeMap<u64, WorkUnitKind>,
    due_schedules: std::collections::BTreeSet<u64>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RemoteInterruptWorkSnapshot {
    pub(crate) executing: Option<(u64, WorkUnitKind)>,
    pub(crate) suspended_ids: Vec<u64>,
    pub(crate) due_schedules: Vec<u64>,
}

impl RemoteCancellationLedger {
    fn insert_pending(
        &mut self,
        request_id: u64,
        target_id: u64,
    ) -> std::result::Result<(), WorkerProtocolError> {
        if request_id == 0 || target_id == 0 || request_id <= self.last_request_id {
            return Err(WorkerProtocolError::Malformed(
                "supervisor reused a cancellation request id",
            ));
        }
        self.last_request_id = request_id;
        self.records.insert(
            request_id,
            RemoteCancellationRecord {
                target_id,
                state: RemoteCancellationState::Pending,
            },
        );
        Ok(())
    }

    fn resolve(
        &mut self,
        request_id: u64,
        target_id: u64,
        resolution: CancellationResolution,
    ) -> std::result::Result<(), WorkerProtocolError> {
        let Some(record) = self.records.get(&request_id).copied() else {
            return Err(WorkerProtocolError::Malformed(
                "worker resolved an unknown cancellation request",
            ));
        };
        if record.target_id != target_id
            || !matches!(record.state, RemoteCancellationState::Pending)
        {
            return Err(WorkerProtocolError::Malformed(
                "worker returned a mismatched or duplicate cancellation resolution",
            ));
        }
        self.records.remove(&request_id);
        #[cfg(test)]
        self.resolved_records.insert(
            request_id,
            RemoteCancellationRecord {
                target_id,
                state: RemoteCancellationState::Resolved(resolution),
            },
        );
        #[cfg(not(test))]
        let _ = resolution;
        Ok(())
    }

    fn fail_pending(&mut self) {
        #[cfg(test)]
        for (request_id, record) in std::mem::take(&mut self.records) {
            self.resolved_records.insert(
                request_id,
                RemoteCancellationRecord {
                    target_id: record.target_id,
                    state: RemoteCancellationState::Resolved(CancellationResolution::Failed),
                },
            );
        }
        #[cfg(not(test))]
        self.records.clear();
    }

    fn apply_work_unit(
        &mut self,
        target_id: u64,
        scheduling_id: u64,
        kind: WorkUnitKind,
        phase: WorkUnitPhase,
    ) -> std::result::Result<Option<u64>, WorkerProtocolError> {
        if matches!(phase, WorkUnitPhase::Due | WorkUnitPhase::Undue) {
            if kind != WorkUnitKind::Timer || target_id != 0 || scheduling_id == 0 {
                return Err(WorkerProtocolError::Malformed(
                    "worker timer transition has invalid identities",
                ));
            }
        } else if target_id == 0 {
            return Err(WorkerProtocolError::Malformed(
                "worker work-unit transition omitted its target",
            ));
        }
        match phase {
            WorkUnitPhase::Due => {
                if !self.live_work.due_schedules.insert(scheduling_id) {
                    return Err(WorkerProtocolError::Malformed(
                        "worker published the same due scheduling identity twice",
                    ));
                }
            }
            WorkUnitPhase::Undue => {
                if !self.live_work.due_schedules.remove(&scheduling_id) {
                    return Err(WorkerProtocolError::Malformed(
                        "worker published undue for an unknown scheduling identity",
                    ));
                }
            }
            WorkUnitPhase::Begin => {
                if self
                    .live_work
                    .executing
                    .iter()
                    .any(|(observed, _)| *observed == target_id)
                {
                    return Err(WorkerProtocolError::Malformed(
                        "worker began an already-executing target",
                    ));
                }
                if self
                    .live_work
                    .suspended
                    .get(&target_id)
                    .is_some_and(|suspended_kind| *suspended_kind != kind)
                {
                    return Err(WorkerProtocolError::Malformed(
                        "worker resumed a suspended target with a different kind",
                    ));
                }
                if kind == WorkUnitKind::Timer && scheduling_id != 0 {
                    self.live_work.due_schedules.remove(&scheduling_id);
                }
                self.live_work.suspended.remove(&target_id);
                self.live_work.executing.push((target_id, kind));
            }
            WorkUnitPhase::Suspended => {
                if self.live_work.suspended.contains_key(&target_id) {
                    return Err(WorkerProtocolError::Malformed(
                        "worker suspended the same target twice",
                    ));
                }
                if self.live_work.executing.last().copied() != Some((target_id, kind)) {
                    return Err(WorkerProtocolError::Malformed(
                        "worker suspended a target out of execution order",
                    ));
                }
                self.live_work.executing.pop();
                self.live_work.suspended.insert(target_id, kind);
            }
            WorkUnitPhase::End => {
                if self.live_work.executing.last().copied() == Some((target_id, kind)) {
                    self.live_work.executing.pop();
                } else if self
                    .live_work
                    .executing
                    .iter()
                    .any(|(observed, _)| *observed == target_id)
                    || (self.live_work.suspended.contains_key(&target_id)
                        && !self.live_work.executing.is_empty())
                {
                    return Err(WorkerProtocolError::Malformed(
                        "worker ended a target out of execution order",
                    ));
                } else if self.live_work.suspended.get(&target_id).copied() == Some(kind) {
                    self.live_work.suspended.remove(&target_id);
                } else {
                    return Err(WorkerProtocolError::Malformed(
                        "worker ended an unknown or mismatched work target",
                    ));
                }
            }
        }
        Ok(self
            .live_work
            .executing
            .last()
            .map(|(target_id, _)| *target_id))
    }

    fn interrupt_work_snapshot(&self) -> RemoteInterruptWorkSnapshot {
        RemoteInterruptWorkSnapshot {
            executing: self.live_work.executing.last().copied(),
            suspended_ids: self.live_work.suspended.keys().copied().collect(),
            due_schedules: self.live_work.due_schedules.iter().copied().collect(),
        }
    }

    fn clear_live_work(&mut self) {
        self.live_work = RemoteLiveWorkState::default();
    }

    #[cfg(test)]
    fn state(&self, request_id: u64) -> Option<RemoteCancellationState> {
        self.records
            .get(&request_id)
            .or_else(|| self.resolved_records.get(&request_id))
            .map(|record| record.state)
    }
}

type SharedRemoteCancellationLedger = Arc<Mutex<RemoteCancellationLedger>>;

fn fail_remote_pending_cancellations(cancellations: &SharedRemoteCancellationLedger) {
    cancellations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .fail_pending();
}

fn close_remote_cancellation_state(
    active_target: &std::sync::atomic::AtomicU64,
    closed: &std::sync::atomic::AtomicBool,
    cancellations: &SharedRemoteCancellationLedger,
) {
    closed.store(true, std::sync::atomic::Ordering::Release);
    active_target.store(0, std::sync::atomic::Ordering::Release);
    let mut cancellations = cancellations
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cancellations.fail_pending();
    cancellations.clear_live_work();
}

#[derive(Clone)]
pub(crate) struct RemoteCancellationPort {
    control: SupervisorRuntimeControl,
    active_target: Arc<std::sync::atomic::AtomicU64>,
    cancellations: SharedRemoteCancellationLedger,
    closed: Arc<std::sync::atomic::AtomicBool>,
    request_gate: Arc<Mutex<()>>,
    next_request: Arc<std::sync::atomic::AtomicU64>,
}

impl RemoteCancellationPort {
    pub(crate) fn is_available(&self) -> bool {
        !self.closed.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn active_target(&self) -> Option<u64> {
        if !self.is_available() {
            return None;
        }
        match self
            .active_target
            .load(std::sync::atomic::Ordering::Acquire)
        {
            0 => None,
            target => Some(target),
        }
    }

    pub(crate) fn interrupt_work_snapshot(&self) -> RemoteInterruptWorkSnapshot {
        if !self.is_available() {
            return RemoteInterruptWorkSnapshot::default();
        }
        self.cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .interrupt_work_snapshot()
    }

    pub(crate) fn request_exact(
        &self,
        target_id: u64,
    ) -> crate::engine::AuthenticatedCancellationStatus {
        // Cloned ports may race. Serialize allocation through the local send
        // acknowledgement so monotonic ids are also monotonic on the ordered
        // authenticated lane; the worker can then reject replay with a fixed-
        // size high-watermark instead of an unbounded history set.
        let _request_guard = self
            .request_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.is_available() {
            return crate::engine::AuthenticatedCancellationStatus::Failed;
        }
        if self.active_target() != Some(target_id) {
            return crate::engine::AuthenticatedCancellationStatus::StaleTarget;
        }
        let request_id = self
            .next_request
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        if request_id == 0 {
            return crate::engine::AuthenticatedCancellationStatus::Failed;
        }
        {
            let mut pending = self
                .cancellations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if pending.insert_pending(request_id, target_id).is_err() {
                return crate::engine::AuthenticatedCancellationStatus::Failed;
            }
        }
        if !self.is_available() {
            fail_remote_pending_cancellations(&self.cancellations);
            return crate::engine::AuthenticatedCancellationStatus::Failed;
        }
        if self.control.cancel(request_id, target_id).is_err() {
            // A stopped controller means the worker/runtime can no longer
            // produce terminal records. Resolve every outstanding request,
            // not only the send which observed the teardown.
            close_remote_cancellation_state(&self.active_target, &self.closed, &self.cancellations);
            return crate::engine::AuthenticatedCancellationStatus::Failed;
        }
        if !self.is_available() {
            fail_remote_pending_cancellations(&self.cancellations);
            return crate::engine::AuthenticatedCancellationStatus::Failed;
        }
        // Request delivery is nonterminal. In particular, there is no timeout:
        // an uninterruptible target remains Pending until supervisor teardown.
        // @ref LLP 0024#6-evaluation-outcomes-and-the-abi
        crate::engine::AuthenticatedCancellationStatus::Accepted
    }

    pub(crate) fn terminate_worker(&self) -> Result<()> {
        close_remote_cancellation_state(&self.active_target, &self.closed, &self.cancellations);
        self.control.terminate_for_interrupt()
    }

    #[cfg(test)]
    fn state(&self, request_id: u64) -> Option<RemoteCancellationState> {
        self.cancellations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .state(request_id)
    }
}

pub(crate) struct RemoteReplSession {
    control: SupervisorRuntimeControl,
    events: SupervisorEventReceiver,
    plan: crate::terminal_session::SessionIoPlan,
    lifecycle: ibex_runtime::session_lifecycle::SessionLifecyclePort,
    active_target: Arc<std::sync::atomic::AtomicU64>,
    cancellations: SharedRemoteCancellationLedger,
    cancellation_closed: Arc<std::sync::atomic::AtomicBool>,
    next_submission: u64,
    next_checkpoint: u64,
    pending_display: Option<u64>,
    pending_outcome_barrier: Option<(u64, u64)>,
    pending_lifecycle_barrier: Option<(u64, u64)>,
    pending_mounts: Option<crate::runtime::ReplMountsDescription>,
    async_failures: BoundedRemoteAsyncBuffer,
    cancellation: RemoteCancellationPort,
    _controller: std::thread::JoinHandle<()>,
}

struct SequencedRemoteAsyncFailure {
    epoch: u64,
    sequence: u64,
    failure: AuthenticatedAsyncFailure,
    _lease: Option<SequencedLaneLease<crate::session_worker::SupervisorEventPayload>>,
}

#[derive(Default)]
struct BoundedRemoteAsyncBuffer {
    queue: std::collections::VecDeque<SequencedRemoteAsyncFailure>,
}

impl BoundedRemoteAsyncBuffer {
    fn push(
        &mut self,
        epoch: u64,
        sequence: u64,
        failure: AuthenticatedAsyncFailure,
        lease: Option<SequencedLaneLease<crate::session_worker::SupervisorEventPayload>>,
    ) {
        self.queue.push_back(SequencedRemoteAsyncFailure {
            epoch,
            sequence,
            failure,
            _lease: lease,
        });
    }

    fn drain(&mut self) -> Vec<AuthenticatedAsyncFailure> {
        let mut failures = Vec::with_capacity(self.queue.len());
        while let Some(record) = self.queue.pop_front() {
            debug_assert_ne!(record.epoch, 0);
            debug_assert_ne!(record.sequence, 0);
            failures.push(record.failure);
        }
        failures
    }

    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.queue
            .iter()
            .filter_map(|record| record._lease.as_ref())
            .map(SequencedLaneLease::charge)
            .sum()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.queue.len()
    }
}

enum RemoteReceivedEvent {
    Event(SequencedLaneDelivery<crate::session_worker::SupervisorEventPayload>),
    Lifecycle(i32),
}

impl From<crate::session_worker::Sequenced<crate::session_worker::SupervisorEventPayload>>
    for RemoteReceivedEvent
{
    fn from(
        event: crate::session_worker::Sequenced<crate::session_worker::SupervisorEventPayload>,
    ) -> Self {
        Self::Event(SequencedLaneDelivery::unleased(event))
    }
}

impl From<SequencedLaneDelivery<crate::session_worker::SupervisorEventPayload>>
    for RemoteReceivedEvent
{
    fn from(event: SequencedLaneDelivery<crate::session_worker::SupervisorEventPayload>) -> Self {
        Self::Event(event)
    }
}

impl RemoteReplSession {
    fn close_cancellation_state(&self) {
        close_remote_cancellation_state(
            &self.active_target,
            &self.cancellation_closed,
            &self.cancellations,
        );
    }

    fn receive_event(&mut self, stopped_context: &'static str) -> Result<RemoteReceivedEvent> {
        match self.events.recv_with_lease() {
            Ok(event) => Ok(RemoteReceivedEvent::Event(event)),
            Err(error) => {
                self.close_cancellation_state();
                if let Some(status) = self.accepted_lifecycle_status()? {
                    Ok(RemoteReceivedEvent::Lifecycle(status))
                } else {
                    Err(anyhow::anyhow!("{error:?}").context(stopped_context))
                }
            }
        }
    }

    pub(crate) const fn mode(&self) -> capsec_semantics::arming::ArmedExecutionMode {
        self.plan.route.mode
    }

    pub(crate) const fn presentation(&self) -> crate::terminal_session::CapturedPresentation {
        self.plan.presentation
    }

    pub(crate) fn session_lifecycle(
        &self,
    ) -> ibex_runtime::session_lifecycle::SessionLifecyclePort {
        self.lifecycle.clone()
    }

    pub(crate) fn cancellation_port(&self) -> RemoteCancellationPort {
        self.cancellation.clone()
    }

    pub(crate) fn terminal_control(&self) -> WorkerTerminalControl {
        WorkerTerminalControl {
            control: self.control.clone(),
        }
    }

    /// Retain only bounded supervisor teardown authority for an unwind guard.
    pub(crate) fn runtime_control(&self) -> SupervisorRuntimeControl {
        self.control.clone()
    }

    pub(crate) fn dispose_preserving_lifecycle(&self) -> Result<()> {
        self.close_cancellation_state();
        self.control.dispose_preserving_lifecycle()
    }

    pub(crate) fn quiesce_preserving_lifecycle(&self) -> Result<()> {
        self.close_cancellation_state();
        self.control.quiesce_preserving_lifecycle()
    }

    pub(crate) fn take_lifecycle_barrier(&mut self) -> Option<(u64, u64)> {
        self.pending_lifecycle_barrier.take()
    }

    pub(crate) fn take_outcome_barrier(&mut self) -> Option<(u64, u64)> {
        self.pending_outcome_barrier.take()
    }

    fn extend_outcome_barrier(&mut self, stdout_cutoff: u64, stderr_cutoff: u64) {
        self.pending_outcome_barrier = Some(match self.pending_outcome_barrier.take() {
            Some((pending_stdout, pending_stderr)) => (
                pending_stdout.max(stdout_cutoff),
                pending_stderr.max(stderr_cutoff),
            ),
            None => (stdout_cutoff, stderr_cutoff),
        });
    }

    fn extend_lifecycle_barrier(&mut self, stdout_cutoff: u64, stderr_cutoff: u64) {
        self.pending_lifecycle_barrier = Some(match self.pending_lifecycle_barrier.take() {
            Some((pending_stdout, pending_stderr)) => (
                pending_stdout.max(stdout_cutoff),
                pending_stderr.max(stderr_cutoff),
            ),
            None => (stdout_cutoff, stderr_cutoff),
        });
    }

    fn accepted_lifecycle_status(&mut self) -> Result<Option<i32>> {
        if let Some(record) = self.control.lifecycle()?.accepted_lifecycle().cloned() {
            self.extend_lifecycle_barrier(record.stdout_cutoff, record.stderr_cutoff);
            return Ok(Some(record.status));
        }
        Ok(self
            .lifecycle
            .latched_request()
            .map(|request| request.status))
    }

    pub(crate) async fn evaluate_inline(
        &mut self,
        source: Vec<u8>,
    ) -> std::result::Result<crate::repl::ReplEvaluation, crate::runtime::ReplEvaluationFailure>
    {
        self.evaluate(SubmissionKind::Inline, source).await
    }

    pub(crate) async fn evaluate_load(
        &mut self,
        path: &str,
    ) -> std::result::Result<crate::repl::ReplEvaluation, crate::runtime::ReplEvaluationFailure>
    {
        self.evaluate(SubmissionKind::Load, path.as_bytes().to_vec())
            .await
    }

    async fn evaluate(
        &mut self,
        kind: SubmissionKind,
        source: Vec<u8>,
    ) -> std::result::Result<crate::repl::ReplEvaluation, crate::runtime::ReplEvaluationFailure>
    {
        let submission_id = match self.begin_submission(kind, source) {
            Ok(id) => id,
            Err(error) => {
                return Err(crate::runtime::AuthenticatedEvaluationFailure::EngineFault(
                    error,
                ))
            }
        };
        self.wait_for_evaluation(submission_id)
    }

    fn begin_submission(&mut self, kind: SubmissionKind, source: Vec<u8>) -> Result<u64> {
        if self.pending_display.is_some() {
            anyhow::bail!("previous worker display is still awaiting acknowledgement");
        }
        let id = self.next_submission;
        self.next_submission = self
            .next_submission
            .checked_add(1)
            .context("session worker submission sequence exhausted")?;
        self.control.submit(id, kind, source)?;
        Ok(id)
    }

    fn wait_for_evaluation(
        &mut self,
        submission_id: u64,
    ) -> std::result::Result<crate::repl::ReplEvaluation, crate::runtime::ReplEvaluationFailure>
    {
        loop {
            let event = match self.receive_event("session worker event channel stopped") {
                Ok(event) => event,
                Err(error) => {
                    return Err(crate::runtime::AuthenticatedEvaluationFailure::EngineFault(
                        error,
                    ))
                }
            };
            match self.apply_event(event) {
                Ok(Some(RemoteEvent::Display {
                    submission_id: id,
                    tree,
                    stdout_cutoff,
                    stderr_cutoff,
                })) if id == submission_id => {
                    self.pending_display = Some(id);
                    return Ok(crate::repl::ReplEvaluation::Value {
                        display: crate::repl::ReplDisplay::Worker(tree),
                        receipt: Some(crate::repl::ReplDisplayReceipt::Worker {
                            submission_id: id,
                            stdout_cutoff,
                            stderr_cutoff,
                        }),
                    });
                }
                Ok(Some(RemoteEvent::Outcome {
                    submission_id: id,
                    kind,
                    status,
                    detail,
                    ..
                })) if id == submission_id => return decode_repl_outcome(kind, status, detail),
                Ok(Some(RemoteEvent::Lifecycle(status))) => {
                    return Ok(crate::repl::ReplEvaluation::Lifecycle(status))
                }
                Ok(Some(_)) | Ok(None) => {}
                Err(error) => {
                    return Err(crate::runtime::AuthenticatedEvaluationFailure::EngineFault(
                        error,
                    ))
                }
            }
        }
    }

    pub(crate) async fn acknowledge_display(
        &mut self,
        submission_id: u64,
        _stdout_cutoff: u64,
        _stderr_cutoff: u64,
        disposition: crate::engine::DisplayDisposition,
    ) -> Result<()> {
        anyhow::ensure!(
            self.pending_display == Some(submission_id),
            "worker display acknowledgement does not match the pending value"
        );
        let disposition = match disposition {
            crate::engine::DisplayDisposition::Displayed => DisplayAckDisposition::Displayed,
            crate::engine::DisplayDisposition::Fallback => DisplayAckDisposition::Fallback,
            crate::engine::DisplayDisposition::WriteFailed => DisplayAckDisposition::WriteFailed,
        };
        self.control.display_ack(submission_id, disposition)?;
        loop {
            let event = self.receive_event("session worker stopped before display settlement")?;
            match self.apply_event(event)? {
                Some(RemoteEvent::Outcome {
                    submission_id: id,
                    kind: EvaluationOutcomeKind::Empty,
                    ..
                }) if id == submission_id => {
                    self.pending_display = None;
                    return Ok(());
                }
                Some(RemoteEvent::Outcome {
                    submission_id: id,
                    kind,
                    status,
                    detail,
                    ..
                }) if id == submission_id => {
                    self.pending_display = None;
                    return match decode_repl_outcome(kind, status, detail) {
                        Ok(_) => Ok(()),
                        Err(error) => Err(anyhow::anyhow!("{error:#}")),
                    };
                }
                Some(RemoteEvent::Lifecycle(status)) => {
                    self.pending_display = None;
                    anyhow::bail!("worker requested lifecycle exit {status} during display")
                }
                _ => {}
            }
        }
    }

    pub(crate) fn request_operator_exit(
        &mut self,
    ) -> ibex_runtime::session_lifecycle::LifecycleRequestDisposition {
        use ibex_runtime::session_lifecycle::{LifecyclePrincipal, LifecycleRequestDisposition};

        let result = self
            .begin_submission(SubmissionKind::OperatorExit, Vec::new())
            .map(|id| self.wait_for_evaluation(id));
        match result {
            Ok(Ok(crate::repl::ReplEvaluation::Lifecycle(status))) => self
                .lifecycle
                .request_exit(LifecyclePrincipal::Root, status),
            _ => LifecycleRequestDisposition::Denied,
        }
    }

    pub(crate) async fn mounts_description(
        &mut self,
    ) -> Result<crate::runtime::ReplMountsDescription> {
        let id = self.begin_submission(SubmissionKind::Mounts, Vec::new())?;
        loop {
            let event = self.receive_event("session worker stopped during mounts query")?;
            match self.apply_event(event)? {
                Some(RemoteEvent::Outcome {
                    submission_id,
                    kind: EvaluationOutcomeKind::Empty,
                    ..
                }) if submission_id == id => {
                    return self
                        .pending_mounts
                        .take()
                        .context("worker mounts query returned no projection")
                }
                Some(RemoteEvent::Outcome {
                    submission_id,
                    kind,
                    status,
                    detail,
                    ..
                }) if submission_id == id => {
                    return match decode_repl_outcome(kind, status, detail) {
                        Err(error) => Err(anyhow::anyhow!("{error:#}")),
                        Ok(_) => anyhow::bail!("worker mounts query returned the wrong outcome"),
                    }
                }
                _ => {}
            }
        }
    }

    pub(crate) async fn drive_ready_tasks(&mut self) -> Result<Vec<AuthenticatedAsyncFailure>> {
        let checkpoint_id = self.next_checkpoint;
        self.next_checkpoint = self
            .next_checkpoint
            .checked_add(1)
            .context("ready-work checkpoint id exhausted")?;
        self.control.ready_checkpoint(checkpoint_id)?;
        loop {
            let event = self.receive_event("session worker stopped during ready-work drain")?;
            match self.apply_event(event)? {
                Some(RemoteEvent::Lifecycle(status)) => {
                    anyhow::bail!("worker requested lifecycle exit {status}")
                }
                Some(RemoteEvent::ReadyCheckpoint {
                    checkpoint_id: observed,
                    stdout_cutoff,
                    stderr_cutoff,
                }) if observed == checkpoint_id => {
                    self.extend_outcome_barrier(stdout_cutoff, stderr_cutoff);
                    break;
                }
                Some(RemoteEvent::ReadyCheckpoint { .. }) => {
                    anyhow::bail!("worker returned a mismatched ready-work checkpoint")
                }
                _ => {}
            }
        }
        Ok(self.async_failures.drain())
    }

    pub(crate) async fn wait_for_pending_tasks(&mut self) {
        tokio::time::sleep(IDLE_PUMP).await;
    }

    fn apply_event(
        &mut self,
        event: impl Into<RemoteReceivedEvent>,
    ) -> Result<Option<RemoteEvent>> {
        let result = match event.into() {
            RemoteReceivedEvent::Event(event) => self.apply_event_inner(event),
            RemoteReceivedEvent::Lifecycle(status) => Ok(Some(RemoteEvent::Lifecycle(status))),
        };
        if result.is_err() {
            self.close_cancellation_state();
        }
        result
    }

    fn apply_event_inner(
        &mut self,
        event: SequencedLaneDelivery<crate::session_worker::SupervisorEventPayload>,
    ) -> Result<Option<RemoteEvent>> {
        use ibex_runtime::session_lifecycle::{LifecyclePrincipal, LifecycleSetDisposition};

        let (event, lease) = event.into_parts();
        let epoch = event.epoch;
        let sequence = event.sequence;
        let message = match event.payload {
            crate::session_worker::SupervisorEventPayload::Worker(message) => message,
            crate::session_worker::SupervisorEventPayload::WorkerDied(death) => {
                self.close_cancellation_state();
                if let Some(status) = self.accepted_lifecycle_status()? {
                    return Ok(Some(RemoteEvent::Lifecycle(status)));
                }
                anyhow::bail!(
                    "session worker died (status {:?}, signal {:?})",
                    death.status,
                    death.signal
                );
            }
            crate::session_worker::SupervisorEventPayload::PostReceiptLoss {
                count,
                highest_dropped_sequence,
            } => {
                anyhow::ensure!(
                    count > 0
                        && highest_dropped_sequence > 0
                        && highest_dropped_sequence < sequence,
                    "supervisor produced an invalid post-receipt loss window"
                );
                self.async_failures.push(
                    epoch,
                    sequence,
                    AuthenticatedAsyncFailure::PostReceiptLoss {
                        count,
                        highest_dropped_sequence,
                    },
                    lease,
                );
                return Ok(None);
            }
            crate::session_worker::SupervisorEventPayload::ControllerFault(reason) => {
                self.close_cancellation_state();
                if let Some(status) = self.accepted_lifecycle_status()? {
                    return Ok(Some(RemoteEvent::Lifecycle(status)));
                }
                anyhow::bail!("session worker controller fault: {reason:?}");
            }
        };
        match message {
            ControlMessage::WorkUnit {
                target_id,
                scheduling_id,
                kind,
                phase,
            } => {
                let active_target = self
                    .cancellations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .apply_work_unit(target_id, scheduling_id, kind, phase)?
                    .unwrap_or(0);
                self.active_target
                    .store(active_target, std::sync::atomic::Ordering::Release);
                Ok(None)
            }
            ControlMessage::CancellationResolved {
                request_id,
                target_id,
                resolution,
            } => {
                self.cancellations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .resolve(request_id, target_id, resolution)?;
                if resolution == CancellationResolution::Failed {
                    self.close_cancellation_state();
                    anyhow::bail!(
                        "authenticated cancellation {request_id} failed its runtime consistency check"
                    );
                }
                Ok(None)
            }
            ControlMessage::ExitCodeMirror { status, .. } => {
                let disposition = self
                    .lifecycle
                    .set_exit_code(LifecyclePrincipal::Root, status);
                anyhow::ensure!(
                    matches!(disposition, LifecycleSetDisposition::Accepted { .. }),
                    "supervisor could not apply an acknowledged exitCode mirror"
                );
                Ok(None)
            }
            ControlMessage::LifecycleCommit(record) => {
                let _ = self
                    .lifecycle
                    .request_exit(LifecyclePrincipal::Root, record.status);
                self.extend_lifecycle_barrier(record.stdout_cutoff, record.stderr_cutoff);
                Ok(Some(RemoteEvent::Lifecycle(record.status)))
            }
            ControlMessage::Display {
                submission_id,
                tree,
                stdout_cutoff,
                stderr_cutoff,
            } => Ok(Some(RemoteEvent::Display {
                submission_id,
                tree,
                stdout_cutoff,
                stderr_cutoff,
            })),
            ControlMessage::Outcome {
                submission_id,
                kind,
                status,
                stdout_cutoff,
                stderr_cutoff,
                detail,
            } => {
                self.extend_outcome_barrier(stdout_cutoff, stderr_cutoff);
                Ok(Some(RemoteEvent::Outcome {
                    submission_id,
                    kind,
                    status,
                    detail,
                }))
            }
            ControlMessage::Step {
                submission_id: _,
                kind: STEP_MOUNTS,
                payload,
            } => {
                self.pending_mounts = Some(decode_mounts_projection(&payload)?);
                Ok(None)
            }
            ControlMessage::AsyncFailure {
                stdout_cutoff,
                stderr_cutoff,
                detail,
            } => {
                // Preserve every report, but one componentwise-monotonic
                // barrier is sufficient to order all reports accumulated for
                // the next ready-work checkpoint.
                self.extend_outcome_barrier(stdout_cutoff, stderr_cutoff);
                let failure = decode_async_failure(&detail)?;
                if matches!(failure, AuthenticatedAsyncFailure::PreReceiptLoss { .. }) {
                    self.close_cancellation_state();
                    if let Some(status) = self.accepted_lifecycle_status()? {
                        return Ok(Some(RemoteEvent::Lifecycle(status)));
                    }
                    anyhow::bail!("{failure}");
                }
                self.async_failures.push(epoch, sequence, failure, lease);
                Ok(None)
            }
            ControlMessage::Quiescent | ControlMessage::Pong { .. } => Ok(None),
            ControlMessage::PreReceiptLoss { count } => {
                self.close_cancellation_state();
                if let Some(status) = self.accepted_lifecycle_status()? {
                    return Ok(Some(RemoteEvent::Lifecycle(status)));
                }
                anyhow::bail!(
                    "session worker lost {count} asynchronous failure event(s) before supervisor receipt"
                )
            }
            ControlMessage::WorkerFault {
                stdout_cutoff,
                stderr_cutoff,
                detail,
            } => {
                self.close_cancellation_state();
                self.extend_outcome_barrier(stdout_cutoff, stderr_cutoff);
                if let Some(status) = self.accepted_lifecycle_status()? {
                    return Ok(Some(RemoteEvent::Lifecycle(status)));
                }
                anyhow::bail!("session worker fault: {}", String::from_utf8_lossy(&detail))
            }
            ControlMessage::ReadyCheckpointAck {
                checkpoint_id,
                stdout_cutoff,
                stderr_cutoff,
            } => Ok(Some(RemoteEvent::ReadyCheckpoint {
                checkpoint_id,
                stdout_cutoff,
                stderr_cutoff,
            })),
            other => anyhow::bail!("unexpected worker event after authentication: {other:?}"),
        }
    }
}

impl Drop for RemoteReplSession {
    fn drop(&mut self) {
        // No later terminal event can be observed once the owning session is
        // gone. Any request which was still nonterminal therefore fails as
        // part of supervisor teardown instead of remaining Pending forever.
        // @ref LLP 0024#6-evaluation-outcomes-and-the-abi
        self.close_cancellation_state();
    }
}

enum RemoteEvent {
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
        detail: Vec<u8>,
    },
    Lifecycle(i32),
    ReadyCheckpoint {
        checkpoint_id: u64,
        stdout_cutoff: u64,
        stderr_cutoff: u64,
    },
}

fn decode_repl_outcome(
    kind: EvaluationOutcomeKind,
    status: i32,
    detail: Vec<u8>,
) -> std::result::Result<crate::repl::ReplEvaluation, crate::runtime::ReplEvaluationFailure> {
    match kind {
        EvaluationOutcomeKind::Empty => Ok(crate::repl::ReplEvaluation::Empty),
        EvaluationOutcomeKind::Throw => {
            let thrown = crate::engine::decode_authenticated_throw(&detail).map_err(|error| {
                crate::runtime::AuthenticatedEvaluationFailure::EngineFault(anyhow::anyhow!(
                    "worker throw envelope is invalid: {error}"
                ))
            })?;
            Ok(crate::repl::ReplEvaluation::Throw(thrown))
        }
        EvaluationOutcomeKind::Cancelled => Ok(crate::repl::ReplEvaluation::Cancelled),
        EvaluationOutcomeKind::Lifecycle => Ok(crate::repl::ReplEvaluation::Lifecycle(status)),
        EvaluationOutcomeKind::Refused => {
            Err(crate::runtime::AuthenticatedEvaluationFailure::Refusal(
                anyhow::anyhow!("{}", String::from_utf8_lossy(&detail)),
            ))
        }
        EvaluationOutcomeKind::EngineFault => {
            Err(crate::runtime::AuthenticatedEvaluationFailure::EngineFault(
                anyhow::anyhow!("{}", String::from_utf8_lossy(&detail)),
            ))
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MountsProjection {
    virtual_cwd: String,
    mounts: Vec<MountProjection>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MountProjection {
    virtual_path: String,
    logical_root: capsec_semantics::model::LogicalRoot,
    attributes: ibex_runtime::vfs::MountAttributes,
}

fn decode_mounts_projection(payload: &[u8]) -> Result<crate::runtime::ReplMountsDescription> {
    let text = std::str::from_utf8(payload).context("worker mounts projection is not UTF-8")?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .context("worker mounts projection is not strict JSON")?;
    let projection: MountsProjection =
        serde_json::from_value(value).context("worker mounts projection has the wrong shape")?;
    Ok(
        crate::runtime::ReplMountsDescription::from_worker_projection(
            Arc::from(projection.virtual_cwd),
            projection
                .mounts
                .into_iter()
                .map(|mount| {
                    crate::runtime::ReplMountDescription::from_worker_projection(
                        Arc::from(mount.virtual_path),
                        mount.logical_root,
                        mount.attributes,
                    )
                })
                .collect(),
        ),
    )
}

/// Prepare, spawn, prove, and start the exact secure session route. This is
/// the only product constructor for REPL and implicit program-stdin workers.
pub(crate) fn spawn_session_worker(
    cli: &crate::cli::Cli,
    plan: crate::terminal_session::SessionIoPlan,
) -> Result<SpawnedSessionWorker> {
    use std::os::unix::fs::OpenOptionsExt;

    let prepared = crate::runtime::prepare_session_worker_runtime(cli, plan)?;
    let root_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(prepared.project_root())
        .with_context(|| {
            format!(
                "failed to open authenticated session root {}",
                prepared.project_root().display()
            )
        })?;
    let root = crate::session_worker::AuthenticatedRootDescriptor::new(
        root_file,
        prepared.project_object(),
    )
    .map_err(anyhow::Error::new)?;
    let role = match plan.route.entry_kind {
        capsec_semantics::arming::ArmedEntryKind::Repl => WorkerApplicationRole::Repl,
        capsec_semantics::arming::ArmedEntryKind::Stdin => WorkerApplicationRole::Inline,
        _ => anyhow::bail!("in-process route was passed to the session-worker spawner"),
    };
    let configuration =
        WorkerBootstrapConfiguration::new(plan, role, prepared.application().to_vec())
            .map_err(anyhow::Error::new)?;
    let sequence_epoch = fresh_sequence_epoch()?;
    let spec = crate::session_worker::WorkerSpawnSpec::new(
        std::env::current_exe().context("failed to resolve the session worker executable")?,
        root,
        prepared.binding().clone(),
        configuration,
        sequence_epoch,
    )
    .map_err(anyhow::Error::new)?;
    let mut worker = crate::session_worker::SupervisorWorker::spawn(spec, Duration::from_secs(2))
        .context("failed to spawn the authenticated session worker")?;
    worker
        .await_ready(Duration::from_secs(30))
        .context("authenticated session worker did not become ready")?;
    let event_sequencer = worker.sequence_allocator();
    let relays = worker.take_relays().map_err(anyhow::Error::new)?;
    let mode = match plan.route.mode {
        capsec_semantics::arming::ArmedExecutionMode::Interactive => SessionInputMode::Interactive,
        capsec_semantics::arming::ArmedExecutionMode::Transcript => SessionInputMode::Transcript,
        capsec_semantics::arming::ArmedExecutionMode::Program => SessionInputMode::Program,
        capsec_semantics::arming::ArmedExecutionMode::OneShot => {
            anyhow::bail!("one-shot execution does not use a session worker")
        }
    };
    worker
        .send(&ControlMessage::Start { mode })
        .map_err(anyhow::Error::new)?;
    if let Some(dimensions) =
        crate::terminal_session::capture_standard_terminal_dimensions(plan.presentation)
            .context("failed to capture initial worker terminal dimensions")?
    {
        worker
            .send(&ControlMessage::Resize {
                columns: dimensions.columns,
                rows: dimensions.rows,
            })
            .map_err(anyhow::Error::new)?;
    }

    let (commands_tx, commands_rx) = mpsc::channel();
    let (events_tx, events_rx) = bounded_lane::sequenced_channel(
        supervisor_event_lane_limits(),
        event_sequencer,
        supervisor_post_receipt_loss,
        supervisor_controller_fault,
    );
    let lifecycle = worker.lifecycle_handle();
    let allow_lossy_async = role == WorkerApplicationRole::Repl;
    let controller = std::thread::Builder::new()
        .name("ibex-session-worker-supervisor".to_owned())
        .spawn(move || supervisor_controller(worker, commands_rx, events_tx, allow_lossy_async))
        .context("failed to start the session worker controller")?;
    Ok(SpawnedSessionWorker {
        control: SupervisorRuntimeControl {
            commands: commands_tx,
            lifecycle,
        },
        events: events_rx,
        relays,
        history_startup: prepared.history_startup(),
        _controller: controller,
    })
}

fn fresh_sequence_epoch() -> Result<u64> {
    loop {
        let mut bytes = [0_u8; 8];
        getrandom::getrandom(&mut bytes)
            .map_err(|error| anyhow::anyhow!("OS randomness unavailable: {error}"))?;
        let epoch = u64::from_le_bytes(bytes);
        if epoch != 0 {
            return Ok(epoch);
        }
    }
}

fn control_delivery_timeout(message: &'static str) -> WorkerProtocolError {
    WorkerProtocolError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
}

fn await_control_delivery(
    reply: mpsc::Receiver<std::result::Result<(), WorkerProtocolError>>,
    state: &std::sync::atomic::AtomicU8,
    timeout: Duration,
    timeout_context: &'static str,
) -> Result<()> {
    match reply.recv_timeout(timeout) {
        Ok(Ok(())) => {
            anyhow::ensure!(
                state.load(std::sync::atomic::Ordering::Acquire) == CONTROL_DELIVERY_ACKNOWLEDGED,
                "session worker returned an unclaimed control-delivery acknowledgement"
            );
            Ok(())
        }
        Ok(Err(error)) => Err(anyhow::Error::new(error)),
        Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {
            match state.compare_exchange(
                CONTROL_DELIVERY_PENDING,
                CONTROL_DELIVERY_TIMED_OUT,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => anyhow::bail!(timeout_context),
                // The controller publishes this only after a bounded,
                // successful action and before the shared deadline. The
                // atomic claim is authoritative even if it is descheduled
                // before the best-effort channel wake-up.
                Err(CONTROL_DELIVERY_ACKNOWLEDGED) => Ok(()),
                Err(_) => anyhow::bail!(timeout_context),
            }
        }
    }
}

fn supervisor_controller(
    mut worker: crate::session_worker::SupervisorWorker,
    commands: mpsc::Receiver<SupervisorCommand>,
    events: SupervisorEventSender,
    allow_lossy_async: bool,
) {
    let mut quiesced = false;
    loop {
        for _ in 0..SUPERVISOR_COMMAND_DRAIN_BUDGET {
            let command = match commands.try_recv() {
                Ok(command) => command,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if quiesced {
                        let _ = worker.reap_preserving_lifecycle();
                    } else {
                        let _ = worker.terminate_preserving_lifecycle();
                    }
                    return;
                }
            };
            match command {
                SupervisorCommand::Send {
                    message,
                    deadline,
                    state,
                    reply,
                } => {
                    if state.load(std::sync::atomic::Ordering::Acquire) != CONTROL_DELIVERY_PENDING
                        || std::time::Instant::now() >= deadline
                    {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(control_delivery_timeout(
                            "supervisor control record expired before the controller could write it",
                        )));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    if let Err(error) =
                        worker.send_with_write_timeout(&message, SUPERVISOR_CONTROL_WRITE)
                    {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(error));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    if std::time::Instant::now() >= deadline {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(control_delivery_timeout(
                            "supervisor control write completed after its acknowledgement deadline",
                        )));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    if state
                        .compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_ACKNOWLEDGED,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        )
                        .is_err()
                    {
                        let _ = reply.send(Err(control_delivery_timeout(
                            "supervisor control requester expired while the controller was writing",
                        )));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    let _ = reply.send(Ok(()));
                }
                SupervisorCommand::CancelDelivery {
                    request_id,
                    target_id,
                    deadline,
                    state,
                    reply,
                } => {
                    if state.load(std::sync::atomic::Ordering::Acquire) != CONTROL_DELIVERY_PENDING
                        || std::time::Instant::now() >= deadline
                    {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(control_delivery_timeout(
                            "cancellation delivery expired before the controller could write it",
                        )));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }

                    let result = worker.send_with_write_timeout(
                        &ControlMessage::Cancel {
                            request_id,
                            target_id,
                        },
                        SUPERVISOR_CONTROL_WRITE,
                    );
                    if let Err(error) = result {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(error));
                        // A timed-out/partial authenticated frame poisons the
                        // lane. Kill through the kernel-owned process-group
                        // handle; never wait for the worker to read again.
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }

                    if std::time::Instant::now() >= deadline {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(control_delivery_timeout(
                            "cancellation delivery completed after its acknowledgement deadline",
                        )));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }

                    if state
                        .compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_ACKNOWLEDGED,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        )
                        .is_err()
                    {
                        let _ = reply.send(Err(control_delivery_timeout(
                            "cancellation requester expired while the controller was writing",
                        )));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    let _ = reply.send(Ok(()));
                }
                SupervisorCommand::TerminateInterrupt { reply } => {
                    let result = worker.terminate_for_interrupt().map(|_| ());
                    let _ = reply.send(result);
                    return;
                }
                SupervisorCommand::SuspendTerminal {
                    deadline,
                    state,
                    reply,
                } => {
                    if state.load(std::sync::atomic::Ordering::Acquire) != CONTROL_DELIVERY_PENDING
                        || std::time::Instant::now() >= deadline
                    {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(control_delivery_timeout(
                            "worker suspension expired before controller dispatch",
                        )));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    if let Err(error) = worker.suspend_for_terminal() {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(error));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    if std::time::Instant::now() >= deadline
                        || state
                            .compare_exchange(
                                CONTROL_DELIVERY_PENDING,
                                CONTROL_DELIVERY_ACKNOWLEDGED,
                                std::sync::atomic::Ordering::AcqRel,
                                std::sync::atomic::Ordering::Acquire,
                            )
                            .is_err()
                    {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(control_delivery_timeout(
                            "worker suspension requester expired during dispatch",
                        )));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    let _ = reply.send(Ok(()));
                }
                SupervisorCommand::ContinueTerminal {
                    deadline,
                    state,
                    reply,
                } => {
                    if state.load(std::sync::atomic::Ordering::Acquire) != CONTROL_DELIVERY_PENDING
                        || std::time::Instant::now() >= deadline
                    {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(control_delivery_timeout(
                            "worker continuation expired before controller dispatch",
                        )));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    if let Err(error) = worker.continue_after_terminal() {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(error));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    if std::time::Instant::now() >= deadline
                        || state
                            .compare_exchange(
                                CONTROL_DELIVERY_PENDING,
                                CONTROL_DELIVERY_ACKNOWLEDGED,
                                std::sync::atomic::Ordering::AcqRel,
                                std::sync::atomic::Ordering::Acquire,
                            )
                            .is_err()
                    {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_TIMED_OUT,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Err(control_delivery_timeout(
                            "worker continuation requester expired during dispatch",
                        )));
                        let _ = worker.terminate_preserving_lifecycle();
                        return;
                    }
                    let _ = reply.send(Ok(()));
                }
                SupervisorCommand::Quiesce { reply } => {
                    let result = if quiesced {
                        Ok(())
                    } else {
                        worker.quiesce_preserving_lifecycle()
                    };
                    if result.is_ok() {
                        quiesced = true;
                    }
                    let _ = reply.send(result);
                }
                SupervisorCommand::Dispose { reply } => {
                    let result = if quiesced {
                        worker.reap_preserving_lifecycle().map(|_| ())
                    } else {
                        worker.terminate_preserving_lifecycle().map(|_| ())
                    };
                    let _ = reply.send(result);
                    return;
                }
            }
        }
        if quiesced {
            std::thread::sleep(CONTROL_POLL);
            continue;
        }
        match worker.receive_event_payload_timeout(CONTROL_POLL) {
            Ok(Some(event)) => {
                let died = matches!(
                    event,
                    crate::session_worker::SupervisorEventPayload::WorkerDied(_)
                );
                if let Err(kind) = publish_supervisor_event(&events, event, allow_lossy_async) {
                    let reason = match kind {
                        PushErrorKind::Closed => return,
                        PushErrorKind::RequiredCapacityExceeded
                        | PushErrorKind::PrioritySlotOccupied => {
                            ControllerFaultReason::RequiredLaneOverflow
                        }
                        PushErrorKind::LossAccountingExhausted => {
                            ControllerFaultReason::LossAccountingExhausted
                        }
                        PushErrorKind::LossCounterOverflow => {
                            ControllerFaultReason::LossCounterOverflow
                        }
                        PushErrorKind::SequenceExhausted => {
                            ControllerFaultReason::SequenceExhausted
                        }
                    };
                    let _ = events.latch_fault(reason);
                    let _ = worker.terminate_preserving_lifecycle();
                    return;
                }
                if died {
                    return;
                }
            }
            Ok(None) => {}
            Err(_) => {
                let _ = events.latch_fault(ControllerFaultReason::WorkerProtocol);
                let _ = worker.terminate_preserving_lifecycle();
                return;
            }
        }
    }
}

#[cfg(test)]
mod work_unit_tests {
    use super::*;

    fn worker_fault_detail(events: &EvaluationEventReceiver) -> Vec<u8> {
        let event = events
            .recv_timeout(Duration::from_secs(1))
            .expect("guarded evaluator owner must publish its terminal fault");
        let LaneDelivery::Event(event) = event else {
            panic!("guarded evaluator owner fault was not a required event")
        };
        let EvaluationEvent::Message(ControlMessage::WorkerFault { detail, .. }) = event else {
            panic!("guarded evaluator owner published a non-fault event")
        };
        detail
    }

    #[test]
    fn evaluator_owner_error_and_panic_publish_authenticated_worker_faults() {
        let (error_tx, error_rx) = bounded_lane::channel(evaluation_lane_limits());
        run_evaluator_owner_guarded(error_tx, || {
            anyhow::bail!("injected evaluator-owner failure")
        });
        assert_eq!(
            worker_fault_detail(&error_rx),
            b"authenticated evaluator owner failed: injected evaluator-owner failure"
        );

        let (panic_tx, panic_rx) = bounded_lane::channel(evaluation_lane_limits());
        run_evaluator_owner_guarded(panic_tx, || -> Result<()> {
            panic!("injected evaluator-owner panic")
        });
        assert_eq!(
            worker_fault_detail(&panic_rx),
            b"authenticated evaluator owner panicked"
        );
    }

    #[test]
    fn disconnected_evaluator_event_lane_is_a_worker_death() {
        let (events_tx, events_rx) = bounded_lane::channel(evaluation_lane_limits());
        assert!(next_evaluation_event(&events_rx).unwrap().is_none());
        drop(events_tx);
        assert!(matches!(
            next_evaluation_event(&events_rx),
            Err(WorkerProtocolError::WorkerDied)
        ));
    }

    fn ordinary_async_event(summary: &str) -> EvaluationEvent {
        EvaluationEvent::Message(ControlMessage::AsyncFailure {
            stdout_cutoff: 0,
            stderr_cutoff: 0,
            detail: unavailable_async_failure(summary),
        })
    }

    #[test]
    fn production_evaluator_lane_bounds_async_and_orders_pre_receipt_loss_before_outcome() {
        let first = ordinary_async_event("first");
        let lossy_bytes = evaluation_event_charge(&first).unwrap();
        let outcome = EvaluationEvent::Outcome {
            submission_id: 7,
            kind: EvaluationOutcomeKind::Empty,
            status: 0,
            detail: Vec::new(),
        };
        let required_bytes = evaluation_event_charge(&outcome).unwrap();
        let (sender, receiver) = bounded_lane::channel(LaneLimits {
            lossy_bytes,
            required_bytes,
            loss_records: 1,
        });

        publish_evaluation_event(&sender, first).unwrap();
        publish_evaluation_event(&sender, ordinary_async_event("second")).unwrap();
        publish_evaluation_event(&sender, ordinary_async_event("third")).unwrap();
        publish_evaluation_event(&sender, outcome).unwrap();

        assert!(matches!(
            next_evaluation_event(&receiver).unwrap(),
            Some(EvaluationEvent::Message(
                ControlMessage::AsyncFailure { .. }
            ))
        ));
        assert!(matches!(
            next_evaluation_event(&receiver).unwrap(),
            Some(EvaluationEvent::Message(ControlMessage::PreReceiptLoss {
                count: 2
            }))
        ));
        assert!(matches!(
            next_evaluation_event(&receiver).unwrap(),
            Some(EvaluationEvent::Outcome {
                submission_id: 7,
                ..
            })
        ));
        assert_eq!(receiver.snapshot().lossy_bytes, 0);
        assert_eq!(receiver.snapshot().required_bytes, 0);
    }

    #[test]
    fn program_async_settlement_is_required_at_evaluator_hop() {
        let first = EvaluationEvent::AsyncFailure {
            submission_id: Some(7),
            detail: unavailable_async_failure("first program settlement"),
        };
        let second = EvaluationEvent::AsyncFailure {
            submission_id: None,
            detail: unavailable_async_failure("second program settlement"),
        };
        let required_bytes = evaluation_event_charge(&first)
            .unwrap()
            .checked_add(evaluation_event_charge(&second).unwrap())
            .unwrap();
        let (sender, receiver) = bounded_lane::channel(LaneLimits {
            lossy_bytes: 0,
            required_bytes,
            loss_records: 1,
        });

        publish_evaluation_event(&sender, first).unwrap();
        publish_evaluation_event(&sender, second).unwrap();

        assert!(matches!(
            next_evaluation_event(&receiver).unwrap(),
            Some(EvaluationEvent::AsyncFailure {
                submission_id: Some(7),
                ..
            })
        ));
        assert!(matches!(
            next_evaluation_event(&receiver).unwrap(),
            Some(EvaluationEvent::AsyncFailure {
                submission_id: None,
                ..
            })
        ));
        assert!(next_evaluation_event(&receiver).unwrap().is_none());
        assert_eq!(receiver.snapshot().lossy_bytes, 0);
        assert_eq!(receiver.snapshot().required_bytes, 0);
        assert_eq!(receiver.snapshot().loss_records, 0);
    }

    #[test]
    fn production_evaluator_lane_admits_lifecycle_when_required_reserve_is_full() {
        let required = EvaluationEvent::Outcome {
            submission_id: 7,
            kind: EvaluationOutcomeKind::Empty,
            status: 0,
            detail: Vec::new(),
        };
        let required_bytes = evaluation_event_charge(&required).unwrap();
        let (sender, receiver) = bounded_lane::channel(LaneLimits {
            lossy_bytes: 0,
            required_bytes,
            loss_records: 1,
        });
        publish_evaluation_event(&sender, required).unwrap();
        assert_eq!(receiver.snapshot().required_bytes, required_bytes);

        let (reply, _ack) = mpsc::sync_channel(1);
        publish_evaluation_event(
            &sender,
            EvaluationEvent::LifecycleCommit {
                request_id: 11,
                status: 23,
                stdout_cutoff: 29,
                stderr_cutoff: 31,
                reply,
            },
        )
        .unwrap();

        assert!(matches!(
            next_evaluation_event(&receiver).unwrap(),
            Some(EvaluationEvent::LifecycleCommit {
                request_id: 11,
                status: 23,
                stdout_cutoff: 29,
                stderr_cutoff: 31,
                ..
            })
        ));
        assert_eq!(receiver.snapshot().required_bytes, required_bytes);
        assert!(matches!(
            next_evaluation_event(&receiver).unwrap(),
            Some(EvaluationEvent::Outcome {
                submission_id: 7,
                ..
            })
        ));
    }

    #[test]
    fn native_pre_receipt_loss_is_required_and_never_recounted_as_one() {
        let kept = ordinary_async_event("kept");
        let lossy_bytes = evaluation_event_charge(&kept).unwrap();
        let native_loss = EvaluationEvent::Message(ControlMessage::AsyncFailure {
            stdout_cutoff: 0,
            stderr_cutoff: 0,
            detail: encode_async_failure(&AuthenticatedAsyncFailure::PreReceiptLoss {
                count: 1025,
            }),
        });
        let required_bytes = evaluation_event_charge(&native_loss).unwrap();
        let (sender, receiver) = bounded_lane::channel(LaneLimits {
            lossy_bytes,
            required_bytes,
            loss_records: 1,
        });
        publish_evaluation_event(&sender, kept).unwrap();
        publish_evaluation_event(&sender, native_loss).unwrap();

        let _ = next_evaluation_event(&receiver).unwrap().unwrap();
        let EvaluationEvent::Message(ControlMessage::AsyncFailure { detail, .. }) =
            next_evaluation_event(&receiver).unwrap().unwrap()
        else {
            panic!("native loss marker was not retained as a required async envelope")
        };
        assert_eq!(
            decode_async_failure(&detail).unwrap(),
            AuthenticatedAsyncFailure::PreReceiptLoss { count: 1025 }
        );
    }

    fn supervisor_async_event(summary: &str) -> crate::session_worker::SupervisorEventPayload {
        crate::session_worker::SupervisorEventPayload::Worker(ControlMessage::AsyncFailure {
            stdout_cutoff: 0,
            stderr_cutoff: 0,
            detail: unavailable_async_failure(summary),
        })
    }

    #[test]
    fn production_supervisor_lane_sequences_post_receipt_loss_before_required_event() {
        let first = supervisor_async_event("first");
        let lossy_bytes = supervisor_event_charge(&first).unwrap();
        let required = crate::session_worker::SupervisorEventPayload::Worker(
            ControlMessage::ReadyCheckpointAck {
                checkpoint_id: 7,
                stdout_cutoff: 0,
                stderr_cutoff: 0,
            },
        );
        let required_bytes = supervisor_event_charge(&required).unwrap();
        let (sender, receiver) = bounded_lane::sequenced_channel(
            LaneLimits {
                lossy_bytes,
                required_bytes,
                loss_records: 1,
            },
            crate::session_worker::SupervisorSequenceAllocator::new(4).unwrap(),
            supervisor_post_receipt_loss,
            supervisor_controller_fault,
        );
        publish_supervisor_event(&sender, first, true).unwrap();
        publish_supervisor_event(&sender, supervisor_async_event("second"), true).unwrap();
        publish_supervisor_event(&sender, supervisor_async_event("third"), true).unwrap();
        publish_supervisor_event(&sender, required, true).unwrap();

        assert_eq!(receiver.recv().unwrap().sequence, 1);
        let marker = receiver.recv().unwrap();
        assert_eq!(marker.sequence, 4);
        assert!(matches!(
            marker.payload,
            crate::session_worker::SupervisorEventPayload::PostReceiptLoss {
                count: 2,
                highest_dropped_sequence: 3,
            }
        ));
        let checkpoint = receiver.recv().unwrap();
        assert_eq!(checkpoint.sequence, 5);
        assert!(matches!(
            checkpoint.payload,
            crate::session_worker::SupervisorEventPayload::Worker(
                ControlMessage::ReadyCheckpointAck {
                    checkpoint_id: 7,
                    ..
                }
            )
        ));
    }

    #[test]
    fn program_async_settlement_is_required_not_lossy() {
        let async_event = supervisor_async_event("program settlement");
        let charge = supervisor_event_charge(&async_event).unwrap();
        let (sender, receiver) = bounded_lane::sequenced_channel(
            LaneLimits {
                lossy_bytes: 0,
                required_bytes: charge,
                loss_records: 1,
            },
            crate::session_worker::SupervisorSequenceAllocator::new(1).unwrap(),
            supervisor_post_receipt_loss,
            supervisor_controller_fault,
        );
        publish_supervisor_event(&sender, async_event, false).unwrap();
        assert!(matches!(
            receiver.recv().unwrap().payload,
            crate::session_worker::SupervisorEventPayload::Worker(
                ControlMessage::AsyncFailure { .. }
            )
        ));
        assert_eq!(receiver.snapshot().loss_records, 0);
    }

    fn test_repl_plan() -> crate::terminal_session::SessionIoPlan {
        crate::terminal_session::SessionIoPlan {
            route: crate::terminal_session::SelectedExecutionRoute {
                entry_kind: capsec_semantics::arming::ArmedEntryKind::Repl,
                mode: capsec_semantics::arming::ArmedExecutionMode::Transcript,
            },
            terminal_facts: crate::terminal_session::NativeTerminalFacts {
                stdin_is_tty: false,
                stdout_is_tty: false,
                stderr_is_tty: false,
            },
            presentation: crate::terminal_session::CapturedPresentation {
                topology: crate::terminal_session::PresentationTopology::Transcript,
                session_ansi: false,
                editor_control: false,
            },
        }
    }

    fn remote_repl_harness(
        accepted_lifecycle: Option<crate::session_worker::LifecycleRecord>,
    ) -> (RemoteReplSession, SupervisorEventSender) {
        let (commands, _command_rx) = mpsc::channel();
        let supervisor_lifecycle = Arc::new(Mutex::new(
            crate::session_worker::SupervisorLifecycleState::default(),
        ));
        if let Some(record) = accepted_lifecycle {
            supervisor_lifecycle
                .lock()
                .unwrap()
                .accept_lifecycle(record)
                .unwrap();
        }
        let control = SupervisorRuntimeControl {
            commands,
            lifecycle: supervisor_lifecycle,
        };
        let active_target = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cancellations = Arc::new(Mutex::new(RemoteCancellationLedger::default()));
        let cancellation_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancellation_request_gate = Arc::new(Mutex::new(()));
        let next_request = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let cancellation = RemoteCancellationPort {
            control: control.clone(),
            active_target: active_target.clone(),
            cancellations: cancellations.clone(),
            closed: cancellation_closed.clone(),
            request_gate: cancellation_request_gate,
            next_request,
        };
        let (events_tx, events) = bounded_lane::sequenced_channel(
            supervisor_event_lane_limits(),
            crate::session_worker::SupervisorSequenceAllocator::new(1).unwrap(),
            supervisor_post_receipt_loss,
            supervisor_controller_fault,
        );
        (
            RemoteReplSession {
                control,
                events,
                plan: test_repl_plan(),
                lifecycle: ibex_runtime::session_lifecycle::SessionLifecyclePort::default(),
                active_target,
                cancellations,
                cancellation_closed,
                next_submission: 1,
                next_checkpoint: 1,
                pending_display: None,
                pending_outcome_barrier: None,
                pending_lifecycle_barrier: None,
                pending_mounts: None,
                async_failures: BoundedRemoteAsyncBuffer::default(),
                cancellation,
                _controller: std::thread::spawn(|| {}),
            },
            events_tx,
        )
    }

    fn worker_event(
        message: ControlMessage,
    ) -> crate::session_worker::Sequenced<crate::session_worker::SupervisorEventPayload> {
        crate::session_worker::Sequenced {
            epoch: 1,
            sequence: 1,
            payload: crate::session_worker::SupervisorEventPayload::Worker(message),
        }
    }

    fn send_worker_event(events: &SupervisorEventSender, message: ControlMessage) {
        publish_supervisor_event(
            events,
            crate::session_worker::SupervisorEventPayload::Worker(message),
            false,
        )
        .unwrap();
    }

    fn remote_program_harness(message: ControlMessage) -> RemoteProgramSession {
        let (commands, command_rx) = mpsc::channel();
        let lifecycle = Arc::new(Mutex::new(
            crate::session_worker::SupervisorLifecycleState::default(),
        ));
        let control = SupervisorRuntimeControl {
            commands,
            lifecycle,
        };
        let (events_tx, events) = bounded_lane::sequenced_channel(
            supervisor_event_lane_limits(),
            crate::session_worker::SupervisorSequenceAllocator::new(1).unwrap(),
            supervisor_post_receipt_loss,
            supervisor_controller_fault,
        );
        publish_supervisor_event(
            &events_tx,
            crate::session_worker::SupervisorEventPayload::Worker(message),
            false,
        )
        .unwrap();
        let controller = std::thread::spawn(move || {
            if let Ok(SupervisorCommand::Send { state, reply, .. }) = command_rx.recv() {
                let _ = state.compare_exchange(
                    CONTROL_DELIVERY_PENDING,
                    CONTROL_DELIVERY_ACKNOWLEDGED,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                );
                let _ = reply.send(Ok(()));
            }
        });
        let active_target = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cancellations = Arc::new(Mutex::new(RemoteCancellationLedger::default()));
        let cancellation_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancellation = RemoteCancellationPort {
            control: control.clone(),
            active_target: active_target.clone(),
            cancellations: cancellations.clone(),
            closed: cancellation_closed.clone(),
            request_gate: Arc::new(Mutex::new(())),
            next_request: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        };
        RemoteProgramSession {
            control,
            events,
            lifecycle: ibex_runtime::session_lifecycle::SessionLifecyclePort::default(),
            active_target,
            cancellations,
            cancellation_closed,
            cancellation,
            _controller: controller,
        }
    }

    #[test]
    fn timer_due_is_scheduling_identity_not_cancellation_target() {
        let message = work_unit_control_message(AuthenticatedWorkUnitEvent {
            target_id: 0,
            scheduling_id: 41,
            kind: AuthenticatedWorkUnitKind::Timer,
            phase: AuthenticatedWorkUnitPhase::Due,
        })
        .unwrap();
        assert_eq!(
            message,
            ControlMessage::WorkUnit {
                target_id: 0,
                scheduling_id: 41,
                kind: WorkUnitKind::Timer,
                phase: WorkUnitPhase::Due,
            }
        );
    }

    #[test]
    fn work_unit_mapping_rejects_ambiguous_identities() {
        assert!(work_unit_control_message(AuthenticatedWorkUnitEvent {
            target_id: 9,
            scheduling_id: 41,
            kind: AuthenticatedWorkUnitKind::Timer,
            phase: AuthenticatedWorkUnitPhase::Undue,
        })
        .is_err());
        assert!(work_unit_control_message(AuthenticatedWorkUnitEvent {
            target_id: 0,
            scheduling_id: 0,
            kind: AuthenticatedWorkUnitKind::Callback,
            phase: AuthenticatedWorkUnitPhase::Begin,
        })
        .is_err());
    }

    #[test]
    fn remote_repl_retains_suspended_and_due_work_for_terminal_selection() {
        let (mut session, _events) = remote_repl_harness(None);
        let cancellation = session.cancellation_port();

        session
            .apply_event(worker_event(ControlMessage::WorkUnit {
                target_id: 41,
                scheduling_id: 0,
                kind: WorkUnitKind::Evaluation,
                phase: WorkUnitPhase::Begin,
            }))
            .unwrap();
        session
            .apply_event(worker_event(ControlMessage::WorkUnit {
                target_id: 42,
                scheduling_id: 0,
                kind: WorkUnitKind::Callback,
                phase: WorkUnitPhase::Begin,
            }))
            .unwrap();
        assert_eq!(
            cancellation.interrupt_work_snapshot().executing,
            Some((42, WorkUnitKind::Callback))
        );
        session
            .apply_event(worker_event(ControlMessage::WorkUnit {
                target_id: 42,
                scheduling_id: 0,
                kind: WorkUnitKind::Callback,
                phase: WorkUnitPhase::End,
            }))
            .unwrap();
        assert_eq!(
            cancellation.interrupt_work_snapshot().executing,
            Some((41, WorkUnitKind::Evaluation)),
            "ending nested work must restore the outer exact target"
        );
        session
            .apply_event(worker_event(ControlMessage::WorkUnit {
                target_id: 41,
                scheduling_id: 0,
                kind: WorkUnitKind::Evaluation,
                phase: WorkUnitPhase::Suspended,
            }))
            .unwrap();
        assert_eq!(
            cancellation.interrupt_work_snapshot(),
            RemoteInterruptWorkSnapshot {
                executing: None,
                suspended_ids: vec![41],
                due_schedules: Vec::new(),
            }
        );

        session
            .apply_event(worker_event(ControlMessage::WorkUnit {
                target_id: 0,
                scheduling_id: 73,
                kind: WorkUnitKind::Timer,
                phase: WorkUnitPhase::Due,
            }))
            .unwrap();
        assert_eq!(
            cancellation.interrupt_work_snapshot(),
            RemoteInterruptWorkSnapshot {
                executing: None,
                suspended_ids: vec![41],
                due_schedules: vec![73],
            }
        );

        session
            .apply_event(worker_event(ControlMessage::WorkUnit {
                target_id: 43,
                scheduling_id: 73,
                kind: WorkUnitKind::Timer,
                phase: WorkUnitPhase::Begin,
            }))
            .unwrap();
        assert_eq!(
            cancellation.interrupt_work_snapshot(),
            RemoteInterruptWorkSnapshot {
                executing: Some((43, WorkUnitKind::Timer)),
                suspended_ids: vec![41],
                due_schedules: Vec::new(),
            }
        );

        session
            .apply_event(worker_event(ControlMessage::WorkUnit {
                target_id: 43,
                scheduling_id: 73,
                kind: WorkUnitKind::Timer,
                phase: WorkUnitPhase::End,
            }))
            .unwrap();
        session
            .apply_event(worker_event(ControlMessage::WorkUnit {
                target_id: 41,
                scheduling_id: 0,
                kind: WorkUnitKind::Evaluation,
                phase: WorkUnitPhase::Begin,
            }))
            .unwrap();
        assert_eq!(
            cancellation.interrupt_work_snapshot(),
            RemoteInterruptWorkSnapshot {
                executing: Some((41, WorkUnitKind::Evaluation)),
                suspended_ids: Vec::new(),
                due_schedules: Vec::new(),
            },
            "resuming a suspended graph must restore its exact cancellation target"
        );
        session
            .apply_event(worker_event(ControlMessage::WorkUnit {
                target_id: 41,
                scheduling_id: 0,
                kind: WorkUnitKind::Evaluation,
                phase: WorkUnitPhase::End,
            }))
            .unwrap();
        assert_eq!(
            cancellation.interrupt_work_snapshot(),
            RemoteInterruptWorkSnapshot::default()
        );
    }

    #[test]
    fn remote_work_ledger_keeps_due_timer_when_another_kind_reuses_its_identity() {
        let mut ledger = RemoteCancellationLedger::default();
        ledger
            .apply_work_unit(0, 73, WorkUnitKind::Timer, WorkUnitPhase::Due)
            .unwrap();
        ledger
            .apply_work_unit(73, 73, WorkUnitKind::Evaluation, WorkUnitPhase::Begin)
            .unwrap();

        assert_eq!(
            ledger.interrupt_work_snapshot(),
            RemoteInterruptWorkSnapshot {
                executing: Some((73, WorkUnitKind::Evaluation)),
                suspended_ids: Vec::new(),
                due_schedules: vec![73],
            },
            "only a timer Begin may consume a due scheduling identity"
        );
    }

    #[test]
    fn remote_work_ledger_rejects_hostile_identities_and_non_lifo_transitions() {
        let mut ledger = RemoteCancellationLedger::default();
        for (target_id, scheduling_id, kind, phase) in [
            (1, 73, WorkUnitKind::Timer, WorkUnitPhase::Due),
            (0, 73, WorkUnitKind::Callback, WorkUnitPhase::Due),
            (0, 0, WorkUnitKind::Timer, WorkUnitPhase::Undue),
            (0, 0, WorkUnitKind::Evaluation, WorkUnitPhase::Begin),
            (0, 0, WorkUnitKind::Evaluation, WorkUnitPhase::Suspended),
            (0, 0, WorkUnitKind::Evaluation, WorkUnitPhase::End),
        ] {
            assert!(ledger
                .apply_work_unit(target_id, scheduling_id, kind, phase)
                .is_err());
        }
        assert_eq!(
            ledger.interrupt_work_snapshot(),
            RemoteInterruptWorkSnapshot::default(),
            "rejected identities must not mutate the live-work projection"
        );

        ledger
            .apply_work_unit(41, 0, WorkUnitKind::Evaluation, WorkUnitPhase::Begin)
            .unwrap();
        ledger
            .apply_work_unit(42, 0, WorkUnitKind::Callback, WorkUnitPhase::Begin)
            .unwrap();
        for (kind, phase) in [
            (WorkUnitKind::Evaluation, WorkUnitPhase::Suspended),
            (WorkUnitKind::Evaluation, WorkUnitPhase::End),
        ] {
            assert!(ledger.apply_work_unit(41, 0, kind, phase).is_err());
        }
        for (kind, phase) in [
            (WorkUnitKind::Evaluation, WorkUnitPhase::Suspended),
            (WorkUnitKind::Evaluation, WorkUnitPhase::End),
        ] {
            assert!(ledger.apply_work_unit(42, 0, kind, phase).is_err());
        }
        assert_eq!(
            ledger.interrupt_work_snapshot().executing,
            Some((42, WorkUnitKind::Callback)),
            "out-of-order or kind-mismatched transitions must leave the stack intact"
        );

        ledger
            .apply_work_unit(42, 0, WorkUnitKind::Callback, WorkUnitPhase::End)
            .unwrap();
        ledger
            .apply_work_unit(41, 0, WorkUnitKind::Evaluation, WorkUnitPhase::Suspended)
            .unwrap();
        ledger
            .apply_work_unit(43, 0, WorkUnitKind::Callback, WorkUnitPhase::Begin)
            .unwrap();
        assert!(ledger
            .apply_work_unit(41, 0, WorkUnitKind::Evaluation, WorkUnitPhase::End)
            .is_err());
        assert_eq!(
            ledger.interrupt_work_snapshot(),
            RemoteInterruptWorkSnapshot {
                executing: Some((43, WorkUnitKind::Callback)),
                suspended_ids: vec![41],
                due_schedules: Vec::new(),
            }
        );
    }

    #[test]
    fn remote_program_interrupt_requests_the_published_exact_target_before_termination() {
        #[derive(Debug, Eq, PartialEq)]
        enum ObservedControl {
            Cancel { request_id: u64, target_id: u64 },
            Terminate,
        }

        let (commands, command_rx) = mpsc::channel();
        let (observed_tx, observed_rx) = mpsc::channel();
        let control = SupervisorRuntimeControl {
            commands,
            lifecycle: Arc::new(Mutex::new(
                crate::session_worker::SupervisorLifecycleState::default(),
            )),
        };
        let controller = std::thread::spawn(move || {
            while let Ok(command) = command_rx.recv() {
                match command {
                    SupervisorCommand::Send { state, reply, .. } => {
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_ACKNOWLEDGED,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Ok(()));
                    }
                    SupervisorCommand::CancelDelivery {
                        request_id,
                        target_id,
                        state,
                        reply,
                        ..
                    } => {
                        observed_tx
                            .send(ObservedControl::Cancel {
                                request_id,
                                target_id,
                            })
                            .unwrap();
                        let _ = state.compare_exchange(
                            CONTROL_DELIVERY_PENDING,
                            CONTROL_DELIVERY_ACKNOWLEDGED,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        );
                        let _ = reply.send(Ok(()));
                    }
                    SupervisorCommand::TerminateInterrupt { reply } => {
                        observed_tx.send(ObservedControl::Terminate).unwrap();
                        let _ = reply.send(Ok(()));
                        break;
                    }
                    _ => panic!("unexpected program interrupt control command"),
                }
            }
        });
        let active_target = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cancellations = Arc::new(Mutex::new(RemoteCancellationLedger::default()));
        let cancellation_closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancellation = RemoteCancellationPort {
            control: control.clone(),
            active_target: active_target.clone(),
            cancellations: cancellations.clone(),
            closed: cancellation_closed.clone(),
            request_gate: Arc::new(Mutex::new(())),
            next_request: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        };
        let (events_tx, events) = bounded_lane::sequenced_channel(
            supervisor_event_lane_limits(),
            crate::session_worker::SupervisorSequenceAllocator::new(1).unwrap(),
            supervisor_post_receipt_loss,
            supervisor_controller_fault,
        );
        let program = RemoteProgramSession {
            control,
            events,
            lifecycle: ibex_runtime::session_lifecycle::SessionLifecyclePort::default(),
            active_target,
            cancellations,
            cancellation_closed,
            cancellation: cancellation.clone(),
            _controller: controller,
        };
        let execution = std::thread::spawn(move || {
            let mut program = program;
            program.execute(b"while (true) {}".to_vec())
        });

        send_worker_event(
            &events_tx,
            ControlMessage::WorkUnit {
                target_id: 41,
                scheduling_id: 0,
                kind: WorkUnitKind::Evaluation,
                phase: WorkUnitPhase::Begin,
            },
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while cancellation.interrupt_work_snapshot().executing
            != Some((41, WorkUnitKind::Evaluation))
        {
            assert!(
                std::time::Instant::now() < deadline,
                "program did not publish its exact executing target"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        assert_eq!(
            cancellation.request_exact(41),
            AuthenticatedCancellationStatus::Accepted
        );
        assert_eq!(
            observed_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            ObservedControl::Cancel {
                request_id: 1,
                target_id: 41,
            }
        );
        cancellation.terminate_worker().unwrap();
        assert_eq!(
            observed_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            ObservedControl::Terminate
        );

        send_worker_event(
            &events_tx,
            ControlMessage::Outcome {
                submission_id: 1,
                kind: EvaluationOutcomeKind::Cancelled,
                status: ibex_runtime::session_constants::EXIT_STATUS_INTERRUPT,
                stdout_cutoff: 0,
                stderr_cutoff: 0,
                detail: Vec::new(),
            },
        );
        assert!(matches!(
            execution.join().unwrap().unwrap(),
            RemoteProgramOutcome::Cancelled { .. }
        ));
    }

    #[test]
    fn worker_cancellation_is_pending_until_native_terminal_publication() {
        let mut pending = PendingWorkerCancellations::default();
        assert_eq!(
            pending
                .dispatched(7, 41, AuthenticatedCancellationStatus::Accepted)
                .unwrap(),
            None,
            "native request delivery must not emit terminal Accepted"
        );
        assert!(pending.is_pending(7));

        let messages = pending
            .resolve_native(AuthenticatedCancellationEvent {
                target_id: 41,
                resolution: AuthenticatedCancellationResolution::Defeated,
            })
            .unwrap();
        assert_eq!(
            messages,
            vec![ControlMessage::CancellationResolved {
                request_id: 7,
                target_id: 41,
                resolution: CancellationResolution::Defeated,
            }]
        );
        assert!(!pending.is_pending(7));
        assert!(pending
            .resolve_native(AuthenticatedCancellationEvent {
                target_id: 41,
                resolution: AuthenticatedCancellationResolution::Accepted,
            })
            .is_err());
    }

    #[test]
    fn stale_failed_and_permanently_pending_cancellations_remain_distinct() {
        let mut pending = PendingWorkerCancellations::default();
        assert_eq!(
            pending
                .dispatched(1, 10, AuthenticatedCancellationStatus::StaleTarget)
                .unwrap(),
            Some(ControlMessage::CancellationResolved {
                request_id: 1,
                target_id: 10,
                resolution: CancellationResolution::Unavailable,
            })
        );
        assert_eq!(
            pending
                .dispatched(2, 10, AuthenticatedCancellationStatus::Failed)
                .unwrap(),
            Some(ControlMessage::CancellationResolved {
                request_id: 2,
                target_id: 10,
                resolution: CancellationResolution::Failed,
            })
        );
        assert!(pending
            .dispatched(3, 10, AuthenticatedCancellationStatus::Accepted)
            .unwrap()
            .is_none());
        assert!(pending.is_pending(3));
        assert_eq!(
            pending.fail_all(),
            vec![ControlMessage::CancellationResolved {
                request_id: 3,
                target_id: 10,
                resolution: CancellationResolution::Failed,
            }]
        );
    }

    #[test]
    fn remote_cancellation_delivery_is_bounded_and_stays_pending_without_reply() {
        let (commands, command_rx) = mpsc::channel();
        let control = SupervisorRuntimeControl {
            commands,
            lifecycle: Arc::new(Mutex::new(
                crate::session_worker::SupervisorLifecycleState::default(),
            )),
        };
        let active_target = Arc::new(std::sync::atomic::AtomicU64::new(73));
        let cancellations = Arc::new(Mutex::new(RemoteCancellationLedger::default()));
        let port = RemoteCancellationPort {
            control,
            active_target,
            cancellations,
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            request_gate: Arc::new(Mutex::new(())),
            next_request: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        };
        let controller = std::thread::spawn(move || {
            let SupervisorCommand::CancelDelivery {
                request_id,
                target_id,
                state,
                reply,
                ..
            } = command_rx.recv().unwrap()
            else {
                panic!("expected cancellation delivery")
            };
            assert_eq!(request_id, 1);
            assert_eq!(target_id, 73);
            state
                .compare_exchange(
                    CONTROL_DELIVERY_PENDING,
                    CONTROL_DELIVERY_ACKNOWLEDGED,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .unwrap();
            reply.send(Ok(())).unwrap();
        });

        let started = std::time::Instant::now();
        assert_eq!(
            port.request_exact(73),
            AuthenticatedCancellationStatus::Accepted
        );
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "controller waited for a terminal cancellation resolution"
        );
        assert_eq!(port.state(1), Some(RemoteCancellationState::Pending));
        controller.join().unwrap();

        assert_eq!(
            port.request_exact(73),
            AuthenticatedCancellationStatus::Failed
        );
        assert_eq!(
            port.state(1),
            Some(RemoteCancellationState::Resolved(
                CancellationResolution::Failed
            )),
            "controller teardown must fail earlier pending requests too"
        );
        assert_eq!(
            port.state(2),
            Some(RemoteCancellationState::Resolved(
                CancellationResolution::Failed
            ))
        );
    }

    #[test]
    fn queued_cancellation_expires_before_a_late_controller_can_deliver_it() {
        let (commands, command_rx) = mpsc::channel();
        let control = SupervisorRuntimeControl {
            commands,
            lifecycle: Arc::new(Mutex::new(
                crate::session_worker::SupervisorLifecycleState::default(),
            )),
        };
        let port = RemoteCancellationPort {
            control,
            active_target: Arc::new(std::sync::atomic::AtomicU64::new(73)),
            cancellations: Arc::new(Mutex::new(RemoteCancellationLedger::default())),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            request_gate: Arc::new(Mutex::new(())),
            next_request: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        };
        let started = std::time::Instant::now();
        // No controller consumes the queued command until after the caller's
        // bounded acknowledgement wait has expired. Keeping the request on
        // this thread avoids making the assertion depend on when a spawned
        // caller happens to be rescheduled on a loaded runner.
        let status = port.request_exact(73);
        let SupervisorCommand::CancelDelivery {
            request_id,
            target_id,
            deadline,
            state,
            reply,
        } = command_rx.recv().unwrap()
        else {
            panic!("expected cancellation delivery")
        };
        assert_eq!(request_id, 1);
        assert_eq!(target_id, 73);
        assert!(std::time::Instant::now() >= deadline);
        assert_eq!(
            state.load(std::sync::atomic::Ordering::Acquire),
            CONTROL_DELIVERY_TIMED_OUT,
            "a queued command must be retired before a late controller can write it"
        );
        drop(reply);

        assert_eq!(status, AuthenticatedCancellationStatus::Failed);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "controller delivery acknowledgement was not bounded"
        );
        assert_eq!(
            port.state(1),
            Some(RemoteCancellationState::Resolved(
                CancellationResolution::Failed
            ))
        );
        assert!(!port.is_available());
    }

    #[test]
    fn supervisor_control_claims_and_cleanup_acknowledgements_are_bounded() {
        let (commands, command_rx) = mpsc::channel();
        let control = SupervisorRuntimeControl {
            commands,
            lifecycle: Arc::new(Mutex::new(
                crate::session_worker::SupervisorLifecycleState::default(),
            )),
        };

        let claimed_resize = {
            let control = control.clone();
            std::thread::spawn(move || control.resize(80, 24))
        };
        let SupervisorCommand::Send {
            message,
            state,
            reply: claimed_reply,
            ..
        } = command_rx.recv().unwrap()
        else {
            panic!("expected claimed resize delivery")
        };
        assert_eq!(
            message,
            ControlMessage::Resize {
                columns: 80,
                rows: 24,
            }
        );
        state
            .compare_exchange(
                CONTROL_DELIVERY_PENDING,
                CONTROL_DELIVERY_ACKNOWLEDGED,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .unwrap();
        std::thread::sleep(SUPERVISOR_CONTROL_ACK + Duration::from_millis(25));
        assert!(claimed_resize.join().unwrap().is_ok());
        assert!(claimed_reply.send(Ok(())).is_err());

        let expired_resize = {
            let control = control.clone();
            std::thread::spawn(move || control.resize(101, 37))
        };
        let SupervisorCommand::Send {
            message,
            deadline,
            state,
            reply: resize_reply,
        } = command_rx.recv().unwrap()
        else {
            panic!("expected bounded resize delivery")
        };
        assert_eq!(
            message,
            ControlMessage::Resize {
                columns: 101,
                rows: 37,
            }
        );
        std::thread::sleep(SUPERVISOR_CONTROL_ACK + Duration::from_millis(25));
        assert!(std::time::Instant::now() >= deadline);
        assert!(expired_resize.join().unwrap().is_err());
        assert_eq!(
            state.load(std::sync::atomic::Ordering::Acquire),
            CONTROL_DELIVERY_TIMED_OUT
        );
        drop(resize_reply);

        let terminate = {
            let control = control.clone();
            std::thread::spawn(move || control.terminate_for_interrupt())
        };
        let SupervisorCommand::TerminateInterrupt {
            reply: terminate_reply,
        } = command_rx.recv().unwrap()
        else {
            panic!("expected bounded interrupt termination")
        };
        std::thread::sleep(SUPERVISOR_CONTROL_ACK + Duration::from_millis(25));
        assert!(terminate.join().unwrap().is_err());
        drop(terminate_reply);

        let quiesce = {
            let control = control.clone();
            std::thread::spawn(move || control.quiesce_preserving_lifecycle())
        };
        let SupervisorCommand::Quiesce {
            reply: quiesce_reply,
        } = command_rx.recv().unwrap()
        else {
            panic!("expected bounded worker quiescence")
        };
        std::thread::sleep(SUPERVISOR_CONTROL_ACK + Duration::from_millis(25));
        assert!(quiesce.join().unwrap().is_err());
        drop(quiesce_reply);

        let dispose = std::thread::spawn(move || control.dispose_preserving_lifecycle());
        let SupervisorCommand::Dispose {
            reply: dispose_reply,
        } = command_rx.recv().unwrap()
        else {
            panic!("expected bounded worker disposal")
        };
        std::thread::sleep(SUPERVISOR_CONTROL_ACK + Duration::from_millis(25));
        assert!(dispose.join().unwrap().is_err());
        drop(dispose_reply);
    }

    #[test]
    fn cloned_cancellation_ports_preserve_monotonic_wire_order() {
        let (commands, command_rx) = mpsc::channel();
        let control = SupervisorRuntimeControl {
            commands,
            lifecycle: Arc::new(Mutex::new(
                crate::session_worker::SupervisorLifecycleState::default(),
            )),
        };
        let cancellations = Arc::new(Mutex::new(RemoteCancellationLedger::default()));
        let port = RemoteCancellationPort {
            control,
            active_target: Arc::new(std::sync::atomic::AtomicU64::new(73)),
            cancellations,
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            request_gate: Arc::new(Mutex::new(())),
            next_request: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        };
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let callers = (0..2)
            .map(|_| {
                let port = port.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    port.request_exact(73)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();

        for expected in 1..=2 {
            let SupervisorCommand::CancelDelivery {
                request_id,
                target_id,
                state,
                reply,
                ..
            } = command_rx.recv().unwrap()
            else {
                panic!("expected cancellation delivery")
            };
            assert_eq!(request_id, expected);
            assert_eq!(target_id, 73);
            state
                .compare_exchange(
                    CONTROL_DELIVERY_PENDING,
                    CONTROL_DELIVERY_ACKNOWLEDGED,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .unwrap();
            reply.send(Ok(())).unwrap();
        }
        for caller in callers {
            assert_eq!(
                caller.join().unwrap(),
                AuthenticatedCancellationStatus::Accepted
            );
        }
        assert_eq!(port.state(1), Some(RemoteCancellationState::Pending));
        assert_eq!(port.state(2), Some(RemoteCancellationState::Pending));
    }

    #[test]
    fn supervisor_records_exact_terminal_resolution_once() {
        let (mut repl, _events) = remote_repl_harness(None);
        repl.cancellations
            .lock()
            .unwrap()
            .insert_pending(9, 55)
            .unwrap();
        repl.apply_event(worker_event(ControlMessage::CancellationResolved {
            request_id: 9,
            target_id: 55,
            resolution: CancellationResolution::Defeated,
        }))
        .unwrap();
        assert_eq!(
            repl.cancellation.state(9),
            Some(RemoteCancellationState::Resolved(
                CancellationResolution::Defeated
            ))
        );
        assert!(repl
            .apply_event(worker_event(ControlMessage::CancellationResolved {
                request_id: 9,
                target_id: 55,
                resolution: CancellationResolution::Accepted,
            }))
            .is_err());
    }

    #[test]
    fn supervisor_failed_cancellation_ends_all_pending_requests() {
        let (mut repl, _events) = remote_repl_harness(None);
        {
            let mut cancellations = repl.cancellations.lock().unwrap();
            cancellations.insert_pending(1, 55).unwrap();
            cancellations.insert_pending(2, 56).unwrap();
        }

        assert!(repl
            .apply_event(worker_event(ControlMessage::CancellationResolved {
                request_id: 1,
                target_id: 55,
                resolution: CancellationResolution::Failed,
            }))
            .is_err());
        assert_eq!(
            repl.cancellation.state(1),
            Some(RemoteCancellationState::Resolved(
                CancellationResolution::Failed
            ))
        );
        assert_eq!(
            repl.cancellation.state(2),
            Some(RemoteCancellationState::Resolved(
                CancellationResolution::Failed
            ))
        );
    }

    #[test]
    fn supervisor_event_channel_teardown_fails_pending_requests() {
        let (mut repl, events) = remote_repl_harness(None);
        repl.cancellations
            .lock()
            .unwrap()
            .insert_pending(3, 57)
            .unwrap();
        drop(events);

        assert!(repl
            .receive_event("session worker event channel stopped")
            .is_err());
        assert_eq!(
            repl.cancellation.state(3),
            Some(RemoteCancellationState::Resolved(
                CancellationResolution::Failed
            ))
        );
    }

    #[test]
    fn dropping_supervisor_session_fails_pending_requests() {
        let (repl, _events) = remote_repl_harness(None);
        let cancellation = repl.cancellation_port();
        repl.active_target
            .store(59, std::sync::atomic::Ordering::Release);
        repl.cancellations
            .lock()
            .unwrap()
            .insert_pending(4, 59)
            .unwrap();

        drop(repl);
        assert_eq!(
            cancellation.state(4),
            Some(RemoteCancellationState::Resolved(
                CancellationResolution::Failed
            ))
        );
        assert!(!cancellation.is_available());
        assert_eq!(
            cancellation.request_exact(59),
            AuthenticatedCancellationStatus::Failed
        );
        assert_eq!(
            cancellation.state(1),
            None,
            "a surviving port must not create new pending work after teardown"
        );
    }

    #[test]
    fn remote_program_diagnostics_retain_supervisor_cutoffs() {
        let mut async_program = remote_program_harness(ControlMessage::AsyncFailure {
            stdout_cutoff: 17,
            stderr_cutoff: 23,
            detail: unavailable_async_failure("rejection"),
        });
        assert!(matches!(
            async_program.execute(Vec::new()).unwrap(),
            RemoteProgramOutcome::AsyncFailure {
                stdout_cutoff: 17,
                stderr_cutoff: 23,
                ..
            }
        ));

        let mut faulted_program = remote_program_harness(ControlMessage::WorkerFault {
            stdout_cutoff: 29,
            stderr_cutoff: 31,
            detail: b"fault".to_vec(),
        });
        assert!(matches!(
            faulted_program.execute(Vec::new()).unwrap(),
            RemoteProgramOutcome::EngineFault {
                stdout_cutoff: 29,
                stderr_cutoff: 31,
                ..
            }
        ));

        let mut pre_receipt_program = remote_program_harness(ControlMessage::AsyncFailure {
            stdout_cutoff: 37,
            stderr_cutoff: 41,
            detail: encode_async_failure(&AuthenticatedAsyncFailure::PreReceiptLoss { count: 7 }),
        });
        assert!(matches!(
            pre_receipt_program.execute(Vec::new()).unwrap(),
            RemoteProgramOutcome::EngineFault {
                stdout_cutoff: 37,
                stderr_cutoff: 41,
                ..
            }
        ));
    }

    #[test]
    fn throw_wire_preserves_nul_metadata_source_label_and_positions() {
        let thrown = crate::engine::AuthenticatedThrow {
            value: crate::engine::AuthenticatedDisplay {
                kind: crate::engine::AuthenticatedDisplayKind::String,
                text: "left\0right".to_owned(),
                truncated: false,
            },
            metadata: crate::engine::AuthenticatedThrowMetadata::Captured {
                error_class: crate::engine::AuthenticatedErrorClass::TypeError,
                message: Some("boom\0after".to_owned()),
                message_truncated: false,
                stack: Some("at run (repl:9:3:7)\0tail".to_owned()),
                stack_truncated: false,
                positions: vec![crate::engine::AuthenticatedSourcePosition {
                    source_label: "repl:9:/project/src/input.ts".to_owned(),
                    line: 3,
                    column: 7,
                }],
            },
        };
        let detail = serde_json::to_vec(&thrown).unwrap();
        assert!(detail.len() > "boom".len());
        let decoded = decode_repl_outcome(EvaluationOutcomeKind::Throw, 1, detail).unwrap();
        let crate::repl::ReplEvaluation::Throw(decoded) = decoded else {
            panic!("expected throw outcome")
        };
        assert_eq!(decoded, thrown);
        assert_eq!(
            decoded.metadata.error_class(),
            Some(crate::engine::AuthenticatedErrorClass::TypeError)
        );
        assert_eq!(decoded.metadata.message(), Some("boom\0after"));
        assert_eq!(decoded.metadata.positions()[0].line, 3);
        assert_eq!(decoded.metadata.positions()[0].column, 7);
    }

    #[test]
    fn worst_case_safe_text_json_stays_inside_the_control_envelope() {
        use ibex_runtime::engine::hermes_structured::{
            SAFE_TEXT_MAX_BYTES, SAFE_TEXT_TRUNCATION_MARKER,
        };

        let bounded = format!(
            "{}{}",
            "\0".repeat(SAFE_TEXT_MAX_BYTES - SAFE_TEXT_TRUNCATION_MARKER.len()),
            SAFE_TEXT_TRUNCATION_MARKER
        );
        let thrown = crate::engine::AuthenticatedThrow {
            value: crate::engine::AuthenticatedDisplay {
                kind: crate::engine::AuthenticatedDisplayKind::String,
                text: serde_json::to_string(&bounded).unwrap(),
                truncated: true,
            },
            metadata: crate::engine::AuthenticatedThrowMetadata::Captured {
                error_class: crate::engine::AuthenticatedErrorClass::Error,
                message: Some(bounded.clone()),
                message_truncated: true,
                stack: Some(bounded),
                stack_truncated: true,
                positions: Vec::new(),
            },
        };
        thrown.validate_wire().unwrap();
        let detail = serde_json::to_vec(&thrown).unwrap();
        assert!(detail.len() < 1024 * 1024);
        assert!(decode_repl_outcome(EvaluationOutcomeKind::Throw, 1, detail).is_ok());

        let async_failure = AuthenticatedAsyncFailure::Captured {
            thrown,
            owning_principal: crate::engine::AuthenticatedAsyncFailureOwner::Unavailable,
            event_identity: "bounded:1".to_owned(),
            associated_evaluation: None,
        };
        let encoded = encode_async_failure(&async_failure);
        assert!(encoded.len() < 1024 * 1024);
        assert_eq!(decode_async_failure(&encoded).unwrap(), async_failure);
    }

    #[test]
    fn hostile_truncation_flags_without_markers_fail_closed() {
        let thrown = crate::engine::AuthenticatedThrow {
            value: crate::engine::AuthenticatedDisplay {
                kind: crate::engine::AuthenticatedDisplayKind::Object,
                text: "[Object]".to_owned(),
                truncated: false,
            },
            metadata: crate::engine::AuthenticatedThrowMetadata::Captured {
                error_class: crate::engine::AuthenticatedErrorClass::Error,
                message: Some("not marked".to_owned()),
                message_truncated: true,
                stack: None,
                stack_truncated: false,
                positions: Vec::new(),
            },
        };
        let detail = serde_json::to_vec(&thrown).unwrap();
        assert!(decode_repl_outcome(EvaluationOutcomeKind::Throw, 1, detail).is_err());

        let async_failure = AuthenticatedAsyncFailure::Captured {
            thrown,
            owning_principal: crate::engine::AuthenticatedAsyncFailureOwner::Unavailable,
            event_identity: "hostile:1".to_owned(),
            associated_evaluation: None,
        };
        assert!(decode_async_failure(&serde_json::to_vec(&async_failure).unwrap()).is_err());
    }

    #[test]
    fn oversized_outcome_becomes_reserved_engine_fault_70() {
        let (events, receiver) = bounded_lane::channel(evaluation_lane_limits());
        send_outcome(
            &events,
            7,
            EvaluationOutcomeKind::Throw,
            1,
            vec![0; 1024 * 1024 + 1],
        );
        let EvaluationEvent::Outcome {
            kind,
            status,
            detail,
            ..
        } = next_evaluation_event(&receiver).unwrap().unwrap()
        else {
            panic!("expected bounded outcome")
        };
        assert_eq!(kind, EvaluationOutcomeKind::EngineFault);
        assert_eq!(status, 70);
        assert_eq!(
            detail,
            b"worker outcome exceeded the bounded control-envelope payload"
        );
    }

    #[test]
    fn async_failure_wire_distinguishes_capture_from_unavailable() {
        use capsec_semantics::model::{NonEmptyString, Principal};

        let captured = AuthenticatedAsyncFailure::Captured {
            thrown: crate::engine::AuthenticatedThrow {
                value: crate::engine::AuthenticatedDisplay {
                    kind: crate::engine::AuthenticatedDisplayKind::Object,
                    text: "[Object]".to_owned(),
                    truncated: false,
                },
                metadata: crate::engine::AuthenticatedThrowMetadata::Unavailable {
                    required_stratum: crate::engine::AuthenticatedCapabilityStratum::SafeThrow,
                },
            },
            owning_principal: crate::engine::AuthenticatedAsyncFailureOwner::Authenticated {
                principal: Principal::Root {
                    identity: NonEmptyString::new("project-root").unwrap(),
                },
            },
            event_identity: "timer:41".to_owned(),
            associated_evaluation: Some(7),
        };
        assert_eq!(
            decode_async_failure(&encode_async_failure(&captured)).unwrap(),
            captured
        );

        let unavailable = AuthenticatedAsyncFailure::capture_unavailable("lost\0metadata");
        assert_eq!(
            decode_async_failure(&encode_async_failure(&unavailable)).unwrap(),
            unavailable
        );
        let loss = AuthenticatedAsyncFailure::PreReceiptLoss { count: 17 };
        assert_eq!(
            decode_async_failure(&encode_async_failure(&loss)).unwrap(),
            loss
        );
        let (mut repl, _events) = remote_repl_harness(None);
        assert!(repl
            .apply_event(crate::session_worker::Sequenced {
                epoch: 1,
                sequence: 1,
                payload: crate::session_worker::SupervisorEventPayload::Worker(
                    ControlMessage::PreReceiptLoss { count: 17 },
                ),
            })
            .is_err());
        assert!(repl.async_failures.drain().is_empty());
        assert!(decode_async_failure(b"not-json").is_err());
    }

    #[test]
    fn remote_repl_preserves_all_async_failures_behind_merged_cutoff() {
        let (mut repl, _events) = remote_repl_harness(None);
        for (sequence, stdout_cutoff, stderr_cutoff, detail) in
            [(1, 5, 11, "first"), (2, 13, 7, "second")]
        {
            repl.apply_event(crate::session_worker::Sequenced {
                epoch: 1,
                sequence,
                payload: crate::session_worker::SupervisorEventPayload::Worker(
                    ControlMessage::AsyncFailure {
                        stdout_cutoff,
                        stderr_cutoff,
                        detail: unavailable_async_failure(detail),
                    },
                ),
            })
            .unwrap();
        }
        assert_eq!(repl.async_failures.len(), 2);
        // Directly injected records have no supervisor-lane lease. Production
        // receipt/lease transfer is covered by the storm test below.
        assert_eq!(repl.async_failures.bytes(), 0);
        assert_eq!(repl.take_outcome_barrier(), Some((13, 11)));
    }

    #[test]
    fn remote_repl_retains_distinct_sequenced_post_receipt_loss() {
        let (mut repl, _events) = remote_repl_harness(None);
        repl.apply_event(crate::session_worker::Sequenced {
            epoch: 4,
            sequence: 12,
            payload: crate::session_worker::SupervisorEventPayload::PostReceiptLoss {
                count: 9,
                highest_dropped_sequence: 11,
            },
        })
        .unwrap();
        assert_eq!(
            repl.async_failures.drain(),
            vec![AuthenticatedAsyncFailure::PostReceiptLoss {
                count: 9,
                highest_dropped_sequence: 11,
            }]
        );
        assert_eq!(repl.async_failures.bytes(), 0);
    }

    #[test]
    fn worker_pre_receipt_loss_is_fatal_but_accepted_lifecycle_still_wins() {
        let (mut faulted, _events) = remote_repl_harness(None);
        assert!(faulted
            .apply_event(worker_event(ControlMessage::PreReceiptLoss { count: 3 }))
            .is_err());

        let (mut native_faulted, _events) = remote_repl_harness(None);
        assert!(native_faulted
            .apply_event(worker_event(ControlMessage::AsyncFailure {
                stdout_cutoff: 2,
                stderr_cutoff: 4,
                detail: encode_async_failure(&AuthenticatedAsyncFailure::PreReceiptLoss {
                    count: 5,
                }),
            }))
            .is_err());

        let record = crate::session_worker::LifecycleRecord {
            request_id: 7,
            status: 23,
            stdout_cutoff: 5,
            stderr_cutoff: 8,
        };
        let (mut lifecycle, _events) = remote_repl_harness(Some(record));
        assert!(matches!(
            lifecycle
                .apply_event(worker_event(ControlMessage::PreReceiptLoss { count: 3 }))
                .unwrap(),
            Some(RemoteEvent::Lifecycle(23))
        ));
        assert_eq!(lifecycle.take_lifecycle_barrier(), Some((5, 8)));
    }

    #[test]
    fn supervisor_lease_bounds_remote_storm_until_checkpoint_drain_then_reopens_capacity() {
        let (mut repl, events) = remote_repl_harness(None);
        let detail = unavailable_async_failure("x".repeat(512 * 1024));
        let event = || {
            crate::session_worker::SupervisorEventPayload::Worker(ControlMessage::AsyncFailure {
                stdout_cutoff: 0,
                stderr_cutoff: 0,
                detail: detail.clone(),
            })
        };
        let charge = supervisor_event_charge(&event()).unwrap();
        let bound = ibex_runtime::session_constants::BROKER_QUEUE_BOUND_BYTES;
        let kept = bound / charge;
        assert!(kept > 0);

        for _ in 0..kept {
            publish_supervisor_event(&events, event(), true).unwrap();
            let received = repl.receive_event("storm receipt").unwrap();
            assert!(repl.apply_event(received).unwrap().is_none());
        }
        assert_eq!(repl.async_failures.bytes(), kept * charge);
        assert_eq!(events.snapshot().lossy_bytes, kept * charge);

        for _ in 0..3 {
            publish_supervisor_event(&events, event(), true).unwrap();
        }
        assert!((kept + 3) * charge > bound);
        publish_supervisor_event(
            &events,
            crate::session_worker::SupervisorEventPayload::Worker(
                ControlMessage::ReadyCheckpointAck {
                    checkpoint_id: 9,
                    stdout_cutoff: 0,
                    stderr_cutoff: 0,
                },
            ),
            true,
        )
        .unwrap();

        let loss_marker = repl.receive_event("loss marker").unwrap();
        assert!(repl.apply_event(loss_marker).unwrap().is_none());
        let checkpoint = repl.receive_event("checkpoint").unwrap();
        assert!(matches!(
            repl.apply_event(checkpoint).unwrap(),
            Some(RemoteEvent::ReadyCheckpoint {
                checkpoint_id: 9,
                ..
            })
        ));
        let drained = repl.async_failures.drain();
        assert_eq!(drained.len(), kept + 1);
        assert!(matches!(
            drained.last(),
            Some(AuthenticatedAsyncFailure::PostReceiptLoss { count: 3, .. })
        ));
        assert_eq!(events.snapshot().lossy_bytes, 0);

        publish_supervisor_event(&events, event(), true).unwrap();
        let received = repl.receive_event("subsequent evaluation").unwrap();
        assert!(repl.apply_event(received).unwrap().is_none());
        assert_eq!(repl.async_failures.bytes(), charge);
        assert_eq!(repl.async_failures.drain().len(), 1);
        assert_eq!(events.snapshot().lossy_bytes, 0);
    }

    #[test]
    fn foreground_repl_worker_fault_and_death_are_typed_engine_faults() {
        let (mut faulted, fault_events) = remote_repl_harness(None);
        send_worker_event(
            &fault_events,
            ControlMessage::WorkerFault {
                stdout_cutoff: 37,
                stderr_cutoff: 41,
                detail: b"native fault".to_vec(),
            },
        );
        assert!(matches!(
            faulted.wait_for_evaluation(1),
            Err(crate::runtime::AuthenticatedEvaluationFailure::EngineFault(
                _
            ))
        ));
        assert_eq!(faulted.take_outcome_barrier(), Some((37, 41)));

        let (mut died, death_events) = remote_repl_harness(None);
        died.cancellations
            .lock()
            .unwrap()
            .insert_pending(11, 97)
            .unwrap();
        publish_supervisor_event(
            &death_events,
            crate::session_worker::SupervisorEventPayload::WorkerDied(
                crate::session_worker::WorkerDeath {
                    status: None,
                    signal: Some(libc::SIGKILL),
                },
            ),
            false,
        )
        .unwrap();
        assert!(matches!(
            died.wait_for_evaluation(1),
            Err(crate::runtime::AuthenticatedEvaluationFailure::EngineFault(
                _
            ))
        ));
        assert_eq!(
            died.cancellation.state(11),
            Some(RemoteCancellationState::Resolved(
                CancellationResolution::Failed
            ))
        );
    }

    #[test]
    fn accepted_lifecycle_wins_over_later_foreground_worker_death() {
        let (mut repl, events) =
            remote_repl_harness(Some(crate::session_worker::LifecycleRecord {
                request_id: 1,
                status: 9,
                stdout_cutoff: 2,
                stderr_cutoff: 3,
            }));
        publish_supervisor_event(
            &events,
            crate::session_worker::SupervisorEventPayload::WorkerDied(
                crate::session_worker::WorkerDeath {
                    status: Some(69),
                    signal: None,
                },
            ),
            false,
        )
        .unwrap();
        assert!(matches!(
            repl.wait_for_evaluation(1),
            Ok(crate::repl::ReplEvaluation::Lifecycle(9))
        ));
        assert_eq!(repl.take_lifecycle_barrier(), Some((2, 3)));
    }

    #[test]
    fn accepted_lifecycle_and_cutoffs_survive_event_channel_disconnect() {
        let (mut repl, events) =
            remote_repl_harness(Some(crate::session_worker::LifecycleRecord {
                request_id: 1,
                status: 17,
                stdout_cutoff: 19,
                stderr_cutoff: 23,
            }));
        drop(events);
        let disconnected = repl.receive_event("disconnected after lifecycle").unwrap();
        assert!(matches!(
            repl.apply_event(disconnected).unwrap(),
            Some(RemoteEvent::Lifecycle(17))
        ));
        assert_eq!(repl.take_lifecycle_barrier(), Some((19, 23)));
    }
}
