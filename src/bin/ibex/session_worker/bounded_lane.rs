//! Byte-bounded, non-blocking producer lane used at session-worker trust
//! boundaries.
//!
//! Required records and explicitly lossy asynchronous records have disjoint
//! budgets. Loss accounting has its own bounded slots, and a terminal record
//! has a final reserved slot outside every data budget. Consequently a full
//! async lane cannot consume lifecycle/outcome capacity or hide the fault that
//! reports exhaustion of a required lane.
//! @ref LLP 0024#9-asynchronous-failures

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::{Sequenced, SupervisorSequenceAllocator, WorkerProtocolError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaneLimits {
    pub(crate) lossy_bytes: usize,
    pub(crate) required_bytes: usize,
    pub(crate) loss_records: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LaneSnapshot {
    pub(crate) queued_records: usize,
    pub(crate) lossy_bytes: usize,
    pub(crate) required_bytes: usize,
    pub(crate) loss_records: usize,
    pub(crate) terminal_latched: bool,
    pub(crate) accepting: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PostReceiptLoss {
    pub(crate) count: u64,
    pub(crate) highest_dropped_sequence: u64,
}

impl PostReceiptLoss {
    pub(crate) fn one(sequence: u64) -> Self {
        Self {
            count: 1,
            highest_dropped_sequence: sequence,
        }
    }

    pub(crate) fn merge(&mut self, next: Self) -> Result<(), ()> {
        self.count = self.count.checked_add(next.count).ok_or(())?;
        self.highest_dropped_sequence = self
            .highest_dropped_sequence
            .max(next.highest_dropped_sequence);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControllerFaultReason {
    RequiredLaneOverflow,
    LossAccountingExhausted,
    LossCounterOverflow,
    WorkerProtocol,
    SequenceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PushErrorKind {
    Closed,
    RequiredCapacityExceeded,
    PrioritySlotOccupied,
    LossAccountingExhausted,
    LossCounterOverflow,
    SequenceExhausted,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct PushError<T> {
    pub(crate) kind: PushErrorKind,
    pub(crate) item: T,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LossyDisposition {
    Queued,
    DroppedAndAccounted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalDisposition {
    Latched,
    AlreadyLatched,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum LaneDelivery<T, L> {
    Event(T),
    Loss(L),
    Terminal(T),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TryReceiveError {
    Empty,
    Disconnected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiveTimeoutError {
    Timeout,
    Disconnected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordClass {
    Lossy,
    Required,
}

enum LaneRecord<T, L> {
    Event {
        class: RecordClass,
        charge: usize,
        item: T,
    },
    Loss(L),
}

struct LaneState<T, L> {
    queue: VecDeque<LaneRecord<T, L>>,
    lossy_bytes: usize,
    required_bytes: usize,
    loss_records: usize,
    priority: Option<T>,
    terminal: Option<T>,
    accepting: bool,
    receiver_open: bool,
    senders: usize,
}

struct LaneShared<T, L> {
    limits: LaneLimits,
    state: Mutex<LaneState<T, L>>,
    available: Condvar,
}

pub(crate) struct BoundedLaneSender<T, L> {
    shared: Arc<LaneShared<T, L>>,
}

pub(crate) struct BoundedLaneReceiver<T, L> {
    shared: Arc<LaneShared<T, L>>,
}

pub(crate) fn channel<T, L>(
    limits: LaneLimits,
) -> (BoundedLaneSender<T, L>, BoundedLaneReceiver<T, L>) {
    let shared = Arc::new(LaneShared {
        limits,
        state: Mutex::new(LaneState {
            queue: VecDeque::new(),
            lossy_bytes: 0,
            required_bytes: 0,
            loss_records: 0,
            priority: None,
            terminal: None,
            accepting: true,
            receiver_open: true,
            senders: 1,
        }),
        available: Condvar::new(),
    });
    (
        BoundedLaneSender {
            shared: Arc::clone(&shared),
        },
        BoundedLaneReceiver { shared },
    )
}

impl<T, L> Clone for BoundedLaneSender<T, L> {
    fn clone(&self) -> Self {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.senders = state
            .senders
            .checked_add(1)
            .expect("bounded-lane sender count exhausted");
        drop(state);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T, L> Drop for BoundedLaneSender<T, L> {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.senders = state
            .senders
            .checked_sub(1)
            .expect("bounded-lane sender count underflowed");
        drop(state);
        self.shared.available.notify_all();
    }
}

impl<T, L> BoundedLaneSender<T, L> {
    /// Admit an ordinary asynchronous record without ever waiting for the
    /// consumer. If it cannot fit, `loss` is inserted at the exact point of
    /// first loss or merged with the immediately preceding loss window.
    pub(crate) fn try_push_lossy<F>(
        &self,
        item: T,
        charge: usize,
        loss: L,
        merge_loss: F,
    ) -> Result<LossyDisposition, PushError<T>>
    where
        F: FnOnce(&mut L, L) -> Result<(), ()>,
    {
        let charge = normalized_charge(charge);
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.accepting || !state.receiver_open {
            return Err(PushError {
                kind: PushErrorKind::Closed,
                item,
            });
        }

        if fits(state.lossy_bytes, charge, self.shared.limits.lossy_bytes) {
            state.lossy_bytes += charge;
            state.queue.push_back(LaneRecord::Event {
                class: RecordClass::Lossy,
                charge,
                item,
            });
            drop(state);
            self.shared.available.notify_one();
            return Ok(LossyDisposition::Queued);
        }

        if let Some(LaneRecord::Loss(previous)) = state.queue.back_mut() {
            if merge_loss(previous, loss).is_err() {
                return Err(PushError {
                    kind: PushErrorKind::LossCounterOverflow,
                    item,
                });
            }
        } else {
            if state.loss_records >= self.shared.limits.loss_records {
                return Err(PushError {
                    kind: PushErrorKind::LossAccountingExhausted,
                    item,
                });
            }
            state.loss_records += 1;
            state.queue.push_back(LaneRecord::Loss(loss));
        }
        drop(state);
        self.shared.available.notify_one();
        Ok(LossyDisposition::DroppedAndAccounted)
    }

    /// Admit a record from the required reserve without waiting for the
    /// consumer. Callers must latch a terminal fault when this returns
    /// `RequiredCapacityExceeded`.
    pub(crate) fn try_push_required(&self, item: T, charge: usize) -> Result<(), PushError<T>> {
        let charge = normalized_charge(charge);
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.accepting || !state.receiver_open {
            return Err(PushError {
                kind: PushErrorKind::Closed,
                item,
            });
        }
        if !fits(
            state.required_bytes,
            charge,
            self.shared.limits.required_bytes,
        ) {
            return Err(PushError {
                kind: PushErrorKind::RequiredCapacityExceeded,
                item,
            });
        }
        state.required_bytes += charge;
        state.queue.push_back(LaneRecord::Event {
            class: RecordClass::Required,
            charge,
            item,
        });
        drop(state);
        self.shared.available.notify_one();
        Ok(())
    }

    /// Admit the single fixed-size lifecycle record independently of both
    /// byte pools. The receiver observes this slot before ordinary records so
    /// evaluator backpressure cannot prevent or delay the lifecycle ACK.
    pub(crate) fn try_push_priority(&self, item: T) -> Result<(), PushError<T>> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.accepting || !state.receiver_open {
            return Err(PushError {
                kind: PushErrorKind::Closed,
                item,
            });
        }
        if state.priority.is_some() {
            return Err(PushError {
                kind: PushErrorKind::PrioritySlotOccupied,
                item,
            });
        }
        state.priority = Some(item);
        drop(state);
        self.shared.available.notify_one();
        Ok(())
    }

    /// Latch the first fail-loud record in the preallocated terminal slot and
    /// close admission. Queued records remain ahead of it and are not erased.
    pub(crate) fn latch_terminal(&self, item: T) -> Result<TerminalDisposition, PushError<T>> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.receiver_open {
            return Err(PushError {
                kind: PushErrorKind::Closed,
                item,
            });
        }
        if state.terminal.is_some() {
            return Ok(TerminalDisposition::AlreadyLatched);
        }
        state.terminal = Some(item);
        state.accepting = false;
        drop(state);
        self.shared.available.notify_all();
        Ok(TerminalDisposition::Latched)
    }

    pub(crate) fn close(&self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.accepting = false;
        drop(state);
        self.shared.available.notify_all();
    }

    pub(crate) fn snapshot(&self) -> LaneSnapshot {
        snapshot(&self.shared)
    }
}

impl<T, L> BoundedLaneReceiver<T, L> {
    pub(crate) fn try_recv(&self) -> Result<LaneDelivery<T, L>, TryReceiveError> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        receive_locked(&mut state)
    }

    pub(crate) fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<LaneDelivery<T, L>, ReceiveTimeoutError> {
        let deadline = Instant::now().checked_add(timeout);
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            match receive_locked(&mut state) {
                Ok(delivery) => return Ok(delivery),
                Err(TryReceiveError::Disconnected) => {
                    return Err(ReceiveTimeoutError::Disconnected)
                }
                Err(TryReceiveError::Empty) => {}
            }

            let Some(deadline) = deadline else {
                return Err(ReceiveTimeoutError::Timeout);
            };
            let now = Instant::now();
            if now >= deadline {
                return Err(ReceiveTimeoutError::Timeout);
            }
            let (next_state, wait) = self
                .shared
                .available
                .wait_timeout(state, deadline.duration_since(now))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next_state;
            if wait.timed_out()
                && state.priority.is_none()
                && state.queue.is_empty()
                && state.terminal.is_none()
            {
                return if state.senders == 0 || !state.accepting {
                    Err(ReceiveTimeoutError::Disconnected)
                } else {
                    Err(ReceiveTimeoutError::Timeout)
                };
            }
        }
    }

    pub(crate) fn snapshot(&self) -> LaneSnapshot {
        snapshot(&self.shared)
    }
}

impl<T, L> Drop for BoundedLaneReceiver<T, L> {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.receiver_open = false;
        state.accepting = false;
        state.queue.clear();
        state.lossy_bytes = 0;
        state.required_bytes = 0;
        state.loss_records = 0;
        state.priority = None;
        state.terminal = None;
        drop(state);
        self.shared.available.notify_all();
    }
}

fn fits(used: usize, charge: usize, bound: usize) -> bool {
    used.checked_add(charge).is_some_and(|next| next <= bound)
}

fn normalized_charge(charge: usize) -> usize {
    charge.max(1)
}

fn receive_locked<T, L>(
    state: &mut LaneState<T, L>,
) -> Result<LaneDelivery<T, L>, TryReceiveError> {
    if let Some(priority) = state.priority.take() {
        return Ok(LaneDelivery::Event(priority));
    }
    if let Some(record) = state.queue.pop_front() {
        return match record {
            LaneRecord::Event {
                class,
                charge,
                item,
            } => {
                let counter = match class {
                    RecordClass::Lossy => &mut state.lossy_bytes,
                    RecordClass::Required => &mut state.required_bytes,
                };
                *counter = counter
                    .checked_sub(charge)
                    .expect("bounded-lane byte accounting underflowed");
                Ok(LaneDelivery::Event(item))
            }
            LaneRecord::Loss(loss) => {
                state.loss_records = state
                    .loss_records
                    .checked_sub(1)
                    .expect("bounded-lane loss-record accounting underflowed");
                Ok(LaneDelivery::Loss(loss))
            }
        };
    }
    if let Some(terminal) = state.terminal.take() {
        return Ok(LaneDelivery::Terminal(terminal));
    }
    if state.senders == 0 || !state.accepting {
        Err(TryReceiveError::Disconnected)
    } else {
        Err(TryReceiveError::Empty)
    }
}

fn snapshot<T, L>(shared: &LaneShared<T, L>) -> LaneSnapshot {
    let state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    LaneSnapshot {
        queued_records: state.queue.len() + usize::from(state.priority.is_some()),
        lossy_bytes: state.lossy_bytes,
        required_bytes: state.required_bytes,
        loss_records: state.loss_records,
        terminal_latched: state.terminal.is_some(),
        accepting: state.accepting,
    }
}

enum SequencedRecord<T> {
    Event {
        class: RecordClass,
        charge: usize,
        item: Sequenced<T>,
    },
    Loss(Sequenced<T>),
}

struct SequencedLaneState<T> {
    queue: VecDeque<SequencedRecord<T>>,
    lossy_bytes: usize,
    leased_lossy_bytes: usize,
    required_bytes: usize,
    loss_records: usize,
    leased_loss_records: usize,
    pending_loss: Option<PostReceiptLoss>,
    terminal: Option<Sequenced<T>>,
    accepting: bool,
    receiver_open: bool,
    senders: usize,
}

struct SequencedLaneShared<T> {
    limits: LaneLimits,
    sequencer: SupervisorSequenceAllocator,
    make_loss: fn(PostReceiptLoss) -> T,
    make_fault: fn(ControllerFaultReason) -> T,
    state: Mutex<SequencedLaneState<T>>,
    available: Condvar,
}

pub(crate) struct SequencedLaneSender<T> {
    shared: Arc<SequencedLaneShared<T>>,
}

pub(crate) struct SequencedLaneReceiver<T> {
    shared: Arc<SequencedLaneShared<T>>,
}

/// A received supervisor record plus its lossy-byte or loss-record accounting
/// lease. Keeping the lease alive keeps that resource charged to the
/// producer's bounded pools even after the record has left the queue.
pub(crate) struct SequencedLaneDelivery<T> {
    pub(crate) item: Sequenced<T>,
    lease: Option<SequencedLaneLease<T>>,
}

pub(crate) struct SequencedLaneLease<T> {
    shared: Arc<SequencedLaneShared<T>>,
    kind: SequencedLaneLeaseKind,
}

#[derive(Clone, Copy)]
enum SequencedLaneLeaseKind {
    LossyBytes(usize),
    LossRecord,
}

impl<T> SequencedLaneDelivery<T> {
    pub(crate) fn unleased(item: Sequenced<T>) -> Self {
        Self { item, lease: None }
    }

    pub(crate) fn into_parts(self) -> (Sequenced<T>, Option<SequencedLaneLease<T>>) {
        (self.item, self.lease)
    }
}

impl<T> From<Sequenced<T>> for SequencedLaneDelivery<T> {
    fn from(item: Sequenced<T>) -> Self {
        Self::unleased(item)
    }
}

impl<T> SequencedLaneLease<T> {
    pub(crate) fn charge(&self) -> usize {
        match self.kind {
            SequencedLaneLeaseKind::LossyBytes(charge) => charge,
            SequencedLaneLeaseKind::LossRecord => 0,
        }
    }
}

impl<T> Drop for SequencedLaneLease<T> {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match self.kind {
            SequencedLaneLeaseKind::LossyBytes(charge) => {
                state.lossy_bytes = state
                    .lossy_bytes
                    .checked_sub(charge)
                    .expect("sequenced bounded-lane leased byte accounting underflowed");
                state.leased_lossy_bytes = state
                    .leased_lossy_bytes
                    .checked_sub(charge)
                    .expect("sequenced bounded-lane lease accounting underflowed");
            }
            SequencedLaneLeaseKind::LossRecord => {
                state.loss_records = state
                    .loss_records
                    .checked_sub(1)
                    .expect("sequenced bounded-lane leased loss accounting underflowed");
                state.leased_loss_records = state
                    .leased_loss_records
                    .checked_sub(1)
                    .expect("sequenced bounded-lane loss-lease accounting underflowed");
            }
        }
        drop(state);
        self.shared.available.notify_all();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SequencedDisposition {
    Queued { epoch: u64, sequence: u64 },
    DroppedAndAccounted { epoch: u64, sequence: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SequencedTryReceiveError {
    Empty,
    Disconnected,
    SequenceExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SequencedReceiveTimeoutError {
    Timeout,
    Disconnected,
    SequenceExhausted,
}

pub(crate) fn sequenced_channel<T>(
    limits: LaneLimits,
    sequencer: SupervisorSequenceAllocator,
    make_loss: fn(PostReceiptLoss) -> T,
    make_fault: fn(ControllerFaultReason) -> T,
) -> (SequencedLaneSender<T>, SequencedLaneReceiver<T>) {
    let shared = Arc::new(SequencedLaneShared {
        limits,
        sequencer,
        make_loss,
        make_fault,
        state: Mutex::new(SequencedLaneState {
            queue: VecDeque::new(),
            lossy_bytes: 0,
            leased_lossy_bytes: 0,
            required_bytes: 0,
            loss_records: 0,
            leased_loss_records: 0,
            pending_loss: None,
            terminal: None,
            accepting: true,
            receiver_open: true,
            senders: 1,
        }),
        available: Condvar::new(),
    });
    (
        SequencedLaneSender {
            shared: Arc::clone(&shared),
        },
        SequencedLaneReceiver { shared },
    )
}

impl<T> Clone for SequencedLaneSender<T> {
    fn clone(&self) -> Self {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.senders = state
            .senders
            .checked_add(1)
            .expect("sequenced bounded-lane sender count exhausted");
        drop(state);
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Drop for SequencedLaneSender<T> {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.senders = state
            .senders
            .checked_sub(1)
            .expect("sequenced bounded-lane sender count underflowed");
        drop(state);
        self.shared.available.notify_all();
    }
}

impl<T> SequencedLaneSender<T> {
    pub(crate) fn try_push_lossy(
        &self,
        item: T,
        charge: usize,
    ) -> Result<SequencedDisposition, PushError<T>> {
        let charge = normalized_charge(charge);
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.accepting || !state.receiver_open {
            return Err(PushError {
                kind: PushErrorKind::Closed,
                item,
            });
        }

        if fits(state.lossy_bytes, charge, self.shared.limits.lossy_bytes) {
            if let Err(kind) = flush_pending_loss(&self.shared, &mut state) {
                return Err(PushError { kind, item });
            }
            let reservation = match self.shared.sequencer.reserve(1) {
                Ok(reservation) => reservation,
                Err(_) => {
                    return Err(PushError {
                        kind: PushErrorKind::SequenceExhausted,
                        item,
                    })
                }
            };
            let sequenced = Sequenced {
                epoch: reservation.epoch,
                sequence: reservation.first_sequence,
                payload: item,
            };
            state.lossy_bytes += charge;
            state.queue.push_back(SequencedRecord::Event {
                class: RecordClass::Lossy,
                charge,
                item: sequenced,
            });
            drop(state);
            self.shared.available.notify_one();
            return Ok(SequencedDisposition::Queued {
                epoch: reservation.epoch,
                sequence: reservation.first_sequence,
            });
        }

        let reservation = match self.shared.sequencer.reserve(1) {
            Ok(reservation) => reservation,
            Err(_) => {
                return Err(PushError {
                    kind: PushErrorKind::SequenceExhausted,
                    item,
                })
            }
        };
        let next_loss = PostReceiptLoss::one(reservation.first_sequence);
        if let Some(loss) = state.pending_loss.as_mut() {
            if loss.merge(next_loss).is_err() {
                return Err(PushError {
                    kind: PushErrorKind::LossCounterOverflow,
                    item,
                });
            }
        } else {
            state.pending_loss = Some(next_loss);
        }
        drop(state);
        self.shared.available.notify_one();
        Ok(SequencedDisposition::DroppedAndAccounted {
            epoch: reservation.epoch,
            sequence: reservation.first_sequence,
        })
    }

    pub(crate) fn try_push_required(
        &self,
        item: T,
        charge: usize,
    ) -> Result<SequencedDisposition, PushError<T>> {
        let charge = normalized_charge(charge);
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.accepting || !state.receiver_open {
            return Err(PushError {
                kind: PushErrorKind::Closed,
                item,
            });
        }
        if let Err(kind) = flush_pending_loss(&self.shared, &mut state) {
            return Err(PushError { kind, item });
        }
        if !fits(
            state.required_bytes,
            charge,
            self.shared.limits.required_bytes,
        ) {
            return Err(PushError {
                kind: PushErrorKind::RequiredCapacityExceeded,
                item,
            });
        }
        let reservation = match self.shared.sequencer.reserve(1) {
            Ok(reservation) => reservation,
            Err(_) => {
                return Err(PushError {
                    kind: PushErrorKind::SequenceExhausted,
                    item,
                })
            }
        };
        let sequenced = Sequenced {
            epoch: reservation.epoch,
            sequence: reservation.first_sequence,
            payload: item,
        };
        state.required_bytes += charge;
        state.queue.push_back(SequencedRecord::Event {
            class: RecordClass::Required,
            charge,
            item: sequenced,
        });
        drop(state);
        self.shared.available.notify_one();
        Ok(SequencedDisposition::Queued {
            epoch: reservation.epoch,
            sequence: reservation.first_sequence,
        })
    }

    pub(crate) fn latch_fault(
        &self,
        mut reason: ControllerFaultReason,
    ) -> Result<TerminalDisposition, WorkerProtocolError> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.receiver_open {
            return Err(WorkerProtocolError::WorkerDied);
        }
        if state.terminal.is_some() {
            return Ok(TerminalDisposition::AlreadyLatched);
        }
        if let Err(kind) = flush_pending_loss(&self.shared, &mut state) {
            state.pending_loss = None;
            reason = controller_fault_for_push(kind);
        }
        let fault = self
            .shared
            .sequencer
            .assign((self.shared.make_fault)(reason))?;
        state.terminal = Some(fault);
        state.accepting = false;
        drop(state);
        self.shared.available.notify_all();
        Ok(TerminalDisposition::Latched)
    }

    pub(crate) fn snapshot(&self) -> LaneSnapshot {
        sequenced_snapshot(&self.shared)
    }
}

impl<T> SequencedLaneReceiver<T> {
    pub(crate) fn try_recv(&self) -> Result<Sequenced<T>, SequencedTryReceiveError> {
        self.try_recv_with_lease().map(drop_lease)
    }

    pub(crate) fn try_recv_with_lease(
        &self,
    ) -> Result<SequencedLaneDelivery<T>, SequencedTryReceiveError> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sequenced_receive_locked(&self.shared, &mut state)
    }

    pub(crate) fn recv(&self) -> Result<Sequenced<T>, SequencedTryReceiveError> {
        self.recv_with_lease().map(drop_lease)
    }

    pub(crate) fn recv_with_lease(
        &self,
    ) -> Result<SequencedLaneDelivery<T>, SequencedTryReceiveError> {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            match sequenced_receive_locked(&self.shared, &mut state) {
                Ok(delivery) => return Ok(delivery),
                Err(SequencedTryReceiveError::Empty) => {
                    state = self
                        .shared
                        .available
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Sequenced<T>, SequencedReceiveTimeoutError> {
        self.recv_timeout_with_lease(timeout).map(drop_lease)
    }

    pub(crate) fn recv_timeout_with_lease(
        &self,
        timeout: Duration,
    ) -> Result<SequencedLaneDelivery<T>, SequencedReceiveTimeoutError> {
        let deadline = Instant::now().checked_add(timeout);
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            match sequenced_receive_locked(&self.shared, &mut state) {
                Ok(delivery) => return Ok(delivery),
                Err(SequencedTryReceiveError::Disconnected) => {
                    return Err(SequencedReceiveTimeoutError::Disconnected)
                }
                Err(SequencedTryReceiveError::SequenceExhausted) => {
                    return Err(SequencedReceiveTimeoutError::SequenceExhausted)
                }
                Err(SequencedTryReceiveError::Empty) => {}
            }
            let Some(deadline) = deadline else {
                return Err(SequencedReceiveTimeoutError::Timeout);
            };
            let now = Instant::now();
            if now >= deadline {
                return Err(SequencedReceiveTimeoutError::Timeout);
            }
            let (next_state, wait) = self
                .shared
                .available
                .wait_timeout(state, deadline.duration_since(now))
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next_state;
            if wait.timed_out()
                && state.queue.is_empty()
                && state.pending_loss.is_none()
                && state.terminal.is_none()
            {
                return if state.senders == 0 || !state.accepting {
                    Err(SequencedReceiveTimeoutError::Disconnected)
                } else {
                    Err(SequencedReceiveTimeoutError::Timeout)
                };
            }
        }
    }

    pub(crate) fn snapshot(&self) -> LaneSnapshot {
        sequenced_snapshot(&self.shared)
    }
}

impl<T> Drop for SequencedLaneReceiver<T> {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.receiver_open = false;
        state.accepting = false;
        let queued = std::mem::take(&mut state.queue);
        for record in queued {
            match record {
                SequencedRecord::Event {
                    class: RecordClass::Lossy,
                    charge,
                    ..
                } => {
                    state.lossy_bytes = state
                        .lossy_bytes
                        .checked_sub(charge)
                        .expect("sequenced bounded-lane queued byte accounting underflowed");
                }
                SequencedRecord::Event {
                    class: RecordClass::Required,
                    charge,
                    ..
                } => {
                    state.required_bytes = state
                        .required_bytes
                        .checked_sub(charge)
                        .expect("sequenced bounded-lane required accounting underflowed");
                }
                SequencedRecord::Loss(_) => {
                    state.loss_records = state
                        .loss_records
                        .checked_sub(1)
                        .expect("sequenced bounded-lane loss accounting underflowed");
                }
            }
        }
        debug_assert_eq!(state.lossy_bytes, state.leased_lossy_bytes);
        debug_assert_eq!(state.required_bytes, 0);
        debug_assert_eq!(state.loss_records, state.leased_loss_records);
        state.pending_loss = None;
        state.terminal = None;
        drop(state);
        self.shared.available.notify_all();
    }
}

fn flush_pending_loss<T>(
    shared: &SequencedLaneShared<T>,
    state: &mut SequencedLaneState<T>,
) -> Result<(), PushErrorKind> {
    let Some(loss) = state.pending_loss.take() else {
        return Ok(());
    };
    if state.loss_records >= shared.limits.loss_records {
        state.pending_loss = Some(loss);
        return Err(PushErrorKind::LossAccountingExhausted);
    }
    let marker = match shared.sequencer.assign((shared.make_loss)(loss)) {
        Ok(marker) => marker,
        Err(_) => {
            state.pending_loss = Some(loss);
            return Err(PushErrorKind::SequenceExhausted);
        }
    };
    state.loss_records += 1;
    state.queue.push_back(SequencedRecord::Loss(marker));
    Ok(())
}

fn sequenced_receive_locked<T>(
    shared: &Arc<SequencedLaneShared<T>>,
    state: &mut SequencedLaneState<T>,
) -> Result<SequencedLaneDelivery<T>, SequencedTryReceiveError> {
    if state.queue.is_empty() && state.pending_loss.is_some() {
        if let Err(kind) = flush_pending_loss(shared, state) {
            state.pending_loss = None;
            state.accepting = false;
            let fault = shared
                .sequencer
                .assign((shared.make_fault)(controller_fault_for_push(kind)))
                .map_err(|_| SequencedTryReceiveError::SequenceExhausted)?;
            state.terminal = Some(fault);
        }
    }
    if let Some(record) = state.queue.pop_front() {
        return match record {
            SequencedRecord::Event {
                class,
                charge,
                item,
            } => {
                let lease = match class {
                    RecordClass::Lossy => {
                        state.leased_lossy_bytes = state
                            .leased_lossy_bytes
                            .checked_add(charge)
                            .expect("sequenced bounded-lane leased accounting overflowed");
                        Some(SequencedLaneLease {
                            shared: Arc::clone(shared),
                            kind: SequencedLaneLeaseKind::LossyBytes(charge),
                        })
                    }
                    RecordClass::Required => {
                        state.required_bytes = state
                            .required_bytes
                            .checked_sub(charge)
                            .expect("sequenced bounded-lane byte accounting underflowed");
                        None
                    }
                };
                Ok(SequencedLaneDelivery { item, lease })
            }
            SequencedRecord::Loss(marker) => {
                state.leased_loss_records = state
                    .leased_loss_records
                    .checked_add(1)
                    .expect("sequenced bounded-lane loss-lease accounting overflowed");
                Ok(SequencedLaneDelivery {
                    item: marker,
                    lease: Some(SequencedLaneLease {
                        shared: Arc::clone(shared),
                        kind: SequencedLaneLeaseKind::LossRecord,
                    }),
                })
            }
        };
    }
    if let Some(terminal) = state.terminal.take() {
        return Ok(SequencedLaneDelivery::unleased(terminal));
    }
    if state.senders == 0 || !state.accepting {
        Err(SequencedTryReceiveError::Disconnected)
    } else {
        Err(SequencedTryReceiveError::Empty)
    }
}

fn controller_fault_for_push(kind: PushErrorKind) -> ControllerFaultReason {
    match kind {
        PushErrorKind::LossCounterOverflow => ControllerFaultReason::LossCounterOverflow,
        PushErrorKind::SequenceExhausted => ControllerFaultReason::SequenceExhausted,
        PushErrorKind::RequiredCapacityExceeded | PushErrorKind::PrioritySlotOccupied => {
            ControllerFaultReason::RequiredLaneOverflow
        }
        PushErrorKind::Closed | PushErrorKind::LossAccountingExhausted => {
            ControllerFaultReason::LossAccountingExhausted
        }
    }
}

fn drop_lease<T>(delivery: SequencedLaneDelivery<T>) -> Sequenced<T> {
    let (item, lease) = delivery.into_parts();
    drop(lease);
    item
}

fn sequenced_snapshot<T>(shared: &SequencedLaneShared<T>) -> LaneSnapshot {
    let state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    LaneSnapshot {
        queued_records: state.queue.len() + usize::from(state.pending_loss.is_some()),
        lossy_bytes: state.lossy_bytes,
        required_bytes: state.required_bytes,
        loss_records: state.loss_records + usize::from(state.pending_loss.is_some()),
        terminal_latched: state.terminal.is_some(),
        accepting: state.accepting,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn add_count(previous: &mut u64, next: u64) -> Result<(), ()> {
        *previous = previous.checked_add(next).ok_or(())?;
        Ok(())
    }

    #[derive(Debug, Eq, PartialEq)]
    enum TestSupervisorEvent {
        Event(&'static str),
        Loss(PostReceiptLoss),
        Fault(ControllerFaultReason),
    }

    fn test_loss(loss: PostReceiptLoss) -> TestSupervisorEvent {
        TestSupervisorEvent::Loss(loss)
    }

    fn test_fault(reason: ControllerFaultReason) -> TestSupervisorEvent {
        TestSupervisorEvent::Fault(reason)
    }

    #[test]
    fn sequenced_lane_places_post_receipt_marker_after_drops_before_required_event() {
        let sequencer = SupervisorSequenceAllocator::new(9).unwrap();
        let (sender, receiver) = sequenced_channel(
            LaneLimits {
                lossy_bytes: 1,
                required_bytes: 1,
                loss_records: 2,
            },
            sequencer,
            test_loss,
            test_fault,
        );
        assert_eq!(
            sender
                .try_push_lossy(TestSupervisorEvent::Event("kept"), 1)
                .unwrap(),
            SequencedDisposition::Queued {
                epoch: 9,
                sequence: 1
            }
        );
        assert_eq!(
            sender
                .try_push_lossy(TestSupervisorEvent::Event("drop-2"), 1)
                .unwrap(),
            SequencedDisposition::DroppedAndAccounted {
                epoch: 9,
                sequence: 2
            }
        );
        assert_eq!(
            sender
                .try_push_lossy(TestSupervisorEvent::Event("drop-3"), 1)
                .unwrap(),
            SequencedDisposition::DroppedAndAccounted {
                epoch: 9,
                sequence: 3
            }
        );
        assert_eq!(
            sender
                .try_push_required(TestSupervisorEvent::Event("outcome"), 1)
                .unwrap(),
            SequencedDisposition::Queued {
                epoch: 9,
                sequence: 5
            }
        );

        assert_eq!(receiver.try_recv().unwrap().sequence, 1);
        let marker = receiver.try_recv().unwrap();
        assert_eq!(marker.sequence, 4);
        assert_eq!(
            marker.payload,
            TestSupervisorEvent::Loss(PostReceiptLoss {
                count: 2,
                highest_dropped_sequence: 3,
            })
        );
        let outcome = receiver.try_recv().unwrap();
        assert_eq!(outcome.sequence, 5);
        assert_eq!(outcome.payload, TestSupervisorEvent::Event("outcome"));
    }

    #[test]
    fn sequenced_lane_flushes_a_trailing_loss_window_without_a_following_event() {
        let sequencer = SupervisorSequenceAllocator::new(1).unwrap();
        let (sender, receiver) = sequenced_channel(
            LaneLimits {
                lossy_bytes: 1,
                required_bytes: 1,
                loss_records: 1,
            },
            sequencer,
            test_loss,
            test_fault,
        );
        sender
            .try_push_lossy(TestSupervisorEvent::Event("kept"), 1)
            .unwrap();
        sender
            .try_push_lossy(TestSupervisorEvent::Event("dropped"), 1)
            .unwrap();
        assert_eq!(receiver.try_recv().unwrap().sequence, 1);
        let marker = receiver.try_recv().unwrap();
        assert_eq!(marker.sequence, 3);
        assert_eq!(
            marker.payload,
            TestSupervisorEvent::Loss(PostReceiptLoss {
                count: 1,
                highest_dropped_sequence: 2,
            })
        );
    }

    #[test]
    fn sequenced_loss_slot_exhaustion_uses_the_reserved_fault_slot() {
        let sequencer = SupervisorSequenceAllocator::new(1).unwrap();
        let (sender, receiver) = sequenced_channel(
            LaneLimits {
                lossy_bytes: 1,
                required_bytes: 1,
                loss_records: 1,
            },
            sequencer,
            test_loss,
            test_fault,
        );
        sender
            .try_push_lossy(TestSupervisorEvent::Event("kept"), 1)
            .unwrap();
        sender
            .try_push_lossy(TestSupervisorEvent::Event("drop-window-1"), 1)
            .unwrap();
        sender
            .try_push_required(TestSupervisorEvent::Event("barrier"), 1)
            .unwrap();
        sender
            .try_push_lossy(TestSupervisorEvent::Event("drop-window-2"), 1)
            .unwrap();
        let error = sender
            .try_push_required(TestSupervisorEvent::Event("outcome"), 1)
            .unwrap_err();
        assert_eq!(error.kind, PushErrorKind::LossAccountingExhausted);
        sender
            .latch_fault(ControllerFaultReason::LossAccountingExhausted)
            .unwrap();

        assert_eq!(receiver.try_recv().unwrap().sequence, 1);
        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            TestSupervisorEvent::Loss(_)
        ));
        assert_eq!(
            receiver.try_recv().unwrap().payload,
            TestSupervisorEvent::Event("barrier")
        );
        assert_eq!(
            receiver.try_recv().unwrap().payload,
            TestSupervisorEvent::Fault(ControllerFaultReason::LossAccountingExhausted)
        );
    }

    #[test]
    fn post_receipt_loss_tracks_the_highest_dropped_receipt_and_checks_count() {
        let mut loss = PostReceiptLoss::one(7);
        loss.merge(PostReceiptLoss {
            count: 2,
            highest_dropped_sequence: 11,
        })
        .unwrap();
        assert_eq!(
            loss,
            PostReceiptLoss {
                count: 3,
                highest_dropped_sequence: 11,
            }
        );

        let mut exhausted = PostReceiptLoss {
            count: u64::MAX,
            highest_dropped_sequence: 12,
        };
        assert_eq!(exhausted.merge(PostReceiptLoss::one(13)), Err(()));
        assert_eq!(exhausted.count, u64::MAX);
    }

    #[test]
    fn loss_is_in_order_and_required_records_use_an_independent_reserve() {
        let (sender, receiver) = channel(LaneLimits {
            lossy_bytes: 5,
            required_bytes: 7,
            loss_records: 2,
        });

        assert_eq!(
            sender.try_push_lossy("async-a", 5, 1, add_count),
            Ok(LossyDisposition::Queued)
        );
        assert_eq!(
            sender.try_push_lossy("async-b", 5, 1, add_count),
            Ok(LossyDisposition::DroppedAndAccounted)
        );
        assert_eq!(
            sender.try_push_lossy("async-c", 5, 1, add_count),
            Ok(LossyDisposition::DroppedAndAccounted)
        );
        sender.try_push_required("outcome", 7).unwrap();

        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Event("async-a")));
        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Loss(2)));
        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Event("outcome")));
        assert_eq!(receiver.try_recv(), Err(TryReceiveError::Empty));
        assert_eq!(
            receiver.snapshot(),
            LaneSnapshot {
                queued_records: 0,
                lossy_bytes: 0,
                required_bytes: 0,
                loss_records: 0,
                terminal_latched: false,
                accepting: true,
            }
        );
    }

    #[test]
    fn a_paused_consumer_cannot_block_or_unbound_the_lossy_producer() {
        let (sender, receiver) = channel(LaneLimits {
            lossy_bytes: 4,
            required_bytes: 1,
            loss_records: 1,
        });
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            for value in 0..100_000u64 {
                sender.try_push_lossy(value, 4, 1u64, add_count).unwrap();
            }
            done_tx.send(sender.snapshot()).unwrap();
        });

        let snapshot = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("producer blocked on a paused consumer");
        assert_eq!(snapshot.lossy_bytes, 4);
        assert_eq!(snapshot.loss_records, 1);
        assert_eq!(snapshot.queued_records, 2);
        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Event(0)));
        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Loss(99_999)));
    }

    #[test]
    fn loss_counter_overflow_is_an_error_and_the_terminal_slot_stays_available() {
        let (sender, receiver) = channel(LaneLimits {
            lossy_bytes: 1,
            required_bytes: 0,
            loss_records: 1,
        });
        sender.try_push_lossy("kept", 1, 1, add_count).unwrap();
        sender
            .try_push_lossy("first-drop", 1, u64::MAX, add_count)
            .unwrap();
        let error = sender
            .try_push_lossy("overflow", 1, 1, add_count)
            .unwrap_err();
        assert_eq!(error.kind, PushErrorKind::LossCounterOverflow);
        assert_eq!(error.item, "overflow");
        assert_eq!(
            sender.latch_terminal("loss-accounting-fault").unwrap(),
            TerminalDisposition::Latched
        );

        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Event("kept")));
        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Loss(u64::MAX)));
        assert_eq!(
            receiver.try_recv(),
            Ok(LaneDelivery::Terminal("loss-accounting-fault"))
        );
        assert_eq!(receiver.try_recv(), Err(TryReceiveError::Disconnected));
    }

    #[test]
    fn exhausted_required_or_loss_reserves_can_fail_loudly() {
        let (sender, receiver) = channel(LaneLimits {
            lossy_bytes: 1,
            required_bytes: 1,
            loss_records: 1,
        });
        sender.try_push_lossy("kept", 1, 1u64, add_count).unwrap();
        sender
            .try_push_lossy("drop-window-one", 1, 1u64, add_count)
            .unwrap();
        sender.try_push_required("barrier", 1).unwrap();

        let loss_error = sender
            .try_push_lossy("drop-window-two", 1, 1u64, add_count)
            .unwrap_err();
        assert_eq!(loss_error.kind, PushErrorKind::LossAccountingExhausted);

        let required_error = sender.try_push_required("outcome", 1).unwrap_err();
        assert_eq!(required_error.kind, PushErrorKind::RequiredCapacityExceeded);
        sender.latch_terminal("worker-fault").unwrap();

        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Event("kept")));
        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Loss(1)));
        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Event("barrier")));
        assert_eq!(
            receiver.try_recv(),
            Ok(LaneDelivery::Terminal("worker-fault"))
        );
    }

    #[test]
    fn sender_and_receiver_closure_are_observable() {
        let (sender, receiver) = channel::<u8, u8>(LaneLimits {
            lossy_bytes: 1,
            required_bytes: 1,
            loss_records: 1,
        });
        let clone = sender.clone();
        drop(sender);
        assert_eq!(receiver.try_recv(), Err(TryReceiveError::Empty));
        drop(clone);
        assert_eq!(receiver.try_recv(), Err(TryReceiveError::Disconnected));

        let (sender, receiver) = channel::<u8, u8>(LaneLimits {
            lossy_bytes: 1,
            required_bytes: 1,
            loss_records: 1,
        });
        drop(receiver);
        let error = sender.try_push_required(7, 1).unwrap_err();
        assert_eq!(error.kind, PushErrorKind::Closed);
        assert_eq!(error.item, 7);
    }

    #[test]
    fn priority_slot_is_independent_of_a_full_required_reserve() {
        let (sender, receiver) = channel::<&'static str, u64>(LaneLimits {
            lossy_bytes: 0,
            required_bytes: 1,
            loss_records: 1,
        });
        sender.try_push_required("ordinary-required", 1).unwrap();
        sender.try_push_priority("lifecycle").unwrap();

        assert_eq!(receiver.snapshot().required_bytes, 1);
        assert_eq!(receiver.try_recv(), Ok(LaneDelivery::Event("lifecycle")));
        assert_eq!(receiver.snapshot().required_bytes, 1);
        assert_eq!(
            receiver.try_recv(),
            Ok(LaneDelivery::Event("ordinary-required"))
        );
    }

    #[test]
    fn lossy_receipt_lease_holds_capacity_until_the_consumer_releases_it() {
        let sequencer = SupervisorSequenceAllocator::new(1).unwrap();
        let (sender, receiver) = sequenced_channel(
            LaneLimits {
                lossy_bytes: 1,
                required_bytes: 1,
                loss_records: 1,
            },
            sequencer,
            test_loss,
            test_fault,
        );
        sender
            .try_push_lossy(TestSupervisorEvent::Event("held"), 1)
            .unwrap();
        let held = receiver.try_recv_with_lease().unwrap();
        assert_eq!(held.item.sequence, 1);
        assert_eq!(receiver.snapshot().lossy_bytes, 1);

        assert!(matches!(
            sender
                .try_push_lossy(TestSupervisorEvent::Event("dropped"), 1)
                .unwrap(),
            SequencedDisposition::DroppedAndAccounted { sequence: 2, .. }
        ));
        sender
            .try_push_required(TestSupervisorEvent::Event("checkpoint"), 1)
            .unwrap();
        assert!(matches!(
            receiver.try_recv().unwrap().payload,
            TestSupervisorEvent::Loss(PostReceiptLoss {
                count: 1,
                highest_dropped_sequence: 2
            })
        ));
        assert_eq!(
            receiver.try_recv().unwrap().payload,
            TestSupervisorEvent::Event("checkpoint")
        );

        drop(held);
        assert_eq!(receiver.snapshot().lossy_bytes, 0);
        assert!(matches!(
            sender
                .try_push_lossy(TestSupervisorEvent::Event("next-evaluation"), 1)
                .unwrap(),
            SequencedDisposition::Queued { .. }
        ));
    }

    #[test]
    fn rejected_required_admission_does_not_consume_a_sequence() {
        let sequencer = SupervisorSequenceAllocator::new(3).unwrap();
        let (sender, receiver) = sequenced_channel(
            LaneLimits {
                lossy_bytes: 0,
                required_bytes: 1,
                loss_records: 1,
            },
            sequencer,
            test_loss,
            test_fault,
        );
        assert!(matches!(
            sender
                .try_push_required(TestSupervisorEvent::Event("first"), 1)
                .unwrap(),
            SequencedDisposition::Queued { sequence: 1, .. }
        ));
        assert_eq!(
            sender
                .try_push_required(TestSupervisorEvent::Event("rejected"), 1)
                .unwrap_err()
                .kind,
            PushErrorKind::RequiredCapacityExceeded
        );
        assert_eq!(receiver.recv().unwrap().sequence, 1);
        assert!(matches!(
            sender
                .try_push_required(TestSupervisorEvent::Event("next"), 1)
                .unwrap(),
            SequencedDisposition::Queued { sequence: 2, .. }
        ));
    }

    #[test]
    fn alternating_required_records_cannot_unbound_received_loss_windows() {
        let sequencer = SupervisorSequenceAllocator::new(5).unwrap();
        let (sender, receiver) = sequenced_channel(
            LaneLimits {
                lossy_bytes: 1,
                required_bytes: 1,
                loss_records: 1,
            },
            sequencer,
            test_loss,
            test_fault,
        );
        sender
            .try_push_lossy(TestSupervisorEvent::Event("held-by-consumer"), 1)
            .unwrap();
        let held_event = receiver.recv_with_lease().unwrap();

        sender
            .try_push_lossy(TestSupervisorEvent::Event("drop-window-1"), 1)
            .unwrap();
        sender
            .try_push_required(TestSupervisorEvent::Event("required-1"), 1)
            .unwrap();
        let held_loss = receiver.recv_with_lease().unwrap();
        assert!(matches!(
            held_loss.item.payload,
            TestSupervisorEvent::Loss(PostReceiptLoss { count: 1, .. })
        ));
        assert_eq!(
            receiver.recv().unwrap().payload,
            TestSupervisorEvent::Event("required-1")
        );

        sender
            .try_push_lossy(TestSupervisorEvent::Event("drop-window-2"), 1)
            .unwrap();
        assert_eq!(
            sender
                .try_push_required(TestSupervisorEvent::Event("required-2"), 1)
                .unwrap_err()
                .kind,
            PushErrorKind::LossAccountingExhausted
        );
        assert_eq!(receiver.snapshot().loss_records, 2);

        drop(held_loss);
        assert_eq!(receiver.snapshot().loss_records, 1);
        sender
            .try_push_required(TestSupervisorEvent::Event("required-2"), 1)
            .unwrap();
        let next_loss = receiver.recv_with_lease().unwrap();
        assert!(matches!(
            next_loss.item.payload,
            TestSupervisorEvent::Loss(PostReceiptLoss { count: 1, .. })
        ));
        drop(next_loss);
        assert_eq!(
            receiver.recv().unwrap().payload,
            TestSupervisorEvent::Event("required-2")
        );
        drop(held_event);
    }

    #[test]
    fn trailing_loss_with_a_leased_slot_delivers_reserved_fault_without_a_follower() {
        let sequencer = SupervisorSequenceAllocator::new(7).unwrap();
        let (sender, receiver) = sequenced_channel(
            LaneLimits {
                lossy_bytes: 1,
                required_bytes: 1,
                loss_records: 1,
            },
            sequencer,
            test_loss,
            test_fault,
        );
        sender
            .try_push_lossy(TestSupervisorEvent::Event("held"), 1)
            .unwrap();
        let held_event = receiver.recv_with_lease().unwrap();
        sender
            .try_push_lossy(TestSupervisorEvent::Event("drop-1"), 1)
            .unwrap();
        let held_loss = receiver.recv_with_lease().unwrap();
        assert!(matches!(
            held_loss.item.payload,
            TestSupervisorEvent::Loss(_)
        ));

        sender
            .try_push_lossy(TestSupervisorEvent::Event("drop-2"), 1)
            .unwrap();
        let fault = receiver.recv().unwrap();
        assert_eq!(fault.sequence, 5);
        assert_eq!(
            fault.payload,
            TestSupervisorEvent::Fault(ControllerFaultReason::LossAccountingExhausted)
        );
        assert_eq!(
            receiver.try_recv(),
            Err(SequencedTryReceiveError::Disconnected)
        );
        drop(held_loss);
        drop(held_event);
    }
}
