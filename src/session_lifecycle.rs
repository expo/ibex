//! Supervisor-owned cooperative lifecycle state shared with the armed Host.
//!
//! JavaScript never receives this port. Native lifecycle adapters first pass
//! their complete typed principal set through the Host decision engine, then
//! use this cell to publish one idempotent, fixed-shape control event. The
//! terminal supervisor holds a clone of the same port, so `exitCode` and an
//! accepted exit request cannot diverge across two process-local mirrors.
//!
//! @ref LLP 0025#8-exit-and-lifecycle — cooperative exits are root-only,
//! idempotent, supervisor-authoritative events and exit-code writes mirror
//! synchronously before returning to JavaScript.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Closed attribution projection used at the lifecycle state boundary.
///
/// The CapSec evaluator still decides over the complete principal set. This
/// projection exists only as a second, local root check on the stateful port;
/// it is not an authority source and cannot replace the typed decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecyclePrincipal {
    Root,
    Package,
    Missing,
    Ambiguous,
    NoUser,
}

/// Fixed-shape supervisor event for the first accepted cooperative request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleExitRequest {
    pub request_id: u64,
    pub status: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRequestDisposition {
    Accepted { request: LifecycleExitRequest },
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
    next_request_id: u64,
    latched_request: Option<LifecycleExitRequest>,
    request_pending: bool,
}

/// Cloneable lifecycle authority shared by the Host and session supervisor.
///
/// Taking the pending event is delivery, not rollback: the latched request and
/// sealed state remain, so a repeated native commit is idempotent even after
/// the supervisor has consumed the first notification.
#[derive(Clone, Debug)]
pub struct SessionLifecyclePort {
    inner: Arc<Mutex<SessionLifecycleState>>,
}

impl Default for SessionLifecyclePort {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionLifecycleState {
                exit_code: crate::session_constants::EXIT_STATUS_ORDERLY_DEFAULT,
                sealed: false,
                next_request_id: 1,
                latched_request: None,
                request_pending: false,
            })),
        }
    }
}

impl SessionLifecyclePort {
    pub fn request_exit(
        &self,
        principal: LifecyclePrincipal,
        status: i32,
    ) -> LifecycleRequestDisposition {
        if principal != LifecyclePrincipal::Root {
            return LifecycleRequestDisposition::Denied;
        }
        let mut state = self.lock_state();
        if state.sealed {
            return LifecycleRequestDisposition::AlreadyInProgress;
        }
        let Some(next_request_id) = state.next_request_id.checked_add(1) else {
            // Never publish an event whose id could later be reused.
            state.sealed = true;
            return LifecycleRequestDisposition::AlreadyInProgress;
        };
        let request = LifecycleExitRequest {
            request_id: state.next_request_id,
            status: normalize_exit_status(status),
        };
        state.next_request_id = next_request_id;
        state.latched_request = Some(request);
        state.request_pending = true;
        state.sealed = true;
        LifecycleRequestDisposition::Accepted { request }
    }

    pub fn get_exit_code(&self, principal: LifecyclePrincipal) -> LifecycleGetDisposition {
        if principal != LifecyclePrincipal::Root {
            return LifecycleGetDisposition::Denied;
        }
        LifecycleGetDisposition::Value(self.lock_state().exit_code)
    }

    pub fn set_exit_code(
        &self,
        principal: LifecyclePrincipal,
        status: i32,
    ) -> LifecycleSetDisposition {
        if principal != LifecyclePrincipal::Root {
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

    /// Mirror a normalized status through a synchronous native callback, then
    /// publish it locally only after that callback acknowledges. The state
    /// lock makes the check, acknowledgement, and local publication one
    /// ordered mutation; the callback must not re-enter this port.
    pub(crate) fn set_exit_code_with_synchronous_mirror(
        &self,
        principal: LifecyclePrincipal,
        status: i32,
        mirror: impl FnOnce(i32) -> bool,
    ) -> LifecycleSetDisposition {
        if principal != LifecyclePrincipal::Root {
            return LifecycleSetDisposition::Denied;
        }
        let mut state = self.lock_state();
        if state.sealed {
            return LifecycleSetDisposition::AlreadyInProgress;
        }
        let status = normalize_exit_status(status);
        if !mirror(status) {
            return LifecycleSetDisposition::Denied;
        }
        state.exit_code = status;
        LifecycleSetDisposition::Accepted { status }
    }

    /// Return the accepted request without consuming its pending notification.
    pub fn latched_request(&self) -> Option<LifecycleExitRequest> {
        self.lock_state().latched_request
    }

    /// Return whether an accepted request has not yet been taken by the owner.
    pub fn has_pending_request(&self) -> bool {
        self.lock_state().request_pending
    }

    /// Consume the one pending supervisor notification.
    pub fn take_pending_request(&self) -> Option<LifecycleExitRequest> {
        let mut state = self.lock_state();
        if !state.request_pending {
            return None;
        }
        state.request_pending = false;
        state.latched_request
    }

    /// Seal the port for a non-cooperative termination cause.
    pub fn seal(&self) {
        self.lock_state().sealed = true;
    }

    pub fn is_sealed(&self) -> bool {
        self.lock_state().sealed
    }

    fn lock_state(&self) -> MutexGuard<'_, SessionLifecycleState> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Normalize the final OS-visible status at the synchronous mirror boundary.
pub fn normalize_exit_status(status: i32) -> i32 {
    #[cfg(unix)]
    {
        status & crate::session_constants::POSIX_EXIT_STATUS_MASK
    }
    #[cfg(not(unix))]
    {
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_operations_share_state_and_publish_one_idempotent_event() {
        let port = SessionLifecyclePort::default();
        let supervisor = port.clone();

        assert_eq!(
            port.set_exit_code(LifecyclePrincipal::Package, 7),
            LifecycleSetDisposition::Denied
        );
        assert_eq!(
            port.set_exit_code(LifecyclePrincipal::Missing, 7),
            LifecycleSetDisposition::Denied
        );
        assert_eq!(
            port.set_exit_code(LifecyclePrincipal::Root, 263),
            LifecycleSetDisposition::Accepted {
                status: normalize_exit_status(263)
            }
        );
        assert_eq!(
            supervisor.get_exit_code(LifecyclePrincipal::Root),
            LifecycleGetDisposition::Value(normalize_exit_status(263))
        );

        let request = match port.request_exit(LifecyclePrincipal::Root, 256) {
            LifecycleRequestDisposition::Accepted { request } => request,
            other => panic!("unexpected request disposition: {other:?}"),
        };
        assert_eq!(request.request_id, 1);
        assert_eq!(request.status, normalize_exit_status(256));
        assert!(supervisor.has_pending_request());
        assert_eq!(supervisor.take_pending_request(), Some(request));
        assert!(!supervisor.has_pending_request());
        assert_eq!(supervisor.latched_request(), Some(request));
        assert_eq!(
            port.request_exit(LifecyclePrincipal::Root, 9),
            LifecycleRequestDisposition::AlreadyInProgress
        );
        assert_eq!(
            port.set_exit_code(LifecyclePrincipal::Root, 9),
            LifecycleSetDisposition::AlreadyInProgress
        );
        assert_eq!(supervisor.take_pending_request(), None);
    }

    #[test]
    fn every_non_root_projection_denies_without_state_change() {
        let port = SessionLifecyclePort::default();
        for principal in [
            LifecyclePrincipal::Package,
            LifecyclePrincipal::Missing,
            LifecyclePrincipal::Ambiguous,
            LifecyclePrincipal::NoUser,
        ] {
            assert_eq!(
                port.request_exit(principal, 7),
                LifecycleRequestDisposition::Denied
            );
            assert_eq!(
                port.get_exit_code(principal),
                LifecycleGetDisposition::Denied
            );
            assert_eq!(
                port.set_exit_code(principal, 7),
                LifecycleSetDisposition::Denied
            );
        }
        assert!(!port.is_sealed());
        assert_eq!(port.latched_request(), None);
        assert_eq!(
            port.get_exit_code(LifecyclePrincipal::Root),
            LifecycleGetDisposition::Value(0)
        );
    }

    #[test]
    fn synchronous_mirror_acknowledges_before_publishing_local_exit_code() {
        let port = SessionLifecyclePort::default();
        let observed = std::sync::Mutex::new(Vec::new());

        assert_eq!(
            port.set_exit_code_with_synchronous_mirror(LifecyclePrincipal::Root, 263, |status| {
                observed.lock().unwrap().push(status);
                false
            },),
            LifecycleSetDisposition::Denied
        );
        assert_eq!(
            port.get_exit_code(LifecyclePrincipal::Root),
            LifecycleGetDisposition::Value(0)
        );
        assert_eq!(&*observed.lock().unwrap(), &[normalize_exit_status(263)]);

        assert_eq!(
            port.set_exit_code_with_synchronous_mirror(LifecyclePrincipal::Root, -9, |status| {
                observed.lock().unwrap().push(status);
                true
            },),
            LifecycleSetDisposition::Accepted {
                status: normalize_exit_status(-9)
            }
        );
        assert_eq!(
            port.get_exit_code(LifecyclePrincipal::Root),
            LifecycleGetDisposition::Value(normalize_exit_status(-9))
        );

        port.seal();
        let called_after_seal = std::sync::atomic::AtomicBool::new(false);
        assert_eq!(
            port.set_exit_code_with_synchronous_mirror(LifecyclePrincipal::Root, 7, |_| {
                called_after_seal.store(true, std::sync::atomic::Ordering::Relaxed);
                true
            },),
            LifecycleSetDisposition::AlreadyInProgress
        );
        assert!(!called_after_seal.load(std::sync::atomic::Ordering::Relaxed));
    }
}
