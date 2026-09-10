use super::*;
use crate::{boundary_abi::ibex2_host_release, task::HostTask};
use std::{
    ptr,
    time::{Duration, Instant},
};

struct Fixture {
    state: Arc<RuntimeState>,
    grants: Arc<GrantSet>,
    owners: Vec<*mut c_void>,
    tickets: Vec<*mut c_void>,
}
impl Fixture {
    fn new() -> Self {
        let state = Arc::new(RuntimeState::new(crate::transport::default_transport()));
        state.processes.enable().unwrap();
        Self {
            state,
            grants: Arc::new(GrantSet::parse("process.spawn /bin/sh").unwrap()),
            owners: vec![],
            tickets: vec![],
        }
    }
    fn prepare(&mut self) -> *mut c_void {
        self.prepare_script("printf abcdef")
    }
    fn prepare_script(&mut self, script: &str) -> *mut c_void {
        let values = [
            HostValue::Number(0.),
            HostValue::Number(0.),
            HostValue::Number(0.),
            HostValue::Str("/bin/sh".into()),
            HostValue::Str("/".into()),
            HostValue::Number(2.),
            HostValue::Str("-c".into()),
            HostValue::Str(script.into()),
            HostValue::Number(0.),
        ];
        let mut args: Vec<_> = values.into_iter().map(leak_value).collect();
        let mut out = leak_value(HostValue::Undefined);
        let owner = unsafe {
            ibex2_process_prepare(
                Arc::as_ptr(&self.state),
                Arc::as_ptr(&self.grants),
                args.as_ptr(),
                args.len(),
                &mut out,
            )
        };
        for arg in &mut args {
            unsafe { ibex2_host_release(arg) };
        }
        assert!(!owner.is_null(), "prepare failed");
        unsafe { ibex2_host_release(&mut out) };
        self.owners.push(owner);
        owner
    }
    fn begin(&mut self, owner: *mut c_void, op: u32, size: Option<usize>) -> Result<(), String> {
        let args: Vec<_> = size
            .into_iter()
            .map(|n| leak_value(HostValue::Number(n as f64)))
            .collect();
        let mut out = leak_value(HostValue::Undefined);
        let ticket = unsafe {
            ibex2_process_begin(
                Arc::as_ptr(&self.state),
                owner,
                op,
                args.as_ptr(),
                args.len(),
                self.tickets.len() as u64,
                &mut out,
            )
        };
        let error = if ticket.is_null() {
            match unsafe { out.borrow() }.unwrap() {
                HostArg::Str(s) => Some(s.to_owned()),
                _ => panic!("missing failure"),
            }
        } else {
            self.tickets.push(ticket);
            None
        };
        unsafe { ibex2_host_release(&mut out) };
        error.map_or(Ok(()), Err)
    }
    fn queued(&self, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.state.queue.len() != count {
            assert!(Instant::now() < deadline, "completion did not arrive");
            std::thread::yield_now();
        }
    }
    fn consume(&mut self) -> HostValue {
        let Some(HostTask::Settlement(completion)) = self.state.queue.take() else {
            panic!("no settlement")
        };
        unsafe {
            ibex2_process_ticket_destroy(std::mem::replace(
                &mut self.tickets[completion.task_id as usize],
                ptr::null_mut(),
            ))
        };
        completion.result.unwrap()
    }
}

#[test]
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn shutdown_reaps_children_while_the_shared_host_pool_is_blocked() {
    // Other unit tests also saturate the process-global pool. A fresh test
    // process keeps this real saturation deterministic without altering it.
    if std::env::var_os("IBEX_PROCESS_POOL_TEST").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process_abi::tests::shutdown_reaps_children_while_the_shared_host_pool_is_blocked",
                "--nocapture",
            ])
            .env("IBEX_PROCESS_POOL_TEST", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let mut f = Fixture::new();
    let owner = f.prepare_script("exec /bin/sleep 30");
    f.begin(owner, 0, None).unwrap();
    f.queued(1);
    let HostValue::Number(pid) = f.consume() else {
        panic!("missing pid")
    };
    let wake = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let (entered, waiting) = std::sync::mpsc::channel();
    for _ in 0..64 {
        let wake = wake.clone();
        let entered = entered.clone();
        crate::pool::run(move || {
            let _ = entered.send(());
            let (lock, changed) = &*wake;
            let _guard = changed
                .wait_while(lock.lock().unwrap(), |released| !*released)
                .unwrap();
        });
    }
    let saturated = (0..64).all(|_| waiting.recv_timeout(Duration::from_secs(5)).is_ok());
    f.state.shutdown();
    let deadline = Instant::now() + Duration::from_secs(2);
    let entry = unsafe { &*owner.cast::<Owner>() }.entry.clone();
    while !entry.closed.load(Ordering::Acquire) && Instant::now() < deadline {
        std::thread::yield_now();
    }
    let closed_while_blocked = entry.closed.load(Ordering::Acquire);
    let (lock, changed) = &*wake;
    *lock.lock().unwrap() = true;
    changed.notify_all();
    assert!(saturated, "failed to occupy all shared host workers");
    assert!(closed_while_blocked, "cleanup queued behind unrelated I/O");
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.state.shutdown();
        for owner in self.owners.drain(..) {
            unsafe { ibex2_process_owner_destroy(owner) };
        }
        for ticket in self.tickets.drain(..) {
            unsafe { ibex2_process_ticket_destroy(ticket) };
        }
    }
}

#[test]
fn undelivered_completions_hold_the_global_admission_limit() {
    let mut f = Fixture::new();
    for n in 1..=MAX_TASKS {
        let owner = f.prepare();
        // Cancel a prepared request without launching. Closed owners no longer
        // occupy the child limit, but their undelivered tickets must still count.
        f.begin(owner, 6, None).unwrap();
        f.queued(n);
    }
    let owner = f.prepare();
    assert!(f
        .begin(owner, 6, None)
        .unwrap_err()
        .contains("completion limit"));
    assert_eq!(f.state.processes.tasks.load(Ordering::Acquire), MAX_TASKS);
    assert_eq!(f.state.queue.len(), MAX_TASKS);
    f.consume();
    assert_eq!(
        f.state.processes.tasks.load(Ordering::Acquire),
        MAX_TASKS - 1
    );
    f.begin(owner, 6, None).unwrap();
    f.queued(MAX_TASKS);
}

#[test]
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn completed_read_stays_busy_until_its_completion_is_consumed() {
    let mut f = Fixture::new();
    let owner = f.prepare();
    f.begin(owner, 0, None).unwrap();
    f.queued(1);
    assert!(matches!(f.consume(), HostValue::Number(_)));
    f.begin(owner, 1, Some(3)).unwrap();
    f.queued(1);
    assert!(f
        .begin(owner, 1, Some(3))
        .unwrap_err()
        .contains("already pending"));
    assert_eq!(f.state.queue.len(), 1);
    assert!(matches!(f.consume(), HostValue::Bytes(b) if b == b"abc"));
    f.begin(owner, 1, Some(3)).unwrap();
    f.queued(1);
    assert!(matches!(f.consume(), HostValue::Bytes(b) if b == b"def"));
    f.begin(owner, 6, None).unwrap();
    f.queued(1);
    f.consume();
}
