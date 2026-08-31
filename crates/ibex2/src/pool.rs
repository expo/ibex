//! Workers for host tasks.
//!
//! An async host operation ran on a thread spawned for it and joined after —
//! tens of microseconds of the round trip a one-byte `fs.readFile` paid, and
//! one thread per in-flight request. This pool keeps a few workers alive,
//! grows on demand when every worker is busy — a burst of parallel fetches
//! must not serialize behind a fixed count, since a transport blocks its
//! worker while the request is in flight — and lets the extra workers go
//! after a quiet spell. Process-wide: a job carries its own runtime state.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

type Job = Box<dyn FnOnce() + Send + 'static>;

struct Pool {
    sender: Mutex<Sender<Job>>,
    receiver: Arc<Mutex<Receiver<Job>>>,
    /// Workers waiting for a job.
    idle: AtomicUsize,
    /// Workers alive.
    total: AtomicUsize,
}

/// Workers kept alive through a quiet spell, so the common case never spawns.
const KEEP: usize = 2;
/// The most workers a burst may grow to.
const MAX: usize = 64;
/// How long an extra worker waits for work before leaving.
const IDLE: Duration = Duration::from_secs(10);

static POOL: OnceLock<Pool> = OnceLock::new();

fn pool() -> &'static Pool {
    POOL.get_or_init(|| {
        let (sender, receiver) = mpsc::channel();
        Pool {
            sender: Mutex::new(sender),
            receiver: Arc::new(Mutex::new(receiver)),
            idle: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
        }
    })
}

/// Run `job` on a worker, spawning one if none is free and the cap allows.
pub fn run(job: impl FnOnce() + Send + 'static) {
    let pool = pool();
    pool.sender
        .lock()
        .expect("pool poisoned")
        .send(Box::new(job))
        .expect("the pool's receiver lives for the process");
    if pool.idle.load(Ordering::Acquire) == 0 && pool.total.load(Ordering::Acquire) < MAX {
        spawn_worker(pool);
    }
}

fn spawn_worker(pool: &'static Pool) {
    pool.total.fetch_add(1, Ordering::AcqRel);
    let receiver = Arc::clone(&pool.receiver);
    std::thread::Builder::new()
        .name("ibex2-host-task".into())
        .spawn(move || loop {
            pool.idle.fetch_add(1, Ordering::AcqRel);
            // The lock is held while waiting: the other idle workers queue on
            // it, and the first job goes to whoever holds the receiver.
            let next = receiver.lock().expect("pool poisoned").recv_timeout(IDLE);
            pool.idle.fetch_sub(1, Ordering::AcqRel);
            match next {
                Ok(job) => job(),
                Err(RecvTimeoutError::Timeout) => {
                    // Quiet: keep a few, let the rest go.
                    if pool.total.load(Ordering::Acquire) > KEEP {
                        pool.total.fetch_sub(1, Ordering::AcqRel);
                        return;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => {
                    pool.total.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
            }
        })
        .expect("spawn a host-task worker");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn jobs_run_and_a_burst_does_not_serialize() {
        let done = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        // Twelve jobs that each block for a moment: with workers spawned on
        // demand they overlap; serialized behind two they would take six
        // times as long.
        let start = std::time::Instant::now();
        for _ in 0..12 {
            let done = Arc::clone(&done);
            let tx = tx.clone();
            run(move || {
                std::thread::sleep(Duration::from_millis(50));
                done.fetch_add(1, Ordering::SeqCst);
                let _ = tx.send(());
            });
        }
        for _ in 0..12 {
            rx.recv_timeout(Duration::from_secs(5))
                .expect("a job finished");
        }
        assert_eq!(done.load(Ordering::SeqCst), 12);
        assert!(
            start.elapsed() < Duration::from_millis(250),
            "{:?}",
            start.elapsed()
        );
    }
}
