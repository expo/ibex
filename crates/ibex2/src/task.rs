//! Off-thread work, and the completion queue the engine drains.
//!
//! This is the Rust half of LLP 0058 OQ1 — how a Rust future completing off
//! the JavaScript thread resolves into the engine's job queue without
//! reordering relative to JavaScript-enqueued jobs.
//!
//! The shape, which is the part that matters:
//!
//! 1. A delegating op returns a promise immediately and does no work on the
//!    JavaScript thread.
//! 2. The work happens on some other thread. It never touches the engine —
//!    `jsi` values are not `Send`, and nothing here is allowed to hold one.
//! 3. Completions land in this queue, which is the only thing crossing threads.
//! 4. The embedder pumps on the JavaScript thread: take completions, resolve
//!    their promises, then drain microtasks.
//!
//! Step 4 is where the ordering guarantee lives, and it is stated in
//! `Pump::CONTRACT` rather than left implicit.
//!
//! @ref LLP 0058#3-the-part-that-cannot-move — the job queue this interleaves with
//! @ref LLP 0059.000#11-which-ops-are-synchronous — delegating ops are async, without exception

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};

use crate::boundary::{HostError, HostValue};

/// A completed unit of off-thread work, waiting to be delivered to the engine.
#[derive(Debug)]
pub struct Completion {
    pub task_id: u64,
    pub result: Result<HostValue, HostError>,
}

/// Completions waiting for **one** runtime.
///
/// Per-runtime, not process-global. A shared queue lets two runtimes in the
/// same process take each other's completions, and their task ids collide
/// because each numbers its own tasks from 1. That is not a theoretical
/// concern — it showed up the moment two runtimes existed at once.
#[derive(Debug, Default)]
pub struct CompletionQueue {
    ready: Mutex<VecDeque<Completion>>,
    /// Lets an embedder block until there is something to pump instead of
    /// spinning. A runtime that polls in a loop burns a core to do nothing,
    /// which is the default failure mode of this design.
    signal: Condvar,
}

impl CompletionQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a completion. Callable from any thread.
    pub fn complete(&self, task_id: u64, result: Result<HostValue, HostError>) {
        self.ready
            .lock()
            .expect("completion queue poisoned")
            .push_back(Completion { task_id, result });
        self.signal.notify_all();
    }

    /// Take the next completion, if any. Called on the JavaScript thread.
    ///
    /// FIFO, and deliberately so: two operations that complete in a given order
    /// are delivered in that order, so the ordering an application observes is
    /// the ordering that actually happened rather than a scheduling artifact.
    pub fn take(&self) -> Option<Completion> {
        self.ready
            .lock()
            .expect("completion queue poisoned")
            .pop_front()
    }

    pub fn len(&self) -> usize {
        self.ready.lock().expect("completion queue poisoned").len()
    }

    /// Block until at least one completion is ready, or the timeout elapses.
    ///
    /// This is what the Condvar is for. An embedder that polls in a loop burns
    /// a core to do nothing; one that blocks here wakes exactly when there is
    /// work. Returns whether anything is ready.
    pub fn wait(&self, timeout: std::time::Duration) -> bool {
        let ready = self.ready.lock().expect("completion queue poisoned");
        if !ready.is_empty() {
            return true;
        }
        let (ready, _) = self
            .signal
            .wait_timeout(ready, timeout)
            .expect("completion queue poisoned");
        !ready.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Everything one runtime owns on the Rust side.
///
/// Per-runtime for the reason C5 exists, and it holds the response registry as
/// well as the completion queue: a `Response` cannot cross the boundary as a
/// value, because §1.1 forbids serializing at the boundary and a `Response` is
/// a status, a header list, and a body. It crosses as a **handle** — the other
/// half of "primitives and handles" — and these are the objects the handle
/// refers to.
pub struct RuntimeState {
    pub queue: CompletionQueue,
    responses: Mutex<std::collections::HashMap<u64, crate::stdlib::fetch::Response>>,
    /// Header lists JavaScript holds by handle, for the same reason responses
    /// are: a header list is not a primitive and §1.1 forbids serializing.
    headers: Mutex<std::collections::HashMap<u64, crate::stdlib::fetch::Headers>>,
    /// The timer wheel (LLP 0059.000 §3.2). Rust owns *when*; the engine keeps
    /// the closures and owns *what*.
    timers: Mutex<crate::stdlib::timers::Timers>,
    /// The runtime's monotonic origin, so `now()` is milliseconds since boot —
    /// the same base `performance.now` will read (§2).
    started: std::time::Instant,
    /// Where modules are loaded from, and what each one may reach.
    loader: Mutex<Option<LoaderConfig>>,
    /// Work started on another thread and not yet delivered.
    ///
    /// Without this, "is the loop idle?" is answered by looking at the
    /// completion queue — which is empty both when there is nothing to do and
    /// when everything is still in flight. A program whose last act is a fetch
    /// would exit before its response arrived.
    in_flight: std::sync::atomic::AtomicUsize,
    next_handle: std::sync::atomic::AtomicU64,
    transport: Box<dyn crate::stdlib::fetch::Transport>,
}

impl RuntimeState {
    pub fn new(transport: Box<dyn crate::stdlib::fetch::Transport>) -> Self {
        Self {
            queue: CompletionQueue::new(),
            responses: Mutex::new(std::collections::HashMap::new()),
            headers: Mutex::new(std::collections::HashMap::new()),
            timers: Mutex::new(crate::stdlib::timers::Timers::new()),
            started: std::time::Instant::now(),
            loader: Mutex::new(None),
            in_flight: std::sync::atomic::AtomicUsize::new(0),
            next_handle: std::sync::atomic::AtomicU64::new(1),
            transport,
        }
    }

    pub fn transport(&self) -> &dyn crate::stdlib::fetch::Transport {
        self.transport.as_ref()
    }

    /// Park a response and return the handle JavaScript will hold.
    pub fn store_response(&self, response: crate::stdlib::fetch::Response) -> u64 {
        let handle = self
            .next_handle
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.responses
            .lock()
            .expect("response registry poisoned")
            .insert(handle, response);
        handle
    }

    pub fn with_response<T>(
        &self,
        handle: u64,
        f: impl FnOnce(&crate::stdlib::fetch::Response) -> T,
    ) -> Option<T> {
        self.responses
            .lock()
            .expect("response registry poisoned")
            .get(&handle)
            .map(f)
    }

    /// Take the response out, so its body can be moved rather than copied.
    pub fn take_response(&self, handle: u64) -> Option<crate::stdlib::fetch::Response> {
        self.responses
            .lock()
            .expect("response registry poisoned")
            .remove(&handle)
    }

    pub fn store_headers(&self, headers: crate::stdlib::fetch::Headers) -> u64 {
        let handle = self
            .next_handle
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.headers
            .lock()
            .expect("header registry poisoned")
            .insert(handle, headers);
        handle
    }

    pub fn with_headers<T>(
        &self,
        handle: u64,
        f: impl FnOnce(&crate::stdlib::fetch::Headers) -> T,
    ) -> Option<T> {
        self.headers
            .lock()
            .expect("header registry poisoned")
            .get(&handle)
            .map(f)
    }

    pub fn with_headers_mut<T>(
        &self,
        handle: u64,
        f: impl FnOnce(&mut crate::stdlib::fetch::Headers) -> T,
    ) -> Option<T> {
        self.headers
            .lock()
            .expect("header registry poisoned")
            .get_mut(&handle)
            .map(f)
    }

    pub fn drop_headers(&self, handle: u64) {
        self.headers
            .lock()
            .expect("header registry poisoned")
            .remove(&handle);
    }

    pub fn task_started(&self) {
        self.in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn task_finished(&self) {
        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Nothing queued, nothing in flight, no timer pending.
    pub fn is_idle(&self) -> bool {
        self.queue.is_empty()
            && self.in_flight.load(std::sync::atomic::Ordering::SeqCst) == 0
            && self.millis_until_next_timer().is_none()
    }

    /// Milliseconds since this runtime started.
    pub fn now(&self) -> f64 {
        self.started.elapsed().as_secs_f64() * 1000.0
    }

    pub fn set_timer(&self, delay_ms: f64, repeating: bool) -> u64 {
        let delay = std::time::Duration::from_secs_f64((delay_ms.max(0.0)) / 1000.0);
        self.timers
            .lock()
            .expect("timers poisoned")
            .set(self.now(), delay, repeating)
    }

    pub fn clear_timer(&self, handle: u64) {
        self.timers.lock().expect("timers poisoned").clear(handle);
    }

    /// The next timer due now, or none. One at a time: each fired timer is a
    /// separate task and the engine owes a microtask checkpoint between them.
    pub fn take_due_timer(&self) -> Option<u64> {
        let now = self.now();
        self.timers.lock().expect("timers poisoned").take_due(now)
    }

    /// Milliseconds until the next timer, for an embedder that wants to sleep
    /// exactly long enough rather than poll.
    pub fn millis_until_next_timer(&self) -> Option<f64> {
        let now = self.now();
        self.timers
            .lock()
            .expect("timers poisoned")
            .next_deadline()
            .map(|deadline| (deadline - now).max(0.0))
    }

    pub fn live_responses(&self) -> usize {
        self.responses
            .lock()
            .expect("response registry poisoned")
            .len()
    }
}

/// Where the loader reads from, and the authority it hands each module.
#[derive(Debug)]
pub struct LoaderConfig {
    pub root: std::path::PathBuf,
    pub grants: crate::loader::ModuleGrants,
    /// Compiles module wrappers ahead of time. Absent means source loading,
    /// which `rules/RULES.md` forbids for anything shippable and which exists
    /// only so a machine without hermesc can still run something.
    pub compiler: Option<crate::bytecode::Compiler>,
    /// Refuse to compile on demand: every module must already be built.
    pub precompiled_only: bool,
    /// Resolved specifier to artifact key, written by the build. When present,
    /// a module is found without reading or hashing its source.
    pub manifest: Option<crate::bytecode::Manifest>,
}

impl RuntimeState {
    pub fn set_loader(&self, config: LoaderConfig) {
        *self.loader.lock().expect("loader poisoned") = Some(config);
    }

    /// Resolve a specifier and produce the module's executable form.
    ///
    /// Resolution refuses anything outside the root before a file is opened, so
    /// a traversal is a loader error rather than a filesystem question. The
    /// second element is Hermes bytecode when a compiler is configured and
    /// wrapped source otherwise; the caller distinguishes them by the HBC
    /// magic rather than by asking.
    pub fn load_module(&self, from: &str, specifier: &str) -> Result<(String, Vec<u8>), String> {
        let guard = self.loader.lock().expect("loader poisoned");
        let config = guard.as_ref().ok_or("no loader configured")?;
        let resolved = crate::loader::resolve(&config.root, from, specifier)?;

        // The fast path: the build already said which artifact this is, so the
        // source file is never opened.
        if let (Some(compiler), Some(manifest)) = (&config.compiler, &config.manifest) {
            if let Some(key) = manifest.get(&resolved) {
                let bytes = compiler
                    .by_key(key)
                    .map_err(|e| format!("{resolved}: {e}"))?;
                return Ok((resolved, bytes));
            }
            if config.precompiled_only {
                return Err(format!("{resolved}: not in the build manifest"));
            }
        }

        let path = config.root.join(resolved.trim_start_matches("./"));
        let source = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;

        // The wrapper is built HERE, once, because it is what gets compiled —
        // the artifact is the wrapper, so a second definition of it elsewhere
        // would be a second definition of the thing the cache is keyed on.
        let wrapped = crate::loader::wrap(&source);

        match &config.compiler {
            Some(compiler) => {
                let bytes = if config.precompiled_only {
                    compiler.cached_only(&wrapped)
                } else {
                    compiler.compile(&wrapped)
                }
                .map_err(|e| format!("{resolved}: {e}"))?;
                Ok((resolved, bytes))
            }
            None => Ok((resolved, wrapped.into_bytes())),
        }
    }

    /// The authority for one module, as an owned handle the binding keeps.
    pub fn grants_for(&self, specifier: &str) -> Arc<crate::grant::GrantSet> {
        let guard = self.loader.lock().expect("loader poisoned");
        match guard.as_ref() {
            Some(config) => Arc::new(config.grants.for_module(specifier).clone()),
            None => Arc::new(crate::grant::GrantSet::none()),
        }
    }
}

/// Create a queue and hand ownership to the caller as a raw pointer.
///
/// # Safety
/// The result must be released exactly once with `ibex2_queue_destroy`.
#[no_mangle]
pub extern "C" fn ibex2_queue_create() -> *const RuntimeState {
    Arc::into_raw(Arc::new(RuntimeState::new(
        crate::transport::default_transport(),
    )))
}

/// # Safety
/// `queue` must come from `ibex2_queue_create` and not have been destroyed.
#[no_mangle]
pub unsafe extern "C" fn ibex2_queue_destroy(queue: *const RuntimeState) {
    if !queue.is_null() {
        drop(Arc::from_raw(queue));
    }
}

/// Borrow the runtime state without taking ownership.
///
/// # Safety
/// `state` must be a live pointer from `ibex2_queue_create`.
pub unsafe fn borrow_state<'a>(state: *const RuntimeState) -> Option<&'a RuntimeState> {
    if state.is_null() {
        None
    } else {
        Some(&*state)
    }
}

/// Borrow a queue pointer as an `Arc` without consuming the caller's reference.
///
/// # Safety
/// `queue` must be a live pointer from `ibex2_queue_create`.
pub(crate) unsafe fn clone_queue(queue: *const RuntimeState) -> Option<Arc<RuntimeState>> {
    if queue.is_null() {
        return None;
    }
    Arc::increment_strong_count(queue);
    Some(Arc::from_raw(queue))
}

/// The ordering contract an engine adapter must satisfy.
///
/// LLP 0058 OQ1 asks what exactly an adapter must guarantee. This is the
/// answer, stated so a second engine can be held to it:
///
/// **C1.** Resolving a promise from a completion enqueues a microtask; it does
/// not run the continuation inline. A host call must never re-enter JavaScript
/// beneath itself.
///
/// **C2.** After a pump delivers completions, every microtask they enqueued —
/// transitively — drains before the pump returns. A pump that leaves
/// microtasks queued has moved work into the next macrotask and changed the
/// order the application sees.
///
/// **C3.** Microtasks already queued by JavaScript before the pump drain
/// **before** any microtask a completion enqueues during it. Completions join
/// the back of the queue; they do not jump it.
///
/// **C4.** Completions are delivered in the order they were published (FIFO),
/// independent of how many the pump takes in one pass.
///
/// **C5.** A completion is delivered to the runtime that started it, and to no
/// other. Queues are per-runtime.
pub struct Pump;

impl Pump {
    pub const CONTRACT: &'static str =
        "C1 resolve enqueues, never re-enters; C2 pump drains transitively; \
         C3 pre-queued microtasks run first; C4 completions are FIFO; \
         C5 completions reach only the runtime that started them";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completions_come_back_in_publication_order() {
        let queue = CompletionQueue::new();
        queue.complete(1, Ok(HostValue::Number(1.0)));
        queue.complete(2, Ok(HostValue::Number(2.0)));
        queue.complete(3, Err(HostError::Failed("third".into())));

        assert_eq!(queue.take().unwrap().task_id, 1);
        assert_eq!(queue.take().unwrap().task_id, 2);
        let third = queue.take().unwrap();
        assert_eq!(third.task_id, 3);
        assert!(third.result.is_err());
        assert!(queue.take().is_none());
    }

    #[test]
    fn completions_published_from_another_thread_are_visible() {
        let queue = Arc::new(CompletionQueue::new());
        let worker = Arc::clone(&queue);
        std::thread::spawn(move || {
            worker.complete(99, Ok(HostValue::Str("from a worker".into())));
        })
        .join()
        .expect("worker thread");

        let completion = queue
            .take()
            .expect("a completion crossed the thread boundary");
        assert_eq!(completion.task_id, 99);
        assert_eq!(
            completion.result.unwrap(),
            HostValue::Str("from a worker".into())
        );
    }

    /// C5 — two queues do not see each other's work. This is the property whose
    /// absence made a global queue wrong.
    #[test]
    fn two_queues_do_not_steal_each_others_completions() {
        let first = CompletionQueue::new();
        let second = CompletionQueue::new();

        // Same task id in both, which is exactly what happens when two runtimes
        // each number their tasks from 1.
        first.complete(1, Ok(HostValue::Str("first".into())));
        second.complete(1, Ok(HostValue::Str("second".into())));

        assert_eq!(
            first.take().unwrap().result.unwrap(),
            HostValue::Str("first".into())
        );
        assert_eq!(
            second.take().unwrap().result.unwrap(),
            HostValue::Str("second".into())
        );
        assert!(first.take().is_none());
        assert!(second.take().is_none());
    }
}
