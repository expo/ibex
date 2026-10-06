//! The vanilla Hermes adapter.
//!
//! Linked by this crate against the platform's unpatched vanilla Hermes lean
//! install.
//! It uses stock JSI and nothing else — see `hermes_shim.cc`.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::time::{Duration, Instant};

#[repr(C)]
struct CompiledScript {
    name: *const c_char,
    bytes: *const u8,
    len: usize,
}

// RuntimeState crosses as an opaque pointer that only Rust ever dereferences;
// the C++ side treats it as `const void *`. clippy's improper_ctypes fires on
// the type name rather than on the usage.
#[allow(improper_ctypes)]
extern "C" {
    fn ibex2_hermes_create(enable_eval: c_int, loader: *const c_void) -> *mut c_void;
    fn ibex2_hermes_destroy(handle: *mut c_void);
    fn ibex2_hermes_eval(
        handle: *mut c_void,
        source: *const c_char,
        out: *mut *mut c_char,
    ) -> c_int;
    fn ibex2_hermes_install_probe(
        handle: *mut c_void,
        name: *const c_char,
        value: *const c_char,
    ) -> c_int;
    fn ibex2_hermes_install_throwing_probe(
        handle: *mut c_void,
        name: *const c_char,
        native: c_int,
    ) -> c_int;
    fn ibex2_hermes_free_string(value: *mut c_char);
    fn ibex2_hermes_install_groups(
        handle: *mut c_void,
        groups: u16,
        bindings: *const crate::bindings::Ibex2Bindings,
        scripts: *const CompiledScript,
        script_count: usize,
        out_error: *mut *mut c_char,
    ) -> c_int;
    fn ibex2_hermes_install_groups_with_options(
        handle: *mut c_void,
        groups: u16,
        bindings: *const crate::bindings::Ibex2Bindings,
        scripts: *const CompiledScript,
        script_count: usize,
        fetch_primitives: *const c_char,
        abort_hooks: *const c_char,
        defer_intrinsic_snapshot: c_int,
        out_error: *mut *mut c_char,
    ) -> c_int;
    fn ibex2_hermes_capture_intrinsics(handle: *mut c_void, out_error: *mut *mut c_char) -> c_int;
    fn ibex2_hermes_verify_harden_preconditions(
        handle: *mut c_void,
        out_error: *mut *mut c_char,
    ) -> c_int;
    fn ibex2_hermes_prepare_runtime(handle: *mut c_void, groups: u16) -> c_int;
    fn ibex2_hermes_pump(handle: *mut c_void, out_ran: *mut c_int) -> c_int;
    fn ibex2_hermes_collect_garbage(handle: *mut c_void) -> c_int;
    fn ibex2_hermes_drain_microtasks(handle: *mut c_void, out: *mut *mut c_char) -> c_int;
    fn ibex2_hermes_set_deadline(handle: *mut c_void, remaining_nanos: u64) -> c_int;
    fn ibex2_hermes_clear_deadline(handle: *mut c_void) -> c_int;
    fn ibex2_hermes_wait(handle: *mut c_void, timeout_ms: u64) -> c_int;
    fn ibex2_hermes_install_async_echo(handle: *mut c_void) -> c_int;
    fn ibex2_hermes_state(handle: *mut c_void) -> *const crate::task::RuntimeState;
    fn ibex2_hermes_eval_bytes(
        handle: *mut c_void,
        data: *const u8,
        len: usize,
        out: *mut *mut c_char,
    ) -> c_int;
    fn ibex2_hermes_run_entry(
        handle: *mut c_void,
        specifier: *const c_char,
        out_error: *mut *mut c_char,
    ) -> c_int;
    #[cfg(test)]
    fn ibex2_hermes_test_subscribe(handle: *mut c_void, callback_name: *const c_char) -> u64;
    #[cfg(test)]
    fn ibex2_hermes_test_unsubscribe(handle: *mut c_void, subscription: u64);
    #[cfg(test)]
    fn ibex2_hermes_test_websocket_keepalive_count(handle: *mut c_void) -> usize;
}

/// Whether JavaScript may compile source of its own.
///
/// `Closed` is the Ibex 2 posture (LLP 0060 D4): with a Rust standard library
/// over an ahead-of-time bytecode graph, nothing on the boot path needs `eval`,
/// so it is refused at construction rather than latched off afterwards. `Open`
/// exists to make that difference testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicCode {
    Closed,
    Open,
}

/// Explicit trusted-bootstrap controls for one binding installation.
///
/// `fetch_primitives`, when set, names the global under which installation
/// publishes one frozen object. The name must be an ASCII JavaScript identifier,
/// `[A-Za-z_$][A-Za-z0-9_$]*`, that is not already a property of the global
/// object or its prototype chain and that no installed binding takes; anything
/// else is refused before the runtime is touched (an installed-binding collision
/// is found after installation and spends the runtime). The option requires the
/// [`crate::bindings::Groups::FETCH`] group.
///
/// `abort_hooks`, when set, follows the same name and collision rules, requires
/// [`crate::bindings::Groups::ABORT`], and publishes the frozen hook object
/// created by `abort.js`, with exactly `{ own, subscribe }`. `own(signal)`
/// returns the binding's private state for an Ibex AbortSignal and throws a
/// `TypeError` for another value. `subscribe(signal, callback[, alive])`
/// registers an abort algorithm and returns an idempotent unsubscribe function.
/// It invokes `callback` synchronously before the public abort event, or
/// immediately when the signal is already aborted. The optional `alive`
/// predicate is checked before delivery. An application listener's
/// `stopImmediatePropagation()` therefore cannot suppress this subscription.
///
/// `defer_intrinsic_snapshot`, when true, makes installation discard the
/// constructor-time SQLite integrity baseline after the selected bindings are
/// installed. The trusted embedder then runs its prelude and calls
/// [`Hermes::capture_intrinsics`] exactly once before [`Hermes::harden`]. Both
/// hardening and SQLite refuse while the baseline is absent. The default is
/// false. Application code may run only after hardening, so capture cannot be
/// moved after application code within the supported lifecycle.
///
/// CONTRACT: trusted embedder bootstrap only. Application code must never reach
/// either object or any member. Between installation and hardening, and before
/// any application code, the bootstrap captures each object, deletes its
/// global, and wraps the members in closures it publishes instead. It then
/// hardens through [`Hermes::harden`], which refuses (and freezes nothing)
/// while the global is still present or while the object or any member is
/// reachable from
/// what the freeze walks: the global object's own string- and symbol-keyed
/// properties, its prototype chain, and transitively each reached object's own
/// data values, accessor functions (never invoked), and prototype. Values held
/// only in closures, native state, collection entries, or behind a concealing
/// Proxy are outside that walk, so a wrapper must never hand `p` or a member to
/// application code.
///
/// Members (synchronous unless a Promise is named):
///
/// ```text
/// fetch(url, method, body, redirect, headersHandle, controlToken)
///     -> Promise<responseHandle>
/// responseField(responseHandle, fieldId[, headerName]) -> value
/// responseRead(responseHandle) -> Promise<ArrayBuffer | null>
/// fetchControl(action[, token]) -> token | undefined
/// textEncode(string) -> ArrayBuffer
/// textDecode(bytes[, fatal[, ignoreBOM]]) -> string
/// textEncodeInto(string, Uint8Array) -> "read,written"
/// headersFree(headersHandle) -> undefined
/// ```
///
/// `fetch` is async op 101 bound to the installation's endowment, so it has the
/// same `net.fetch` grants as the ordinary installed fetch. `url` is a string;
/// `method` a string or undefined (undefined or "" means GET; it is uppercased);
/// `body` undefined or null for none, or an ArrayBuffer or typed array whose
/// bytes are sent (a string must be encoded first). `redirect` is a string or
/// undefined: "manual" resolves with the 3xx response itself; "error" rejects on
/// a 3xx; anything else, undefined included, follows up to 20 redirects inside
/// the transport, admitting every hop against the same grants (an ungranted hop
/// rejects with "denied: net.fetch"), turning 303 and a non-GET/HEAD 301/302
/// into a bodiless GET, and dropping authorization, cookie, and
/// proxy-authorization on a cross-origin hop. `headersHandle` is undefined or a
/// live Headers registry handle (a standard `Headers` object's `_handle`); it is
/// validated first and from then on belongs to this object, so release it with
/// `headersFree` exactly once after the returned promise settles, even when a
/// later argument check throws. `controlToken` is undefined or a token from this
/// object's `fetchControl(0)`. The promise resolves to a response handle owned by
/// this object, or rejects with the host error text as message.
///
/// `responseField` field ids: 0 status (number), 1 ok (boolean), 2 final URL
/// (string), 3 one header value by `headerName`, a string (string, or null when
/// absent), 5 redirected (boolean), 7 every header as a JSON string of
/// `[name, value]` pairs sorted by name, 8 cancel: abort the body, drop the row,
/// release its control, and stop accepting the handle (returns undefined). Any
/// other id is a RangeError.
///
/// `responseRead` reads one chunk of 1 to 16384 bytes as an ArrayBuffer and
/// resolves null at end of body; await each read before issuing the next. Null
/// or a rejection (transport error or abort) is terminal: the row is dropped and
/// the handle is no longer accepted.
///
/// `fetchControl` actions: 0 allocates and returns a new token; 1 aborts the
/// request or body read using `token`; 2 releases `token`, which is then no
/// longer accepted. Any other action is a RangeError. Release every token once,
/// even after its response has finished.
///
/// The text members are UTF-8 operations 20-22 with the semantics of the
/// standard binding scripts; `headersFree` is op 51.
///
/// Ownership. Each published object is its own handle domain: it accepts only
/// response handles its `fetch` resolved, tokens its `fetchControl(0)`
/// allocated, and headers handles its `fetch` accepted, and only until they are
/// released. A handle from ordinary `fetch` or `Headers`, from another object, or
/// already released is a TypeError even when the id is live. Numeric arguments
/// are validated before conversion: a non-number is a TypeError; NaN, an
/// infinity, a fraction, or an out-of-range value is a RangeError (handles and
/// tokens 1 to 2^53 - 1, field ids 0 to 2^32 - 1, actions 0 to 2). Primitive
/// response rows have no garbage-collection owner: finish every response handle
/// with a null read, a rejected read, or field 8, or its row and connection stay
/// open until the runtime is destroyed.
///
/// Lifecycle (bootstrap source, evaluated after installation):
///
/// ```text
/// globalThis.embedderFetch = (function (p) {
///   delete globalThis.__embedder_fetch_primitives;   // capture, then delete
///   return function embedderFetch(url) {             // wrap: only closures hold p
///     var token = p.fetchControl(0);
///     return p.fetch(String(url), "GET", undefined, "follow", undefined, token)
///       .then(function (handle) {
///         var status = p.responseField(handle, 0);
///         p.responseField(handle, 8);                // done: cancel, drop the row
///         p.fetchControl(2, token);
///         return status;
///       }, function (error) { p.fetchControl(2, token); throw error; });
///   };
/// })(globalThis.__embedder_fetch_primitives);
/// ```
///
/// then [`Hermes::harden`] before any application code.
// @ref LLP 0068#opt-in-fetch-primitives-protocol — the normative L1e handoff protocol
// @ref LLP 0057.000#l1--the-bindings-door — L1e lets an embedder own its fetch layer without adding an authority path
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InstallOptions<'a> {
    pub fetch_primitives: Option<&'a str>,
    // @ref LLP 0068#opt-in-abort-hooks-protocol — abort algorithms cross only into trusted bootstrap
    pub abort_hooks: Option<&'a str>,
    // @ref LLP 0068#deferred-intrinsic-integrity-baseline — the trusted prelude establishes one complete baseline
    pub defer_intrinsic_snapshot: bool,
}

/// The one accepted spelling of a trusted-bootstrap global: an ASCII
/// JavaScript identifier, `[A-Za-z_$][A-Za-z0-9_$]*`. The C++ adapter applies
/// the same rule and builds every property key for the name with
/// `PropNameID::forAscii`, so the Rust string, the C++ string, and the
/// JavaScript key are one byte sequence.
fn bootstrap_output_name(kind: &str, name: &str) -> Result<CString, JsError> {
    if name.is_empty() {
        return Err(JsError::Thrown(format!(
            "{kind} require a non-empty global name"
        )));
    }
    let start = |byte: u8| byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$';
    let bytes = name.as_bytes();
    if !start(bytes[0])
        || !bytes[1..]
            .iter()
            .all(|&byte| start(byte) || byte.is_ascii_digit())
    {
        return Err(JsError::Thrown(format!(
            "{kind} global name must be an ASCII JavaScript identifier \
             ([A-Za-z_$][A-Za-z0-9_$]*)"
        )));
    }
    Ok(CString::new(name).expect("an ASCII identifier contains no NUL"))
}

/// A vanilla Hermes runtime.
pub struct Hermes {
    handle: *mut c_void,
    loader: Box<crate::loader_state::LoaderState>,
    installed_groups: Option<crate::bindings::Groups>,
    /// The armed deadline as this side handed it over. The engine holds the
    /// same point on its own clock and is what stops JavaScript; this copy
    /// is what the helpers that block *between* entrances cap their waits
    /// by, so that no wait outlives the deadline either.
    deadline: Option<Instant>,
}

/// Why an entrance returned no value.
///
/// The entrances are `eval`, `eval_bytes`, `drain_microtasks`, `pump`, and
/// `run_entry`: every way JavaScript runs on a runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsError {
    /// JavaScript threw, and this is what it threw, as text.
    Thrown(String),
    /// The deadline armed by [`Hermes::set_deadline`] passed: at the door, so
    /// nothing ran, or while JavaScript was running, so the engine stopped
    /// it. Reported by kind and never by the text of what was thrown — text
    /// is JavaScript's to forge. Nothing JavaScript did on the way to the
    /// deadline is reported, and its state is whatever the stop left.
    // @ref LLP 0058.000.000#8-tasks-microtasks-timers-and-callbacks — the one outcome a consumer may act on without reading text: classified by the clock, uncatchable in JavaScript
    Deadline,
}

impl std::fmt::Display for JsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsError::Thrown(text) => f.write_str(text),
            JsError::Deadline => f.write_str("the deadline passed"),
        }
    }
}

impl std::error::Error for JsError {}

/// What one entrance reported, with the string the shim handed back. The
/// statuses are the shim's IBEX2_STATUS_* constants; anything else is a
/// programming error on this side of the boundary, not a JavaScript outcome.
fn checked(status: c_int, out: *mut c_char, entrance: &str) -> Result<String, JsError> {
    let text = take_c_string(out);
    match status {
        0 => Ok(text.unwrap_or_default()),
        1 => Err(JsError::Thrown(
            text.unwrap_or_else(|| "unknown error".into()),
        )),
        2 => Err(JsError::Deadline),
        other => panic!("{entrance} returned {other}"),
    }
}

impl Hermes {
    /// Configure stable app mounts before evaluating application modules.
    pub fn set_app_directories(
        &self,
        directories: crate::stdlib::app_fs::AppDirectories,
    ) -> Result<(), crate::boundary::HostError> {
        let state = unsafe { crate::task::borrow_state(ibex2_hermes_state(self.handle)) }
            .expect("live runtime state");
        state.set_app_directories(directories)
    }
    /// Install a separately linked SQLite provider; no database opens at startup.
    pub fn set_sqlite_provider(
        &self,
        provider: std::sync::Arc<dyn crate::stdlib::sqlite::Provider>,
    ) -> Result<(), crate::boundary::HostError> {
        let state = unsafe { crate::task::borrow_state(ibex2_hermes_state(self.handle)) }
            .expect("live runtime state");
        state.set_sqlite_provider(provider)
    }

    pub fn new(dynamic_code: DynamicCode) -> Option<Self> {
        hermes_lean_sys::ensure_linked();
        let enable = match dynamic_code {
            DynamicCode::Open => 1,
            DynamicCode::Closed => 0,
        };
        let loader = Box::new(crate::loader_state::LoaderState::default());
        // SAFETY: the shim returns either null or a pointer we own until
        // ibex2_hermes_destroy, which Drop is the only other caller of.
        let handle = unsafe {
            ibex2_hermes_create(
                enable,
                (&*loader as *const crate::loader_state::LoaderState).cast(),
            )
        };
        if handle.is_null() {
            return None;
        }
        Some(Self {
            handle,
            loader,
            installed_groups: None,
            deadline: None,
        })
    }

    /// Evaluate source as the **host**. This is not JavaScript's `eval`: it
    /// stays available with `DynamicCode::Closed`, which is what lets a closed
    /// runtime still run prepared code.
    pub fn eval(&mut self, source: &str) -> Result<String, JsError> {
        let source = CString::new(source).expect("source contains a NUL byte");
        let mut out: *mut c_char = std::ptr::null_mut();
        // SAFETY: `handle` is non-null for the lifetime of self; `out` receives
        // a malloc'd string we take ownership of and free below.
        let status = unsafe { ibex2_hermes_eval(self.handle, source.as_ptr(), &mut out) };
        checked(status, out, "ibex2_hermes_eval")
    }

    /// Arm this runtime's one deadline, replacing any already armed.
    ///
    /// From now until [`clear_deadline`](Self::clear_deadline), every
    /// entrance — `eval`, `eval_bytes`, `drain_microtasks`, `pump`,
    /// `run_entry` — is refused with [`JsError::Deadline`] once the deadline
    /// has passed, and stopped with it if it passes while JavaScript runs.
    /// What each entrance is given is the time left of this same deadline,
    /// never a fresh budget per call or per drain iteration.
    ///
    /// The stop is the engine's own: the pinned Hermes's time-limit monitor
    /// raises an uncatchable error at the next async-break check, which
    /// evaluated source carries at every loop back-edge and every return.
    /// Bytecode carries only the checks it was compiled with, so a
    /// check-free program runs to its end and is reported at exit — a
    /// deadline is not, by itself, a bound on precompiled code, and an
    /// adapter running bytecode it does not trust with time needs a bound
    /// of its own.
    ///
    /// The deadline is a point on the monotonic clock. It crosses to the
    /// engine as the time left at this call, which the engine adds to its
    /// own monotonic clock — the same clock the `Instant` reads on this
    /// platform is not guaranteed, so the deadline cannot be handed over as
    /// an absolute value; the microseconds this costs are in the caller's
    /// favour.
    ///
    /// Owner thread only, like every entrance (LLP 0058.000.000 §2,
    /// invariant 8): the deadline is read at each entrance without
    /// synchronization, so arming or clearing it from another thread races
    /// an entrance in flight.
    // @ref LLP 0058.000.000#8-tasks-microtasks-timers-and-callbacks — one deadline per runtime; every entrance is given what is left of it, never a fresh budget
    pub fn set_deadline(&mut self, deadline: Instant) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let nanos = u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX);
        // SAFETY: `handle` is non-null for the lifetime of self.
        let status = unsafe { ibex2_hermes_set_deadline(self.handle, nanos) };
        assert_eq!(status, 0, "ibex2_hermes_set_deadline returned {status}");
        self.deadline = Some(deadline);
    }

    /// Disarm the deadline. A runtime whose deadline fired is usable again
    /// after this; its JavaScript state is whatever the stop left, which is
    /// the consumer's to judge (Snapback 2 discards the runtime). Harmless
    /// when nothing is armed. Owner thread only, as `set_deadline` says.
    // @ref LLP 0058.000.000#8-tasks-microtasks-timers-and-callbacks — a fired deadline leaves the runtime reusable once cleared; its pending break was flushed at the entrance that ended past it
    pub fn clear_deadline(&mut self) {
        // SAFETY: `handle` is non-null for the lifetime of self.
        let status = unsafe { ibex2_hermes_clear_deadline(self.handle) };
        assert_eq!(status, 0, "ibex2_hermes_clear_deadline returned {status}");
        self.deadline = None;
    }

    /// Cap a wait between entrances by the armed deadline. A helper that
    /// blocks must not outlive the deadline any more than an entrance may:
    /// the wait is cut to the time left, rounded up so it ends at or after
    /// the deadline and the next entrance is what reports it, and is zero
    /// once the deadline has passed.
    fn capped_by_deadline(&self, millis: u64) -> u64 {
        let Some(deadline) = self.deadline else {
            return millis;
        };
        let left = deadline.saturating_duration_since(Instant::now());
        let whole = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
        let ceil = whole.saturating_add(u64::from(left.subsec_nanos() % 1_000_000 != 0));
        millis.min(ceil)
    }

    /// Install named bindings into this runtime through the caller-owned JSI
    /// adapter. `context` is the library authority captured by global
    /// capability values; the adapter never parses a grant or infers one.
    ///
    /// The bytecode is compiled by `build.rs` with this engine's `hermesc` and
    /// is passed in exactly [`crate::bindings::scripts`] order. This call does
    /// not run a checkpoint, task, timer, or wait.
    // @ref LLP 0057.000#50-three-doors-one-implementation — the runtime calls the same bindings door an embedder calls
    pub fn install(
        &mut self,
        groups: crate::bindings::Groups,
        context: &crate::bindings::Context,
    ) -> Result<(), JsError> {
        self.install_with(groups, context, InstallOptions::default())
    }

    /// Install named bindings plus explicitly requested trusted-bootstrap
    /// outputs. This is the same one-shot adapter call as [`Self::install`].
    pub fn install_with(
        &mut self,
        groups: crate::bindings::Groups,
        context: &crate::bindings::Context,
        options: InstallOptions<'_>,
    ) -> Result<(), JsError> {
        if self.installed_groups.is_some() {
            return Err(JsError::Thrown(
                "the Ibex2 binding groups are already installed".into(),
            ));
        }
        if options.fetch_primitives.is_some() && !groups.contains(crate::bindings::Groups::FETCH) {
            return Err(JsError::Thrown(
                "fetch primitives require the FETCH group".into(),
            ));
        }
        if options.abort_hooks.is_some() && !groups.contains(crate::bindings::Groups::ABORT) {
            return Err(JsError::Thrown(
                "abort hooks require the ABORT group".into(),
            ));
        }
        if options.fetch_primitives.is_some() && options.fetch_primitives == options.abort_hooks {
            return Err(JsError::Thrown(
                "trusted-bootstrap outputs require distinct global names".into(),
            ));
        }
        let fetch_primitives = options
            .fetch_primitives
            .map(|name| bootstrap_output_name("fetch primitives", name))
            .transpose()?;
        let abort_hooks = options
            .abort_hooks
            .map(|name| bootstrap_output_name("abort hooks", name))
            .transpose()?;
        let scripts = crate::bindings::compiled_scripts(groups)
            .map_err(|error| JsError::Thrown(error.to_string()))?;
        let names: Vec<_> = scripts
            .iter()
            .map(|script| CString::new(script.name).expect("binding name contains NUL"))
            .collect();
        let compiled: Vec<_> = scripts
            .iter()
            .zip(&names)
            .map(|(script, name)| CompiledScript {
                name: name.as_ptr(),
                bytes: script.bytes.as_ptr(),
                len: script.bytes.len(),
            })
            .collect();
        let mut out: *mut c_char = std::ptr::null_mut();
        // SAFETY: the runtime is live; every byte/name span is static and the
        // context's Arc-backed endowment supplies the state and authority.
        let status = unsafe {
            if fetch_primitives.is_some()
                || abort_hooks.is_some()
                || options.defer_intrinsic_snapshot
            {
                ibex2_hermes_install_groups_with_options(
                    self.handle,
                    groups.bits(),
                    context.bindings_ptr(),
                    compiled.as_ptr(),
                    compiled.len(),
                    fetch_primitives
                        .as_ref()
                        .map_or(std::ptr::null(), |name| name.as_ptr()),
                    abort_hooks
                        .as_ref()
                        .map_or(std::ptr::null(), |name| name.as_ptr()),
                    c_int::from(options.defer_intrinsic_snapshot),
                    &mut out,
                )
            } else {
                ibex2_hermes_install_groups(
                    self.handle,
                    groups.bits(),
                    context.bindings_ptr(),
                    compiled.as_ptr(),
                    compiled.len(),
                    &mut out,
                )
            }
        };
        if status != 0 {
            return Err(JsError::Thrown(
                take_c_string(out).unwrap_or_else(|| "could not install Ibex2 bindings".into()),
            ));
        }
        self.installed_groups = Some(groups);
        Ok(())
    }

    /// Runtime bootstrap through the engine-independent bindings door. The
    /// loader's ESM helpers are runtime machinery, not a bindings group, and
    /// remain absent from caller-owned runtimes. Their slots are reserved
    /// before installation to preserve the shipping global insertion order.
    pub fn install_runtime(
        &mut self,
        groups: crate::bindings::Groups,
        context: &crate::bindings::Context,
    ) -> Result<(), JsError> {
        self.install_runtime_with(groups, context, InstallOptions::default())
    }

    /// Runtime bootstrap with the same trusted-bootstrap outputs supported by
    /// [`Self::install_with`]. Runtime-only ESM helpers are installed normally.
    pub fn install_runtime_with(
        &mut self,
        groups: crate::bindings::Groups,
        context: &crate::bindings::Context,
        options: InstallOptions<'_>,
    ) -> Result<(), JsError> {
        if self.installed_groups.is_some() {
            return Err(JsError::Thrown(
                "the Ibex2 binding groups are already installed".into(),
            ));
        }
        if options.fetch_primitives.is_some() && !groups.contains(crate::bindings::Groups::FETCH) {
            return Err(JsError::Thrown(
                "fetch primitives require the FETCH group".into(),
            ));
        }
        if options.abort_hooks.is_some() && !groups.contains(crate::bindings::Groups::ABORT) {
            return Err(JsError::Thrown(
                "abort hooks require the ABORT group".into(),
            ));
        }
        if options.fetch_primitives.is_some() && options.fetch_primitives == options.abort_hooks {
            return Err(JsError::Thrown(
                "trusted-bootstrap outputs require distinct global names".into(),
            ));
        }
        if let Some(name) = options.fetch_primitives {
            bootstrap_output_name("fetch primitives", name)?;
        }
        if let Some(name) = options.abort_hooks {
            bootstrap_output_name("abort hooks", name)?;
        }
        groups
            .validate()
            .map_err(|error| JsError::Thrown(error.to_string()))?;
        // SAFETY: the runtime is live and this creates only placeholder data
        // properties; the compiled helpers replace them below.
        if unsafe { ibex2_hermes_prepare_runtime(self.handle, groups.bits()) } != 0 {
            return Err(JsError::Thrown(
                "could not prepare the Ibex2 runtime globals".into(),
            ));
        }
        self.install_with(groups, context, options)?;
        self.eval_bytes(include_bytes!(concat!(env!("OUT_DIR"), "/esm.hbc")))?;
        Ok(())
    }

    pub fn installed_groups(&self) -> Option<crate::bindings::Groups> {
        self.installed_groups
    }

    /// Capture the complete intrinsic-integrity baseline after a trusted
    /// prelude when [`InstallOptions::defer_intrinsic_snapshot`] was selected.
    /// This succeeds exactly once, after installation and before hardening.
    /// The default installation path already captured at construction and
    /// therefore refuses this method.
    // @ref LLP 0068#deferred-intrinsic-integrity-baseline — one auditable transition from trusted prelude to fixed baseline
    pub fn capture_intrinsics(&mut self) -> Result<(), JsError> {
        let mut out: *mut c_char = std::ptr::null_mut();
        // SAFETY: the runtime and its bindings adapter are live; `out` receives
        // a malloc'd message that take_c_string owns on refusal.
        if unsafe { ibex2_hermes_capture_intrinsics(self.handle, &mut out) } != 0 {
            return Err(JsError::Thrown(take_c_string(out).unwrap_or_else(|| {
                "could not capture the deferred intrinsic snapshot".into()
            })));
        }
        Ok(())
    }

    /// The LLP 0067 R4 freeze, from bytecode: after the standard library and
    /// bindings are installed and before any module code runs.
    ///
    /// When [`InstallOptions`] published fetch primitives or abort hooks, this
    /// first runs the adapter's trusted-bootstrap guard (the same check as the
    /// C++ `Adapter::harden`) and refuses, without freezing anything, if a
    /// chosen global is still present or if a published object or member is
    /// reachable from what the freeze walks: the global object's own string-
    /// and symbol-keyed properties, its prototype chain, and transitively
    /// every reached object's own data values, accessor functions (never
    /// invoked), and prototype. A value held only in a closure, native state,
    /// a collection entry, or behind a concealing Proxy is invisible to that
    /// walk, as it is to the freeze itself.
    // @ref LLP 0068#opt-in-fetch-primitives-protocol — one guard for both doors; the walk mirrors harden.js
    pub fn harden(&mut self) -> Result<(), JsError> {
        let mut out: *mut c_char = std::ptr::null_mut();
        // SAFETY: the runtime is live; `out` receives a malloc'd message we
        // take ownership of on refusal.
        if unsafe { ibex2_hermes_verify_harden_preconditions(self.handle, &mut out) } != 0 {
            return Err(JsError::Thrown(take_c_string(out).unwrap_or_else(|| {
                "could not verify the hardening preconditions".into()
            })));
        }
        self.eval_bytes(crate::bindings::HARDEN_BYTECODE)
            .map(|_| ())
    }

    /// The WPT test harness. Tests only; never installed by the binary.
    pub fn install_test_harness(&mut self) -> Result<(), JsError> {
        self.eval(include_str!("../bindings/testharness.js"))?;
        Ok(())
    }

    /// Ask the engine to collect unreachable objects and their native resources.
    /// Normal execution uses the engine's own collection schedule.
    pub fn collect_garbage(&mut self) -> bool {
        // SAFETY: the handle is live and this is the owning JavaScript thread.
        unsafe { ibex2_hermes_collect_garbage(self.handle) == 0 }
    }

    #[cfg(test)]
    pub(crate) fn subscribe_test_event(&mut self, callback_name: &str) -> u64 {
        let callback_name = CString::new(callback_name).expect("callback name contains NUL");
        // SAFETY: the runtime is live and the callback name remains valid for
        // the call. The adapter roots the callback it finds.
        unsafe { ibex2_hermes_test_subscribe(self.handle, callback_name.as_ptr()) }
    }

    #[cfg(test)]
    pub(crate) fn publish_test_event(
        &self,
        subscription: u64,
        payload: crate::boundary::HostValue,
    ) -> bool {
        // SAFETY: an owned Hermes handle retains its runtime state.
        let state =
            unsafe { ibex2_hermes_state(self.handle).as_ref() }.expect("live Hermes runtime state");
        state.publish_event(subscription, payload)
    }

    #[cfg(test)]
    pub(crate) fn unsubscribe_test_event(&mut self, subscription: u64) {
        // SAFETY: owner-thread call on the live adapter.
        unsafe { ibex2_hermes_test_unsubscribe(self.handle, subscription) }
    }

    #[cfg(test)]
    pub(crate) fn websocket_keepalive_count_for_test(&self) -> usize {
        // SAFETY: the runtime is live and tests call this on its owner thread.
        unsafe { ibex2_hermes_test_websocket_keepalive_count(self.handle) }
    }

    /// Number of Rust `Headers` registry entries owned by this runtime.
    ///
    /// Test instrumentation for checking that binding-internal snapshots are
    /// released; applications must not use registry counts as an API.
    #[doc(hidden)]
    pub fn live_header_handles_for_test(&self) -> usize {
        // SAFETY: the runtime owns this state for the lifetime of `self`.
        let state =
            unsafe { ibex2_hermes_state(self.handle).as_ref() }.expect("live Hermes runtime state");
        state.live_headers()
    }

    /// Number of Rust-side `CryptoKey` handles held by this runtime.
    /// Used to witness garbage-collection release in integration tests.
    #[doc(hidden)]
    pub fn crypto_key_count(&self) -> usize {
        // SAFETY: the runtime owns this state for the lifetime of `self`.
        let state =
            unsafe { ibex2_hermes_state(self.handle).as_ref() }.expect("live Hermes runtime state");
        state.crypto_key_count()
    }

    /// Drain the console records this runtime's thread has queued.
    pub fn drain_console(&self) -> Vec<crate::stdlib::console::Record> {
        crate::boundary_abi::drain_console()
    }

    /// Run at most one host task, with a microtask checkpoint either side.
    ///
    /// One task per cycle, per LLP 0058.000.000 §8 — so this returns 0 or 1 and
    /// a caller wanting to reach quiescence loops. A callback or job that
    /// throws is a console error, never a return: one bad task does not stop
    /// the tasks behind it. The deadline does, and is the only `Err`.
    pub fn pump(&mut self) -> Result<i32, JsError> {
        let mut ran: c_int = 0;
        // SAFETY: `handle` is non-null for the lifetime of self, and this is
        // the JavaScript thread.
        let status = unsafe { ibex2_hermes_pump(self.handle, &mut ran) };
        match status {
            0 => Ok(ran),
            2 => Err(JsError::Deadline),
            other => panic!("ibex2_hermes_pump returned {other}"),
        }
    }

    /// Pump until `expected` host tasks have run, the armed deadline passes,
    /// or thirty seconds go by.
    ///
    /// Blocks on the completion signal rather than spinning. The earlier
    /// version looped a fixed number of times yielding, which raced through
    /// 10,000 iterations in microseconds and gave up long before a real network
    /// request could finish — fine against a loopback socket, useless against
    /// NSURLSession.
    ///
    /// Under an armed deadline no wait outlives it: the deadline ends this
    /// loop as it ends any entrance, and what was delivered by then is the
    /// answer. The count does not say which of the three ended the loop; a
    /// caller that must tell the deadline from the rest checks its own clock
    /// against the deadline it armed.
    pub fn pump_until(&mut self, expected: i32) -> i32 {
        let give_up = Instant::now() + Duration::from_secs(30);
        let mut delivered = 0;
        loop {
            match self.pump() {
                Ok(ran) => delivered += ran.max(0),
                // The runtime's own deadline: what was delivered is the answer.
                Err(_) => return delivered,
            }
            if delivered >= expected || Instant::now() >= give_up {
                return delivered;
            }
            let wait = self.capped_by_deadline(100);
            // SAFETY: `handle` is non-null for the lifetime of self.
            unsafe { ibex2_hermes_wait(self.handle, wait) };
        }
    }

    /// Evaluate a buffer, which may be Hermes bytecode.
    ///
    /// Hermes detects the HBC magic, so this is the same entry point as source
    /// with a different payload.
    pub fn eval_bytes(&mut self, bytes: &[u8]) -> Result<String, JsError> {
        let mut out: *mut c_char = std::ptr::null_mut();
        // SAFETY: the slice outlives the call; `out` receives an owned string.
        let status =
            unsafe { ibex2_hermes_eval_bytes(self.handle, bytes.as_ptr(), bytes.len(), &mut out) };
        checked(status, out, "ibex2_hermes_eval_bytes")
    }

    /// Point the loader at a project root and its grant manifest.
    ///
    /// Without a compiler the loader falls back to source, which
    /// `rules/RULES.md` forbids for anything shippable; see `set_loader_with`.
    pub fn set_loader(
        &mut self,
        root: crate::loader::Root,
        grants: crate::loader::ModuleGrants,
    ) -> Result<(), String> {
        self.set_loader_with(root, grants, None, false)
    }

    /// Point the loader at a root, with ahead-of-time compilation.
    ///
    /// Fails when the manifest cannot be bound to the root — a package section
    /// naming something not installed — because a manifest that silently
    /// grants nothing is worse than one refused.
    pub fn set_loader_with(
        &mut self,
        root: crate::loader::Root,
        mut grants: crate::loader::ModuleGrants,
        compiler: Option<crate::bytecode::Compiler>,
        precompiled_only: bool,
    ) -> Result<(), String> {
        grants.bind(root.path())?;
        let cache = root.join(".ibex2/cache");
        let mut manifest = compiler
            .as_ref()
            .and_then(|_| crate::bytecode::Manifest::read(&cache));
        // Artifacts are bytecode for one engine. A manifest built by another
        // binary would still resolve by key and hand this engine bytecode it
        // may not accept — so the manifest carries the engine it was built
        // for, and this is where it is checked, before any module loads.
        if let Some(found) = &manifest {
            let linked = crate::bytecode::Compiler::linked_engine();
            let stale = match found.engine() {
                Some(built_for) => built_for != linked,
                None => true,
            };
            if stale && precompiled_only {
                return Err(format!(
                    "the precompiled artifacts under {} were built for another engine\n  \
                     built for: {}\n  this runtime links: {linked}\n\
                     Run `ibex2 build` again with this binary.",
                    cache.display(),
                    found
                        .engine()
                        .unwrap_or("(a build that predates engine binding)")
                ));
            }
            if stale {
                manifest = None;
            }
        }
        // The bundle is read only behind an accepted manifest: its keys are the
        // manifest's, and a manifest refused above takes its bundle with it.
        let bundle = manifest
            .as_ref()
            .and_then(|_| crate::bytecode::Bundle::read(&cache));
        self.loader.set(crate::loader_state::LoaderConfig {
            root,
            grants,
            compiler,
            precompiled_only,
            manifest,
            cache: Default::default(),
            bundle,
        });
        Ok(())
    }

    /// Load and run an entry module. Its dependencies load through `require`.
    pub fn run_entry(&mut self, specifier: &str) -> Result<(), JsError> {
        let specifier = CString::new(specifier).expect("specifier contains a NUL");
        let mut error: *mut c_char = std::ptr::null_mut();
        // SAFETY: `handle` is non-null; `error` receives a Rust-owned string.
        let status = unsafe { ibex2_hermes_run_entry(self.handle, specifier.as_ptr(), &mut error) };
        let message = take_c_string(error);
        match status {
            0 => Ok(()),
            1 => Err(JsError::Thrown(
                message.unwrap_or_else(|| "module failed".into()),
            )),
            2 => Err(JsError::Deadline),
            other => panic!("ibex2_hermes_run_entry returned {other}"),
        }
    }

    /// Run the loop until nothing is pending: no completions, no timers —
    /// or until `budget` or the armed deadline passes.
    ///
    /// The embedder's turn, and the thing that makes a program with a
    /// `setTimeout` in it terminate at the right moment rather than early.
    ///
    /// Under an armed deadline no wait outlives it: the deadline ends this
    /// loop as it ends any entrance. Returning says nothing about which of
    /// the three ended it; a caller that must tell the deadline from
    /// quiescence checks its own clock against the deadline it armed.
    pub fn run_to_quiescence(&mut self, budget: Duration) {
        let give_up = Instant::now() + budget;
        loop {
            // The runtime's own deadline, if one is armed, ends the loop too.
            if self.pump().is_err() {
                return;
            }
            if Instant::now() >= give_up {
                return;
            }
            // SAFETY: `handle` is non-null for the lifetime of self.
            let state = unsafe { ibex2_hermes_state(self.handle) };
            let idle = unsafe { crate::task::borrow_state(state) }
                .map(|s| s.is_idle())
                .unwrap_or(true);
            if idle {
                return;
            }
            // Wait for the next thing that can make work: a completion, which
            // signals the Condvar, or the next timer's deadline. Exactly what
            // the Condvar in `CompletionQueue` is for — this loop used to sleep
            // 1 ms and poll, which put up to a millisecond of latency on every
            // async round trip (issues/20260829-async-host-op-spawns-a-thread.md).
            let until_timer = unsafe { crate::task::borrow_state(state) }
                .and_then(|s| s.millis_until_next_timer())
                .map(|ms| ms.ceil() as u64);
            let remaining = give_up
                .saturating_duration_since(Instant::now())
                .as_millis() as u64;
            let timeout = self.capped_by_deadline(until_timer.unwrap_or(u64::MAX).min(remaining));
            if timeout == 0 {
                continue;
            }
            // SAFETY: `handle` is non-null for the lifetime of self.
            unsafe { ibex2_hermes_wait(self.handle, timeout) };
        }
    }

    /// The global names a module can see.
    ///
    /// LLP 0062 R5: R1 is a property of a list, and a list nothing checks
    /// drifts. This is what makes the check mechanical.
    pub fn global_names(&mut self) -> Vec<String> {
        let mut names = self.global_names_in_order();
        names.sort();
        names
    }

    /// The global names in JavaScript's specified property insertion order.
    pub fn global_names_in_order(&mut self) -> Vec<String> {
        let raw = self
            .eval("Object.getOwnPropertyNames(globalThis).join('\\n')")
            .unwrap_or_default();
        raw.split('\n').map(str::to_string).collect()
    }

    /// Install the `__ibex2_async_echo` op. Tests only: a delegating op with
    /// no transport behind it, for holding the pump to its ordering contract.
    pub fn install_async_echo(&mut self) -> bool {
        // SAFETY: `handle` is non-null for the lifetime of self.
        unsafe { ibex2_hermes_install_async_echo(self.handle) == 0 }
    }

    /// Drain microtasks without delivering completions.
    ///
    /// A job that throws out of the queue is `Thrown` — only an engine-raised
    /// error can, since Promise reactions and `queueMicrotask` catch their own
    /// — and the deadline is `Deadline`.
    pub fn drain_microtasks(&mut self) -> Result<(), JsError> {
        let mut out: *mut c_char = std::ptr::null_mut();
        // SAFETY: as above; `out` receives an owned string.
        let status = unsafe { ibex2_hermes_drain_microtasks(self.handle, &mut out) };
        checked(status, out, "ibex2_hermes_drain_microtasks").map(|_| ())
    }

    /// Install a zero-argument host function returning a fixed string.
    ///
    /// A placeholder for the real boundary, present to prove the LLP 0058
    /// requirement-2 path works on stock JSI before anything is built on it.
    pub fn install_probe(&mut self, name: &str, value: &str) -> bool {
        let name = CString::new(name).expect("name contains a NUL byte");
        let value = CString::new(value).expect("value contains a NUL byte");
        // SAFETY: both pointers outlive the call; the shim copies what it keeps.
        unsafe { ibex2_hermes_install_probe(self.handle, name.as_ptr(), value.as_ptr()) == 0 }
    }

    /// Install a zero-argument host function that throws `"<name> threw"`:
    /// natively, as a `std::runtime_error` the engine translates into a
    /// JavaScript error, or as a JavaScript error outright. Tests only — it
    /// is how the pump is held to its contract for a task that fails.
    pub fn install_throwing_probe(&mut self, name: &str, native: bool) -> bool {
        let name = CString::new(name).expect("name contains a NUL byte");
        // SAFETY: the pointer outlives the call; the shim copies what it keeps.
        unsafe {
            ibex2_hermes_install_throwing_probe(self.handle, name.as_ptr(), c_int::from(native))
                == 0
        }
    }
}

fn take_c_string(raw: *mut c_char) -> Option<String> {
    if raw.is_null() {
        return None;
    }
    // SAFETY: the shim malloc'd this and transferred ownership to us.
    let text = unsafe { CStr::from_ptr(raw) }
        .to_string_lossy()
        .into_owned();
    unsafe { ibex2_hermes_free_string(raw) };
    Some(text)
}

impl Drop for Hermes {
    fn drop(&mut self) {
        // SAFETY: constructed non-null, destroyed exactly once.
        unsafe { ibex2_hermes_destroy(self.handle) };
    }
}

#[cfg(test)]
#[path = "hermes_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "hermes_deadline_tests.rs"]
mod deadline_tests;
