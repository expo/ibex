//! The vanilla Hermes adapter.
//!
//! Built only with the `hermes` feature, against `ios/Frameworks-vanilla/`.
//! It uses stock JSI and nothing else — see `hermes_shim.cc`.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

// RuntimeState crosses as an opaque pointer that only Rust ever dereferences;
// the C++ side treats it as `const void *`. clippy's improper_ctypes fires on
// the type name rather than on the usage.
#[allow(improper_ctypes)]
extern "C" {
    fn ibex2_hermes_create(enable_eval: c_int) -> *mut c_void;
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
    fn ibex2_hermes_free_string(value: *mut c_char);
    fn ibex2_hermes_install_stdlib(handle: *mut c_void) -> c_int;
    fn ibex2_hermes_pump(handle: *mut c_void) -> c_int;
    fn ibex2_hermes_drain_microtasks(handle: *mut c_void) -> c_int;
    fn ibex2_hermes_wait(handle: *mut c_void, timeout_ms: u64) -> c_int;
    fn ibex2_hermes_install_fetch(handle: *mut c_void, grants: *const c_void) -> c_int;
    fn ibex2_hermes_install_async_echo(handle: *mut c_void) -> c_int;
    fn ibex2_hermes_install_fetch_factory(
        handle: *mut c_void,
        bytes: *const u8,
        len: usize,
    ) -> c_int;
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
    fn ibex2_grants_create(spec: *const c_char) -> *const c_void;
    fn ibex2_grants_destroy(grants: *const c_void);
}

/// A grant set, owned for as long as the bindings that carry it.
pub struct Grants(*const c_void);

impl Grants {
    /// Parse a grant spec. See `GrantSet::parse`.
    pub fn parse(spec: &str) -> Option<Self> {
        let spec = CString::new(spec).ok()?;
        // SAFETY: the pointer is either null or an owned grant set.
        let raw = unsafe { ibex2_grants_create(spec.as_ptr()) };
        if raw.is_null() {
            return None;
        }
        Some(Self(raw))
    }
}

impl Drop for Grants {
    fn drop(&mut self) {
        // SAFETY: created here, released exactly once.
        unsafe { ibex2_grants_destroy(self.0) };
    }
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

/// A vanilla Hermes runtime.
pub struct Hermes {
    handle: *mut c_void,
}

/// What JavaScript threw, as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsError(pub String);

impl Hermes {
    pub fn new(dynamic_code: DynamicCode) -> Option<Self> {
        let enable = match dynamic_code {
            DynamicCode::Open => 1,
            DynamicCode::Closed => 0,
        };
        // SAFETY: the shim returns either null or a pointer we own until
        // ibex2_hermes_destroy, which Drop is the only other caller of.
        let handle = unsafe { ibex2_hermes_create(enable) };
        if handle.is_null() {
            return None;
        }
        Some(Self { handle })
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
        let text = take_c_string(out);
        match status {
            0 => Ok(text.unwrap_or_default()),
            1 => Err(JsError(text.unwrap_or_else(|| "unknown error".into()))),
            other => panic!("ibex2_hermes_eval returned {other}"),
        }
    }

    /// Evaluate the JavaScript binding preludes that SHIP.
    ///
    /// Source, not bytecode, for now — a production boot compiles these with
    /// hermesc so nothing is parsed at launch (LLP 0058 §1.1). They are small
    /// enough that it does not yet matter, and this is the seam where that
    /// changes.
    ///
    /// The test harness is deliberately not here. It used to be, and the
    /// LLP 0062 R5 global-name assertion caught it the first time the binary
    /// ran: fourteen assertion helpers were being published to every program's
    /// global object. That is the whole argument for R5 — R1 is a property of a
    /// list, and a list nothing checks drifts.
    pub fn install_bindings(&mut self) -> Result<(), JsError> {
        // Bytecode, compiled by build.rs from src/bindings/*.js with the
        // engine's own hermesc: the runtime parses nothing of its own at
        // start, which is the rule application code already lives under.
        for binding in [
            &include_bytes!(concat!(env!("OUT_DIR"), "/esm.hbc"))[..],
            &include_bytes!(concat!(env!("OUT_DIR"), "/headers.hbc"))[..],
            &include_bytes!(concat!(env!("OUT_DIR"), "/timers.hbc"))[..],
            &include_bytes!(concat!(env!("OUT_DIR"), "/url.hbc"))[..],
        ] {
            self.eval_bytes(binding)?;
        }
        // fetch.js is different: its value is the fetch factory, and it must
        // not be a global (see the file). The shim keeps it.
        let fetch = include_bytes!(concat!(env!("OUT_DIR"), "/fetch.hbc"));
        // SAFETY: `handle` is non-null for the lifetime of self; the bytes
        // outlive the call.
        let status =
            unsafe { ibex2_hermes_install_fetch_factory(self.handle, fetch.as_ptr(), fetch.len()) };
        if status != 0 {
            return Err(JsError("the fetch binding did not evaluate to its factory".into()));
        }
        Ok(())
    }

    /// The LLP 0067 R4 freeze, from bytecode: after the standard library and
    /// bindings are installed and before any module code runs.
    pub fn harden(&mut self) -> Result<(), JsError> {
        self.eval_bytes(include_bytes!(concat!(env!("OUT_DIR"), "/harden.hbc")))
            .map(|_| ())
    }

    /// The WPT test harness. Tests only; never installed by the binary.
    pub fn install_test_harness(&mut self) -> Result<(), JsError> {
        self.eval(include_str!("../bindings/testharness.js"))?;
        Ok(())
    }

    /// Install the pure standard-library tier: `console`, `btoa`/`atob`, and
    /// the text/URL host calls the binding layer will wrap.
    pub fn install_stdlib(&mut self) -> bool {
        // SAFETY: `handle` is non-null for the lifetime of self.
        unsafe { ibex2_hermes_install_stdlib(self.handle) == 0 }
    }

    /// Drain the console records this runtime's thread has queued.
    pub fn drain_console(&self) -> Vec<crate::stdlib::console::Record> {
        crate::boundary_abi::drain_console()
    }

    /// Run at most one host task, with a microtask checkpoint either side.
    ///
    /// One task per cycle, per LLP 0058.000.000 §8 — so this returns 0 or 1 and
    /// a caller wanting to reach quiescence loops.
    pub fn pump(&mut self) -> i32 {
        // SAFETY: `handle` is non-null for the lifetime of self, and this is
        // the JavaScript thread.
        unsafe { ibex2_hermes_pump(self.handle) }
    }

    /// Pump until `expected` host tasks have run, or the deadline passes.
    ///
    /// Blocks on the completion signal rather than spinning. The earlier
    /// version looped a fixed number of times yielding, which raced through
    /// 10,000 iterations in microseconds and gave up long before a real network
    /// request could finish — fine against a loopback socket, useless against
    /// NSURLSession.
    pub fn pump_until(&mut self, expected: i32) -> i32 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut delivered = 0;
        loop {
            delivered += self.pump().max(0);
            if delivered >= expected || std::time::Instant::now() >= deadline {
                return delivered;
            }
            // SAFETY: `handle` is non-null for the lifetime of self.
            unsafe { ibex2_hermes_wait(self.handle, 100) };
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
        let text = take_c_string(out).unwrap_or_default();
        if status == 0 {
            Ok(text)
        } else {
            Err(JsError(text))
        }
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
                    found.engine().unwrap_or("(a build that predates engine binding)")
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
        // SAFETY: `handle` is non-null for the lifetime of self.
        let state = unsafe { ibex2_hermes_state(self.handle) };
        // SAFETY: the state pointer belongs to this runtime and outlives the call.
        if let Some(state) = unsafe { crate::task::borrow_state(state) } {
            state.set_loader(crate::task::LoaderConfig {
                root,
                grants,
                compiler,
                precompiled_only,
                manifest,
                cache: Default::default(),
                bundle,
            });
        }
        Ok(())
    }

    /// Load and run an entry module. Its dependencies load through `require`.
    pub fn run_entry(&mut self, specifier: &str) -> Result<(), JsError> {
        let specifier = CString::new(specifier).expect("specifier contains a NUL");
        let mut error: *mut c_char = std::ptr::null_mut();
        // SAFETY: `handle` is non-null; `error` receives a Rust-owned string.
        let status = unsafe { ibex2_hermes_run_entry(self.handle, specifier.as_ptr(), &mut error) };
        let message = take_c_string(error);
        if status == 0 {
            Ok(())
        } else {
            Err(JsError(message.unwrap_or_else(|| "module failed".into())))
        }
    }

    /// Run the loop until nothing is pending: no completions, no timers.
    ///
    /// The embedder's turn, and the thing that makes a program with a
    /// `setTimeout` in it terminate at the right moment rather than early.
    pub fn run_to_quiescence(&mut self, budget: std::time::Duration) {
        let deadline = std::time::Instant::now() + budget;
        loop {
            self.pump();
            if std::time::Instant::now() >= deadline {
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
            let remaining = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis() as u64;
            let timeout = until_timer.unwrap_or(u64::MAX).min(remaining);
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
        let raw = self
            .eval("Object.getOwnPropertyNames(globalThis).sort().join(',')")
            .unwrap_or_default();
        raw.split(',').map(str::to_string).collect()
    }

    /// Install the `__ibex2_async_echo` op. Tests only: a delegating op with
    /// no transport behind it, for holding the pump to its ordering contract.
    pub fn install_async_echo(&mut self) -> bool {
        // SAFETY: `handle` is non-null for the lifetime of self.
        unsafe { ibex2_hermes_install_async_echo(self.handle) == 0 }
    }

    /// Install `fetch`, carrying `grants` for the lifetime of the binding.
    pub fn install_fetch(&mut self, grants: &Grants) -> bool {
        // SAFETY: both pointers outlive the call; the binding keeps its own
        // reference to the grants.
        unsafe { ibex2_hermes_install_fetch(self.handle, grants.0) == 0 }
    }

    /// Drain microtasks without delivering completions.
    pub fn drain_microtasks(&mut self) {
        // SAFETY: as above.
        unsafe { ibex2_hermes_drain_microtasks(self.handle) };
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
