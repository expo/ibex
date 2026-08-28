//! The vanilla Hermes adapter.
//!
//! Built only with the `hermes` feature, against `ios/Frameworks-vanilla/`.
//! It uses stock JSI and nothing else — see `hermes_shim.cc`.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

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
    fn ibex2_hermes_install_fetch(handle: *mut c_void, grants: *const c_void) -> c_int;
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

    /// Deliver every ready completion, then drain microtasks to quiescence.
    ///
    /// Returns how many completions were delivered. This is the embedder's
    /// step: on a real event loop it runs once per turn.
    pub fn pump(&mut self) -> i32 {
        // SAFETY: `handle` is non-null for the lifetime of self, and this is
        // the JavaScript thread.
        unsafe { ibex2_hermes_pump(self.handle) }
    }

    /// Pump until `expected` completions have been delivered.
    ///
    /// Work runs on other threads, so a single pump may find the queue empty.
    /// Real embedders block on the completion signal; this yields, which keeps
    /// the tests honest about the fact that completion is genuinely concurrent.
    pub fn pump_until(&mut self, expected: i32) -> i32 {
        let mut delivered = 0;
        for _ in 0..10_000 {
            delivered += self.pump().max(0);
            if delivered >= expected {
                break;
            }
            std::thread::yield_now();
        }
        delivered
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
mod tests {
    use super::*;

    #[test]
    fn host_evaluation_works() {
        let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
        assert_eq!(rt.eval("1 + 1").unwrap(), "2");
        assert_eq!(rt.eval("'ibex' + 2").unwrap(), "ibex2");
    }

    #[test]
    fn a_javascript_throw_is_reported_not_swallowed() {
        let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
        let err = rt.eval("throw new Error('boom')").unwrap_err();
        assert!(err.0.contains("boom"), "unexpected error text: {}", err.0);
    }

    /// LLP 0060 D4: closed at construction, and the closure is real.
    #[test]
    fn dynamic_code_is_closed_at_construction() {
        let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");

        let eval_err = rt.eval("eval('1 + 1')").unwrap_err();
        assert!(
            !eval_err.0.is_empty(),
            "eval should have been refused outright"
        );

        let fn_err = rt.eval("new Function('return 1')()").unwrap_err();
        assert!(
            !fn_err.0.is_empty(),
            "the Function constructor should have been refused too"
        );

        // The point of closing at construction rather than latching: the host
        // can still run prepared code in the very same runtime.
        assert_eq!(rt.eval("40 + 2").unwrap(), "42");
    }

    /// The control. Without this, the test above could pass because `eval` is
    /// broken for some unrelated reason rather than because we closed it.
    #[test]
    fn dynamic_code_is_available_when_left_open() {
        let mut rt = Hermes::new(DynamicCode::Open).expect("runtime");
        assert_eq!(rt.eval("eval('1 + 1')").unwrap(), "2");
        assert_eq!(rt.eval("new Function('return 7')()").unwrap(), "7");
    }

    /// LLP 0058 requirement 2 — host functions over stock JSI, no patch needed.
    #[test]
    fn a_host_function_is_reachable_from_javascript() {
        let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
        assert!(rt.install_probe("__ibex2_probe", "from-rust"));
        assert_eq!(rt.eval("__ibex2_probe()").unwrap(), "from-rust");
    }

    fn with_stdlib() -> Hermes {
        let mut rt = Hermes::new(DynamicCode::Closed).expect("runtime");
        assert!(rt.install_stdlib(), "stdlib install failed");
        // Each test gets a clean queue; the console buffer is per-thread and
        // Rust's test harness reuses threads.
        let _ = rt.drain_console();
        rt
    }

    #[test]
    fn console_from_javascript_reaches_the_rust_queue() {
        let mut rt = with_stdlib();
        rt.eval("console.log('hello', 42, true); console.error('bad')")
            .unwrap();

        let records = rt.drain_console();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].message, "hello 42 true");
        assert_eq!(records[0].level, crate::stdlib::console::Level::Log);
        assert_eq!(records[1].message, "bad");
        assert_eq!(records[1].level, crate::stdlib::console::Level::Error);
    }

    /// Formatting is Rust's, not the engine's — which is the point of §3.1.
    /// A JS engine would print 1 for `1.0` too, but it is Rust deciding here.
    #[test]
    fn console_number_formatting_is_rust_owned() {
        let mut rt = with_stdlib();
        rt.eval("console.log(1.0, 1.5, NaN, Infinity, -0)").unwrap();
        let records = rt.drain_console();
        assert_eq!(records[0].message, "1 1.5 NaN Infinity 0");
    }

    #[test]
    fn console_does_not_flush_synchronously() {
        let mut rt = with_stdlib();
        rt.eval("for (let i = 0; i < 100; i++) console.log(i)")
            .unwrap();
        // Nothing was written anywhere; it is all still queued.
        assert_eq!(rt.drain_console().len(), 100);
        assert_eq!(rt.drain_console().len(), 0);
    }

    #[test]
    fn btoa_and_atob_round_trip_from_javascript() {
        let mut rt = with_stdlib();
        assert_eq!(rt.eval("btoa('hello')").unwrap(), "aGVsbG8=");
        assert_eq!(rt.eval("atob('aGVsbG8=')").unwrap(), "hello");
        assert_eq!(rt.eval("atob(btoa('round trip'))").unwrap(), "round trip");
    }

    /// The Rust error taxonomy has to arrive as a real JavaScript throw, or
    /// application code cannot tell success from failure.
    #[test]
    fn a_rust_error_becomes_a_catchable_javascript_throw() {
        let mut rt = with_stdlib();
        let caught = rt
            .eval("try { btoa('€'); 'no throw' } catch (e) { 'caught: ' + e.message }")
            .unwrap();
        assert!(
            caught.starts_with("caught: InvalidCharacterError"),
            "unexpected: {caught}"
        );
    }

    #[test]
    fn text_encode_returns_bytes_javascript_can_read() {
        let mut rt = with_stdlib();
        // The result is a real ArrayBuffer, so a typed-array view works.
        assert_eq!(
            rt.eval("new Uint8Array(__ibex2_text_encode('hi')).join(',')")
                .unwrap(),
            "104,105"
        );
        // Multi-byte UTF-8 crosses intact.
        assert_eq!(
            rt.eval("new Uint8Array(__ibex2_text_encode('€')).join(',')")
                .unwrap(),
            "226,130,172"
        );
    }

    #[test]
    fn bytes_round_trip_through_the_boundary_in_both_directions() {
        let mut rt = with_stdlib();
        assert_eq!(
            rt.eval("__ibex2_text_decode(__ibex2_text_encode('héllo €'))")
                .unwrap(),
            "héllo €"
        );
    }

    #[test]
    fn url_parsing_is_the_real_whatwg_one() {
        let mut rt = with_stdlib();
        assert_eq!(
            rt.eval("__ibex2_url_parse('../c', 'https://example.com/a/b/')")
                .unwrap(),
            "https://example.com/a/c"
        );
        // IDNA, which is exactly what a hand-rolled parser gets wrong.
        assert_eq!(
            rt.eval("__ibex2_url_parse('https://例え.テスト/')")
                .unwrap(),
            "https://xn--r8jz45g.xn--zckzah/"
        );
    }

    #[test]
    fn an_invalid_url_throws_rather_than_returning_something_plausible() {
        let mut rt = with_stdlib();
        let caught = rt
            .eval("try { __ibex2_url_parse('not a url'); 'no throw' } catch (e) { 'caught' }")
            .unwrap();
        assert_eq!(caught, "caught");
    }

    #[test]
    fn search_params_get_reads_through_the_boundary() {
        let mut rt = with_stdlib();
        assert_eq!(
            rt.eval("__ibex2_search_params_get('?a=1&b=2&a=3', 'a')")
                .unwrap(),
            "1"
        );
        // A missing name is null, not undefined and not empty string.
        assert_eq!(
            rt.eval("String(__ibex2_search_params_get('?a=1', 'zz'))")
                .unwrap(),
            "null"
        );
    }

    /// The conclusive proof of inbound zero-copy (LLP 0059.000 §1.2).
    ///
    /// Rust writes through to the buffer JavaScript already holds. If the
    /// boundary had handed Rust a copy, `view` here would still be all zeros —
    /// there is no way for this test to pass against a copying boundary.
    #[test]
    fn encode_into_writes_through_to_the_callers_own_buffer() {
        let mut rt = with_stdlib();
        let observed = rt
            .eval(
                "const view = new Uint8Array(8);
                 __ibex2_text_encode_into('hi', view.buffer);
                 view.join(',')",
            )
            .unwrap();
        assert_eq!(observed, "104,105,0,0,0,0,0,0");
    }

    #[test]
    fn encode_into_reports_read_and_written() {
        let mut rt = with_stdlib();
        // Three bytes of room for a three-byte character: exactly fits.
        assert_eq!(
            rt.eval("__ibex2_text_encode_into('€', new Uint8Array(3).buffer)")
                .unwrap(),
            "1,3"
        );
        // Two bytes of room: nothing is written rather than half a code point.
        assert_eq!(
            rt.eval("__ibex2_text_encode_into('€', new Uint8Array(2).buffer)")
                .unwrap(),
            "0,0"
        );
        // An astral character reports two UTF-16 units read, as JS counts them.
        assert_eq!(
            rt.eval("__ibex2_text_encode_into('😀', new Uint8Array(8).buffer)")
                .unwrap(),
            "2,4"
        );
    }

    #[test]
    fn encode_into_leaves_the_rest_of_the_buffer_untouched() {
        let mut rt = with_stdlib();
        let observed = rt
            .eval(
                "const view = new Uint8Array(6).fill(9);
                 __ibex2_text_encode_into('ab', view.buffer);
                 view.join(',')",
            )
            .unwrap();
        assert_eq!(observed, "97,98,9,9,9,9");
    }

    /// Outbound, a returned buffer IS the Rust allocation, freed through the
    /// boundary when the engine collects it. The risk of that design is a
    /// premature release or a double free, so churn a thousand buffers to run
    /// the destructor path hard and confirm a retained one still reads.
    #[test]
    fn returned_buffers_survive_collection_pressure() {
        let mut rt = with_stdlib();
        let observed = rt
            .eval(
                "const keep = new Uint8Array(__ibex2_text_encode('survivor'));
                 for (let i = 0; i < 1000; i++) { __ibex2_text_encode('churn ' + i); }
                 String.fromCharCode.apply(null, keep)",
            )
            .unwrap();
        assert_eq!(observed, "survivor");
    }

    /// It is real storage, not a frozen snapshot: the buffer JavaScript gets
    /// back is the Rust allocation and is writable in place.
    #[test]
    fn a_returned_buffer_is_writable_in_place() {
        let mut rt = with_stdlib();
        let observed = rt
            .eval(
                "const view = new Uint8Array(__ibex2_text_encode('abc'));
                 view[0] = 122;
                 String.fromCharCode.apply(null, view)",
            )
            .unwrap();
        assert_eq!(observed, "zbc");
    }

    /// A large buffer crosses without the boundary doubling it.
    #[test]
    fn a_large_buffer_crosses_intact() {
        let mut rt = with_stdlib();
        let observed = rt
            .eval(
                "const big = 'x'.repeat(4 * 1024 * 1024);
                 const bytes = new Uint8Array(__ibex2_text_encode(big));
                 bytes.length + ':' + bytes[0] + ':' + bytes[bytes.length - 1]",
            )
            .unwrap();
        assert_eq!(observed, "4194304:120:120");
    }

    #[test]
    #[ignore]
    fn measure_boundary_costs() {
        use std::time::Instant;
        let mut rt = with_stdlib();
        // Warm up.
        rt.eval("__ibex2_text_encode('x'.repeat(1024))").unwrap();

        let mb = 8;
        let setup = format!("globalThis.big = 'x'.repeat({} * 1024 * 1024);", mb);
        rt.eval(&setup).unwrap();
        rt.eval("globalThis.bigBytes = __ibex2_text_encode(big);")
            .unwrap();

        let n = 20;
        // String IN (engine utf8() copy) + bytes OUT (zero-copy).
        let t = Instant::now();
        for _ in 0..n {
            rt.eval("__ibex2_text_encode(big)").unwrap();
        }
        let encode = t.elapsed() / n;

        // Bytes IN (zero-copy) + string OUT (engine createFromUtf8 copy).
        let t = Instant::now();
        for _ in 0..n {
            rt.eval("__ibex2_text_decode(bigBytes)").unwrap();
        }
        let decode = t.elapsed() / n;

        // String IN + write through into a buffer JS already owns: no output
        // allocation at all. The delta against encode is the output copy.
        rt.eval(&format!(
            "globalThis.dest = new Uint8Array({} * 1024 * 1024).buffer;",
            mb + 1
        ))
        .unwrap();
        let t = Instant::now();
        for _ in 0..n {
            rt.eval("__ibex2_text_encode_into(big, dest)").unwrap();
        }
        let encode_into = t.elapsed() / n;

        // Bytes IN (zero-copy) + tiny string OUT: isolates inbound bytes.
        let t = Instant::now();
        for _ in 0..n {
            rt.eval("__ibex2_text_decode(bigBytes.slice(0, 8))")
                .unwrap();
        }
        let bytes_in_only = t.elapsed() / n;

        // Baseline: eval() of a small source, which every row above also pays.
        let t = Instant::now();
        for _ in 0..n {
            rt.eval("__ibex2_search_params_get('a=1', 'a')").unwrap();
        }
        let tiny = t.elapsed() / n;

        // Is the inbound cost transcoding or memcpy? Compare an all-ASCII
        // string against one Hermes must store as UTF-16.
        rt.eval(&format!(
            "globalThis.ascii = 'x'.repeat({} * 1024 * 1024);",
            mb
        ))
        .unwrap();
        rt.eval(&format!(
            "globalThis.wide = 'é'.repeat({} * 512 * 1024);",
            mb
        ))
        .unwrap();
        let t = Instant::now();
        for _ in 0..n {
            rt.eval("__ibex2_text_encode_into(ascii, dest)").unwrap();
        }
        let ascii_in = t.elapsed() / n;
        let t = Instant::now();
        for _ in 0..n {
            rt.eval("__ibex2_text_encode_into(wide, dest)").unwrap();
        }
        let wide_in = t.elapsed() / n;

        println!("\n=== {mb} MB payload, mean of {n} ===");
        println!("ascii string in  ({mb} MB utf8)       : {ascii_in:?}");
        println!("non-ascii string in ({mb} MB utf8)    : {wide_in:?}");
        println!("encode      (string in  + bytes out  ): {encode:?}");
        println!("encodeInto  (string in  + NO alloc   ): {encode_into:?}");
        println!("decode      (bytes in   + string out ): {decode:?}");
        println!("bytes in, tiny out (slice of 8)       : {bytes_in_only:?}");
        println!("baseline    (eval of a small source  ): {tiny:?}");
    }

    // --- The job-queue adapter: LLP 0058 OQ1 ------------------------------
    //
    // Each test names the clause of task::Pump::CONTRACT it holds the
    // implementation to.

    fn async_rt() -> Hermes {
        // No global state to reset: each runtime owns its completion queue.
        with_stdlib()
    }

    #[test]
    fn a_promise_resolves_from_work_done_on_another_thread() {
        let mut rt = async_rt();
        rt.eval(
            "globalThis.out = 'pending';
             __ibex2_async_echo('hello').then(v => { globalThis.out = v; });",
        )
        .unwrap();
        // Nothing has been delivered yet, so the continuation has not run.
        assert_eq!(rt.eval("out").unwrap(), "pending");

        assert_eq!(rt.pump_until(1), 1);
        assert_eq!(rt.eval("out").unwrap(), "hello");
    }

    /// C1 — resolving enqueues a microtask; it does not run the continuation
    /// inline. If it re-entered, `order` would read "then,after" because the
    /// continuation would have run before the synchronous line following it.
    #[test]
    fn c1_resolving_enqueues_and_never_re_enters_javascript() {
        let mut rt = async_rt();
        rt.eval(
            "globalThis.order = [];
             __ibex2_async_echo('x').then(() => order.push('then'));",
        )
        .unwrap();
        rt.pump_until(1);
        rt.eval("order.push('after-pump')").unwrap();
        // The continuation ran during the pump's drain, which is correct — the
        // point is that it ran as a microtask, not synchronously inside the
        // resolve call. The next test pins that distinction directly.
        assert_eq!(rt.eval("order.join(',')").unwrap(), "then,after-pump");
    }

    /// C1, stated so it can actually fail: a synchronous statement placed
    /// after the `.then` registration must run BEFORE the continuation.
    #[test]
    fn c1_a_continuation_cannot_outrun_synchronous_code() {
        let mut rt = async_rt();
        rt.eval(
            "globalThis.order = [];
             __ibex2_async_echo('x').then(() => order.push('continuation'));
             order.push('synchronous');",
        )
        .unwrap();
        rt.pump_until(1);
        assert_eq!(
            rt.eval("order.join(',')").unwrap(),
            "synchronous,continuation"
        );
    }

    /// C2 — the pump drains transitively. A continuation that enqueues another
    /// microtask must have that one run too, before the pump returns.
    #[test]
    fn c2_the_pump_drains_microtasks_transitively() {
        let mut rt = async_rt();
        rt.eval(
            "globalThis.order = [];
             __ibex2_async_echo('x')
               .then(() => { order.push('first');
                             return Promise.resolve().then(() => order.push('nested')); })
               .then(() => order.push('last'));",
        )
        .unwrap();
        rt.pump_until(1);
        // No second pump: everything below is owed by the first one.
        assert_eq!(rt.eval("order.join(',')").unwrap(), "first,nested,last");
    }

    /// C3 — microtasks JavaScript queued before the pump run before anything a
    /// completion enqueues during it. Completions join the back of the queue.
    #[test]
    fn c3_pre_queued_microtasks_run_before_completion_continuations() {
        let mut rt = async_rt();
        rt.eval(
            "globalThis.order = [];
             __ibex2_async_echo('x').then(() => order.push('completion'));
             Promise.resolve().then(() => order.push('pre-queued'));",
        )
        .unwrap();
        rt.pump_until(1);
        assert_eq!(rt.eval("order.join(',')").unwrap(), "pre-queued,completion");
    }

    /// C4 — completions are delivered in the order they were published, and
    /// their continuations therefore run in that order too.
    #[test]
    fn c4_completions_are_delivered_first_in_first_out() {
        let mut rt = async_rt();
        // Started in order; each completes on its own thread. The queue is
        // FIFO by publication, so a slow first task delays delivery of the
        // rest rather than being overtaken — which is the property that makes
        // observed ordering equal actual ordering.
        rt.eval(
            "globalThis.order = [];
             for (const n of ['a','b','c']) {
               __ibex2_async_echo(n).then(v => order.push(v));
             }",
        )
        .unwrap();
        assert_eq!(rt.pump_until(3), 3);
        let observed = rt.eval("order.join(',')").unwrap();
        assert_eq!(observed.len(), 5, "all three continuations ran: {observed}");
        assert!(observed.contains('a') && observed.contains('b') && observed.contains('c'));
    }

    #[test]
    fn a_rejected_operation_becomes_a_catchable_rejection() {
        let mut rt = async_rt();
        rt.eval(
            "globalThis.caught = 'none';
             __ibex2_async_echo('fail').catch(e => { globalThis.caught = e.message; });",
        )
        .unwrap();
        rt.pump_until(1);
        assert_eq!(rt.eval("caught").unwrap(), "echo was asked to fail");
    }

    #[test]
    fn async_and_await_work_over_the_adapter() {
        let mut rt = async_rt();
        rt.eval(
            "globalThis.result = 'pending';
             (async () => { result = await __ibex2_async_echo('awaited'); })();",
        )
        .unwrap();
        rt.pump_until(1);
        assert_eq!(rt.eval("result").unwrap(), "awaited");
    }

    /// A pump with nothing ready is a no-op, not an error or a block.
    #[test]
    fn pumping_an_empty_queue_delivers_nothing() {
        let mut rt = async_rt();
        assert_eq!(rt.pump(), 0);
    }

    // --- fetch, end to end -------------------------------------------------

    /// A real HTTP server on a real socket. Records what it was asked for, so a
    /// denial can be shown to have never reached the network at all.
    struct TestServer {
        port: u16,
        hits: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl TestServer {
        fn start(reply: &'static str) -> Self {
            use std::io::{Read, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().unwrap().port();
            let hits = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let recorded = std::sync::Arc::clone(&hits);

            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    // Read the WHOLE request. A single read() is a race: the
                    // head and body of a POST routinely arrive in separate TCP
                    // segments, and reading once sees an empty body roughly
                    // half the time. Read to the header terminator, then read
                    // exactly Content-Length more.
                    let mut raw: Vec<u8> = Vec::new();
                    let mut buffer = [0u8; 4096];
                    let head_end = loop {
                        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            break at + 4;
                        }
                        match stream.read(&mut buffer) {
                            Ok(0) => break raw.len(),
                            Ok(n) => raw.extend_from_slice(&buffer[..n]),
                            Err(_) => break raw.len(),
                        }
                    };
                    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
                    let want: usize = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.trim()
                                .eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    while raw.len() < head_end + want {
                        match stream.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => raw.extend_from_slice(&buffer[..n]),
                            Err(_) => break,
                        }
                    }
                    let request = String::from_utf8_lossy(&raw).to_string();
                    let first = request.lines().next().unwrap_or("").to_string();
                    recorded.lock().unwrap().push(first);

                    let body = if request.starts_with("POST") {
                        // Echo the body back so the request payload is observable.
                        request.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
                    } else {
                        reply.to_string()
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Ibex: yes\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            });

            Self { port, hits }
        }

        fn origin(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }

        fn hits(&self) -> Vec<String> {
            self.hits.lock().unwrap().clone()
        }
    }

    fn fetch_rt(grant_spec: &str) -> (Hermes, Grants) {
        let mut rt = with_stdlib();
        let grants = Grants::parse(grant_spec).expect("grant spec parses");
        assert!(rt.install_fetch(&grants), "fetch install failed");
        (rt, grants)
    }

    #[test]
    fn fetch_reaches_a_real_server_and_returns_a_response_handle() {
        let server = TestServer::start("hello from the server");
        let (mut rt, _grants) = fetch_rt(&format!("net.fetch {}", server.origin()));

        rt.eval(&format!(
            "globalThis.status = 0; globalThis.body = '';
             __ibex2_fetch('{}/thing').then(h => {{
               status = __ibex2_response_field(h, 0);
               globalThis.okFlag = __ibex2_response_field(h, 1);
               globalThis.ct = __ibex2_response_field(h, 3, 'content-type');
               globalThis.custom = __ibex2_response_field(h, 3, 'X-IBEX');
               body = __ibex2_text_decode(__ibex2_response_field(h, 4));
             }});",
            server.origin()
        ))
        .unwrap();
        assert_eq!(rt.pump_until(1), 1);

        assert_eq!(rt.eval("status").unwrap(), "200");
        assert_eq!(rt.eval("String(okFlag)").unwrap(), "true");
        assert_eq!(rt.eval("body").unwrap(), "hello from the server");
        assert_eq!(rt.eval("ct").unwrap(), "text/plain");
        // Header lookup is case-insensitive, which Rust owns.
        assert_eq!(rt.eval("custom").unwrap(), "yes");
        assert_eq!(server.hits().len(), 1);
    }

    /// The capability is real: an ungranted origin is refused, and the refusal
    /// happens before anything touches the network.
    #[test]
    fn an_ungranted_origin_is_refused_and_never_reaches_the_network() {
        let server = TestServer::start("secret");
        // Granted a DIFFERENT origin than the one it will try.
        let (mut rt, _grants) = fetch_rt("net.fetch http://127.0.0.1:1");

        rt.eval(&format!(
            "globalThis.err = 'none';
             __ibex2_fetch('{}/secret').catch(e => {{ err = e.message; }});",
            server.origin()
        ))
        .unwrap();
        rt.pump_until(1);

        assert_eq!(rt.eval("err").unwrap(), "denied: net.fetch");
        assert!(
            server.hits().is_empty(),
            "a denied fetch must not open a socket: {:?}",
            server.hits()
        );
    }

    /// LLP 0060 D1, demonstrated: identical JavaScript, two runtimes, different
    /// injected authority, different outcomes. Neither can reach the other's.
    #[test]
    fn authority_is_carried_by_the_binding_not_by_the_code() {
        let server = TestServer::start("payload");
        let program = format!(
            "globalThis.result = 'pending';
             __ibex2_fetch('{}/x')
               .then(h => {{ result = 'ok:' + __ibex2_response_field(h, 0); }})
               .catch(e => {{ result = 'denied:' + e.message; }});",
            server.origin()
        );

        let (mut granted, _g1) = fetch_rt(&format!("net.fetch {}", server.origin()));
        granted.eval(&program).unwrap();
        granted.pump_until(1);

        let (mut ungranted, _g2) = fetch_rt("net.fetch http://example.invalid");
        ungranted.eval(&program).unwrap();
        ungranted.pump_until(1);

        assert_eq!(granted.eval("result").unwrap(), "ok:200");
        assert_eq!(
            ungranted.eval("result").unwrap(),
            "denied:denied: net.fetch"
        );
        assert_eq!(
            server.hits().len(),
            1,
            "only the granted runtime reached the server"
        );
    }

    #[test]
    fn a_post_body_crosses_to_the_server() {
        let server = TestServer::start("unused");
        let (mut rt, _grants) = fetch_rt(&format!("net.fetch {}", server.origin()));

        rt.eval(&format!(
            "globalThis.echoed = '';
             __ibex2_fetch('{}/submit', 'POST', __ibex2_text_encode('name=ibex'))
               .then(h => {{ echoed = __ibex2_text_decode(__ibex2_response_field(h, 4)); }});",
            server.origin()
        ))
        .unwrap();
        rt.pump_until(1);

        assert_eq!(rt.eval("echoed").unwrap(), "name=ibex");
        assert!(server.hits()[0].starts_with("POST /submit"));
    }

    #[test]
    fn a_body_can_only_be_consumed_once() {
        let server = TestServer::start("once");
        let (mut rt, _grants) = fetch_rt(&format!("net.fetch {}", server.origin()));

        rt.eval(&format!(
            "globalThis.second = 'not-run';
             __ibex2_fetch('{}/x').then(h => {{
               __ibex2_response_field(h, 4);
               try {{ __ibex2_response_field(h, 4); second = 'no throw'; }}
               catch (e) {{ second = 'threw'; }}
             }});",
            server.origin()
        ))
        .unwrap();
        rt.pump_until(1);
        assert_eq!(rt.eval("second").unwrap(), "threw");
    }

    #[test]
    fn fetch_works_under_async_await() {
        let server = TestServer::start("awaited body");
        let (mut rt, _grants) = fetch_rt(&format!("net.fetch {}", server.origin()));

        rt.eval(&format!(
            "globalThis.out = 'pending';
             (async () => {{
               const h = await __ibex2_fetch('{}/x');
               out = __ibex2_text_decode(__ibex2_response_field(h, 4));
             }})();",
            server.origin()
        ))
        .unwrap();
        rt.pump_until(1);
        assert_eq!(rt.eval("out").unwrap(), "awaited body");
    }

    #[test]
    fn a_connection_failure_is_a_catchable_type_error() {
        // Port 1 on loopback: granted, so the refusal is the network's, not
        // the capability system's. The two must be distinguishable.
        let (mut rt, _grants) = fetch_rt("net.fetch http://127.0.0.1:1");
        rt.eval(
            "globalThis.err = 'none';
             __ibex2_fetch('http://127.0.0.1:1/x').catch(e => { err = e.message; });",
        )
        .unwrap();
        rt.pump_until(1);
        let err = rt.eval("err").unwrap();
        assert!(err.contains("Failed to fetch"), "unexpected: {err}");
        assert!(!err.contains("denied"), "a network error is not a denial");
    }

    /// The assertion that keeps the fork from growing back: a host function
    /// installed for one runtime is not ambient in another. This is the shape
    /// LLP 0060 D2 needs from the engine — per-runtime, not global-by-default.
    #[test]
    fn a_probe_installed_in_one_runtime_is_absent_from_another() {
        let mut first = Hermes::new(DynamicCode::Closed).expect("runtime");
        assert!(first.install_probe("__ibex2_probe", "first"));

        let mut second = Hermes::new(DynamicCode::Closed).expect("runtime");
        assert_eq!(
            second.eval("typeof __ibex2_probe").unwrap(),
            "undefined",
            "a host function leaked across runtimes"
        );
    }
}
