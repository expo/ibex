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
