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
