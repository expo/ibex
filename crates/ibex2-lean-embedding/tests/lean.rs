use ibex2::{
    bindings::{CompiledBinding, Context, Groups},
    grant::GrantSet,
};
use std::ffi::{c_char, c_void, CStr, CString};

#[repr(C)]
struct CompiledScript {
    name: *const c_char,
    bytes: *const u8,
    len: usize,
}

unsafe extern "C" {
    fn ibex2_lean_bytecode_version() -> u32;
    fn ibex2_lean_create(
        queue: *const c_void,
        bindings: *const ibex2::bindings::Ibex2Bindings,
        groups: u16,
        scripts: *const CompiledScript,
        script_count: usize,
        error: *mut *mut c_char,
    ) -> *mut c_void;
    fn ibex2_lean_evaluate(
        handle: *mut c_void,
        bytes: *const u8,
        len: usize,
        source_url: *const c_char,
        result: *mut *mut c_char,
    ) -> i32;
    fn ibex2_lean_destroy(handle: *mut c_void);
    fn ibex2_lean_free(value: *mut c_char);
}

fn take(value: *mut c_char) -> String {
    if value.is_null() {
        return String::new();
    }
    let result = unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned();
    unsafe { ibex2_lean_free(value) };
    result
}

fn evaluate(handle: *mut c_void, bytes: &[u8], name: &str) -> Result<String, String> {
    let name = CString::new(name).expect("source URL");
    let mut result = std::ptr::null_mut();
    let status = unsafe {
        ibex2_lean_evaluate(
            handle,
            bytes.as_ptr(),
            bytes.len(),
            name.as_ptr(),
            &mut result,
        )
    };
    let text = take(result);
    if status == 0 {
        Ok(text)
    } else {
        Err(text)
    }
}

#[test]
fn pure_bindings_and_precompiled_app_run_on_lean_while_source_is_impossible() {
    ibex2_lean_embedding::ensure_linked();
    hermes_lean_sys::ensure_linked();
    let lean_digest = hermes_lean_sys::LEAN_ENGINE_DIGEST
        .expect("the lean archive selected by link-lean has an identity");
    assert_eq!(
        hermes_lean_sys::LINKED_ENGINE_DIGEST,
        Some(lean_digest),
        "the process identity names the lean archive it links"
    );
    assert_eq!(
        hermes_lean_sys::LINKED_ARCHIVE,
        hermes_lean_sys::LEAN_ARCHIVE
    );
    assert_eq!(ibex2::bindings::LEAN_ENGINE_DIGEST, Some(lean_digest));
    assert_ne!(lean_digest, hermes_lean_sys::ENGINE_DIGEST);
    assert_eq!(
        Some(ibex2::bindings::BYTECODE_VERSION),
        ibex2::bindings::LEAN_BYTECODE_VERSION
    );
    assert_eq!(
        Some(unsafe { ibex2_lean_bytecode_version() }.to_string().as_str()),
        ibex2::bindings::LEAN_BYTECODE_VERSION
    );

    let groups = Groups::PURE;
    let context = Context::new(GrantSet::none());
    let compiled: Vec<CompiledBinding> =
        ibex2::bindings::compiled_scripts(groups).expect("PURE dependencies");
    let names: Vec<CString> = compiled
        .iter()
        .map(|script| CString::new(script.name).expect("script name"))
        .collect();
    let scripts: Vec<CompiledScript> = compiled
        .iter()
        .zip(&names)
        .map(|(script, name)| CompiledScript {
            name: name.as_ptr(),
            bytes: script.bytes.as_ptr(),
            len: script.bytes.len(),
        })
        .collect();
    let mut error = std::ptr::null_mut();
    let handle = unsafe {
        ibex2_lean_create(
            context.state_ptr(),
            context.bindings_ptr(),
            groups.bits(),
            scripts.as_ptr(),
            scripts.len(),
            &mut error,
        )
    };
    assert!(!handle.is_null(), "{}", take(error));

    evaluate(handle, ibex2::bindings::HARDEN_BYTECODE, "harden.hbc")
        .expect("harden bytecode runs on lean");
    let app = include_bytes!(env!("IBEX2_LEAN_APP_BYTECODE"));
    assert_eq!(
        evaluate(handle, app, "lean-app.hbc").expect("precompiled app runs on lean"),
        "https://example.com/lean"
    );
    let source_error =
        evaluate(handle, b"1 + 1", "source.js").expect_err("the lean VM has no source compiler");
    assert!(
        !source_error.is_empty(),
        "lean source rejection names an error"
    );

    unsafe { ibex2_lean_destroy(handle) };
}
