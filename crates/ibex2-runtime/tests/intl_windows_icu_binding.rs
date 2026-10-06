//! The Windows INTL probe binds the shims' `icu.dll` pointers from System32 by
//! full path, whatever other module named `icu.dll` the process has mapped
//! (LLP 0057.000 §5.1.1). Its own test binary, so no other test has run the
//! one-time probe first.
#![cfg(all(windows, feature = "intl"))]

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use ibex2::bindings::{Context, Groups};
use ibex2::grant::GrantSet;
use ibex2_runtime::engine::hermes::{DynamicCode, Hermes};

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetModuleFileNameW(module: *mut c_void, buffer: *mut u16, size: u32) -> u32;
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
}

const PLANTED_CHILD: &str = "IBEX2_TEST_PLANTED_ICU_CHILD";

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn system32_icu() -> PathBuf {
    let mut buffer = [0u16; 512];
    // SAFETY: the buffer is writable for its length.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    assert!(length > 0 && (length as usize) < buffer.len());
    PathBuf::from(String::from_utf16_lossy(&buffer[..length as usize])).join("icu.dll")
}

fn file_name(module: *mut c_void) -> String {
    let mut buffer = [0u16; 1024];
    // SAFETY: `module` is a loaded module; the buffer is writable.
    let length = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) };
    assert!(length > 0, "GetModuleFileNameW failed");
    String::from_utf16_lossy(&buffer[..length as usize])
}

fn same(a: &str, b: &Path) -> bool {
    a.eq_ignore_ascii_case(&b.to_string_lossy())
}

/// A fresh directory holding a copy of System32's icu.dll.
fn directory_with_icu_copy(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ibex2-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(system32_icu(), dir.join("icu.dll")).unwrap();
    dir
}

/// Bind, then check what the probe bound and that Intl works through it.
fn assert_bound_to_system32_and_intl_works(other: *mut c_void, other_path: &Path) {
    let observed = ibex2::bindings::os_icu().expect("the probe binds System32's icu.dll");
    let system32 = system32_icu();
    assert!(
        same(&observed.path, &system32),
        "bound {} instead of {}",
        observed.path,
        system32.display()
    );
    assert!(!same(&observed.path, other_path));
    // SAFETY: a NUL-terminated absolute path.
    let bound = unsafe { GetModuleHandleW(wide(&system32).as_ptr()) };
    assert!(!bound.is_null(), "System32's icu.dll is loaded");
    assert_ne!(bound, other, "the bound module is not the other icu.dll");

    let mut runtime = Hermes::new(DynamicCode::Closed).expect("runtime");
    runtime
        .install_runtime(Groups::DEFAULT, &Context::new(GrantSet::none()))
        .expect("install DEFAULT with INTL");
    assert_eq!(
        runtime
            .eval(
                r#"const f = new Intl.NumberFormat("en-US", {style: "currency", currency: "USD"});
                   f.format(1234.5) + "|" + f.formatToParts(1234.5).map(p => p.type).join(",")"#
            )
            .unwrap(),
        "$1,234.50|currency,integer,group,integer,decimal,fraction"
    );
}

/// A copy of icu.dll loaded first, by its own full path, does not become the
/// module the shims call.
#[test]
fn a_preloaded_icu_dll_copy_does_not_capture_the_shims() {
    if std::env::var_os(PLANTED_CHILD).is_some() {
        return;
    }
    let dir = directory_with_icu_copy("preloaded-icu");
    let copy = dir.join("icu.dll");
    // SAFETY: a NUL-terminated absolute path; the module stays loaded for
    // the rest of the process.
    let preloaded = unsafe { LoadLibraryExW(wide(&copy).as_ptr(), std::ptr::null_mut(), 0) };
    assert!(!preloaded.is_null(), "load the copy");
    assert!(
        same(&file_name(preloaded), &copy),
        "the copy is its own module: {}",
        file_name(preloaded)
    );
    assert_bound_to_system32_and_intl_works(preloaded, &copy);
}

/// The planted case: this test binary run from a directory that also holds
/// an `icu.dll`. Hermes's load-time icuuc/icuin forwarders may resolve their
/// `icu.dll` there before `main` (the recorded residual in
/// issues/20261006-windows-icu-forwarder-search-order.md), but the shims'
/// `icu.dll`-only entry points must still come from System32.
#[test]
fn an_application_directory_icu_dll_does_not_capture_the_bound_pointers() {
    if std::env::var_os(PLANTED_CHILD).is_some() {
        return;
    }
    let dir = directory_with_icu_copy("planted-icu");
    let exe = dir.join("intl_windows_icu_binding.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
    let output = std::process::Command::new(&exe)
        .args([
            "--exact",
            "planted_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PLANTED_CHILD, "1")
        .current_dir(&dir)
        .output()
        .expect("run the planted copy");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("{stdout}");
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("1 passed"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn planted_child() {
    if std::env::var_os(PLANTED_CHILD).is_none() {
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let planted = exe.parent().unwrap().join("icu.dll");
    // Which icu.dll the load-time forwarders reached, before any probe:
    // reported, not asserted, because it is Windows's behaviour, not Ibex's.
    // SAFETY: a NUL-terminated module name.
    let first = unsafe { GetModuleHandleW(wide(Path::new("icu.dll")).as_ptr()) };
    let first_path = if first.is_null() {
        "<none>".to_owned()
    } else {
        file_name(first)
    };
    println!("load-time icu.dll before the probe: {first_path}");
    // SAFETY: a NUL-terminated absolute path.
    let planted_module = unsafe { GetModuleHandleW(wide(&planted).as_ptr()) };
    assert_bound_to_system32_and_intl_works(planted_module, &planted);
}
