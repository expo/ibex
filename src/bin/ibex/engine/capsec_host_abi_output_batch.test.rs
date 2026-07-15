// Test-only native output executor.
//
// @ref LLP 0002#memory-ownership-rules-observed — every native string,
// buffer, file, SQLite statement, and context minted here is released through
// its owning ABI.
// @ref LLP 0021#wp10--prove-targets-and-publish-the-conformance-report — the
// executor rechecks exact source identities and records only actual returns.

use super::*;
use base64::Engine as _;
use serde_json::{json, Value};
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

const DESCRIPTOR_KIND: &str = "source-bound-host-abi-output";
const INVOCATION_SCHEMA: &str = "ibex/capsec-host-abi-output-invocation/1";
const OUTPUT_CONTRACT_SCHEMA: &str = "ibex/host-abi-output-contract/1";

extern "C" {
    fn ex_hermes_create() -> *mut HermesRuntimeOpaque;
    fn ex_hermes_engine_binary_path(out: *mut std::os::raw::c_char, out_len: usize) -> i32;
    fn ex_hermes_engine_mapped_object(out_device: *mut u64, out_inode: *mut u64) -> i32;
    fn ex_hermes_bytecode_version() -> u32;
    fn ex_hermes_evaluation_result_init(result: *mut std::ffi::c_void);
    fn ex_hermes_evaluation_result_dispose(result: *mut std::ffi::c_void);
    fn ex_hermes_callback_backlog(runtime: *mut HermesRuntimeOpaque) -> u32;
    fn ex_hermes_set_keep_alive_on_async_error(runtime: *mut HermesRuntimeOpaque, enabled: i32);
    fn ex_hermes_gc(runtime: *mut HermesRuntimeOpaque);
    fn ex_hermes_get_heap_info(
        runtime: *mut HermesRuntimeOpaque,
        include_expensive: i32,
    ) -> *mut std::os::raw::c_char;
    fn ex_hermes_get_gc_stats(runtime: *mut HermesRuntimeOpaque) -> *mut std::os::raw::c_char;

    fn ex_worklet_create() -> *mut HermesRuntimeOpaque;
    fn ex_worklet_destroy(runtime: *mut HermesRuntimeOpaque);
    fn ex_worklet_set_generation(runtime: *mut HermesRuntimeOpaque, generation: u64);
    fn ex_worklet_generation(runtime: *mut HermesRuntimeOpaque) -> u64;
    fn ex_worklet_install(
        runtime: *mut HermesRuntimeOpaque,
        worklet_id: *const std::os::raw::c_char,
        source: *const u8,
        source_len: usize,
        generation: u64,
        out_error: *mut *mut std::os::raw::c_char,
    ) -> i32;
    fn ex_worklet_invoke(
        runtime: *mut HermesRuntimeOpaque,
        worklet_id: *const std::os::raw::c_char,
        args_json: *const std::os::raw::c_char,
        out_result_json: *mut *mut std::os::raw::c_char,
    ) -> i32;
    fn ex_worklet_bind_shared_values(
        runtime: *mut HermesRuntimeOpaque,
        slab: *mut std::ffi::c_void,
        slot_count: usize,
    ) -> i32;
    fn ex_worklet_set_measure_callback(
        runtime: *mut HermesRuntimeOpaque,
        callback: Option<
            extern "C" fn(
                node_id: u32,
                out_frame4: *mut f32,
                context: *mut std::ffi::c_void,
            ) -> i32,
        >,
        context: *mut std::ffi::c_void,
    );
    fn ex_worklet_drain_logs(runtime: *mut HermesRuntimeOpaque) -> *mut std::os::raw::c_char;
    fn ex_worklet_drain_scheduled(runtime: *mut HermesRuntimeOpaque) -> *mut std::os::raw::c_char;
}

fn tagged_bytes_digest(bytes: &[u8]) -> String {
    format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(bytes))
    )
}

fn tagged_jcs_digest(value: &Value) -> String {
    tagged_bytes_digest(
        &capsec_semantics::canonical::to_jcs_bytes(value)
            .expect("serialize Host ABI descriptor as JCS"),
    )
}

fn raw(kind: &str, shape: &str, value: Value) -> Value {
    json!({
        "kind": kind,
        "rawValueShape": shape,
        "value": value,
        "errorCode": null,
    })
}

fn returned_number(value: impl Into<Value>) -> Value {
    raw("return", "number", value.into())
}

fn returned_undefined() -> Value {
    raw("return", "undefined", Value::Null)
}

fn returned_null() -> Value {
    raw("return", "null", Value::Null)
}

fn returned_string(value: String) -> Value {
    raw("return", "string", Value::String(value))
}

fn returned_object() -> Value {
    raw("return", "object", Value::Null)
}

fn c_string(path: &Path) -> CString {
    CString::new(path.to_string_lossy().as_bytes()).expect("Host ABI fixture path contains NUL")
}

fn take_host_string(pointer: *mut std::ffi::c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    crate::host::abi::ex_host_free_string(pointer);
    Some(value)
}

fn raw_host_string(pointer: *mut std::ffi::c_char) -> Value {
    take_host_string(pointer).map_or_else(returned_null, returned_string)
}

fn take_hermes_string(pointer: *mut std::os::raw::c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned();
    unsafe { ex_hermes_free_string(pointer) };
    Some(value)
}

fn raw_hermes_string(pointer: *mut std::os::raw::c_char) -> Value {
    take_hermes_string(pointer).map_or_else(returned_null, returned_string)
}

struct FsSandbox {
    root: PathBuf,
}

impl FsSandbox {
    fn new() -> Self {
        let nonce = format!(
            "ibex-capsec-host-abi-output-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("fixture clock before epoch")
                .as_nanos()
        );
        let root = std::env::temp_dir().join(nonce);
        std::fs::create_dir(&root).expect("create Host ABI output fixture directory");
        Self { root }
    }

    fn reset_file(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::write(&path, b"host-abi-output").expect("write Host ABI fixture file");
        path
    }
}

impl Drop for FsSandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn open_fixture(path: &Path, flags: u32) -> *mut crate::host::abi::ExactFileHandle {
    let path = c_string(path);
    let handle = crate::host::abi::ex_host_fs_open(path.as_ptr(), flags);
    assert!(!handle.is_null(), "open Host ABI fixture");
    handle
}

fn execute_fs(function_name: &str, sandbox: &FsSandbox) -> Result<Value, String> {
    let file = sandbox.reset_file(&format!("{function_name}.txt"));
    let path = c_string(&file);
    let bytes = b"bounded";
    let result = match function_name {
        "ex_host_fs_access" => {
            returned_number(crate::host::abi::ex_host_fs_access(path.as_ptr(), 4))
        }
        "ex_host_fs_append" => returned_number(crate::host::abi::ex_host_fs_append(
            path.as_ptr(),
            bytes.as_ptr(),
            bytes.len() as u32,
        )),
        "ex_host_fs_chmod" => {
            returned_number(crate::host::abi::ex_host_fs_chmod(path.as_ptr(), 0o600))
        }
        "ex_host_fs_close" => {
            let handle = open_fixture(&file, 1);
            crate::host::abi::ex_host_fs_close(handle);
            returned_undefined()
        }
        "ex_host_fs_copy" | "ex_host_fs_copy_exclusive" => {
            let destination = sandbox.root.join(format!("{function_name}-copy.txt"));
            let destination = c_string(&destination);
            let value = if function_name == "ex_host_fs_copy" {
                crate::host::abi::ex_host_fs_copy(path.as_ptr(), destination.as_ptr())
            } else {
                crate::host::abi::ex_host_fs_copy_exclusive(path.as_ptr(), destination.as_ptr())
            };
            returned_number(value)
        }
        "ex_host_fs_fstat" => {
            let handle = open_fixture(&file, 1);
            let value = raw_host_string(crate::host::abi::ex_host_fs_fstat(handle));
            crate::host::abi::ex_host_fs_close(handle);
            value
        }
        "ex_host_fs_last_error" => returned_number(crate::host::abi::ex_host_fs_last_error()),
        "ex_host_fs_lstat" => raw_host_string(crate::host::abi::ex_host_fs_lstat(path.as_ptr())),
        "ex_host_fs_mkdir" => {
            let directory = c_string(&sandbox.root.join("mkdir"));
            returned_number(crate::host::abi::ex_host_fs_mkdir(directory.as_ptr(), 0))
        }
        "ex_host_fs_mkdir_recursive_result" => {
            let directory = c_string(&sandbox.root.join("recursive").join("child"));
            raw_host_string(crate::host::abi::ex_host_fs_mkdir_recursive_result(
                directory.as_ptr(),
            ))
        }
        "ex_host_fs_mkdtemp" => {
            let prefix = CString::new("ibex-capsec-host-output-").unwrap();
            let pointer = crate::host::abi::ex_host_fs_mkdtemp(prefix.as_ptr(), 0);
            let value = take_host_string(pointer);
            if let Some(path) = value.as_deref() {
                let _ = std::fs::remove_dir(path);
            }
            value.map_or_else(returned_null, returned_string)
        }
        "ex_host_fs_open" => {
            let handle = crate::host::abi::ex_host_fs_open(path.as_ptr(), 1);
            if handle.is_null() {
                returned_null()
            } else {
                crate::host::abi::ex_host_fs_close(handle);
                returned_object()
            }
        }
        "ex_host_fs_pread" | "ex_host_fs_read" => {
            let handle = open_fixture(&file, 1);
            let mut buffer = [0_u8; 8];
            let value = if function_name == "ex_host_fs_pread" {
                crate::host::abi::ex_host_fs_pread(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    0,
                )
            } else {
                crate::host::abi::ex_host_fs_read(handle, buffer.as_mut_ptr(), buffer.len() as u32)
            };
            crate::host::abi::ex_host_fs_close(handle);
            returned_number(value)
        }
        "ex_host_fs_pwrite" | "ex_host_fs_write" => {
            let handle = open_fixture(&file, 3);
            let value = if function_name == "ex_host_fs_pwrite" {
                crate::host::abi::ex_host_fs_pwrite(handle, bytes.as_ptr(), bytes.len() as u32, 0)
            } else {
                crate::host::abi::ex_host_fs_write(handle, bytes.as_ptr(), bytes.len() as u32)
            };
            crate::host::abi::ex_host_fs_close(handle);
            returned_number(value)
        }
        "ex_host_fs_read_file" => {
            let mut length = 0_u64;
            let mut errno = 0_i32;
            let pointer =
                crate::host::abi::ex_host_fs_read_file(path.as_ptr(), &mut length, &mut errno);
            if pointer.is_null() {
                returned_null()
            } else {
                let value =
                    unsafe { std::slice::from_raw_parts(pointer, length as usize) }.to_vec();
                crate::host::abi::ex_host_free_buffer(pointer, length);
                raw("return", "array", json!(value))
            }
        }
        "ex_host_fs_readdir" => {
            let root = c_string(&sandbox.root);
            raw_host_string(crate::host::abi::ex_host_fs_readdir(root.as_ptr()))
        }
        "ex_host_fs_realpath" => {
            raw_host_string(crate::host::abi::ex_host_fs_realpath(path.as_ptr()))
        }
        "ex_host_fs_rename" => {
            let destination = c_string(&sandbox.root.join("renamed.txt"));
            returned_number(crate::host::abi::ex_host_fs_rename(
                path.as_ptr(),
                destination.as_ptr(),
            ))
        }
        "ex_host_fs_rmdir" => {
            let directory_path = sandbox.root.join("rmdir");
            std::fs::create_dir(&directory_path).unwrap();
            let directory = c_string(&directory_path);
            returned_number(crate::host::abi::ex_host_fs_rmdir(directory.as_ptr()))
        }
        "ex_host_fs_seek" => {
            let handle = open_fixture(&file, 1);
            let value = crate::host::abi::ex_host_fs_seek(handle, 1);
            crate::host::abi::ex_host_fs_close(handle);
            returned_number(value)
        }
        "ex_host_fs_stat" => raw_host_string(crate::host::abi::ex_host_fs_stat(path.as_ptr())),
        "ex_host_fs_statfs" => raw_host_string(crate::host::abi::ex_host_fs_statfs(path.as_ptr())),
        "ex_host_fs_sync" => {
            let handle = open_fixture(&file, 3);
            let value = crate::host::abi::ex_host_fs_sync(handle, 1);
            crate::host::abi::ex_host_fs_close(handle);
            returned_number(value)
        }
        "ex_host_fs_truncate" => {
            returned_number(crate::host::abi::ex_host_fs_truncate(path.as_ptr(), 4))
        }
        "ex_host_fs_unlink" => returned_number(crate::host::abi::ex_host_fs_unlink(path.as_ptr())),
        "ex_host_fs_utimes" => returned_number(crate::host::abi::ex_host_fs_utimes(
            path.as_ptr(),
            1_700_000_000.0,
            1_700_000_001.0,
        )),
        other => return Err(format!("unsupported Rust Host FS function {other}")),
    };
    Ok(result)
}

fn prepare_sqlite(db: u64, sql: &str) -> (u64, String) {
    let sql = CString::new(sql).unwrap();
    let text = take_host_string(crate::host::abi::ex_host_sqlite_prepare(db, sql.as_ptr()))
        .expect("prepare SQLite fixture");
    let value: Value = serde_json::from_str(&text).expect("parse SQLite prepare result");
    let handle = value["handle"].as_u64().expect("SQLite prepare handle");
    (handle, text)
}

fn open_sqlite_memory() -> u64 {
    let handle = crate::host::abi::ex_host_sqlite_open_isolated_memory(std::ptr::null());
    assert_ne!(handle, 0, "open isolated SQLite output fixture");
    handle
}

fn execute_sqlite(function_name: &str, sandbox: &FsSandbox) -> Result<Value, String> {
    let result = match function_name {
        "ex_host_sqlite_open" => {
            let memory = CString::new(":memory:").unwrap();
            let db = crate::host::abi::ex_host_sqlite_open(memory.as_ptr(), std::ptr::null());
            assert_ne!(db, 0);
            let raw = returned_number(db);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_open_checked_fd" => {
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd as _;
                let file_path = sandbox.reset_file("checked.sqlite");
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(file_path)
                    .unwrap();
                let db = crate::host::abi::ex_host_sqlite_open_checked_fd(
                    file.as_raw_fd(),
                    std::ptr::null(),
                );
                if db == 0 {
                    returned_number(0)
                } else {
                    let raw = returned_number(db);
                    assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
                    raw
                }
            }
            #[cfg(not(unix))]
            {
                returned_number(crate::host::abi::ex_host_sqlite_open_checked_fd(
                    -1,
                    std::ptr::null(),
                ))
            }
        }
        "ex_host_sqlite_open_isolated_memory" => {
            let db = open_sqlite_memory();
            let raw = returned_number(db);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_close" => {
            let db = open_sqlite_memory();
            returned_number(crate::host::abi::ex_host_sqlite_close(db))
        }
        "ex_host_sqlite_prepare" => {
            let db = open_sqlite_memory();
            let (statement, text) = prepare_sqlite(db, "SELECT 1 AS value");
            assert_eq!(crate::host::abi::ex_host_sqlite_finalize(statement), 0);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            returned_string(text)
        }
        "ex_host_sqlite_finalize" => {
            let db = open_sqlite_memory();
            let (statement, _) = prepare_sqlite(db, "SELECT 1");
            let raw = returned_number(crate::host::abi::ex_host_sqlite_finalize(statement));
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_expanded_sql" => {
            let db = open_sqlite_memory();
            let (statement, _) = prepare_sqlite(db, "SELECT 1");
            let raw = raw_host_string(crate::host::abi::ex_host_sqlite_expanded_sql(statement));
            assert_eq!(crate::host::abi::ex_host_sqlite_finalize(statement), 0);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_in_transaction" => {
            let db = open_sqlite_memory();
            let raw = returned_number(crate::host::abi::ex_host_sqlite_in_transaction(db));
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        name @ ("ex_host_sqlite_all" | "ex_host_sqlite_get" | "ex_host_sqlite_values") => {
            let db = open_sqlite_memory();
            let (statement, _) = prepare_sqlite(db, "SELECT 1 AS value");
            let pointer = match name {
                "ex_host_sqlite_all" => {
                    crate::host::abi::ex_host_sqlite_all(statement, std::ptr::null())
                }
                "ex_host_sqlite_get" => {
                    crate::host::abi::ex_host_sqlite_get(statement, std::ptr::null())
                }
                _ => crate::host::abi::ex_host_sqlite_values(statement, std::ptr::null()),
            };
            let raw = raw_host_string(pointer);
            assert_eq!(crate::host::abi::ex_host_sqlite_finalize(statement), 0);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_run" => {
            let db = open_sqlite_memory();
            let (statement, _) = prepare_sqlite(db, "CREATE TABLE output(value INTEGER)");
            let raw = raw_host_string(crate::host::abi::ex_host_sqlite_run(
                statement,
                std::ptr::null(),
            ));
            assert_eq!(crate::host::abi::ex_host_sqlite_finalize(statement), 0);
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        "ex_host_sqlite_exec" => {
            let db = open_sqlite_memory();
            let sql = CString::new("CREATE TABLE output(value INTEGER)").unwrap();
            let raw = raw_host_string(crate::host::abi::ex_host_sqlite_exec(
                db,
                sql.as_ptr(),
                std::ptr::null(),
            ));
            assert_eq!(crate::host::abi::ex_host_sqlite_close(db), 0);
            raw
        }
        other => return Err(format!("unsupported Rust Host SQLite function {other}")),
    };
    Ok(result)
}

fn execute_terminal(function_name: &str) -> Result<Value, String> {
    let result = match function_name {
        "ex_host_session_descriptor_alias_source_route" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_alias_source_route(0))
        }
        "ex_host_session_descriptor_alias_target_route" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_alias_target_route(3))
        }
        "ex_host_session_descriptor_close_route" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_close_route(1))
        }
        "ex_host_session_descriptor_is_protected" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_is_protected(3))
        }
        "ex_host_session_descriptor_read_route" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_read_route(0))
        }
        "ex_host_session_descriptor_write_route" => {
            returned_number(crate::host::abi::ex_host_session_descriptor_write_route(1))
        }
        "ex_host_terminal_session_close_is_noop" => {
            returned_number(crate::host::abi::ex_host_terminal_session_close_is_noop(1))
        }
        "ex_host_terminal_session_stdio_query" => {
            let (mut tty, mut columns, mut rows) = (0_i32, 0_u16, 0_u16);
            returned_number(unsafe {
                crate::host::abi::ex_host_terminal_session_stdio_query(
                    0,
                    &mut tty,
                    &mut columns,
                    &mut rows,
                )
            })
        }
        other => return Err(format!("unsupported inert terminal Host ABI {other}")),
    };
    Ok(result)
}

fn fresh_legacy_host() {
    assert_ne!(
        crate::host::abi::install_host(crate::host::Host::default_legacy()),
        0,
        "install isolated legacy Host ABI output fixture"
    );
}

fn execute_basic(function_name: &str) -> Result<Value, String> {
    fresh_legacy_host();
    let capability = CString::new("fs:read:/project/output.js").unwrap();
    let specifier = CString::new("node:path").unwrap();
    let package = CString::new("output-package").unwrap();
    let locator = CString::new("output-package@1.0.0").unwrap();
    let integrity = CString::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    let event = CString::new("output-shape").unwrap();
    let root_stack = [0_u64];
    let result = match function_name {
        "ex_host_armed_endowments" => raw_host_string(crate::host::abi::ex_host_armed_endowments()),
        "ex_host_check_capability" => returned_number(crate::host::abi::ex_host_check_capability(
            0,
            capability.as_ptr(),
        )),
        "ex_host_check_capability_no_follow_final" => returned_number(
            crate::host::abi::ex_host_check_capability_no_follow_final(0, capability.as_ptr()),
        ),
        "ex_host_check_capability_stack" => {
            returned_number(crate::host::abi::ex_host_check_capability_stack(
                root_stack.as_ptr(),
                1,
                capability.as_ptr(),
            ))
        }
        "ex_host_check_capability_stack_no_follow_final" => returned_number(
            crate::host::abi::ex_host_check_capability_stack_no_follow_final(
                root_stack.as_ptr(),
                1,
                capability.as_ptr(),
            ),
        ),
        "ex_host_check_handle_mint" => returned_number(
            crate::host::abi::ex_host_check_handle_mint(0, capability.as_ptr()),
        ),
        "ex_host_check_import" => returned_number(crate::host::abi::ex_host_check_import(
            0,
            specifier.as_ptr(),
        )),
        "ex_host_claim_armed_context" => returned_number(unsafe {
            crate::host::abi::ex_host_claim_armed_context(integrity.as_ptr())
        }),
        "ex_host_claim_diagnostic_context" => {
            let context = crate::host::abi::ex_host_claim_diagnostic_context();
            let raw = returned_number(context);
            if context != 0 {
                crate::host::abi::ex_host_release_context(context);
            }
            raw
        }
        "ex_host_console_flush" => {
            crate::host::abi::ex_host_console_flush(0);
            returned_undefined()
        }
        "ex_host_console_log" => {
            crate::host::abi::ex_host_console_log(0, event.as_ptr());
            returned_undefined()
        }
        "ex_host_console_log_bytes" => {
            unsafe { crate::host::abi::ex_host_console_log_bytes(0, std::ptr::null(), 0) };
            returned_undefined()
        }
        "ex_host_enter_context" => {
            let context = crate::host::abi::ex_host_claim_diagnostic_context();
            assert_ne!(context, 0);
            let previous = crate::host::abi::ex_host_enter_context(context);
            crate::host::abi::ex_host_restore_context(previous);
            crate::host::abi::ex_host_release_context(context);
            returned_number(previous)
        }
        "ex_host_env_get" => {
            let key = CString::new("PATH").unwrap();
            returned_number(crate::host::abi::ex_host_env_get(
                key.as_ptr(),
                std::ptr::null_mut(),
                0,
            ))
        }
        "ex_host_free_buffer" => {
            crate::host::abi::ex_host_free_buffer(std::ptr::null_mut(), 0);
            returned_undefined()
        }
        "ex_host_free_string" => {
            crate::host::abi::ex_host_free_string(std::ptr::null_mut());
            returned_undefined()
        }
        "ex_host_grant_capability" => {
            crate::host::abi::ex_host_grant_capability(0, capability.as_ptr());
            returned_undefined()
        }
        "ex_host_handle_check" => returned_number(crate::host::abi::ex_host_handle_check(
            0,
            capability.as_ptr(),
        )),
        "ex_host_handle_create" => {
            let handle = crate::host::abi::ex_host_handle_create(capability.as_ptr());
            let raw = returned_number(handle);
            crate::host::abi::ex_host_handle_revoke(handle);
            raw
        }
        "ex_host_handle_revoke" => {
            let handle = crate::host::abi::ex_host_handle_create(capability.as_ptr());
            crate::host::abi::ex_host_handle_revoke(handle);
            returned_undefined()
        }
        "ex_host_handle_scoped" => {
            let parent = crate::host::abi::ex_host_handle_create(capability.as_ptr());
            let narrower = CString::new("/project/output.js").unwrap();
            let child = crate::host::abi::ex_host_handle_scoped(parent, narrower.as_ptr());
            let raw = returned_number(child);
            crate::host::abi::ex_host_handle_revoke(parent);
            raw
        }
        "ex_host_has_deputy_classes" => {
            returned_number(crate::host::abi::ex_host_has_deputy_classes())
        }
        "ex_host_init" => {
            crate::host::abi::ex_host_init();
            returned_undefined()
        }
        "ex_host_is_allow_all" => returned_number(crate::host::abi::ex_host_is_allow_all()),
        "ex_host_is_armed" => returned_number(crate::host::abi::ex_host_is_armed()),
        "ex_host_legacy_authorization_cacheable" => {
            returned_number(crate::host::abi::ex_host_legacy_authorization_cacheable())
        }
        "ex_host_legacy_authorization_generation" => {
            returned_number(crate::host::abi::ex_host_legacy_authorization_generation())
        }
        "ex_host_log_event" => {
            crate::host::abi::ex_host_log_event(event.as_ptr(), 0, capability.as_ptr(), 1);
            returned_undefined()
        }
        "ex_host_module_resolve" => raw_host_string(crate::host::abi::ex_host_module_resolve(
            0,
            specifier.as_ptr(),
            std::ptr::null(),
        )),
        "ex_host_module_resolve_meta" => raw_host_string(
            crate::host::abi::ex_host_module_resolve_meta(0, specifier.as_ptr(), std::ptr::null()),
        ),
        "ex_host_permission_request" => returned_number(
            crate::host::abi::ex_host_permission_request(capability.as_ptr()),
        ),
        "ex_host_permission_revoke" => {
            crate::host::abi::ex_host_permission_revoke(capability.as_ptr());
            returned_undefined()
        }
        "ex_host_permission_status" => returned_number(
            crate::host::abi::ex_host_permission_status(capability.as_ptr()),
        ),
        "ex_host_random_fill" => {
            let mut bytes = [0_u8; 16];
            returned_number(crate::host::abi::ex_host_random_fill(
                bytes.as_mut_ptr(),
                bytes.len() as u32,
            ))
        }
        "ex_host_register_module_package" => {
            crate::host::abi::ex_host_register_module_package(
                1,
                package.as_ptr(),
                locator.as_ptr(),
                integrity.as_ptr(),
            );
            returned_undefined()
        }
        "ex_host_release_context" => {
            let context = crate::host::abi::ex_host_claim_diagnostic_context();
            assert_ne!(context, 0);
            crate::host::abi::ex_host_release_context(context);
            returned_undefined()
        }
        "ex_host_resolve_manifest_builtin_internal" => raw_host_string(
            crate::host::abi::ex_host_resolve_manifest_builtin_internal(specifier.as_ptr()),
        ),
        "ex_host_restore_context" => {
            crate::host::abi::ex_host_restore_context(0);
            returned_undefined()
        }
        "ex_host_time_now_ms" => returned_number(crate::host::abi::ex_host_time_now_ms()),
        "ex_host_version" => returned_number(crate::host::abi::ex_host_version()),
        other => return Err(format!("unsupported bounded basic Host ABI {other}")),
    };
    Ok(result)
}

struct OwnedDiagnosticRuntime {
    raw: *mut HermesRuntimeOpaque,
}

impl OwnedDiagnosticRuntime {
    fn new() -> Result<Self, String> {
        fresh_legacy_host();
        let raw = unsafe { ex_hermes_create_diagnostic() };
        if raw.is_null() {
            Err("ex_hermes_create_diagnostic returned NULL".into())
        } else {
            Ok(Self { raw })
        }
    }

    fn destroy(mut self) {
        unsafe { ex_hermes_destroy(self.raw) };
        self.raw = std::ptr::null_mut();
    }
}

impl Drop for OwnedDiagnosticRuntime {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ex_hermes_destroy(self.raw) };
        }
    }
}

extern "C" fn bounded_sync_host_call(
    _op: *const std::os::raw::c_char,
    _args_json: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_char {
    std::ptr::null_mut()
}

extern "C" fn bounded_async_host_call(
    _runtime: *mut HermesRuntimeOpaque,
    _call_id: u64,
    _op: *const std::os::raw::c_char,
    _args_json: *const std::os::raw::c_char,
) {
}

fn execute_hermes_stateless(function_name: &str) -> Result<Value, String> {
    let result = match function_name {
        "ex_hermes_bytecode_version" => returned_number(unsafe { ex_hermes_bytecode_version() }),
        "ex_hermes_create" => {
            let runtime = unsafe { ex_hermes_create() };
            if runtime.is_null() {
                returned_null()
            } else {
                unsafe { ex_hermes_destroy(runtime) };
                returned_object()
            }
        }
        "ex_hermes_current_principal_id" => {
            returned_number(unsafe { ex_hermes_current_principal_id() })
        }
        "ex_hermes_current_runtime_nonce" => {
            returned_number(unsafe { ex_hermes_current_runtime_nonce() })
        }
        "ex_hermes_engine_binary_path" => {
            let mut path = [0_i8; 4096];
            returned_number(unsafe { ex_hermes_engine_binary_path(path.as_mut_ptr(), path.len()) })
        }
        "ex_hermes_engine_mapped_object" => {
            let (mut device, mut inode) = (0_u64, 0_u64);
            returned_number(unsafe { ex_hermes_engine_mapped_object(&mut device, &mut inode) })
        }
        "ex_hermes_evaluation_result_dispose" => {
            unsafe { ex_hermes_evaluation_result_dispose(std::ptr::null_mut()) };
            returned_undefined()
        }
        "ex_hermes_evaluation_result_init" => {
            unsafe { ex_hermes_evaluation_result_init(std::ptr::null_mut()) };
            returned_undefined()
        }
        "ex_hermes_free_string" => {
            unsafe { ex_hermes_free_string(std::ptr::null_mut()) };
            returned_undefined()
        }
        "ex_hermes_now_ms" => returned_number(unsafe { ex_hermes_now_ms() }),
        other => return Err(format!("unsupported stateless Hermes ABI {other}")),
    };
    Ok(result)
}

fn execute_hermes_diagnostic(function_name: &str) -> Result<Value, String> {
    let runtime = OwnedDiagnosticRuntime::new()?;
    let result = match function_name {
        "ex_hermes_callback_backlog" => {
            returned_number(unsafe { ex_hermes_callback_backlog(runtime.raw) })
        }
        "ex_hermes_cancel_structured_work_target" => {
            returned_number(unsafe { ex_hermes_cancel_structured_work_target(runtime.raw, 0) })
        }
        "ex_hermes_create_diagnostic" => returned_object(),
        "ex_hermes_destroy" => {
            runtime.destroy();
            return Ok(returned_undefined());
        }
        "ex_hermes_eval" => {
            let source = b"void 0";
            let source_url = CString::new("ibex:capsec-host-abi-output").unwrap();
            let mut output = std::ptr::null_mut();
            let status = unsafe {
                ex_hermes_eval(
                    runtime.raw,
                    source.as_ptr(),
                    source.len(),
                    source_url.as_ptr(),
                    0,
                    &mut output,
                )
            };
            let _ = take_hermes_string(output);
            returned_number(status)
        }
        "ex_hermes_finish_bootstrap" => {
            returned_number(unsafe { ex_hermes_finish_bootstrap(runtime.raw) })
        }
        "ex_hermes_gc" => {
            unsafe { ex_hermes_gc(runtime.raw) };
            returned_undefined()
        }
        "ex_hermes_get_gc_stats" => {
            raw_hermes_string(unsafe { ex_hermes_get_gc_stats(runtime.raw) })
        }
        "ex_hermes_get_heap_info" => {
            raw_hermes_string(unsafe { ex_hermes_get_heap_info(runtime.raw, 0) })
        }
        "ex_hermes_has_pending_tasks" => {
            returned_number(unsafe { ex_hermes_has_pending_tasks(runtime.raw) })
        }
        "ex_hermes_next_timer" => returned_number(unsafe { ex_hermes_next_timer(runtime.raw) }),
        "ex_hermes_poll" => {
            returned_number(unsafe { ex_hermes_poll(runtime.raw, ex_hermes_now_ms()) })
        }
        "ex_hermes_resolve_host_call" => {
            let payload = CString::new("null").unwrap();
            unsafe { ex_hermes_resolve_host_call(runtime.raw, 1, payload.as_ptr()) };
            returned_undefined()
        }
        "ex_hermes_runtime_nonce" => {
            returned_number(unsafe { ex_hermes_runtime_nonce(runtime.raw) })
        }
        "ex_hermes_set_host_call" => {
            unsafe { ex_hermes_set_host_call(runtime.raw, bounded_sync_host_call) };
            returned_undefined()
        }
        "ex_hermes_set_host_call_async" => {
            unsafe { ex_hermes_set_host_call_async(runtime.raw, bounded_async_host_call) };
            returned_undefined()
        }
        "ex_hermes_set_keep_alive_on_async_error" => {
            unsafe { ex_hermes_set_keep_alive_on_async_error(runtime.raw, 1) };
            returned_undefined()
        }
        "ex_hermes_structured_active_work_target" => {
            returned_number(unsafe { ex_hermes_structured_active_work_target(runtime.raw) })
        }
        "ex_hermes_take_async_failure_event" => {
            let mut event = NativeAsyncFailureEvent::current();
            returned_number(unsafe { ex_hermes_take_async_failure_event(runtime.raw, &mut event) })
        }
        "ex_hermes_take_cancellation_event" => {
            let mut event = NativeCancellationEvent::current();
            returned_number(unsafe { ex_hermes_take_cancellation_event(runtime.raw, &mut event) })
        }
        "ex_hermes_take_work_unit_event" => {
            let mut event = NativeWorkUnitEvent::current();
            returned_number(unsafe { ex_hermes_take_work_unit_event(runtime.raw, &mut event) })
        }
        other => return Err(format!("unsupported diagnostic Hermes ABI {other}")),
    };
    Ok(result)
}

struct OwnedWorkletRuntime {
    raw: *mut HermesRuntimeOpaque,
}

impl OwnedWorkletRuntime {
    fn new() -> Result<Self, String> {
        let raw = unsafe { ex_worklet_create() };
        if raw.is_null() {
            Err("ex_worklet_create returned NULL".into())
        } else {
            Ok(Self { raw })
        }
    }

    fn destroy(mut self) {
        unsafe { ex_worklet_destroy(self.raw) };
        self.raw = std::ptr::null_mut();
    }
}

impl Drop for OwnedWorkletRuntime {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { ex_worklet_destroy(self.raw) };
        }
    }
}

fn install_bounded_worklet(
    runtime: *mut HermesRuntimeOpaque,
    worklet_id: &CString,
) -> Result<i32, String> {
    let source = b"(function(event){ return event; })";
    let mut error = std::ptr::null_mut();
    let status = unsafe {
        ex_worklet_install(
            runtime,
            worklet_id.as_ptr(),
            source.as_ptr(),
            source.len(),
            1,
            &mut error,
        )
    };
    let detail = take_hermes_string(error);
    if status == 1 {
        Err(format!(
            "bounded worklet install failed: {}",
            detail.unwrap_or_else(|| "missing diagnostic".into())
        ))
    } else {
        Ok(status)
    }
}

fn execute_worklet(function_name: &str) -> Result<Value, String> {
    let runtime = OwnedWorkletRuntime::new()?;
    unsafe { ex_worklet_set_generation(runtime.raw, 1) };
    let worklet_id = CString::new("capsec-host-abi-output").unwrap();
    let result = match function_name {
        "ex_worklet_bind_shared_values" => returned_number(unsafe {
            ex_worklet_bind_shared_values(runtime.raw, std::ptr::null_mut(), 0)
        }),
        "ex_worklet_create" => returned_object(),
        "ex_worklet_destroy" => {
            runtime.destroy();
            return Ok(returned_undefined());
        }
        "ex_worklet_drain_logs" => raw_hermes_string(unsafe { ex_worklet_drain_logs(runtime.raw) }),
        "ex_worklet_drain_scheduled" => {
            raw_hermes_string(unsafe { ex_worklet_drain_scheduled(runtime.raw) })
        }
        "ex_worklet_generation" => returned_number(unsafe { ex_worklet_generation(runtime.raw) }),
        "ex_worklet_install" => returned_number(install_bounded_worklet(runtime.raw, &worklet_id)?),
        "ex_worklet_invoke" => {
            if install_bounded_worklet(runtime.raw, &worklet_id)? != 0 {
                return Err("bounded worklet was not installed at the active generation".into());
            }
            let args = CString::new("{\"value\":1}").unwrap();
            let mut output = std::ptr::null_mut();
            let status = unsafe {
                ex_worklet_invoke(runtime.raw, worklet_id.as_ptr(), args.as_ptr(), &mut output)
            };
            let _ = take_hermes_string(output);
            returned_number(status)
        }
        "ex_worklet_set_generation" => {
            unsafe { ex_worklet_set_generation(runtime.raw, 2) };
            returned_undefined()
        }
        "ex_worklet_set_measure_callback" => {
            unsafe { ex_worklet_set_measure_callback(runtime.raw, None, std::ptr::null_mut()) };
            returned_undefined()
        }
        other => return Err(format!("unsupported worklet Hermes ABI {other}")),
    };
    Ok(result)
}

fn compiled_host_abi_edges() -> std::collections::BTreeMap<String, String> {
    let coverage: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/registry/coverage-edges.json"
    )))
    .expect("compiled coverage registry is JSON");
    coverage["edges"]
        .as_array()
        .expect("compiled coverage edges")
        .iter()
        .filter(|edge| edge["surface"]["kind"] == "host-abi")
        .map(|edge| {
            (
                edge["id"].as_str().unwrap().to_owned(),
                edge["surface"]["name"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn validate_row(row: &Value) -> Result<(&str, &str), String> {
    let key = row
        .get("key")
        .and_then(Value::as_object)
        .ok_or("missing output key")?;
    let probe = row
        .get("probe")
        .and_then(Value::as_object)
        .ok_or("missing output probe")?;
    if key.get("sourceKind").and_then(Value::as_str) != Some("host-abi")
        || key.get("output").and_then(Value::as_str) != Some("[[return]]")
        || key.get("mode").and_then(Value::as_str) != Some("all")
        || probe.get("kind").and_then(Value::as_str) != Some("loaded-engine-return-record")
    {
        return Err("Host ABI output row selected an unsupported key or proof kind".into());
    }
    let descriptor = probe
        .get("sourceDescriptor")
        .ok_or("missing source descriptor")?;
    let function_name = descriptor["functionName"]
        .as_str()
        .ok_or("missing function name")?;
    if descriptor["kind"] != DESCRIPTOR_KIND
        || descriptor["invocationSchema"] != INVOCATION_SCHEMA
        || probe["sourceDescriptorDigest"] != tagged_jcs_digest(descriptor)
        || probe["recordPath"] != json!(["[[return]]"])
    {
        return Err(format!("{function_name}: source descriptor drift"));
    }
    let edge_id = key
        .get("surfaceId")
        .and_then(Value::as_str)
        .ok_or("missing surface id")?;
    if compiled_host_abi_edges().get(edge_id).map(String::as_str) != Some(function_name) {
        return Err(format!("{function_name}: compiled coverage identity drift"));
    }
    for binding in descriptor["sourceFiles"]
        .as_array()
        .ok_or("missing source files")?
    {
        let source_path = binding["path"].as_str().ok_or("missing source path")?;
        let bytes = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(source_path))
            .map_err(|error| format!("{function_name}: read {source_path}: {error}"))?;
        if binding["rawContentDigest"] != tagged_bytes_digest(&bytes)
            || !bytes
                .windows(function_name.len())
                .any(|window| window == function_name.as_bytes())
        {
            return Err(format!("{function_name}: exact source binding drift"));
        }
    }
    let operation = descriptor["operation"]["kind"]
        .as_str()
        .ok_or("missing operation")?;
    let expected_language = if operation.starts_with("rust-host-") {
        "rust"
    } else if operation.starts_with("native-hermes-") {
        "c++"
    } else {
        return Err(format!("{function_name}: unsupported operation family"));
    };
    let selected_definitions = descriptor["selectedDefinitions"]
        .as_array()
        .ok_or("missing selected definitions")?;
    if selected_definitions.is_empty()
        || selected_definitions.iter().any(|definition| {
            definition["language"] != expected_language
                || definition["targetVariant"] != "default"
                || !descriptor["sourceRefs"]
                    .as_array()
                    .is_some_and(|refs| refs.contains(&definition["sourceRef"]))
        })
    {
        return Err(format!(
            "{function_name}: selected compiled definition drift"
        ));
    }
    let output_contracts = descriptor["outputContracts"]
        .as_array()
        .ok_or("missing source-derived output contracts")?;
    if descriptor["outputContractSchema"] != OUTPUT_CONTRACT_SCHEMA
        || descriptor["selectedOutput"]
            != json!({
                "kind": "scalar",
                "ownership": "not-applicable",
                "selector": "[[return]]"
            })
        || output_contracts.len() != selected_definitions.len()
    {
        return Err(format!(
            "{function_name}: selected output contract binding drift"
        ));
    }
    for (definition, contract) in selected_definitions.iter().zip(output_contracts) {
        if contract["schema"] != OUTPUT_CONTRACT_SCHEMA
            || contract["functionName"] != function_name
            || contract["sourceRef"] != definition["sourceRef"]
            || contract["language"] != definition["language"]
            || contract["return"]["role"] != "value"
            || contract["return"]["kind"] != "scalar"
            || contract["return"]["ownership"]["kind"] != "not-applicable"
            || !contract["outputChannels"].as_array().is_some_and(|channels| {
                channels.iter().any(|channel| {
                    channel["selector"] == "[[return]]"
                        && channel["role"] == "return"
                        && channel["kind"] == "scalar"
                })
            })
        {
            return Err(format!(
                "{function_name}: source-derived scalar return contract drift"
            ));
        }
    }
    Ok((function_name, operation))
}

fn return_record_result(row: &Value, raw: Value) -> Value {
    json!({
        "key": row["key"],
        "proof": {
            "kind": "loaded-engine-return-record",
            "fixtureId": row["probe"]["fixtureId"],
            "sourceDescriptorDigest": row["probe"]["sourceDescriptorDigest"],
            "outputContractSchema": row["probe"]["sourceDescriptor"]["outputContractSchema"],
            "selectedOutput": row["probe"]["sourceDescriptor"]["selectedOutput"],
            "recordPath": row["probe"]["recordPath"],
            "rawValueShape": raw["rawValueShape"],
        },
        "raw": raw,
    })
}

pub(super) fn execute_host_abi_output_rows(rows: &[Value]) -> (Vec<Value>, Vec<Value>) {
    if rows.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let sandbox = FsSandbox::new();
    let mut observations = Vec::with_capacity(rows.len());
    let mut unexercisable = Vec::new();
    for row in rows {
        let execution = validate_row(row).and_then(|(function_name, operation)| {
            let raw = match operation {
                "rust-host-fs-sandbox" => execute_fs(function_name, &sandbox),
                "rust-host-sqlite-memory" => execute_sqlite(function_name, &sandbox),
                "rust-host-terminal-inert" => execute_terminal(function_name),
                "rust-host-bounded-basic" => execute_basic(function_name),
                "native-hermes-stateless-current-target" => execute_hermes_stateless(function_name),
                "native-hermes-diagnostic-runtime" => execute_hermes_diagnostic(function_name),
                "native-hermes-worklet-runtime" => execute_worklet(function_name),
                other => Err(format!(
                    "{function_name}: unsupported Host ABI operation {other}"
                )),
            }?;
            if raw["kind"] != "return" || raw["rawValueShape"] != "number" {
                return Err(format!(
                    "{function_name}: scalar return contract produced a non-number runtime fact"
                ));
            }
            Ok(raw)
        });
        match execution {
            Ok(raw) => observations.push(return_record_result(row, raw)),
            Err(reason) => unexercisable.push(json!({ "key": row["key"], "reason": reason })),
        }
    }
    (observations, unexercisable)
}

#[test]
fn host_abi_output_executor_rejects_an_unbound_source_digest() {
    let row = json!({
        "key": {
            "surfaceId": "surface.host.abi.ex.host.version.1xgws98",
            "output": "[[return]]",
            "alias": "ex_host_version",
            "mode": "all",
            "sourceKind": "host-abi",
            "returnVariant": "default"
        },
        "probe": {
            "kind": "loaded-engine-return-record",
            "fixtureId": "host-abi-output-invalid",
            "sourceDescriptor": {
                "kind": DESCRIPTOR_KIND,
                "invocationSchema": INVOCATION_SCHEMA,
                "functionName": "ex_host_version",
                "sourceFiles": [],
                "operation": {"kind": "rust-host-bounded-basic"}
            },
            "sourceDescriptorDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "recordPath": ["[[return]]"]
        }
    });
    assert!(validate_row(&row).is_err());
}

#[test]
fn capsec_host_abi_output_batch() {
    let Ok(plan_path) = std::env::var("IBEX_CAPSEC_HOST_ABI_OUTPUT_PLAN") else {
        eprintln!("IBEX_CAPSEC_HOST_ABI_OUTPUT_PLAN is unset; skipping Host ABI output batch");
        return;
    };
    let output_path = std::env::var("IBEX_CAPSEC_HOST_ABI_OUTPUT_BATCH_OUTPUT")
        .expect("Host ABI output batch requires an owned output path");
    let bytes = std::fs::read(plan_path).expect("read Host ABI output plan");
    let text = std::str::from_utf8(&bytes).expect("Host ABI output plan is UTF-8");
    let plan = capsec_semantics::strict_json::parse_strict(text)
        .expect("Host ABI output plan is strict JSON");
    let rows = plan["rows"].as_array().expect("Host ABI output plan rows");
    let (results, unexercisable) = execute_host_abi_output_rows(rows);
    assert_eq!(
        results.len() + unexercisable.len(),
        rows.len(),
        "every authored Host ABI output row is accounted for"
    );
    let artifact = json!({
        "hostAbiOutputExecutorBatchSchema": "ibex/capsec-host-abi-output-executor-batch/1",
        "results": results,
        "unexercisable": unexercisable,
    });
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .expect("create owned Host ABI output batch");
    serde_json::to_writer_pretty(&mut output, &artifact).expect("write Host ABI output batch");
    use std::io::Write as _;
    output
        .write_all(b"\n")
        .expect("terminate Host ABI output batch");
}
