//! Hermes JavaScript engine adapter
//!
//! This module implements the Engine trait for the Hermes JS engine.
//! Hermes is embedded via a C++/JSI adapter compiled in build.rs.

use super::{async_trait, Engine, EngineFeature};
use crate::cdp::{self, BreakpointInfo, CdpBackend, DebugCommand, ScriptInfo};
use crate::subprocess::{output_with_timeout, timeout_from_env, DEFAULT_HERMESC_TIMEOUT_MS};
use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::process::Command;
use tokio::sync::Mutex;
use {std::sync::OnceLock, tokio::sync::Notify};

const REQUIRED_RUNTIME_MARKERS: &[&[u8]] = &[b"globalThis.__exactRuntime", b"ExactBundle"];

// The native bootstrap installs this one-shot trusted hook before any bundled
// runtime code executes. Rust invokes it only after the embedded/disk runtime
// path is complete, then removes the hook so application code cannot recapture
// or replace the package-global baseline. @ref LLP 0013#mechanism-2
pub(crate) const FINALIZE_COMPARTMENT_BASELINE: &str = r#"(function(){
  var g = globalThis;
  var hasOwn = Object.prototype.hasOwnProperty;
  function owns(name) {
    return hasOwn.call(g, name);
  }

  var hasRegistry = owns('__compartments');
  var hasRefresh = owns('__ibexRefreshCompartmentBaseline');
  var hasReady = owns('__ibexCompartmentRegistryReady');
  var hasFinalized = owns('__ibexCompartmentBaselineFinalized');

  // Native compartment support is disabled only when the entire handshake is
  // absent. Any partial state is malformed and must fail closed.
  if (!hasRegistry && !hasRefresh && !hasReady && !hasFinalized) return true;

  function discardRefresh() {
    if (hasRefresh) {
      try { delete g.__ibexRefreshCompartmentBaseline; } catch (_) {}
    }
  }
  function validFinalizedMarker() {
    if (!owns('__ibexCompartmentBaselineFinalized') ||
        g.__ibexCompartmentBaselineFinalized !== true) return false;
    var descriptor = Object.getOwnPropertyDescriptor(
      g,
      '__ibexCompartmentBaselineFinalized'
    );
    return descriptor &&
      descriptor.value === true &&
      descriptor.writable === false &&
      descriptor.enumerable === false &&
      descriptor.configurable === false;
  }
  function validRegistry(expected) {
    return owns('__compartments') &&
      g.__compartments === expected &&
      typeof expected === 'object' && expected !== null &&
      owns('__ibexCompartmentRegistryReady') &&
      g.__ibexCompartmentRegistryReady === true;
  }

  if (!hasRegistry || !hasReady || !hasFinalized) {
    discardRefresh();
    return false;
  }

  var registry = g.__compartments;

  // A completed handshake is the idempotent path used by a repeated Windows
  // Runtime::load_runtime call. The native hook owns the final marker so Rust
  // never infers completion from mutable environment state.
  if (!hasRefresh) {
    return validRegistry(registry) && validFinalizedMarker();
  }

  var refresh = g.__ibexRefreshCompartmentBaseline;
  if ((typeof registry !== 'object' || registry === null) ||
      typeof refresh !== 'function' ||
      g.__ibexCompartmentRegistryReady !== true ||
      g.__ibexCompartmentBaselineFinalized !== false) {
    discardRefresh();
    return false;
  }

  try {
    refresh();
  } finally {
    try { delete g.__ibexRefreshCompartmentBaseline; } catch (_) {}
  }
  return validRegistry(registry) &&
    !owns('__ibexRefreshCompartmentBaseline') &&
    validFinalizedMarker();
})()"#;

pub(crate) async fn finalize_compartment_baseline(engine: &dyn Engine) -> Result<()> {
    let finalized = engine
        .eval_immediate(FINALIZE_COMPARTMENT_BASELINE)
        .await
        .context("trusted compartment baseline refresh failed")?;
    if !matches!(finalized.as_deref().map(str::trim), Some("true")) {
        anyhow::bail!(
            "compartment registry state was malformed or its trusted baseline was not finalized"
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn hermes_engine_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(Mutex::default)
}

fn contains_any_marker(bytes: &[u8], markers: &[&[u8]]) -> bool {
    markers
        .iter()
        .any(|marker| bytes.windows(marker.len()).any(|window| window == *marker))
}

fn looks_like_ibex_runtime_bundle(bytes: &[u8]) -> bool {
    contains_any_marker(bytes, REQUIRED_RUNTIME_MARKERS)
}

fn normalize_hashbang_bytes(bytes: &[u8]) -> Cow<'_, [u8]> {
    if !bytes.starts_with(b"#!") {
        return Cow::Borrowed(bytes);
    }

    let mut normalized = bytes.to_vec();
    normalized[0] = b'/';
    normalized[1] = b'/';
    Cow::Owned(normalized)
}

// Embed the runtime bundle (HBC or JS) as static bytes compiled into the binary.
// Generated by build.rs — see embed_runtime_bundle() for details.
include!(concat!(env!("OUT_DIR"), "/embedded_runtime.rs"));

#[repr(C)]
struct HermesRuntimeOpaque {
    _private: [u8; 0],
}

extern "C" {
    fn ex_hermes_create_diagnostic() -> *mut HermesRuntimeOpaque;
    fn ex_hermes_create_armed(
        armed_snapshot_digest: *const std::os::raw::c_char,
    ) -> *mut HermesRuntimeOpaque;
    #[cfg(all(test, unix))]
    fn ex_hermes_runtime_nonce(runtime: *mut HermesRuntimeOpaque) -> u64;
    fn ex_hermes_destroy(runtime: *mut HermesRuntimeOpaque);
    fn ex_hermes_set_host_call(
        runtime: *mut HermesRuntimeOpaque,
        callback: extern "C" fn(
            op: *const std::os::raw::c_char,
            args_json: *const std::os::raw::c_char,
        ) -> *mut std::os::raw::c_char,
    );
    fn ex_hermes_set_host_call_async(
        runtime: *mut HermesRuntimeOpaque,
        callback: extern "C" fn(
            runtime: *mut HermesRuntimeOpaque,
            call_id: u64,
            op: *const std::os::raw::c_char,
            args_json: *const std::os::raw::c_char,
        ),
    );
    fn ex_hermes_resolve_host_call(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        payload: *const std::os::raw::c_char,
    );
    #[cfg(test)]
    fn ex_hermes_set_exact_host_call_async(
        runtime: *mut HermesRuntimeOpaque,
        context_kind: i32,
        allowed_operation_ids: *const u32,
        allowed_operation_count: usize,
        operation_manifest_digest: *const std::os::raw::c_char,
        callback: extern "C" fn(
            runtime: *mut HermesRuntimeOpaque,
            call_id: u64,
            operation_id: u32,
            payload: *const u8,
            payload_len: usize,
            context: *mut std::ffi::c_void,
        ),
        context: *mut std::ffi::c_void,
    ) -> i32;
    #[cfg(test)]
    fn ex_hermes_resolve_exact_host_call(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        status: i32,
        payload: *const u8,
        payload_len: usize,
    );
    fn ex_hermes_eval(
        runtime: *mut HermesRuntimeOpaque,
        data: *const u8,
        len: usize,
        source_url: *const std::os::raw::c_char,
        is_bytecode: i32,
        out_value: *mut *mut std::os::raw::c_char,
    ) -> i32;
    fn ex_hermes_free_string(value: *mut std::os::raw::c_char);
    fn ex_hermes_poll(runtime: *mut HermesRuntimeOpaque, now_ms: u64) -> i32;
    // Monotonic timer clock shared with the C++ scheduler (nowMs). See
    // current_time_ms() for why the Rust loop must not use its own clock.
    fn ex_hermes_now_ms() -> u64;
    fn ex_hermes_next_timer(runtime: *mut HermesRuntimeOpaque) -> i64;
    fn ex_hermes_has_pending_tasks(runtime: *mut HermesRuntimeOpaque) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ex_hermes_current_runtime_nonce() -> u64;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ex_hermes_current_principal_id() -> u64;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_install_capsec_context_observer(
        runtime: *mut HermesRuntimeOpaque,
        global_name: *const std::os::raw::c_char,
    ) -> i32;
    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    fn ibex_test_set_armed_startup_failure_stage(stage: *const std::os::raw::c_char);
    fn ex_hermes_debugger_enable(runtime: *mut HermesRuntimeOpaque) -> i32;
    fn ex_hermes_debugger_get_scripts(
        runtime: *mut HermesRuntimeOpaque,
    ) -> *mut std::os::raw::c_char;
    fn ex_hermes_debugger_get_script_source(
        runtime: *mut HermesRuntimeOpaque,
        script_id: u32,
    ) -> *mut std::os::raw::c_char;
    fn ex_hermes_debugger_set_breakpoint(
        runtime: *mut HermesRuntimeOpaque,
        script_id: u32,
        line_number: u32,
        column_number: u32,
        condition: *const std::os::raw::c_char,
    ) -> *mut std::os::raw::c_char;
    fn ex_hermes_debugger_remove_breakpoint(runtime: *mut HermesRuntimeOpaque, breakpoint_id: u64);
    fn ex_hermes_debugger_pause(runtime: *mut HermesRuntimeOpaque);
    fn ex_hermes_debugger_resume(runtime: *mut HermesRuntimeOpaque, command: i32);
    fn ex_hermes_debugger_next_event(
        runtime: *mut HermesRuntimeOpaque,
    ) -> *mut std::os::raw::c_char;
    fn ex_hermes_debugger_eval(
        runtime: *mut HermesRuntimeOpaque,
        expression: *const std::os::raw::c_char,
        frame_index: u32,
    ) -> *mut std::os::raw::c_char;
    fn ex_host_http_has_referenced() -> i32;
    fn ex_host_http_has_pending_requests() -> i32;
    fn native_ws_has_active() -> i32;
}

// Event loop notification: wakes the event loop when a callback is pushed
// from C++ (e.g. HTTP request arrives, timer fires, etc.)
static CALLBACK_NOTIFY: OnceLock<Arc<Notify>> = OnceLock::new();

fn callback_notify() -> &'static Arc<Notify> {
    CALLBACK_NOTIFY.get_or_init(|| Arc::new(Notify::new()))
}

// (ENG-23234/ENG-24265) The library owns the sole
// ex_hermes_notify_callback symbol in every feature profile. The CLI
// registers this runtime hook to bridge it to tokio; a cross-thread
// callback push (fetch/WS completion, HTTP request — and now signal
// dispatch) sat queued until the next due timer expired, so an external
// SIGINT to a parked runtime was not delivered until that timer fired.
// Runtime registration avoids mutually-exclusive global definitions and is
// link-safe for library, CLI, unit, integration, and all-feature builds.
extern "C" fn cli_wake_hook(_context: *mut std::ffi::c_void) {
    callback_notify().notify_one();
}

fn register_default_profile_wake_hook() {
    static REGISTERED: OnceLock<()> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        ibex_runtime::engine::ex_hermes_set_host_wake_hook(
            Some(cli_wake_hook),
            std::ptr::null_mut(),
        );
    });
}

async fn wait_for_callback_or_sleep(duration: std::time::Duration) {
    tokio::select! {
        _ = callback_notify().notified() => {},
        _ = tokio::time::sleep(duration) => {},
    }
}

// How long the event loop parks when host work is pending but no timer is due
// (e.g. an idle `Bun.serve` server waiting for the next request). There is no
// deadline to wait for here, only an external event, so the park duration is a
// wakeup-safety fallback rather than a poll cadence.
//
// With `cli-notify` every cross-thread callback push signals the loop
// (pushRuntimeCallback + the HTTP server both call ex_hermes_notify_callback),
// so we park until notified and only re-poll after a long safety interval in the
// (should-be-impossible) case a notification was missed. Parking a fixed 5 ms
// here instead made an idle server re-poll ~200×/sec forever, each iteration
// taking the tokio Mutex, the ffi_lock, and four FFI calls.
//
// Without `cli-notify` the wakeup source is the host wake hook registered by
// register_default_profile_wake_hook (ENG-23234) — every callback push still
// signals the parked select! — but the short interval is kept as a
// conservative safety net for that profile.
#[cfg(feature = "cli-notify")]
const IDLE_PARK: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(not(feature = "cli-notify"))]
const IDLE_PARK: std::time::Duration = std::time::Duration::from_millis(5);

// Upper bound on how long the REPL-EOF drain (`drain_event_loop`) runs before
// giving up. At EOF we flush work that is ready now and one-shots already due,
// but a referenced perpetual `setInterval`/a self-rescheduling 0-delay timer
// stays "pending" forever; this deadline stops Ctrl+D from hanging on it.
// @ref LLP 0003#the-event-loop — the host drives Hermes by polling; at EOF that
// drive must be bounded. (ENG-23030 #1)
const EOF_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_millis(200);

// Maximum `ex_hermes_poll` calls per idle pump (`pump_ready_tasks`). A
// self-rescheduling 0-delay timer (`setInterval(fn,0)` / `setTimeout(tick,0)`)
// is due on every poll, so without a bound the pump never returns and starves
// the REPL select! of the chance to read the next line. The next idle tick
// pumps again, so the timer still runs — it just no longer locks out input.
// (ENG-23030 #3)
const PUMP_MAX_POLLS_PER_TICK: usize = 1024;

// Floor for the REPL idle park so a due-soon (or 0-delay) timer cannot make the
// prompt busy-spin; mirrors the pre-ENG-23030 fixed pump cadence. (ENG-23030 #5)
const REPL_PARK_FLOOR: std::time::Duration = std::time::Duration::from_millis(50);

fn host_call_response(payload: String) -> *mut std::os::raw::c_char {
    match CString::new(payload) {
        Ok(value) => value.into_raw(),
        Err(_) => CString::new("-Host call response contained interior nulls")
            .expect("valid fallback host-call error")
            .into_raw(),
    }
}

#[cfg(all(test, feature = "capsec-conformance-observer"))]
/// Test-only in-process typed adapter. It is deliberately not routed through
/// `exact_agent_host_call` or exposed as a JavaScript global.
fn evaluate_capsec_conformance_adapter(args: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Request {
        terminal_branch_id: String,
        decision_set_json: String,
        gates_json: String,
    }

    let request_value = capsec_semantics::strict_json::parse_strict(args)
        .map_err(|error| anyhow!("invalid conformance adapter request: {error}"))?;
    let request: Request =
        serde_json::from_value(request_value).context("malformed conformance adapter request")?;
    if request.terminal_branch_id.is_empty() {
        anyhow::bail!("conformance adapter request has no terminal branch id");
    }
    if !ibex_runtime::host::abi::begin_installed_conformance_observation(
        &request.terminal_branch_id,
    ) {
        anyhow::bail!("conformance adapter has no installed host");
    }
    let response = unsafe {
        ibex_runtime::host::abi::ex_host_evaluate_typed_decision(
            request.decision_set_json.as_ptr(),
            request.decision_set_json.len(),
            request.gates_json.as_ptr(),
            request.gates_json.len(),
        )
    };
    if response.is_null() {
        let _ = ibex_runtime::host::abi::take_installed_conformance_observations();
        anyhow::bail!("typed decision adapter returned no response");
    }
    let response_text = unsafe { CStr::from_ptr(response) }
        .to_string_lossy()
        .into_owned();
    ibex_runtime::host::abi::ex_host_free_string(response);
    let (legacy_observations, typed_observations) =
        ibex_runtime::host::abi::take_installed_conformance_observations();
    // Read these on the runtime thread while the host call's exact JS frame and
    // any scoped native callback principal are still live. Callback-invariant
    // public evidence uses them to bind the typed request to the actual engine
    // execution context instead of trusting the actor encoded in JSON.
    // @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence
    let execution_context = unsafe {
        serde_json::json!({
            "principalId": format!("u64:{}", ex_hermes_current_principal_id()),
            "runtimeNonce": format!("u64:{}", ex_hermes_current_runtime_nonce()),
        })
    };
    let adapter = capsec_semantics::strict_json::parse_strict(&response_text)
        .map_err(|error| anyhow!("typed decision adapter returned invalid JSON: {error}"))?;
    serde_json::to_string(&serde_json::json!({
        "adapter": adapter,
        "legacyObservations": legacy_observations,
        "typedObservations": typed_observations,
        "executionContext": execution_context,
    }))
    .context("conformance adapter response serialization failed")
}

/// Generic string-dispatch handler retained for unarmed diagnostic runtimes.
/// Armed runtimes reject its installation at the native ABI boundary.
extern "C" fn exact_agent_host_call(
    op: *const std::os::raw::c_char,
    args_json: *const std::os::raw::c_char,
) -> *mut std::os::raw::c_char {
    if op.is_null() {
        return host_call_response("-Missing host call operation".to_string());
    }

    let operation = unsafe { CStr::from_ptr(op) }.to_string_lossy().into_owned();
    let args = if args_json.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(args_json) }
            .to_string_lossy()
            .into_owned()
    };

    match crate::agent_logs::handle_host_call(&operation, &args) {
        Ok(json) => host_call_response(format!("+{json}")),
        Err(message) => host_call_response(format!("-{message}")),
    }
}

/// Async host-call handler for unarmed diagnostic runtimes (LLP 0297 W3). The
/// CLI host has no cross-thread hop to make, so it services the same op table
/// as the sync bridge and resolves inline; resolution still flows through the
/// runtime callback queue. Armed runtimes reject installation and resolution
/// at the C++ ABI boundary.
extern "C" fn exact_agent_host_call_async(
    runtime: *mut HermesRuntimeOpaque,
    call_id: u64,
    op: *const std::os::raw::c_char,
    args_json: *const std::os::raw::c_char,
) {
    let payload = if op.is_null() {
        "-Missing host call operation".to_string()
    } else {
        let operation = unsafe { CStr::from_ptr(op) }.to_string_lossy().into_owned();
        let args = if args_json.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(args_json) }
                .to_string_lossy()
                .into_owned()
        };
        match crate::agent_logs::handle_host_call(&operation, &args) {
            Ok(json) => format!("+{json}"),
            Err(message) => format!("-{message}"),
        }
    };

    let payload_c = CString::new(payload).unwrap_or_else(|_| {
        CString::new("-Host call response contained interior nulls")
            .expect("valid fallback host-call error")
    });
    unsafe { ex_hermes_resolve_host_call(runtime, call_id, payload_c.as_ptr()) };
}

fn workspace_root_from(start: &Path) -> Option<PathBuf> {
    start.ancestors().find_map(|ancestor| {
        if ancestor.join("vendored-generated").is_dir()
            && ancestor
                .join("packages")
                .join("ibex-runtime-js")
                .join("package.json")
                .is_file()
            && ancestor
                .join("packages")
                .join("ibex-devtools")
                .join("package.json")
                .is_file()
        {
            Some(ancestor.to_path_buf())
        } else {
            None
        }
    })
}

fn runtime_workspace_roots() -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();

    if let Some(raw) =
        std::env::var_os("IBEX_REPO_ROOT").or_else(|| std::env::var_os("EXACT_REPO_ROOT"))
    {
        let candidate = PathBuf::from(raw);
        if !candidate.is_absolute() {
            anyhow::bail!("IBEX_REPO_ROOT must be an absolute authenticated directory");
        }
        let root = workspace_root_from(&candidate)
            .and_then(|root| std::fs::canonicalize(root).ok())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "IBEX_REPO_ROOT does not identify an Ibex checkout: {}",
                    candidate.display()
                )
            })?;
        return Ok(vec![root]);
    }

    // The compile-time checkout is authenticated by the build. Never inspect
    // the application cwd or its ancestors: a project can create a lookalike
    // workspace and otherwise select executable runtime bootstrap code.
    if let Some(found) = workspace_root_from(Path::new(env!("CARGO_MANIFEST_DIR")))
        .and_then(|root| std::fs::canonicalize(root).ok())
    {
        roots.push(found);
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(found) =
            workspace_root_from(&exe_path).and_then(|root| std::fs::canonicalize(root).ok())
        {
            if !roots.contains(&found) {
                roots.push(found);
            }
        }
    }

    if roots.is_empty() {
        anyhow::bail!(
            "Failed to resolve an authenticated Ibex runtime root. Set IBEX_REPO_ROOT to an absolute trusted checkout"
        );
    }
    Ok(roots)
}

fn target_arch_to_hermes_dir(arch: &str) -> &str {
    match arch {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" | "i686" => "x86",
        other => other,
    }
}

fn local_hermes_tool_candidates(tools: &Path, tool: &str) -> Vec<PathBuf> {
    let target_os = std::env::consts::OS;
    let target_arch = target_arch_to_hermes_dir(std::env::consts::ARCH);
    let mut candidates = vec![tools.join(tool)];
    if target_os == "windows" {
        candidates.push(tools.join(format!("{tool}.exe")));
        candidates.push(
            tools
                .join(format!("windows-{target_arch}"))
                .join("bin")
                .join(format!("{tool}.exe")),
        );
    } else {
        candidates.push(tools.join(format!("{tool}-{target_os}-{target_arch}")));
    }
    candidates
}

/// Directories from which production may execute an external Hermes tool.
/// An explicit operator-selected directory takes precedence. Otherwise only
/// the Ibex build checkout and executable-relative installation locations are
/// considered; the application cwd, its ancestors, PATH, and HOME are never
/// executable discovery roots (ENG-24254).
fn trusted_hermes_tool_roots() -> Result<Vec<PathBuf>> {
    if let Some(raw) = std::env::var_os("IBEX_HERMES_TOOL_DIR")
        .or_else(|| std::env::var_os("EXACT_HERMES_TOOL_DIR"))
    {
        let root = PathBuf::from(raw);
        if !root.is_absolute() {
            anyhow::bail!("IBEX_HERMES_TOOL_DIR must be an absolute directory");
        }
        let canonical = std::fs::canonicalize(&root).with_context(|| {
            format!(
                "Failed to authenticate explicit Hermes tool directory {}",
                root.display()
            )
        })?;
        if !canonical.is_dir() {
            anyhow::bail!(
                "IBEX_HERMES_TOOL_DIR is not a directory: {}",
                canonical.display()
            );
        }
        return Ok(vec![canonical]);
    }

    let mut roots = Vec::new();
    let build_tools = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tools")
        .join("hermes");
    if let Ok(root) = std::fs::canonicalize(build_tools) {
        roots.push(root);
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(bin_dir) = exe.parent() {
            for candidate in [
                bin_dir.join("hermes-tools"),
                bin_dir.join("../libexec/ibex"),
            ] {
                if let Ok(root) = std::fs::canonicalize(candidate) {
                    if !roots.contains(&root) {
                        roots.push(root);
                    }
                }
            }
        }
    }
    Ok(roots)
}

fn discover_hermes_tool_in_roots(tool: &str, roots: &[PathBuf]) -> Result<PathBuf> {
    let mut matches = Vec::new();
    for root in roots {
        let canonical_root = std::fs::canonicalize(root).with_context(|| {
            format!("Failed to authenticate Hermes tool root {}", root.display())
        })?;
        for candidate in local_hermes_tool_candidates(&canonical_root, tool) {
            if !candidate.is_file() {
                continue;
            }
            let canonical = std::fs::canonicalize(&candidate).with_context(|| {
                format!("Failed to authenticate Hermes tool {}", candidate.display())
            })?;
            if !canonical.starts_with(&canonical_root) {
                anyhow::bail!(
                    "Hermes tool {} escapes authenticated root {}",
                    canonical.display(),
                    canonical_root.display()
                );
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if std::fs::metadata(&canonical)?.permissions().mode() & 0o111 == 0 {
                    anyhow::bail!("Hermes tool is not executable: {}", canonical.display());
                }
            }
            if !matches.contains(&canonical) {
                matches.push(canonical);
            }
        }
    }
    match matches.as_slice() {
        [path] => Ok(path.clone()),
        [] => anyhow::bail!(
            "Hermes {tool} not found in an authenticated install location. Run ./scripts/download-hermes.sh or set IBEX_HERMES_TOOL_DIR to an absolute trusted directory"
        ),
        paths => anyhow::bail!(
            "Ambiguous Hermes {tool} installation; refusing to choose among: {}",
            paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Find the Hermes binary
pub(crate) fn find_hermes_binary() -> Result<PathBuf> {
    discover_hermes_tool_in_roots("hermes", &trusted_hermes_tool_roots()?)
}

/// Find the hermesc compiler
fn find_hermesc_binary() -> Result<PathBuf> {
    discover_hermes_tool_in_roots("hermesc", &trusted_hermes_tool_roots()?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HermesToolIdentity {
    path: PathBuf,
    bytes: Arc<Vec<u8>>,
    sha256: String,
    length: u64,
    modified_nanos: u128,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl HermesToolIdentity {
    fn capture(path: &Path) -> Result<Self> {
        let path = std::fs::canonicalize(path)
            .with_context(|| format!("Failed to authenticate Hermes tool {}", path.display()))?;
        path.to_str()
            .context("Hermes tool paths must be valid UTF-8")?;
        // Bind bytes and metadata to one opened file object. Reading the path
        // and then stat'ing it allowed a replacement between those syscalls to
        // produce a mixed identity.
        let mut file = std::fs::File::open(&path)
            .with_context(|| format!("Failed to open Hermes tool {}", path.display()))?;
        let metadata = file.metadata()?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        std::io::Read::read_to_end(&mut file, &mut bytes)?;
        let modified_nanos = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            path,
            bytes: Arc::new(bytes.clone()),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            length: metadata.len(),
            modified_nanos,
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
        })
    }

    fn verify_selected_path(&self) -> Result<()> {
        let current = Self::capture(&self.path)?;
        if &current != self {
            anyhow::bail!(
                "Hermes tool changed after selection: {}",
                self.path.display()
            );
        }
        Ok(())
    }

    fn cache_fingerprint(&self) -> String {
        #[cfg(unix)]
        let object = format!("{}:{}", self.device, self.inode);
        #[cfg(not(unix))]
        let object = String::new();
        format!(
            "{}\0{}\0{}\0{}\0{}",
            self.path
                .to_str()
                .expect("HermesToolIdentity rejects non-UTF-8 paths"),
            self.sha256,
            self.length,
            self.modified_nanos,
            object
        )
    }
}

struct StagedHermesTool(PathBuf);

impl Drop for StagedHermesTool {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn stage_authenticated_hermes_tool(identity: &HermesToolIdentity) -> Result<StagedHermesTool> {
    let stage_dir = temporary_output_path(&std::env::temp_dir().join("ibex-hermes-tool"));
    std::fs::create_dir(&stage_dir)
        .with_context(|| format!("Failed to create Hermes tool stage {}", stage_dir.display()))?;
    let staged_path = stage_dir.join(if cfg!(windows) {
        "hermes.exe"
    } else {
        "hermes"
    });
    std::fs::write(&staged_path, identity.bytes.as_slice())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged_path, std::fs::Permissions::from_mode(0o700))?;
    }
    let staged_digest = format!("{:x}", Sha256::digest(std::fs::read(&staged_path)?));
    if staged_digest != identity.sha256 {
        anyhow::bail!("Hermes runtime tool changed while staging authenticated bytes");
    }
    Ok(StagedHermesTool(stage_dir))
}

fn find_hermesc_identity() -> Result<HermesToolIdentity> {
    HermesToolIdentity::capture(&find_hermesc_binary()?)
}

/// Find the runtime bundle
fn find_runtime_bundle() -> Result<PathBuf> {
    // Use the committed Ibex runtime bundle by default.
    let candidates = ["vendored-generated/embedded_runtime_bundle.js"];

    for base_path in runtime_workspace_roots()? {
        for search_root in runtime_bundle_search_roots(&base_path) {
            for candidate in &candidates {
                let path = search_root.join(candidate);
                if !path.exists() {
                    continue;
                }
                let authenticated = std::fs::canonicalize(&path).with_context(|| {
                    format!("Failed to authenticate runtime bundle {}", path.display())
                })?;
                if !authenticated.starts_with(&base_path) || !authenticated.is_file() {
                    anyhow::bail!(
                        "Runtime bundle {} escapes authenticated root {}",
                        authenticated.display(),
                        base_path.display()
                    );
                }
                return Ok(authenticated);
            }
        }
    }

    anyhow::bail!(
        "Runtime bundle not found. Please build it:\n  \
        IBEX_REGENERATE_RUNTIME=1 IBEX_UPDATE_VENDORED_GENERATED=1 cargo build"
    )
}

fn runtime_bundle_search_roots(base_path: &Path) -> Vec<PathBuf> {
    vec![base_path.to_path_buf()]
}

/// The Hermes engine implementation
pub struct HermesEngine {
    runtime_loaded: Mutex<bool>,
    runtime: Mutex<Option<RuntimeHandle>>,
    cdp_handle: Mutex<Option<cdp::CdpServerHandle>>,
    bytecode_compile_tasks: std::sync::Mutex<Vec<JoinHandle<()>>>,
    thread_id: std::thread::ThreadId,
    debugger_requested: Arc<AtomicBool>,
    debugger_enabled: AtomicBool,
    debugger_warned: AtomicBool,
    armed_snapshot_digest: Option<String>,
}

struct RuntimeHandle {
    shared: Arc<SharedRuntime>,
}

struct SharedRuntime {
    raw: AtomicPtr<HermesRuntimeOpaque>,
    // Hermes/JSI values have thread-affine destruction. Keep the creator here
    // as a Rust-side fail-safe so a legal `Arc<dyn Engine + Send + Sync>` last
    // drop on another thread leaks the native runtime instead of crossing the
    // C ABI and terminating the process. Full reclamation still requires an
    // explicit owner-thread teardown handoff.
    // @ref LLP 0003#the-event-loop — Hermes is driven and destroyed on one owner thread.
    owner_thread: std::thread::ThreadId,
    // Serializes runtime-thread FFI (`ex_hermes_eval`/`ex_hermes_poll`) and
    // gates destruction against it. CDP debugger ops deliberately do NOT take
    // this lock — see `with_debugger`.
    ffi_lock: std::sync::Mutex<()>,
    // Count of in-flight CDP debugger-thread FFI calls. Debugger ops run without
    // `ffi_lock` (so they can't deadlock against a JS thread parked at a
    // breakpoint while holding `ffi_lock`, or against the runtime thread they
    // must interrupt); `shutdown` instead nulls the pointer and drains this
    // counter before freeing, so no debugger op ever touches a freed runtime.
    // (ENG-22958)
    debugger_inflight: AtomicUsize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use = "runtime shutdown may be rejected when called off the owner thread"]
enum RuntimeShutdown {
    Destroyed,
    NotLive,
    WrongThread,
}

/// Decrements the in-flight debugger counter on scope exit (incl. early return
/// through `?`), so a bailing or failing debugger op can never leave `shutdown`
/// spinning forever.
struct DebuggerInflightGuard<'a>(&'a AtomicUsize);

impl Drop for DebuggerInflightGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl SharedRuntime {
    fn new(armed_snapshot_digest: Option<&str>) -> Result<Self> {
        let digest = armed_snapshot_digest
            .map(CString::new)
            .transpose()
            .context("armed snapshot digest contains an interior NUL")?;
        let raw = unsafe {
            match digest.as_ref() {
                Some(digest) => ex_hermes_create_armed(digest.as_ptr()),
                None => ex_hermes_create_diagnostic(),
            }
        };
        if raw.is_null() {
            if armed_snapshot_digest.is_some() {
                anyhow::bail!(
                    "Failed to create Hermes runtime: armed snapshot handshake was rejected"
                );
            }
            anyhow::bail!("Failed to create Hermes runtime");
        }
        unsafe {
            ex_hermes_set_host_call(raw, exact_agent_host_call);
            ex_hermes_set_host_call_async(raw, exact_agent_host_call_async);
        }
        Ok(Self {
            raw: AtomicPtr::new(raw),
            owner_thread: std::thread::current().id(),
            ffi_lock: std::sync::Mutex::new(()),
            debugger_inflight: AtomicUsize::new(0),
        })
    }

    /// Runtime-thread FFI (eval/poll/enable). Serialized by `ffi_lock`; only
    /// ever called from the runtime's owning thread.
    fn with_runtime<T>(&self, f: impl FnOnce(*mut HermesRuntimeOpaque) -> T) -> Result<T> {
        if std::thread::current().id() != self.owner_thread {
            anyhow::bail!("Hermes runtime operation must run on its owner thread");
        }
        let _guard = match self.ffi_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let raw = self.raw.load(Ordering::SeqCst);
        if raw.is_null() {
            anyhow::bail!("Hermes runtime has been shut down");
        }
        Ok(f(raw))
    }

    /// Debugger-thread FFI (CDP: pause/resume/eval/breakpoints/…). Runs WITHOUT
    /// `ffi_lock`: the Hermes async debugger API is built to be driven from a
    /// thread other than the runtime thread, and taking `ffi_lock` here would
    /// deadlock — the JS thread holds it for the whole of `ex_hermes_eval` while
    /// parked at a breakpoint, and some debugger ops interrupt the runtime
    /// thread and wait for it (which itself needs `ffi_lock` to poll). Liveness
    /// of `raw` is protected by the in-flight counter, which `shutdown` drains
    /// before freeing. (ENG-22958)
    fn with_debugger<T>(&self, f: impl FnOnce(*mut HermesRuntimeOpaque) -> T) -> Result<T> {
        self.debugger_inflight.fetch_add(1, Ordering::SeqCst);
        let _guard = DebuggerInflightGuard(&self.debugger_inflight);
        // Load AFTER registering as in-flight: if the load sees a non-null
        // pointer it was read before `shutdown`'s swap, so `shutdown` is
        // guaranteed to observe this increment and wait for us before freeing.
        let raw = self.raw.load(Ordering::SeqCst);
        if raw.is_null() {
            anyhow::bail!("Hermes runtime has been shut down");
        }
        Ok(f(raw))
    }

    /// Rejecting before swapping `raw` leaves an owner-held clone able to
    /// reclaim it. An off-owner final drop intentionally leaks rather than
    /// running thread-affine JSI destruction or aborting the host process.
    fn shutdown(&self) -> RuntimeShutdown {
        if self.raw.load(Ordering::SeqCst).is_null() {
            return RuntimeShutdown::NotLive;
        }
        if std::thread::current().id() != self.owner_thread {
            return RuntimeShutdown::WrongThread;
        }
        // Null the pointer under `ffi_lock` so no runtime-thread op is mid-call
        // and later runtime-thread ops bail instead of using a freed pointer.
        let raw = {
            let _guard = match self.ffi_lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            self.raw.swap(std::ptr::null_mut(), Ordering::SeqCst)
        };
        // Drain in-flight debugger-thread ops WITHOUT holding `ffi_lock`, so a
        // debugger op that needs the runtime thread to make progress can't
        // deadlock against us. New debugger ops now observe null and bail. This
        // is normally a no-op: the CDP thread is joined (stop_inspector) before
        // the runtime is dropped, so no debugger op is in flight here.
        while self.debugger_inflight.load(Ordering::SeqCst) != 0 {
            std::thread::yield_now();
        }
        if raw.is_null() {
            return RuntimeShutdown::NotLive;
        }
        unsafe { ex_hermes_destroy(raw) };
        RuntimeShutdown::Destroyed
    }
}

impl RuntimeHandle {
    fn new(armed_snapshot_digest: Option<&str>) -> Result<Self> {
        Ok(Self {
            shared: Arc::new(SharedRuntime::new(armed_snapshot_digest)?),
        })
    }

    fn shared(&self) -> Arc<SharedRuntime> {
        self.shared.clone()
    }

    fn with_runtime<T>(&self, f: impl FnOnce(*mut HermesRuntimeOpaque) -> T) -> Result<T> {
        self.shared.with_runtime(f)
    }
}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        match self.shared.shutdown() {
            RuntimeShutdown::Destroyed
            | RuntimeShutdown::NotLive
            | RuntimeShutdown::WrongThread => {}
        }
    }
}

struct HermesCdpBackend {
    runtime: Arc<SharedRuntime>,
    debugger_requested: Arc<AtomicBool>,
}

impl HermesCdpBackend {
    fn new(runtime: Arc<SharedRuntime>, debugger_requested: Arc<AtomicBool>) -> Self {
        Self {
            runtime,
            debugger_requested,
        }
    }

    unsafe fn take_c_string(ptr: *mut std::os::raw::c_char) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let message = CStr::from_ptr(ptr).to_string_lossy().to_string();
        ex_hermes_free_string(ptr);
        Some(message)
    }
}

impl CdpBackend for HermesCdpBackend {
    fn enable(&self) -> bool {
        self.debugger_requested.store(true, Ordering::SeqCst);
        true
    }

    fn get_scripts(&self) -> Result<Vec<ScriptInfo>> {
        let json = self
            .runtime
            .with_debugger(|runtime| unsafe {
                Self::take_c_string(ex_hermes_debugger_get_scripts(runtime))
            })?
            .unwrap_or_else(|| "[]".to_string());
        let value: Value = serde_json::from_str(&json).unwrap_or(Value::Array(Vec::new()));
        let mut scripts = Vec::new();
        if let Value::Array(items) = value {
            for item in items {
                if let Value::Object(map) = item {
                    if let (Some(id), Some(url)) = (
                        map.get("id").and_then(|v| v.as_u64()),
                        map.get("url").and_then(|v| v.as_str()),
                    ) {
                        scripts.push(ScriptInfo {
                            id: id as u32,
                            url: url.to_string(),
                        });
                    }
                }
            }
        }
        Ok(scripts)
    }

    fn get_script_source(&self, script_id: &str) -> Result<Option<String>> {
        let id = script_id.parse::<u32>().unwrap_or(0);
        self.runtime.with_debugger(|runtime| unsafe {
            Self::take_c_string(ex_hermes_debugger_get_script_source(runtime, id))
        })
    }

    fn set_breakpoint(
        &self,
        script_id: u32,
        line: u32,
        column: u32,
        condition: Option<&str>,
    ) -> Result<BreakpointInfo> {
        let condition = condition.unwrap_or("");
        let condition_c = CString::new(condition)?;
        let json = self
            .runtime
            .with_debugger(|runtime| unsafe {
                Self::take_c_string(ex_hermes_debugger_set_breakpoint(
                    runtime,
                    script_id,
                    line,
                    column,
                    condition_c.as_ptr(),
                ))
            })?
            .ok_or_else(|| anyhow::anyhow!("Failed to set breakpoint"))?;

        let value: Value = serde_json::from_str(&json)?;
        let id = value
            .get("id")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("Missing breakpoint id"))?;
        let script_id = value
            .get("scriptId")
            .and_then(|v| v.as_u64())
            .unwrap_or(script_id as u64);
        let line = value
            .get("line")
            .and_then(|v| v.as_u64())
            .unwrap_or(line as u64);
        let column = value
            .get("column")
            .and_then(|v| v.as_u64())
            .unwrap_or(column as u64);

        Ok(BreakpointInfo {
            id,
            script_id: script_id as u32,
            line: line as u32,
            column: column as u32,
        })
    }

    fn remove_breakpoint(&self, breakpoint_id: u64) {
        let _ = self.runtime.with_debugger(|runtime| unsafe {
            ex_hermes_debugger_remove_breakpoint(runtime, breakpoint_id);
        });
    }

    fn pause(&self) {
        let _ = self.runtime.with_debugger(|runtime| unsafe {
            ex_hermes_debugger_pause(runtime);
        });
    }

    fn resume(&self, command: DebugCommand) {
        let cmd = match command {
            DebugCommand::Continue => 0,
            DebugCommand::StepInto => 1,
            DebugCommand::StepOver => 2,
            DebugCommand::StepOut => 3,
        };
        let _ = self.runtime.with_debugger(|runtime| unsafe {
            ex_hermes_debugger_resume(runtime, cmd);
        });
    }

    fn next_event(&self) -> Option<String> {
        self.runtime
            .with_debugger(|runtime| unsafe {
                Self::take_c_string(ex_hermes_debugger_next_event(runtime))
            })
            .ok()
            .flatten()
    }

    fn eval(&self, expression: &str, frame_index: u32) -> Result<Value> {
        let expression_c = CString::new(expression)?;
        let json = self
            .runtime
            .with_debugger(|runtime| unsafe {
                Self::take_c_string(ex_hermes_debugger_eval(
                    runtime,
                    expression_c.as_ptr(),
                    frame_index,
                ))
            })?
            .ok_or_else(|| anyhow::anyhow!("Eval failed"))?;
        Ok(serde_json::from_str(&json)?)
    }
}

impl HermesEngine {
    pub(crate) fn loaded_engine_identity(
    ) -> Result<ibex_runtime::engine::LoadedEngineBinaryIdentity> {
        ibex_runtime::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg)
    }

    /// Create a new Hermes engine instance
    #[cfg(test)]
    pub fn new() -> Result<Self> {
        Self::new_with_armed_snapshot(None)
    }

    /// Create Hermes bound to the exact immutable snapshot already installed
    /// in the host. Runtime allocation fails if the host does not authenticate
    /// this digest.
    pub fn new_with_armed_snapshot(armed_snapshot_digest: Option<&str>) -> Result<Self> {
        // (ENG-23234) Must run before the first event-loop park so callback
        // pushes wake the select! in wait_for_callback_or_sleep even without
        // the `cli-notify` feature. No-op under `cli-notify`.
        register_default_profile_wake_hook();
        Ok(Self {
            runtime_loaded: Mutex::new(false),
            runtime: Mutex::new(None),
            cdp_handle: Mutex::new(None),
            bytecode_compile_tasks: std::sync::Mutex::new(Vec::new()),
            thread_id: std::thread::current().id(),
            debugger_requested: Arc::new(AtomicBool::new(false)),
            debugger_enabled: AtomicBool::new(false),
            debugger_warned: AtomicBool::new(false),
            armed_snapshot_digest: armed_snapshot_digest.map(str::to_owned),
        })
    }

    fn ensure_thread(&self) -> Result<()> {
        if std::thread::current().id() != self.thread_id {
            anyhow::bail!("Hermes runtime must be used from the creating thread");
        }
        Ok(())
    }

    fn track_bytecode_compile_task(&self, task: JoinHandle<()>) {
        let mut tasks = match self.bytecode_compile_tasks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let mut pending = Vec::with_capacity(tasks.len() + 1);
        for handle in tasks.drain(..) {
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                pending.push(handle);
            }
        }

        pending.push(task);
        *tasks = pending;
    }

    async fn ensure_runtime(&self) -> Result<Arc<SharedRuntime>> {
        self.ensure_thread()?;
        let mut runtime = self.runtime.lock().await;
        if runtime.is_none() {
            *runtime = Some(RuntimeHandle::new(self.armed_snapshot_digest.as_deref())?);
        }
        runtime
            .as_ref()
            .map(RuntimeHandle::shared)
            .ok_or_else(|| anyhow!("Hermes runtime missing after initialization"))
    }

    #[cfg(all(test, feature = "capsec-conformance-observer"))]
    async fn install_capsec_context_test_observer(&self) -> Result<String> {
        self.ensure_thread()?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .context("failed to generate an ephemeral CapSec context-observer name")?;
        let suffix = nonce
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let name = format!("__ibexCapsecContextObserver_{suffix}");
        let name_c = CString::new(name.as_str()).expect("hex observer name has no interior NUL");
        let runtime = self.ensure_runtime().await?;
        let installed = runtime.with_runtime(|raw| unsafe {
            ibex_test_install_capsec_context_observer(raw, name_c.as_ptr())
        })?;
        if installed != 1 {
            anyhow::bail!("armed Hermes refused the ephemeral CapSec context observer");
        }
        Ok(name)
    }

    async fn maybe_enable_debugger(&self) -> Result<()> {
        if !self.debugger_requested.load(Ordering::SeqCst) {
            return Ok(());
        }
        if self.debugger_enabled.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.ensure_thread()?;
        let runtime = self.ensure_runtime().await?;
        let ok = runtime.with_runtime(|raw| unsafe { ex_hermes_debugger_enable(raw) != 0 })?;
        if ok {
            self.debugger_enabled.store(true, Ordering::SeqCst);
        } else if !self.debugger_warned.swap(true, Ordering::SeqCst) {
            eprintln!("Debugger not available in this Hermes build. Rebuild Hermes with debugger enabled.");
        }
        Ok(())
    }

    async fn eval_bytes(
        &self,
        data: &[u8],
        source_url: &str,
        is_bytecode: bool,
    ) -> Result<Option<String>> {
        self.maybe_enable_debugger().await?;
        self.ensure_thread()?;
        let mut runtime = self.runtime.lock().await;
        if runtime.is_none() {
            *runtime = Some(RuntimeHandle::new(self.armed_snapshot_digest.as_deref())?);
        }
        let handle = runtime
            .as_ref()
            .ok_or_else(|| anyhow!("Hermes runtime missing after initialization"))?;

        let source_c = CString::new(source_url)?;
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let status = handle.with_runtime(|raw| unsafe {
            ex_hermes_eval(
                raw,
                data.as_ptr(),
                data.len(),
                source_c.as_ptr(),
                if is_bytecode { 1 } else { 0 },
                &mut out,
            )
        })?;

        if status != 0 {
            let message = if out.is_null() {
                "Hermes evaluation failed".to_string()
            } else {
                let msg = unsafe { CStr::from_ptr(out) }.to_string_lossy().to_string();
                unsafe { ex_hermes_free_string(out) };
                msg
            };
            if status == 2 {
                return Err(anyhow::Error::new(BytecodeLoadError(message)));
            }
            // Try to apply source map to rewrite stack traces
            let message = Self::apply_source_map(&message, source_url);
            anyhow::bail!(message);
        }

        if out.is_null() {
            Ok(None)
        } else {
            let msg = unsafe { CStr::from_ptr(out) }.to_string_lossy().to_string();
            unsafe { ex_hermes_free_string(out) };
            Ok(Some(msg))
        }
    }

    async fn eval_str(&self, code: &str, source_url: &str) -> Result<Option<String>> {
        self.eval_bytes(code.as_bytes(), source_url, false).await
    }

    async fn runtime_bundle_installed(&self) -> Result<bool> {
        #[cfg(windows)]
        let probe = r#"(function(){
  return (
    typeof globalThis === 'object' &&
    globalThis &&
    globalThis.__exactRuntimeLoaded === true
  ) ? 'true' : 'false';
})();"#;

        #[cfg(not(windows))]
        let probe = r#"(function(){
  return (
    typeof globalThis === 'object' &&
    globalThis &&
    globalThis.__exactRuntimeLoaded === true &&
    typeof globalThis.ExactBundle === 'object' &&
    globalThis.ExactBundle !== null
  ) ? 'true' : 'false';
})();"#;
        let result = self.eval_str(probe, "<runtime-installed>").await?;
        Ok(matches!(result.as_deref().map(str::trim), Some("true")))
    }

    async fn ensure_runtime_bundle_installed(&self) -> Result<()> {
        let bootstrap = r#"(function(){
  if (typeof globalThis === 'object' && globalThis) {
    var g = globalThis;
    if (g.__exactRuntimeLoaded === true) {
      return;
    }
    if (g.ExactBundle && typeof g.ExactBundle.installGlobals === 'function') {
      g.ExactBundle.installGlobals();
      return;
    }
  }

  if (
    typeof ExactBundle !== 'undefined' &&
    ExactBundle &&
    typeof ExactBundle.installGlobals === 'function' &&
    (typeof globalThis !== 'object' || !globalThis || globalThis.__exactRuntimeLoaded !== true)
  ) {
    ExactBundle.installGlobals();
  }
})();"#;
        let _ = self.eval_str(bootstrap, "<bootstrap>").await?;
        Ok(())
    }

    async fn finalize_runtime_setup(&self) -> Result<()> {
        if cfg!(windows) {
            return Ok(());
        }

        if !self.runtime_bundle_installed().await? {
            self.ensure_runtime_bundle_installed().await?;
        }
        if !self.runtime_bundle_installed().await? {
            self.ensure_crypto_fallback().await?;
        }
        Ok(())
    }

    async fn ensure_crypto_fallback(&self) -> Result<()> {
        if cfg!(windows) {
            return Ok(());
        }

        let fallback = r#"(function(){
  const hasCrypto = typeof globalThis.crypto !== 'undefined' && globalThis.crypto !== null;
  const hasGetRandomValues = hasCrypto && typeof globalThis.crypto.getRandomValues === 'function';
  const hasRandomUUID = hasCrypto && typeof globalThis.crypto.randomUUID === 'function';
  if ((!hasCrypto || !hasGetRandomValues || !hasRandomUUID) && typeof __exactRandomBytes === 'function') {
    const cryptoObj = hasCrypto ? globalThis.crypto : {};
    if (!hasGetRandomValues) {
      cryptoObj.getRandomValues = function(arr) {
        const bytes = __exactRandomBytes(arr.byteLength);
        arr.set(bytes);
        return arr;
      };
    }
    if (!hasRandomUUID) {
      cryptoObj.randomUUID = function() {
        const bytes = __exactRandomBytes(16);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        const hex = Array.from(bytes, function(b) { return b.toString(16).padStart(2, '0'); });
        return hex.slice(0, 4).join('') + '-' +
               hex.slice(4, 6).join('') + '-' +
               hex.slice(6, 8).join('') + '-' +
               hex.slice(8, 10).join('') + '-' +
               hex.slice(10).join('');
      };
    }
    globalThis.crypto = cryptoObj;
  }
})();"#;
        let _ = self.eval_str(fallback, "<crypto-fallback>").await?;
        Ok(())
    }

    async fn drive_event_loop(&self) -> Result<()> {
        self.ensure_thread()?;
        let trace_loop = std::env::var("IBEX_LOOP_TRACE")
            .or_else(|_| std::env::var("EXACT_LOOP_TRACE"))
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let mut trace_iterations = 0usize;
        loop {
            let (pending, next_due, executed) = {
                let runtime = self.runtime.lock().await;
                let handle = match runtime.as_ref() {
                    Some(handle) => handle,
                    None => return Ok(()),
                };
                let now = current_time_ms();
                let (executed, pending, next) = handle.with_runtime(|raw| {
                    let executed = unsafe { ex_hermes_poll(raw, now) };
                    let host_pending = unsafe {
                        ex_host_http_has_referenced() != 0
                            || ex_host_http_has_pending_requests() != 0
                            || native_ws_has_active() != 0
                    };
                    let pending = if host_pending {
                        1
                    } else {
                        unsafe { ex_hermes_has_pending_tasks(raw) }
                    };
                    let next = unsafe { ex_hermes_next_timer(raw) };
                    (executed, pending, next)
                })?;
                if executed < 0 {
                    return Err(anyhow::anyhow!("Hermes task execution failed"));
                }
                if trace_loop && trace_iterations < 200 {
                    eprintln!(
                        "[loop] iteration={} executed={} pending={} next={} now={}",
                        trace_iterations, executed, pending, next, now
                    );
                    trace_iterations += 1;
                }
                (pending, (next, now), executed)
            };

            if executed > 0 {
                continue;
            }
            if pending == 0 {
                break;
            }

            let (next, now) = next_due;
            if next < 0 {
                // No timers but tasks pending (HTTP server, callbacks, etc.)
                // Wait for a callback notification. The HTTP server and every
                // cross-thread callback push signal this via
                // ex_hermes_notify_callback(), so requests wake the event loop
                // with zero latency. IDLE_PARK is only a wakeup-safety fallback
                // (see its definition), NOT a busy-poll cadence — parking a
                // fixed 5ms here made an idle server re-poll ~200×/sec. (Item 7)
                wait_for_callback_or_sleep(IDLE_PARK).await;
                continue;
            }
            let delay = (next as u64).saturating_sub(now);
            if delay > 0 {
                // Also wake on callback notification (e.g., HTTP request
                // arrives) rather than sleeping the full timer duration when
                // the CLI notify feature is enabled.
                wait_for_callback_or_sleep(std::time::Duration::from_millis(delay)).await;
            }
        }

        Ok(())
    }

    /// Execute all runtime work that is ready *right now* — timers already due,
    /// drained microtasks/callbacks, and any pending debugger interrupts — then
    /// return without blocking to wait for future timers.
    ///
    /// The keep-alive / inspector loop calls this on its own cadence so that a
    /// `--keep-alive` (or `--inspect`) session actually pumps the event loop:
    /// DevTools `Runtime.evaluate` needs the runtime thread to service its
    /// interrupt, and timers scheduled from DevTools need the loop to run. The
    /// old loop only ticked a counter and never polled, so both hung. Unlike
    /// `drive_event_loop`, this never parks on a future timer, leaving the
    /// caller in charge of the wait cadence and shutdown handling.
    /// @ref LLP 0003#the-event-loop — the host drives Hermes by polling
    /// `ex_hermes_poll`; the keep-alive loop must do so too. (ENG-22958)
    async fn pump_ready_tasks(&self) -> Result<()> {
        self.ensure_thread()?;
        // Bounded: a self-rescheduling 0-delay timer is due on every poll, so an
        // unbounded `while executed != 0` loop would never return control to the
        // caller — wedging the REPL prompt (and the keep-alive loop). Cap the
        // polls per pump; the next tick pumps again, so the timer still runs but
        // no longer starves input. (ENG-23030 #3)
        for _ in 0..PUMP_MAX_POLLS_PER_TICK {
            let executed = {
                let runtime = self.runtime.lock().await;
                let handle = match runtime.as_ref() {
                    Some(handle) => handle,
                    None => return Ok(()),
                };
                let now = current_time_ms();
                handle.with_runtime(|raw| unsafe { ex_hermes_poll(raw, now) })?
            };
            if executed < 0 {
                return Err(anyhow::anyhow!("Hermes task execution failed"));
            }
            if executed == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Read and evaluate a JS/HBC file WITHOUT driving the event loop to
    /// quiescence afterwards. `run_file` adds that drive (for `ibex <file>`);
    /// the REPL's `.load` uses this directly (via `run_file_immediate`) so a
    /// loaded `Bun.serve`/`setInterval` returns control to the prompt instead of
    /// wedging, with the idle pump driving background work. (ENG-23030 #2)
    async fn eval_file(&self, path: &str) -> Result<Option<String>> {
        self.maybe_enable_debugger().await?;
        let path_buf = PathBuf::from(path);
        let is_bytecode = path_buf.extension().and_then(|s| s.to_str()) == Some("hbc");
        let bytes = tokio::fs::read(&path_buf)
            .await
            .with_context(|| format!("Failed to read file {}", path))?;
        let bytes = if is_bytecode {
            Cow::Borrowed(bytes.as_slice())
        } else {
            normalize_hashbang_bytes(&bytes)
        };
        let source = path_buf.to_string_lossy().to_string();
        self.eval_bytes(bytes.as_ref(), &source, is_bytecode).await
    }

    /// Try to apply source map to rewrite stack traces in error messages.
    /// Returns the rewritten message if a source map is found, otherwise the original.
    fn apply_source_map(message: &str, source_url: &str) -> String {
        use std::path::Path;

        // Extract bundle paths from stack trace lines.
        // Stack frames look like: at funcName (/path/to/bundle.js:line:col)
        // We look for .bundle.js paths in the Ibex cache directory.
        let mut bundle_path: Option<String> = None;

        // First try: the source_url itself (direct file execution)
        if source_url != "<eval>" && source_url != "<module-loader>" {
            let map_path = format!("{}.map", source_url);
            if Path::new(&map_path).exists() {
                let source_map = if Path::new(source_url)
                    .extension()
                    .and_then(|ext| ext.to_str())
                    == Some("hbc")
                {
                    verified_bytecode_source_map(Path::new(source_url), Path::new(&map_path))
                } else {
                    super::sourcemap::SourceMap::load_cached(Path::new(&map_path))
                };
                if let Some(sm) = source_map {
                    return super::sourcemap::rewrite_error(message, &sm, source_url);
                }
            }
        }

        // Second try: extract bundle path from stack trace lines
        for line in message.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("at ") {
                continue;
            }
            if let (Some(paren_start), Some(paren_end)) = (trimmed.find('('), trimmed.rfind(')')) {
                let location = &trimmed[paren_start + 1..paren_end];
                // Extract filename from filename:line:col
                let parts: Vec<&str> = location.rsplitn(3, ':').collect();
                if parts.len() >= 3 && !parts[2].is_empty() {
                    let filename = parts[2];
                    // Skip internal frames
                    if filename == "<module-loader>" || filename == "<eval>" {
                        continue;
                    }
                    let map_file = format!("{}.map", filename);
                    if Path::new(&map_file).exists() {
                        bundle_path = Some(filename.to_string());
                        break;
                    }
                }
            }
        }

        if let Some(bp) = bundle_path {
            let map_file = format!("{}.map", bp);
            let source_map =
                if Path::new(&bp).extension().and_then(|ext| ext.to_str()) == Some("hbc") {
                    verified_bytecode_source_map(Path::new(&bp), Path::new(&map_file))
                } else {
                    super::sourcemap::SourceMap::load_cached(Path::new(&map_file))
                };
            if let Some(sm) = source_map {
                return super::sourcemap::rewrite_error(message, &sm, &bp);
            }
        }

        message.to_string()
    }

    fn is_bytecode_version_error(message: &str) -> bool {
        message.contains("Wrong bytecode version")
    }

    /// Load the runtime bundle from disk (fallback when no embedded runtime is available
    /// or when the embedded runtime fails to load).
    async fn load_runtime_from_disk(&self) -> Result<()> {
        let trace_startup = std::env::var("IBEX_STARTUP_TRACE")
            .or_else(|_| std::env::var("EX_STARTUP_TRACE"))
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        if trace_startup {
            eprintln!("[startup] load_runtime_from_disk_start");
        }
        match find_runtime_bundle() {
            Ok(runtime_path) => {
                if trace_startup {
                    eprintln!(
                        "[startup] load_runtime_from_disk_found {}",
                        runtime_path.display()
                    );
                }
                let is_already_bytecode =
                    runtime_path.extension().and_then(|s| s.to_str()) == Some("hbc");

                if is_already_bytecode {
                    // Already a bytecode file, load directly
                    let bytes = tokio::fs::read(&runtime_path).await.with_context(|| {
                        format!("Failed to read runtime bundle {}", runtime_path.display())
                    })?;
                    let source = runtime_path.to_string_lossy();
                    match self.eval_bytes(&bytes, &source, true).await {
                        Ok(_) => {}
                        Err(err) => {
                            let js_path = runtime_path.with_extension("js");
                            let _ = tokio::fs::remove_file(&runtime_path).await;
                            crate::runtime::mark_bytecode_incompatible();
                            if js_path.exists() {
                                let source = js_path.to_string_lossy();
                                let bytes = tokio::fs::read(&js_path).await.with_context(|| {
                                    format!("Failed to read runtime source {}", js_path.display())
                                })?;
                                let _ = self.eval_bytes(&bytes, &source, false).await?;
                            } else if Self::is_bytecode_version_error(&err.to_string()) {
                                // If no JS fallback exists, keep the existing behavior for
                                // bytecode-version mismatch so the caller can surface the exact failure.
                                return Err(err);
                            } else {
                                anyhow::bail!("{}", err);
                            }
                        }
                    }
                } else {
                    // JS source — try to load a cached .hbc alongside it
                    let hbc_path = runtime_path.with_extension("hbc");
                    let use_cached = if hbc_path.exists() {
                        // Use cached bytecode only if it's newer than the JS source
                        match (
                            tokio::fs::metadata(&hbc_path)
                                .await
                                .and_then(|m| m.modified()),
                            tokio::fs::metadata(&runtime_path)
                                .await
                                .and_then(|m| m.modified()),
                        ) {
                            (Ok(hbc_time), Ok(js_time)) => hbc_time >= js_time,
                            _ => false,
                        }
                    } else {
                        false
                    };

                    let mut loaded_from_cache = false;
                    let mut cache_failed = false;
                    if use_cached {
                        match tokio::fs::read(&hbc_path).await {
                            Ok(bytes) => {
                                let source = runtime_path.to_string_lossy();
                                match self.eval_bytes(&bytes, &source, true).await {
                                    Ok(_) => {
                                        loaded_from_cache = true;
                                    }
                                    Err(_e) => {
                                        // Bytecode version mismatch or other error.
                                        // Delete stale cache file and fall through to JS source.
                                        let _ = tokio::fs::remove_file(&hbc_path).await;
                                        cache_failed = true;
                                        crate::runtime::mark_bytecode_incompatible();
                                    }
                                }
                            }
                            Err(_) => {
                                // Can't read cache file, fall through
                            }
                        }
                    }

                    if !loaded_from_cache {
                        // Load JS source
                        let bytes = tokio::fs::read(&runtime_path).await.with_context(|| {
                            format!("Failed to read runtime bundle {}", runtime_path.display())
                        })?;
                        if runtime_path.extension().and_then(|s| s.to_str()) == Some("js")
                            && !looks_like_ibex_runtime_bundle(&bytes)
                        {
                            anyhow::bail!(
                                "runtime.js at {} is not an Ibex runtime bundle",
                                runtime_path.display()
                            );
                        }
                        let source = runtime_path.to_string_lossy();
                        let _ = self.eval_bytes(&bytes, &source, false).await?;

                        // Try to compile to .hbc in the background for next startup.
                        // Skip if we just deleted a stale .hbc (version mismatch),
                        // since recompiling would produce the same incompatible bytecode.
                        if !cache_failed {
                            let js_path = runtime_path.clone();
                            let hbc_out = hbc_path.clone();
                            let compile_task = std::thread::spawn(move || {
                                if !bytecode_versions_compatible() {
                                    return;
                                }
                                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                else {
                                    return;
                                };

                                let _ = runtime.block_on(async {
                                    compile_attested_cache_bytecode(
                                        &js_path.to_string_lossy(),
                                        &hbc_out,
                                        None,
                                    )
                                    .await
                                    .ok()
                                });
                            });
                            self.track_bytecode_compile_task(compile_task);
                        }
                    }
                }
                #[cfg(not(windows))]
                self.finalize_runtime_setup().await?;
            }
            Err(_) => {
                if trace_startup {
                    eprintln!("[startup] load_runtime_from_disk_missing");
                }
                // Only print the note if not in a child process context
                if std::env::var("IBEX_QUIET")
                    .or_else(|_| std::env::var("EXACT_QUIET"))
                    .is_err()
                {
                    eprintln!("Note: Runtime bundle not found. Running without Ibex runtime.");
                    eprintln!(
                        "      Build it with: IBEX_REGENERATE_RUNTIME=1 IBEX_UPDATE_VENDORED_GENERATED=1 cargo build"
                    );
                }
                if trace_startup {
                    eprintln!("[startup] ensure_crypto_fallback_start");
                }
                self.ensure_crypto_fallback().await?;
                if trace_startup {
                    eprintln!("[startup] ensure_crypto_fallback_end");
                }
            }
        }
        if trace_startup {
            eprintln!("[startup] load_runtime_from_disk_end");
        }
        Ok(())
    }
}

impl Drop for HermesEngine {
    fn drop(&mut self) {
        let mut tasks = match self.bytecode_compile_tasks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Do not block process teardown on background hermesc compiles. These
        // threads only warm a next-startup bytecode cache and publish it via an
        // atomic rename, so abandoning an in-flight compile can never leave a
        // partial or corrupt `.hbc`. Reap any that already finished; detach the
        // rest by dropping their handles, so a short-lived invocation
        // (e.g. `ibex -e '1+1'`) exits immediately instead of stalling in Drop
        // for the duration of the compile (up to the hermesc timeout). (ENG-22958)
        for handle in tasks.drain(..) {
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
    }
}

#[async_trait]
impl Engine for HermesEngine {
    fn name(&self) -> &str {
        "hermes"
    }

    fn version(&self) -> Result<String> {
        get_version()
    }

    async fn load_runtime(&self) -> Result<()> {
        let mut loaded = self.runtime_loaded.lock().await;
        if *loaded {
            return Ok(());
        }
        let trace_startup = std::env::var("IBEX_STARTUP_TRACE")
            .or_else(|_| std::env::var("EX_STARTUP_TRACE"))
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

        self.maybe_enable_debugger().await?;
        self.ensure_runtime().await?;

        let already_installed = if cfg!(windows) {
            false
        } else {
            if trace_startup {
                eprintln!("[startup] runtime_bundle_installed_probe_start");
            }
            let already_installed = self.runtime_bundle_installed().await?;
            if trace_startup {
                eprintln!(
                    "[startup] runtime_bundle_installed_probe_end installed={}",
                    already_installed
                );
            }
            already_installed
        };
        if already_installed {
            finalize_compartment_baseline(self).await?;
            *loaded = true;
            return Ok(());
        }

        // When disk fallback is disabled, the runtime must use only its
        // embedded bytes and abort if they are unavailable or fail. This keeps
        // benchmark binaries self-contained.
        let no_disk_fallback = std::env::var("IBEX_NO_DISK_RUNTIME_FALLBACK")
            .or_else(|_| std::env::var("EX_NO_DISK_RUNTIME_FALLBACK"))
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

        // Try embedded runtime first (compiled into binary by build.rs).
        // This eliminates ~2.3ms of disk I/O on every startup.
        let use_embedded_runtime = !embedded_runtime::EMBEDDED_RUNTIME.is_empty() && !cfg!(windows);
        if use_embedded_runtime {
            match self
                .eval_bytes(
                    embedded_runtime::EMBEDDED_RUNTIME,
                    embedded_runtime::EMBEDDED_RUNTIME_NAME,
                    embedded_runtime::EMBEDDED_RUNTIME_IS_BYTECODE,
                )
                .await
            {
                Ok(_) => {
                    self.finalize_runtime_setup().await?;
                }
                Err(e) => {
                    // Embedded runtime failed (e.g. bytecode version mismatch).
                    if no_disk_fallback {
                        anyhow::bail!(
                            "Embedded runtime failed and IBEX_NO_DISK_RUNTIME_FALLBACK=1 \
                             prevents disk fallback: {e}"
                        );
                    }
                    // Fall through to disk-based loading below.
                    if embedded_runtime::EMBEDDED_RUNTIME_IS_BYTECODE
                        && Self::is_bytecode_version_error(&e.to_string())
                    {
                        crate::runtime::mark_bytecode_incompatible();
                    }
                    self.load_runtime_from_disk().await?;
                }
            }
        } else {
            if no_disk_fallback {
                anyhow::bail!(
                    "No embedded runtime available and IBEX_NO_DISK_RUNTIME_FALLBACK=1 \
                     prevents disk fallback. Build with embedded runtime support."
                );
            }
            // No embedded runtime — fall back to disk-based loading
            self.load_runtime_from_disk().await?;
        }
        finalize_compartment_baseline(self).await?;
        *loaded = true;
        Ok(())
    }

    async fn eval(&self, code: &str) -> Result<Option<String>> {
        self.maybe_enable_debugger().await?;
        let result = self.eval_str(code, "<eval>").await?;
        self.drive_event_loop().await?;
        Ok(result)
    }

    async fn eval_immediate(&self, code: &str) -> Result<Option<String>> {
        self.maybe_enable_debugger().await?;
        self.eval_str(code, "<eval>").await
    }

    async fn drive_ready_tasks(&self) -> Result<()> {
        self.pump_ready_tasks().await
    }

    async fn wait_for_pending_tasks(&self) {
        // Size the idle wait from the soonest scheduled timer and park until it
        // is due — or, with nothing scheduled, park for IDLE_PARK, waking early
        // on a background-callback notification (an HTTP request, a cross-thread
        // callback). This replaces the REPL's fixed 20 Hz poll: an idle prompt no
        // longer runs an FFI poll 20×/s, and a scheduled timer is serviced when
        // it comes due rather than on the next fixed tick. (ENG-23030 #5)
        let wait = {
            let runtime = self.runtime.lock().await;
            match runtime.as_ref() {
                None => IDLE_PARK,
                Some(handle) => {
                    let now = current_time_ms();
                    let next_timer = handle
                        .with_runtime(|raw| unsafe { ex_hermes_next_timer(raw) })
                        .unwrap_or(-1);
                    repl_idle_wait(next_timer, now, REPL_PARK_FLOOR, IDLE_PARK)
                }
            }
        };
        wait_for_callback_or_sleep(wait).await;
    }

    async fn drain_event_loop(&self) -> Result<()> {
        // At EOF, flush work that is ready now and one-shots already due, then
        // stop — do NOT drive to quiescence. A referenced perpetual `setInterval`
        // (or a self-rescheduling 0-delay timer) keeps the loop pending forever,
        // which hung Ctrl+D with the tty in raw mode (Ctrl+C dead, external kill
        // required). Poll only while something ran or a timer is already due,
        // never sleep-waiting for a future timer, and cap the whole drain with a
        // deadline as a hard backstop against a 0-delay self-reschedule.
        // (ENG-23030 #1)
        self.ensure_thread()?;
        let deadline = std::time::Instant::now() + EOF_DRAIN_BUDGET;
        loop {
            let (executed, next_timer, now) = {
                let runtime = self.runtime.lock().await;
                let handle = match runtime.as_ref() {
                    Some(handle) => handle,
                    None => return Ok(()),
                };
                let now = current_time_ms();
                let (executed, next_timer) = handle.with_runtime(|raw| {
                    let executed = unsafe { ex_hermes_poll(raw, now) };
                    let next_timer = unsafe { ex_hermes_next_timer(raw) };
                    (executed, next_timer)
                })?;
                (executed, next_timer, now)
            };
            if executed < 0 {
                return Err(anyhow::anyhow!("Hermes task execution failed"));
            }
            if eof_drain_complete(executed, next_timer, now) {
                break;
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
        }
        Ok(())
    }

    async fn run_file(&self, path: &str) -> Result<Option<String>> {
        let result = self.eval_file(path).await?;
        self.drive_event_loop().await?;
        Ok(result)
    }

    async fn run_bytecode_bytes(&self, bytes: &[u8], source_url: &str) -> Result<Option<String>> {
        self.maybe_enable_debugger().await?;
        let result = self.eval_bytes(bytes, source_url, true).await?;
        self.drive_event_loop().await?;
        Ok(result)
    }

    async fn run_file_immediate(&self, path: &str) -> Result<Option<String>> {
        // Like `run_file` but without driving the event loop to quiescence, so a
        // `.load server.js` that starts a long-lived server/timer returns to the
        // prompt. Background work runs via the REPL idle pump. (ENG-23030 #2)
        self.eval_file(path).await
    }

    async fn start_inspector(&self, host: &str, port: u16) -> Result<()> {
        let mut handle = self.cdp_handle.lock().await;
        if handle.is_some() {
            return Ok(());
        }

        let runtime = self.ensure_runtime().await?;
        let backend: Arc<dyn CdpBackend> = Arc::new(HermesCdpBackend::new(
            runtime,
            self.debugger_requested.clone(),
        ));
        let server = cdp::start_server(host, port, backend)?;
        *handle = Some(server);
        Ok(())
    }

    async fn stop_inspector(&self) -> Result<()> {
        let mut handle = self.cdp_handle.lock().await;
        if let Some(server) = handle.take() {
            server.stop();
        }
        Ok(())
    }

    async fn wait_for_inspector(&self) -> Result<()> {
        let waiter = {
            let handle = self.cdp_handle.lock().await;
            handle.as_ref().map(|server| server.connection_waiter())
        };
        if let Some(waiter) = waiter {
            waiter.wait().await;
        }
        Ok(())
    }

    async fn wait_for_debugger(&self) -> Result<()> {
        let waiter = {
            let handle = self.cdp_handle.lock().await;
            handle.as_ref().map(|server| server.debugger_waiter())
        };
        if let Some(waiter) = waiter {
            waiter.wait().await;
        }
        self.maybe_enable_debugger().await?;
        Ok(())
    }

    fn supports_feature(&self, feature: EngineFeature) -> bool {
        match feature {
            EngineFeature::BytecodeCompilation => true,
            EngineFeature::CdpDebugging => true,
            EngineFeature::SourceMaps => true,
            EngineFeature::TopLevelAwait => false, // Hermes doesn't support this natively
            EngineFeature::EsmModules => false,    // Not in standalone Hermes
            EngineFeature::CommonJsModules => false,
        }
    }
}

/// Get the Hermes version
pub fn get_version() -> Result<String> {
    let identity = HermesToolIdentity::capture(&find_hermes_binary()?)?;
    let staged = stage_authenticated_hermes_tool(&identity)?;
    let hermes_path = staged.0.join(if cfg!(windows) {
        "hermes.exe"
    } else {
        "hermes"
    });

    let output = std::process::Command::new(&hermes_path)
        .arg("--version")
        .output()
        .context("Failed to get Hermes version")?;
    identity.verify_selected_path()?;

    let version = String::from_utf8_lossy(&output.stdout);
    // Parse the version from output like "Hermes JavaScript compiler version 0.12.0"
    Ok(version.trim().to_string())
}

fn get_hermesc_version() -> Result<String> {
    let identity = find_hermesc_identity()?;

    let version = get_hermesc_version_at(&identity.path)?;
    identity.verify_selected_path()?;
    Ok(version)
}

fn get_hermesc_version_at(path: &Path) -> Result<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .context("Failed to get hermesc version")?;

    let version = String::from_utf8_lossy(&output.stdout);
    Ok(version.trim().to_string())
}

/// Extract the `HBC bytecode version: N` from hermesc --version output.
fn extract_hbc_version(version_output: &str) -> Option<u32> {
    for line in version_output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("HBC bytecode version:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Check whether the hermesc compiler produces bytecode compatible with
/// the embedded Hermes runtime. Returns false if hermesc is unavailable
/// or the bytecode versions don't match.
fn bytecode_versions_compatible() -> bool {
    // Get the hermesc HBC bytecode version
    let hermesc_hbc = get_hermesc_version()
        .ok()
        .and_then(|v| extract_hbc_version(&v));

    // Query the root API exported by the engine binary that is actually mapped
    // into this process. A neighboring `hermes --version` executable can be a
    // different build and is never runtime compatibility truth.
    let hermes_hbc = ibex_runtime::engine::loaded_engine_bytecode_version().ok();

    match (hermesc_hbc, hermes_hbc) {
        (Some(compiler), Some(runtime)) => compiler == runtime,
        // If we can't determine versions, don't attempt compilation
        _ => false,
    }
}

fn current_time_ms() -> u64 {
    // Read the SAME monotonic clock the C++ timer scheduler uses to compute
    // due_ms (nowMs). The value we return is fed to ex_hermes_poll as `now_ms`
    // and subtracted from ex_hermes_next_timer's due_ms to size the park
    // duration, so it must share a clock domain with due_ms. Using a Rust
    // wall clock (SystemTime) made timers vulnerable to NTP steps, and a Rust
    // monotonic clock (Instant) is not guaranteed to share an epoch with the
    // C++ steady_clock — so we route through the one C++ source of truth.
    unsafe { ex_hermes_now_ms() }
}

/// Whether the REPL-EOF drain has run out of work that is ready *now*. Keep
/// draining while a poll executed something (`executed > 0`) or a timer is
/// already due (`next_timer <= now`); stop otherwise so a future/perpetual timer
/// (a referenced `setInterval`) cannot block process exit. `next_timer < 0` means
/// no timers scheduled. (ENG-23030 #1)
fn eof_drain_complete(executed: i32, next_timer: i64, now: u64) -> bool {
    if executed > 0 {
        return false;
    }
    next_timer < 0 || (next_timer as u64) > now
}

/// How long the idle REPL should park before pumping ready event-loop work,
/// given the soonest scheduled timer (`next_timer`, ms on the shared clock; < 0
/// when none) and `now`. Nothing scheduled parks for `idle_park` (waking early on
/// a background-callback notification); a scheduled timer parks until it is due,
/// floored so a 0-delay timer cannot busy-spin the prompt and capped at
/// `idle_park`. Replaces the fixed 20 Hz poll. (ENG-23030 #5)
fn repl_idle_wait(
    next_timer: i64,
    now: u64,
    floor: std::time::Duration,
    idle_park: std::time::Duration,
) -> std::time::Duration {
    if next_timer < 0 {
        return idle_park;
    }
    let delay = std::time::Duration::from_millis((next_timer as u64).saturating_sub(now));
    // `floor.min(idle_park)` keeps the lower bound <= the cap even when a build
    // configures a very short IDLE_PARK (non-`cli-notify`), so the clamp is well
    // formed.
    delay.max(floor.min(idle_park)).min(idle_park)
}

fn temporary_output_path(path: &std::path::Path) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let mut file_name = std::ffi::OsString::from(".");
    file_name.push(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("ibex-bytecode")),
    );
    file_name.push(format!(".{}.{seq}.tmp", std::process::id()));
    path.with_file_name(file_name)
}

struct CachePublishLock(std::fs::File);

impl Drop for CachePublishLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

async fn acquire_cache_publish_lock(output: &Path) -> Result<CachePublishLock> {
    let lock_path = path_with_suffix(output, ".lock");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("Failed to open bytecode cache lock {}", lock_path.display()))?;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(CachePublishLock(file)),
            Err(std::fs::TryLockError::WouldBlock) => {
                if std::time::Instant::now() >= deadline {
                    anyhow::bail!(
                        "Timed out waiting to publish bytecode cache {}",
                        output.display()
                    );
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(error).with_context(|| {
                    format!("Failed to lock bytecode cache {}", output.display())
                });
            }
        }
    }
}

#[derive(Debug)]
struct BytecodeLoadError(String);

impl std::fmt::Display for BytecodeLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BytecodeLoadError {}

/// A cached entry may be retried from source only when the native engine
/// returned its dedicated pre-execution bytecode-rejection status. Exception
/// messages are user-controlled and are never classification input.
pub(crate) fn is_bytecode_load_error(error: &anyhow::Error) -> bool {
    error.is::<BytecodeLoadError>()
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct BytecodeArtifactManifest {
    version: u32,
    source_path: String,
    source_sha256: String,
    bytecode_sha256: String,
    source_map_path: Option<String>,
    source_map_sha256: Option<String>,
    toolchain_identity: String,
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn bytecode_manifest_path(bytecode: &Path) -> PathBuf {
    path_with_suffix(bytecode, ".meta.json")
}

fn hermesc_source_map_path(bytecode: &Path) -> PathBuf {
    path_with_suffix(bytecode, ".map")
}

fn configure_hermesc_compile_command(
    cmd: &mut Command,
    output: &Path,
    emit_source_map: bool,
    input: &Path,
) {
    cmd.arg("-emit-binary");
    cmd.arg("-out");
    cmd.arg(output);
    if emit_source_map {
        // hermesc's -output-source-map is a boolean flag. It always writes to
        // `<-out>.map`; a following pathname is parsed as another input.
        cmd.arg("-output-source-map");
    }
    cmd.arg(input);
}

#[cfg(test)]
fn bytecode_source_map_is_fresh(bytecode: &Path, source_map: &Path) -> bool {
    verified_bytecode_source_map(bytecode, source_map).is_some()
}

fn verified_bytecode_source_map(
    bytecode: &Path,
    source_map: &Path,
) -> Option<std::sync::Arc<super::sourcemap::SourceMap>> {
    // No attestation means no generated-code trust, irrespective of what a
    // cache manifest claims its toolchain identity was.
    ibex_runtime::engine::loaded_engine_binary_identity().ok()?;
    let Ok(raw) = std::fs::read(bytecode_manifest_path(bytecode)) else {
        return None;
    };
    let Ok(manifest) = serde_json::from_slice::<BytecodeArtifactManifest>(&raw) else {
        return None;
    };
    if manifest.version != 2 || manifest.toolchain_identity != bytecode_cache_identity() {
        return None;
    }
    let expected_map = std::fs::canonicalize(source_map).ok()?;
    let expected_map_utf8 = expected_map.to_str()?;
    if manifest.source_map_path.as_deref() != Some(expected_map_utf8) {
        return None;
    }
    let source_path = std::fs::canonicalize(&manifest.source_path).ok()?;
    if source_path.to_str()? != manifest.source_path {
        return None;
    }

    // Verify the exact vectors consumed below rather than hashing each path
    // and reopening the map afterwards. This closes the verify/use race for
    // both the HBC buffer and its source map.
    let source_bytes = std::fs::read(source_path).ok()?;
    let bytecode_bytes = std::fs::read(bytecode).ok()?;
    let map_bytes = std::fs::read(expected_map).ok()?;
    let expected_map_digest = manifest.source_map_sha256.as_deref()?;
    if format!("{:x}", Sha256::digest(&source_bytes)) != manifest.source_sha256
        || format!("{:x}", Sha256::digest(&bytecode_bytes)) != manifest.bytecode_sha256
        || format!("{:x}", Sha256::digest(&map_bytes)) != expected_map_digest
    {
        return None;
    }
    super::sourcemap::SourceMap::from_bytes(&map_bytes)
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

async fn sha256_path(path: &Path) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(tokio::fs::read(path).await?)
    ))
}

pub(crate) fn bytecode_cache_identity() -> String {
    let compiler = find_hermesc_identity().ok();
    bytecode_cache_identity_for(compiler.as_ref())
}

fn bytecode_cache_identity_for(compiler: Option<&HermesToolIdentity>) -> String {
    // Bind generated HBC to the engine artifact that is actually mapped, not a
    // separately discovered `hermes` executable. Path/inode are deliberately
    // excluded: identical verified engine bytes may move between installs,
    // while digest + architecture + structural features capture every input
    // that changes the runtime's bytecode contract.
    let runtime =
        match ibex_runtime::engine::loaded_engine_binary_identity().map_err(anyhow::Error::msg) {
            Ok(identity) => {
                let mut structural_features = identity.structural_features;
                structural_features.sort();
                structural_features.dedup();
                serde_json::to_vec(&(
                    "ibex-loaded-hermes-v1",
                    identity.kind,
                    identity.binary_digest,
                    identity.target_architecture,
                    structural_features,
                ))
                .expect("loaded Hermes identity contains only serializable strings")
            }
            Err(error) => {
                // Cache consumers independently require mapped-engine
                // attestation. Keep fallback keys distinct within this process
                // as a second guard and to avoid converging failed publishers.
                static UNATTESTED_SEQUENCE: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let sequence = UNATTESTED_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                format!(
                    "ibex-unattested-hermes\0{}\0{sequence}\0{error}",
                    std::process::id()
                )
                .into_bytes()
            }
        };
    let compiler = compiler
        .map(HermesToolIdentity::cache_fingerprint)
        .unwrap_or_else(|| "compiler-identity-unavailable".into());
    let mut digest = Sha256::new();
    digest.update(b"ibex-hbc-toolchain-v3\0");
    digest.update(runtime);
    digest.update(b"\0");
    digest.update(compiler.as_bytes());
    format!("{:x}", digest.finalize())
}

pub(crate) struct VerifiedBytecodeArtifact {
    pub(crate) bytes: Vec<u8>,
    pub(crate) source_path: PathBuf,
}

pub(crate) async fn load_verified_bytecode_artifact(
    expected_source: Option<&Path>,
    bytecode: &Path,
) -> Result<VerifiedBytecodeArtifact> {
    ibex_runtime::engine::loaded_engine_binary_identity()
        .map_err(anyhow::Error::msg)
        .context("cannot authenticate the loaded Hermes engine for bytecode cache use")?;
    let Ok(raw) = tokio::fs::read(bytecode_manifest_path(bytecode)).await else {
        anyhow::bail!("bytecode cache manifest is missing");
    };
    let manifest = serde_json::from_slice::<BytecodeArtifactManifest>(&raw)
        .context("invalid bytecode cache manifest")?;
    if manifest.version != 2 || manifest.toolchain_identity != bytecode_cache_identity() {
        anyhow::bail!("bytecode cache toolchain identity mismatch");
    }
    let source_path = std::fs::canonicalize(&manifest.source_path)
        .with_context(|| format!("bytecode source is missing: {}", manifest.source_path))?;
    let source_path_utf8 = source_path
        .to_str()
        .context("bytecode cache does not support non-UTF-8 source paths")?;
    if source_path_utf8 != manifest.source_path {
        anyhow::bail!("bytecode source path is not canonical");
    }
    if let Some(expected_source) = expected_source {
        let expected_source = std::fs::canonicalize(expected_source).with_context(|| {
            format!("bytecode source is missing: {}", expected_source.display())
        })?;
        if expected_source != source_path {
            anyhow::bail!("bytecode cache source identity mismatch");
        }
    }
    if manifest.source_map_path.is_some() || manifest.source_map_sha256.is_some() {
        anyhow::bail!("entry bytecode cache unexpectedly contains a source map");
    }
    // Read each selected object once. The byte vector returned below is the
    // same vector whose digest is checked, so pathname replacement after this
    // point cannot change what Hermes executes.
    let source_bytes = tokio::fs::read(&source_path).await?;
    let bytecode_bytes = tokio::fs::read(bytecode).await?;
    if format!("{:x}", Sha256::digest(&source_bytes)) != manifest.source_sha256
        || format!("{:x}", Sha256::digest(&bytecode_bytes)) != manifest.bytecode_sha256
    {
        anyhow::bail!("bytecode cache digest mismatch");
    }
    Ok(VerifiedBytecodeArtifact {
        bytes: bytecode_bytes,
        source_path,
    })
}

pub(crate) async fn bytecode_artifact_is_fresh(source: &Path, bytecode: &Path) -> bool {
    load_verified_bytecode_artifact(Some(source), bytecode)
        .await
        .is_ok()
}

async fn replace_file_atomically(staged: &Path, final_path: &Path) -> Result<()> {
    #[cfg(not(windows))]
    {
        tokio::fs::rename(staged, final_path).await?;
        return Ok(());
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        extern "system" {
            fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
        }
        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
        let mut from: Vec<u16> = staged.as_os_str().encode_wide().collect();
        let mut to: Vec<u16> = final_path.as_os_str().encode_wide().collect();
        from.push(0);
        to.push(0);
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

struct TemporaryCompileDirectory(PathBuf);

impl Drop for TemporaryCompileDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn rewrite_staged_source_map(
    source_map: &Path,
    staged_source: &Path,
    original_source: &Path,
) -> Result<()> {
    let bytes = std::fs::read(source_map)?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("Invalid hermesc source map {}", source_map.display()))?;
    if let Some(sources) = value
        .get_mut("sources")
        .and_then(serde_json::Value::as_array_mut)
    {
        let staged = staged_source.to_string_lossy();
        let staged_name = staged_source.file_name().and_then(|name| name.to_str());
        let original = absolute_path(original_source)
            .to_string_lossy()
            .into_owned();
        for source in sources {
            let Some(text) = source.as_str() else {
                continue;
            };
            if text == staged || staged_name.is_some_and(|name| text == name) {
                *source = serde_json::Value::String(original.clone());
            }
        }
    }
    std::fs::write(source_map, serde_json::to_vec(&value)?)?;
    Ok(())
}

async fn wait_for_hbc_test_barrier(name: &str, output: &Path) -> Result<()> {
    let Ok(dir) = std::env::var("IBEX_TEST_HBC_COMPILE_BARRIER") else {
        return Ok(());
    };
    let dir = PathBuf::from(dir);
    tokio::fs::create_dir_all(&dir).await?;
    if let Ok(target) = tokio::fs::read_to_string(dir.join("target")).await {
        if target != output.to_string_lossy() {
            return Ok(());
        }
    }
    tokio::fs::write(dir.join(format!("{name}.ready")), []).await?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !dir.join(format!("{name}.release")).exists() {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for HBC {name} test barrier");
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    Ok(())
}

/// Compile a JavaScript file to Hermes bytecode
pub async fn compile_to_bytecode(
    input: &str,
    output: &std::path::Path,
    source_map: Option<&std::path::Path>,
) -> Result<()> {
    let input_path = std::fs::canonicalize(input)
        .with_context(|| format!("Failed to authenticate bytecode source {input}"))?;
    let source = tokio::fs::read(&input_path)
        .await
        .with_context(|| format!("Failed to read bytecode source {input}"))?;
    compile_source_to_bytecode_with_attestation(
        &input_path,
        &source,
        output,
        source_map,
        BytecodeOutputKind::ExplicitBuild,
    )
    .await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BytecodeOutputKind {
    ExplicitBuild,
    GeneratedCache,
}

impl BytecodeOutputKind {
    fn requires_runtime_attestation(self) -> bool {
        matches!(self, Self::GeneratedCache)
    }
}

pub(crate) async fn compile_source_to_bytecode(
    input_path: &Path,
    source: &[u8],
    output: &Path,
    source_map: Option<&Path>,
) -> Result<()> {
    compile_source_to_bytecode_with_attestation(
        input_path,
        source,
        output,
        source_map,
        BytecodeOutputKind::GeneratedCache,
    )
    .await
}

async fn compile_attested_cache_bytecode(
    input: &str,
    output: &Path,
    source_map: Option<&Path>,
) -> Result<()> {
    let input_path = std::fs::canonicalize(input)
        .with_context(|| format!("Failed to authenticate bytecode source {input}"))?;
    let source = tokio::fs::read(&input_path)
        .await
        .with_context(|| format!("Failed to read bytecode source {input}"))?;
    compile_source_to_bytecode_with_attestation(
        &input_path,
        &source,
        output,
        source_map,
        BytecodeOutputKind::GeneratedCache,
    )
    .await
}

async fn compile_source_to_bytecode_with_attestation(
    input_path: &Path,
    source: &[u8],
    output: &Path,
    source_map: Option<&Path>,
    output_kind: BytecodeOutputKind,
) -> Result<()> {
    let compiler_identity = find_hermesc_identity()?;
    compile_source_to_bytecode_with_compiler(
        input_path,
        source,
        output,
        source_map,
        &compiler_identity,
        output_kind,
    )
    .await
}

async fn compile_source_to_bytecode_with_compiler(
    input_path: &Path,
    source: &[u8],
    output: &Path,
    source_map: Option<&Path>,
    compiler_identity: &HermesToolIdentity,
    output_kind: BytecodeOutputKind,
) -> Result<()> {
    if output_kind.requires_runtime_attestation() {
        ibex_runtime::engine::loaded_engine_binary_identity()
            .map_err(anyhow::Error::msg)
            .context("cannot authenticate the loaded Hermes engine for bytecode cache use")?;
    }
    // Select/canonicalize the source identity before any async compile work.
    // Callers read the exact bytes through this canonical path, so the
    // manifest never canonicalizes a different pathname object after compile.
    let source_path = std::fs::canonicalize(input_path)
        .with_context(|| format!("Failed to authenticate source {}", input_path.display()))?;
    let source_path_string = source_path
        .to_str()
        .context("bytecode cache does not support non-UTF-8 source paths")?
        .to_owned();
    let _publish_lock = acquire_cache_publish_lock(output).await?;
    // Gate on the `HBC bytecode version:` line both tools print — the version
    // that actually determines whether the runtime can load hermesc's output.
    // Comparing an arbitrary token of the multi-line `--version` output
    // (previously: the LAST whitespace token, which is `input` from hermes'
    // trailing "Zip file input" feature line vs `99` from hermesc) made this
    // gate a false positive on every call and silently disabled entry-bytecode
    // caching (ENG-23495). When either version line is absent we proceed, as
    // before: a genuinely incompatible buffer is caught at load time and falls
    // back to source (`is_bytecode_load_error`, ENG-23484).
    // @ref LLP 0005#bytecode-precompilation-hermesc — run-time entry cache gates on HBC version
    let compile_dir = temporary_output_path(&output.with_extension("compile"));
    tokio::fs::create_dir(&compile_dir)
        .await
        .with_context(|| format!("Failed to create compile stage {}", compile_dir.display()))?;
    let _compile_dir = TemporaryCompileDirectory(compile_dir.clone());
    let compiler_name = if cfg!(windows) {
        "hermesc.exe"
    } else {
        "hermesc"
    };
    let staged_compiler = compile_dir.join(compiler_name);
    tokio::fs::write(&staged_compiler, compiler_identity.bytes.as_slice()).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&staged_compiler, std::fs::Permissions::from_mode(0o700))
            .await?;
    }
    if sha256_path(&staged_compiler).await? != compiler_identity.sha256 {
        anyhow::bail!("Hermes compiler changed while staging authenticated binary");
    }
    compiler_identity.verify_selected_path()?;

    let source_name = source_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("entry.js"));
    let staged_input = compile_dir.join(source_name);
    tokio::fs::write(&staged_input, source).await?;
    let source_digest = format!("{:x}", Sha256::digest(source));
    wait_for_hbc_test_barrier("input-staged", output).await?;

    let runtime_hbc = ibex_runtime::engine::loaded_engine_bytecode_version().ok();
    let compiler_hbc = get_hermesc_version_at(&staged_compiler)
        .ok()
        .and_then(|v| extract_hbc_version(&v));
    if let (Some(runtime), Some(compiler)) = (runtime_hbc, compiler_hbc) {
        if runtime != compiler {
            anyhow::bail!(
                "Hermes bytecode version mismatch: runtime HBC {} vs hermesc HBC {}. Rebuild bytecode with matching Hermes.",
                runtime,
                compiler
            );
        }
    }

    let timeout = std::env::var("IBEX_HERMESC_TIMEOUT_MS")
        .ok()
        .map(|value| crate::subprocess::parse_timeout_ms(Some(&value), DEFAULT_HERMESC_TIMEOUT_MS))
        .unwrap_or_else(|| {
            timeout_from_env("EXACT_HERMESC_TIMEOUT_MS", DEFAULT_HERMESC_TIMEOUT_MS)
        });
    let temp_output = temporary_output_path(output);
    // @ref LLP 0005#bytecode-precompilation-hermesc — hermesc derives the
    // source-map path from `-out`; only publication uses the caller's path.
    let temp_source_map = source_map.map(|_| hermesc_source_map_path(&temp_output));

    let mut cmd = Command::new(&staged_compiler);
    configure_hermesc_compile_command(
        &mut cmd,
        &temp_output,
        temp_source_map.is_some(),
        &staged_input,
    );

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let result = output_with_timeout(&mut cmd, timeout, "hermesc")
        .await
        .context("Failed to run hermesc")?;

    if !result.status.success() {
        let _ = tokio::fs::remove_file(&temp_output).await;
        if let Some(map_path) = temp_source_map.as_ref() {
            let _ = tokio::fs::remove_file(map_path).await;
        }
        let stderr = String::from_utf8_lossy(&result.stderr);
        anyhow::bail!("Bytecode compilation failed:\n{}", stderr);
    }

    wait_for_hbc_test_barrier("compile-finished", output).await?;
    compiler_identity.verify_selected_path()?;
    if let Some(map_path) = temp_source_map.as_ref() {
        rewrite_staged_source_map(map_path, &staged_input, &source_path)?;
    }

    let source_map_path = source_map
        .map(|path| {
            let path = absolute_path(path);
            path.to_str()
                .context("bytecode cache does not support non-UTF-8 source-map paths")
                .map(str::to_owned)
        })
        .transpose()?;
    let source_map_sha256 = match temp_source_map.as_ref() {
        Some(path) => Some(sha256_path(path).await?),
        None => None,
    };
    let manifest = BytecodeArtifactManifest {
        version: 2,
        source_path: source_path_string,
        source_sha256: source_digest,
        bytecode_sha256: sha256_path(&temp_output).await?,
        source_map_path,
        source_map_sha256,
        toolchain_identity: bytecode_cache_identity_for(Some(compiler_identity)),
    };
    let final_manifest = bytecode_manifest_path(output);
    let temp_manifest = temporary_output_path(&final_manifest);
    tokio::fs::write(&temp_manifest, serde_json::to_vec(&manifest)?)
        .await
        .with_context(|| format!("Failed to stage {}", final_manifest.display()))?;

    // The manifest is the completion marker for the HBC+map unit. Invalidate
    // the old marker before replacing either member, then publish a new marker
    // only after both digest-bound files are in place.
    tokio::fs::remove_file(&final_manifest).await.ok();

    if let (Some(final_map), Some(temp_map)) = (source_map, temp_source_map.as_ref()) {
        replace_file_atomically(temp_map, final_map)
            .await
            .with_context(|| {
                format!("Failed to publish source map cache {}", final_map.display())
            })?;
    }

    replace_file_atomically(&temp_output, output)
        .await
        .with_context(|| format!("Failed to publish bytecode cache {}", output.display()))?;
    replace_file_atomically(&temp_manifest, &final_manifest)
        .await
        .with_context(|| format!("Failed to publish {}", final_manifest.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hermesc_source_map_flag_is_boolean_and_uses_derived_output_path() {
        let mut command = Command::new("hermesc");
        let output = Path::new("bundle.hbc");
        let input = Path::new("bundle.js");
        configure_hermesc_compile_command(&mut command, output, true, input);
        let args = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "-emit-binary",
                "-out",
                "bundle.hbc",
                "-output-source-map",
                "bundle.js"
            ]
        );
        assert_eq!(
            hermesc_source_map_path(output),
            PathBuf::from("bundle.hbc.map")
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_conformance_batch {
        include!("capsec_conformance_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_builtin_batch {
        include!("capsec_public_builtin_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_closed_batch {
        include!("capsec_public_closed_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_callback_invariant_batch {
        include!("capsec_public_callback_invariant_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_target_absence_batch {
        include!("capsec_public_target_absence_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_noncap_builtin_batch {
        include!("capsec_public_noncap_builtin_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_startup_batch {
        include!("capsec_public_startup_batch.rs");
    }

    #[cfg(feature = "capsec-conformance-observer")]
    mod capsec_public_startup_environment_batch {
        include!("capsec_public_startup_environment_batch.test.rs");
    }

    use std::fs;
    #[cfg(feature = "host-http-server")]
    use std::io::{Read, Write};
    #[cfg(feature = "host-http-server")]
    use std::net::TcpStream;
    #[cfg(feature = "host-http-server")]
    use std::sync::mpsc;
    #[cfg(feature = "host-http-server")]
    use std::time::{Duration as StdDuration, Instant};
    #[cfg(feature = "host-http-server")]
    use tokio::time::{sleep, timeout, Duration};

    #[test]
    fn only_generated_bytecode_caches_require_mapped_engine_attestation() {
        assert!(BytecodeOutputKind::GeneratedCache.requires_runtime_attestation());
        assert!(
            !BytecodeOutputKind::ExplicitBuild.requires_runtime_attestation(),
            "explicit ibex build output must remain available on Windows"
        );
    }

    struct TestEnvVar {
        name: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl TestEnvVar {
        fn set(name: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(name);
            std::env::set_var(name, value);
            Self { name, previous }
        }

        fn remove(name: &'static str) -> Self {
            let previous = std::env::var_os(name);
            std::env::remove_var(name);
            Self { name, previous }
        }
    }

    impl Drop for TestEnvVar {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.name, value),
                None => std::env::remove_var(self.name),
            }
        }
    }

    #[cfg(feature = "host-http-server")]
    async fn eval_json(engine: &HermesEngine, code: &str) -> serde_json::Value {
        let raw = engine
            .eval_immediate(code)
            .await
            .expect("Hermes eval should succeed")
            .unwrap_or_default();
        serde_json::from_str(&raw).expect("Hermes eval should return valid JSON")
    }

    #[cfg(feature = "host-http-server")]
    async fn wait_for_exact_wait_status(engine: &HermesEngine) -> serde_json::Value {
        let deadline = Instant::now() + StdDuration::from_secs(2);
        let mut status = serde_json::json!({ "status": "pending" });
        while Instant::now() < deadline {
            match timeout(Duration::from_millis(250), engine.drive_event_loop()).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => panic!("event loop pump should succeed: {err:?}"),
                Err(_) => {}
            }
            status = eval_json(
                engine,
                r#"(function() {
                    return JSON.stringify({ status: globalThis.__exactWaitStatus });
                })()"#,
            )
            .await;
            if status.get("status").and_then(serde_json::Value::as_str) != Some("pending") {
                return status;
            }
            sleep(Duration::from_millis(25)).await;
        }
        status
    }

    #[cfg(feature = "host-http-server")]
    fn blocking_http_get(port: u16, path: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect(("127.0.0.1", port))?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes())?;

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    #[cfg(feature = "host-http-server")]
    fn blocking_http_get_with_retry(
        port: u16,
        path: &str,
        attempts: usize,
    ) -> std::io::Result<String> {
        let mut last_err = None;
        for _ in 0..attempts {
            match blocking_http_get(port, path) {
                Ok(response) if !response.is_empty() => return Ok(response),
                Ok(_) => {
                    last_err = Some(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "empty HTTP response",
                    ));
                }
                Err(err) => last_err = Some(err),
            }
            std::thread::sleep(StdDuration::from_millis(25));
        }
        Err(last_err.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP response did not arrive")
        }))
    }

    #[cfg(feature = "host-http-server")]
    async fn close_server(engine: &HermesEngine, server_id_global: &str) {
        let script = format!(
            r#"(function() {{
                var serverId = globalThis[{server_id_global:?}];
                if (typeof serverId === 'number') {{
                  __exactHttpClose(serverId, 1);
                }}
                return JSON.stringify({{ closed: true }});
            }})()"#
        );
        let _ = engine.eval_immediate(&script).await;
        sleep(Duration::from_millis(25)).await;
        let _ = timeout(Duration::from_secs(1), engine.drive_event_loop()).await;
    }

    #[test]
    fn test_find_hermes_binary() {
        // This test will fail if Hermes isn't installed, which is expected
        // in CI environments without Hermes
        let result = find_hermes_binary();
        println!("Hermes binary search result: {:?}", result);
    }

    #[cfg(unix)]
    #[test]
    fn hermes_tool_discovery_rejects_ambiguity_and_root_escape() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root =
            std::env::temp_dir().join(format!("ibex-hermes-tool-roots-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let first = root.join("first");
        let second = root.join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        for directory in [&first, &second] {
            let tool = directory.join("hermes");
            fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
            let mut permissions = fs::metadata(&tool).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&tool, permissions).unwrap();
        }
        let ambiguous =
            discover_hermes_tool_in_roots("hermes", &[first.clone(), second.clone()]).unwrap_err();
        assert!(ambiguous.to_string().contains("Ambiguous"));

        fs::remove_file(first.join("hermes")).unwrap();
        symlink(second.join("hermes"), first.join("hermes")).unwrap();
        let escaped = discover_hermes_tool_in_roots("hermes", &[first]).unwrap_err();
        assert!(escaped.to_string().contains("escapes authenticated root"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_bundle_search_roots_stay_local() {
        let temp_root = std::env::temp_dir().join("ibex-hermes-runtime-roots-local");
        let _ = fs::remove_dir_all(&temp_root);
        fs::create_dir_all(&temp_root).unwrap();

        let roots = runtime_bundle_search_roots(&temp_root);
        assert_eq!(roots, vec![temp_root.clone()]);

        let _ = fs::remove_dir_all(&temp_root);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn capsec_loaded_engine_identity_attestation() {
        let Ok(output_path) = std::env::var("IBEX_CAPSEC_ENGINE_IDENTITY_OUTPUT") else {
            // The normal unit suite still compiles and exercises all helpers;
            // the conformance runner supplies this path for the exact-artifact
            // execution and requires the resulting record.
            return;
        };
        let expected_path = std::fs::canonicalize(
            std::env::var("IBEX_CAPSEC_ENGINE_ARTIFACT")
                .expect("conformance attestation requires the named engine artifact"),
        )
        .expect("named conformance engine artifact must be canonicalizable");
        let expected_digest = std::env::var("IBEX_CAPSEC_ENGINE_DIGEST")
            .expect("conformance attestation requires the named artifact digest");

        let _lock = hermes_engine_test_lock().lock().await;
        let identity = HermesEngine::loaded_engine_identity()
            .expect("the linked Hermes object must expose a loaded identity");
        assert_eq!(identity.engine_artifact_path, expected_path);
        assert_eq!(identity.binary_digest, expected_digest);

        let engine = HermesEngine::new().expect("exact Hermes engine must initialize");
        engine
            .load_runtime()
            .await
            .expect("exact Hermes runtime bundle must load");
        let marker = engine
            .eval_immediate("'IBEX_CAPSEC_EXACT_ENGINE_EXECUTED'")
            .await
            .expect("exact Hermes artifact must evaluate the attestation program");
        assert_eq!(marker.as_deref(), Some("IBEX_CAPSEC_EXACT_ENGINE_EXECUTED"));
        let verified = ibex_runtime::engine::verify_loaded_engine_binary_identity(&identity)
            .expect("loaded Hermes object changed during exact-artifact execution");
        assert_eq!(verified, identity);

        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output_path)
            .expect("identity output must be a new runner-owned file");
        serde_json::to_writer(&mut output, &verified)
            .expect("loaded engine identity must serialize");
        use std::io::Write as _;
        output
            .write_all(b"\n")
            .expect("loaded engine identity must be written completely");
        output
            .sync_all()
            .expect("loaded engine identity must be durable before success");
    }

    #[tokio::test]
    async fn application_cwd_cannot_select_lookalike_runtime_bundle() {
        let _lock = hermes_engine_test_lock().lock().await;

        struct RestoreProcessState {
            cwd: PathBuf,
            ibex_repo_root: Option<std::ffi::OsString>,
            exact_repo_root: Option<std::ffi::OsString>,
        }
        impl Drop for RestoreProcessState {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.cwd);
                match self.ibex_repo_root.take() {
                    Some(value) => std::env::set_var("IBEX_REPO_ROOT", value),
                    None => std::env::remove_var("IBEX_REPO_ROOT"),
                }
                match self.exact_repo_root.take() {
                    Some(value) => std::env::set_var("EXACT_REPO_ROOT", value),
                    None => std::env::remove_var("EXACT_REPO_ROOT"),
                }
            }
        }
        let _restore = RestoreProcessState {
            cwd: std::env::current_dir().unwrap(),
            ibex_repo_root: std::env::var_os("IBEX_REPO_ROOT"),
            exact_repo_root: std::env::var_os("EXACT_REPO_ROOT"),
        };
        std::env::remove_var("IBEX_REPO_ROOT");
        std::env::remove_var("EXACT_REPO_ROOT");

        let fake = tempfile::tempdir().unwrap();
        fs::create_dir_all(fake.path().join("vendored-generated")).unwrap();
        fs::create_dir_all(fake.path().join("packages/ibex-runtime-js")).unwrap();
        fs::create_dir_all(fake.path().join("packages/ibex-devtools")).unwrap();
        fs::write(
            fake.path().join("packages/ibex-runtime-js/package.json"),
            "{}",
        )
        .unwrap();
        fs::write(
            fake.path().join("packages/ibex-devtools/package.json"),
            "{}",
        )
        .unwrap();
        fs::write(
            fake.path()
                .join("vendored-generated/embedded_runtime_bundle.js"),
            "throw new Error('application-controlled runtime executed');",
        )
        .unwrap();

        std::env::set_current_dir(fake.path()).unwrap();
        let fake_root = fs::canonicalize(fake.path()).unwrap();
        let roots = runtime_workspace_roots().unwrap();
        assert!(roots.iter().all(|root| root != &fake_root));
        assert!(!find_runtime_bundle().unwrap().starts_with(fake_root));
    }

    #[test]
    fn eof_drain_stops_on_future_or_perpetual_timer() {
        let now = 1_000u64;
        // Something ran this poll: keep draining ready work.
        assert!(!eof_drain_complete(1, -1, now));
        assert!(!eof_drain_complete(3, (now + 5000) as i64, now));
        // Nothing ran and no timers scheduled: done.
        assert!(eof_drain_complete(0, -1, now));
        // Nothing ran and only a FUTURE timer (a referenced setInterval that
        // rescheduled to now+1000): done — must not hang Ctrl+D. (ENG-23030 #1)
        assert!(eof_drain_complete(0, (now + 1000) as i64, now));
        // Nothing ran but a one-shot is already due: keep draining it.
        assert!(!eof_drain_complete(0, (now - 1) as i64, now));
        assert!(!eof_drain_complete(0, now as i64, now));
    }

    // Real (verbatim) multi-line `--version` outputs of the checked-in
    // toolchain. The runtime binary appends a `Features:` block after the
    // version lines, so any "last token" parse reads `input` instead of a
    // version — the misparse that disabled entry-bytecode caching (ENG-23495).
    const HERMES_RUNTIME_VERSION_OUTPUT: &str = "LLVM (http://llvm.org/):\n  \
        LLVH version 8.0.0svn\n  Optimized build\n\n\
        Hermes JavaScript compiler and Virtual Machine.\n  \
        Hermes release version: 1.0.0\n  \
        HBC bytecode version: 99\n\n  \
        Features:\n    Unicode RegExp Property Escapes\n    Zip file input";
    const HERMESC_VERSION_OUTPUT: &str = "LLVM (http://llvm.org/):\n  \
        LLVH version 8.0.0svn\n  Optimized build\n\n\
        Hermes JavaScript compiler.\n  \
        Hermes release version: 1.0.0\n  \
        HBC bytecode version: 99";

    #[test]
    fn extract_hbc_version_parses_real_multiline_outputs() {
        // Both tools expose the HBC line; the runtime's trailing Features
        // block must not confuse the parse.
        assert_eq!(extract_hbc_version(HERMES_RUNTIME_VERSION_OUTPUT), Some(99));
        assert_eq!(extract_hbc_version(HERMESC_VERSION_OUTPUT), Some(99));
        // The gate in compile_to_bytecode compares exactly these two values,
        // so the checked-in toolchain must gate as compatible.
        assert_eq!(
            extract_hbc_version(HERMES_RUNTIME_VERSION_OUTPUT),
            extract_hbc_version(HERMESC_VERSION_OUTPUT)
        );
    }

    #[test]
    fn extract_hbc_version_rejects_output_without_hbc_line() {
        // No HBC line -> None (gate then proceeds and defers to load-time
        // rejection rather than comparing junk tokens).
        assert_eq!(
            extract_hbc_version("Hermes JavaScript compiler.\n  Hermes release version: 1.0.0"),
            None
        );
        assert_eq!(extract_hbc_version(""), None);
        // Non-numeric version value -> None.
        assert_eq!(extract_hbc_version("HBC bytecode version: abc"), None);
    }

    #[test]
    fn extract_hbc_version_detects_real_mismatch() {
        let older = "Hermes JavaScript compiler.\n  Hermes release version: 0.12.0\n  \
            HBC bytecode version: 96";
        assert_eq!(extract_hbc_version(older), Some(96));
        assert_ne!(
            extract_hbc_version(older),
            extract_hbc_version(HERMES_RUNTIME_VERSION_OUTPUT)
        );
    }

    #[test]
    fn compiler_identity_changes_for_same_version_binary_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("hermesc");
        fs::write(&tool, b"same version binary A").unwrap();
        let first = HermesToolIdentity::capture(&tool).unwrap();
        fs::write(&tool, b"same version binary B").unwrap();
        let second = HermesToolIdentity::capture(&tool).unwrap();
        assert_ne!(first.sha256, second.sha256);
        assert_ne!(first.cache_fingerprint(), second.cache_fingerprint());
        assert!(first.verify_selected_path().is_err());
    }

    /// The live gate must compare the checked-in compiler to the HBC version
    /// reported by the mapped engine's root API. The standalone `hermes`
    /// executable is intentionally not consulted: it may be a different build.
    #[test]
    fn checked_in_toolchain_gates_as_compatible() {
        let (Ok(runtime), Ok(compiler_out)) = (
            ibex_runtime::engine::loaded_engine_bytecode_version(),
            get_hermesc_version(),
        ) else {
            // Toolchain not present in this environment; the fixture tests
            // above still cover the parse.
            return;
        };
        let compiler = extract_hbc_version(&compiler_out);
        assert_eq!(
            Some(runtime),
            compiler,
            "checked-in hermes/hermesc HBC versions must match"
        );
        assert!(bytecode_versions_compatible());
    }

    #[tokio::test]
    async fn bytecode_and_source_map_manifest_rejects_mixed_or_tampered_unit() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("entry.js");
        let bytecode = dir.path().join("entry.hbc");
        let source_map = dir.path().join("entry.hbc.map");
        fs::write(&source, "function answer() { return 42; }\nanswer();\n").unwrap();
        if compile_to_bytecode(&source.to_string_lossy(), &bytecode, Some(&source_map))
            .await
            .is_err()
        {
            return; // optional checked-in toolchain in minimal environments
        }
        assert!(bytecode.is_file());
        assert!(source_map.is_file());
        assert!(bytecode_manifest_path(&bytecode).is_file());
        assert!(bytecode_source_map_is_fresh(&bytecode, &source_map));

        let mut tampered = fs::read(&source_map).unwrap();
        if let Some(first) = tampered.first_mut() {
            *first ^= 1;
        }
        fs::write(&source_map, tampered).unwrap();
        assert!(!bytecode_source_map_is_fresh(&bytecode, &source_map));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bytecode_compile_uses_staged_source_across_two_barrier_aba_mutations() {
        use std::os::unix::fs::PermissionsExt;

        struct EnvGuard;
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var("IBEX_TEST_HBC_COMPILE_BARRIER");
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let compiler = dir.path().join("hermesc");
        let compiler_script = "#!/bin/sh\n\
if [ \"$1\" = \"--version\" ]; then\n\
  printf 'HBC bytecode version: 99\\n'\n\
  exit 0\n\
fi\n\
out=''\n\
input=''\n\
while [ \"$#\" -gt 0 ]; do\n\
  case \"$1\" in\n\
    -out) shift; out=\"$1\" ;;\n\
    -emit-binary) ;;\n\
    *) input=\"$1\" ;;\n\
  esac\n\
  shift\n\
done\n\
cp \"$input\" \"$out\"\n";
        fs::write(&compiler, compiler_script).unwrap();
        let mut permissions = fs::metadata(&compiler).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&compiler, permissions).unwrap();
        let identity = HermesToolIdentity::capture(&compiler).unwrap();

        let source_path = dir.path().join("entry.js");
        let output = dir.path().join("entry.hbc");
        let source_a = b"console.log('A');\n".to_vec();
        let source_b = b"console.log('B');\n";
        fs::write(&source_path, &source_a).unwrap();
        let barrier = dir.path().join("barrier");
        fs::create_dir(&barrier).unwrap();
        fs::write(barrier.join("target"), output.to_string_lossy().as_bytes()).unwrap();
        std::env::set_var("IBEX_TEST_HBC_COMPILE_BARRIER", &barrier);
        let _env = EnvGuard;

        let task_source = source_path.clone();
        let task_output = output.clone();
        let compile = tokio::spawn(async move {
            compile_source_to_bytecode_with_compiler(
                &task_source,
                &source_a,
                &task_output,
                None,
                &identity,
                BytecodeOutputKind::ExplicitBuild,
            )
            .await
        });

        async fn wait_for(path: &Path) {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !path.exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
            })
            .await
            .unwrap();
        }

        wait_for(&barrier.join("input-staged.ready")).await;
        fs::write(&source_path, source_b).unwrap();
        fs::write(&source_path, b"console.log('A');\n").unwrap();
        fs::write(barrier.join("input-staged.release"), []).unwrap();

        wait_for(&barrier.join("compile-finished.ready")).await;
        fs::write(&source_path, source_b).unwrap();
        fs::write(&source_path, b"console.log('A');\n").unwrap();
        fs::write(barrier.join("compile-finished.release"), []).unwrap();

        compile.await.unwrap().unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"console.log('A');\n");
        let manifest: BytecodeArtifactManifest =
            serde_json::from_slice(&fs::read(bytecode_manifest_path(&output)).unwrap()).unwrap();
        assert_eq!(
            manifest.source_sha256,
            format!("{:x}", Sha256::digest(b"console.log('A');\n"))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bytecode_publish_lock_never_steals_from_slow_live_writer() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("entry.hbc");
        let first = acquire_cache_publish_lock(&output).await.unwrap();
        let second_output = output.clone();
        let second = tokio::spawn(async move { acquire_cache_publish_lock(&second_output).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !second.is_finished(),
            "a live writer lock must not be stolen based on elapsed time"
        );
        drop(first);
        tokio::time::timeout(std::time::Duration::from_secs(2), second)
            .await
            .expect("OS lock should release when its owner drops")
            .unwrap()
            .unwrap();
    }

    #[test]
    fn bytecode_retry_classification_is_structured_not_message_based() {
        let user_throw =
            anyhow::anyhow!("Compiling JS failed: user-controlled throw after SIDE_EFFECT");
        assert!(
            !is_bytecode_load_error(&user_throw),
            "user exception text must never authorize a source retry"
        );

        let native_rejection = anyhow::Error::new(BytecodeLoadError(
            "Bytecode sanity check failed: wrong version".to_string(),
        ));
        assert!(is_bytecode_load_error(&native_rejection));
    }

    #[test]
    fn repl_idle_wait_parks_when_idle_and_tracks_timers() {
        use std::time::Duration;
        let floor = Duration::from_millis(50);
        let idle = Duration::from_secs(1);
        let now = 10_000u64;
        // Nothing scheduled -> park the full idle interval (wake on notify).
        assert_eq!(repl_idle_wait(-1, now, floor, idle), idle);
        // A far-future timer is capped at the idle interval.
        assert_eq!(repl_idle_wait((now + 5000) as i64, now, floor, idle), idle);
        // A timer due soon waits until it is due.
        assert_eq!(
            repl_idle_wait((now + 200) as i64, now, floor, idle),
            Duration::from_millis(200)
        );
        // A 0-delay / already-due timer is floored so the prompt cannot busy-spin.
        assert_eq!(repl_idle_wait(now as i64, now, floor, idle), floor);
        assert_eq!(repl_idle_wait((now - 100) as i64, now, floor, idle), floor);
        // A very short IDLE_PARK (non-cli-notify) keeps the clamp well formed.
        let tiny = Duration::from_millis(5);
        assert_eq!(repl_idle_wait(now as i64, now, floor, tiny), tiny);
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn install_armed_test_host() -> (HostResetGuard, String) {
        install_armed_test_host_at(None, false, false, false, vec![])
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn install_armed_exact_test_host() -> (HostResetGuard, String) {
        let manifest_digest = "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA";
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, vec![], None, |value| {
                value["exactEmbedder"] = serde_json::json!({
                    "schema": "exact/host-operation-endowments/1",
                    "operationManifestDigest": manifest_digest,
                    "endowments": {
                        "app": [7, 11],
                        "agentIsolate": [19],
                        "uiWorklet": [],
                    }
                });
                value["protectedObjects"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({
                        "role": "exact-operation-manifest",
                        "object": {
                            "platform": "unix",
                            "volume": "fixture-volume",
                            "file": "exact-operation-manifest"
                        },
                        "deniedActions": ["fs:write"]
                    }));
            });
        assert_ne!(crate::host::abi::install_host(host), 0);
        (HostResetGuard, digest)
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn install_armed_test_host_at(
        project_root: Option<&std::path::Path>,
        allow_write: bool,
        allow_read: bool,
        allow_list: bool,
        extra_floor: Vec<serde_json::Value>,
    ) -> (HostResetGuard, String) {
        let (host, digest) = build_armed_test_host_at(
            project_root,
            allow_write,
            allow_read,
            allow_list,
            extra_floor,
        );
        assert_ne!(
            crate::host::abi::install_host(host),
            0,
            "test Host context token allocation"
        );
        (HostResetGuard, digest)
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn build_armed_test_host_at(
        project_root: Option<&std::path::Path>,
        allow_write: bool,
        allow_read: bool,
        allow_list: bool,
        extra_floor: Vec<serde_json::Value>,
    ) -> (crate::host::Host, String) {
        build_armed_test_host_at_with_protected(
            project_root,
            allow_write,
            allow_read,
            allow_list,
            extra_floor,
            None,
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn build_armed_test_host_at_with_protected(
        project_root: Option<&std::path::Path>,
        allow_write: bool,
        allow_read: bool,
        allow_list: bool,
        extra_floor: Vec<serde_json::Value>,
        protected_objects: Option<Vec<serde_json::Value>>,
    ) -> (crate::host::Host, String) {
        build_armed_test_host_custom(
            project_root,
            allow_write,
            allow_read,
            allow_list,
            extra_floor,
            protected_objects,
            |_| {},
        )
    }

    #[cfg(feature = "capsec-conformance-observer")]
    fn build_armed_test_host_custom(
        project_root: Option<&std::path::Path>,
        allow_write: bool,
        allow_read: bool,
        allow_list: bool,
        extra_floor: Vec<serde_json::Value>,
        protected_objects: Option<Vec<serde_json::Value>>,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> (crate::host::Host, String) {
        build_armed_test_host_control(
            project_root,
            allow_write,
            allow_read,
            allow_list,
            extra_floor,
            Vec::new(),
            true,
            0,
            protected_objects,
            mutate,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(feature = "capsec-conformance-observer")]
    fn build_armed_test_host_control(
        project_root: Option<&std::path::Path>,
        allow_write: bool,
        allow_read: bool,
        allow_list: bool,
        extra_floor: Vec<serde_json::Value>,
        extra_escalation_ceiling: Vec<serde_json::Value>,
        deny_ungranted_fs: bool,
        fs_principal_index: usize,
        protected_objects: Option<Vec<serde_json::Value>>,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> (crate::host::Host, String) {
        use capsec_semantics::arming::{ArmedSnapshot, ExpectedArmingIdentity};
        use capsec_semantics::model::Digest;

        let mut value: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/armed-snapshot.canonical.json"
        )))
        .unwrap();
        value["workflow"] = serde_json::Value::String("production".into());
        value["effectiveMode"] = serde_json::Value::String("enforce".into());
        if let Some(protected_objects) = protected_objects {
            value["protectedObjects"] = serde_json::Value::Array(protected_objects);
        }
        if let Some(project_root) = project_root {
            let components = project_root
                .components()
                .filter_map(|component| match component {
                    std::path::Component::Normal(value) => Some(serde_json::json!({
                        "encoding": "utf8",
                        "value": value.to_str().expect("test path must be UTF-8"),
                    })),
                    _ => None,
                })
                .collect::<Vec<_>>();
            value["rootBindings"][1]["hostPath"] = serde_json::json!({
                "root": "absolute",
                "components": components,
                "hostBound": true,
            });
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let metadata = std::fs::metadata(project_root).unwrap();
                value["rootBindings"][1]["object"] = serde_json::json!({
                    "platform": if cfg!(any(target_os = "macos", target_os = "ios")) {
                        "apple"
                    } else {
                        "unix"
                    },
                    "volume": format!("dev:{}", metadata.dev()),
                    "file": format!("ino:{}", metadata.ino()),
                });
            }
            let mut floor = Vec::new();
            let mut denials = Vec::new();
            if allow_list {
                floor.push(serde_json::json!({
                    "cap":"fs:list",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            } else if deny_ungranted_fs {
                denials.push(serde_json::json!({
                    "cap":"fs:list",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            }
            if allow_read {
                floor.push(serde_json::json!({
                    "cap":"fs:read",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            } else if deny_ungranted_fs {
                denials.push(serde_json::json!({
                    "cap":"fs:read",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            }
            if allow_write {
                floor.push(serde_json::json!({
                    "cap":"fs:write",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            } else if deny_ungranted_fs {
                denials.push(serde_json::json!({
                    "cap":"fs:write",
                    "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
                }));
            }
            value["principals"][fs_principal_index]["floor"] = serde_json::Value::Array(floor);
            value["principals"][fs_principal_index]["denials"] = serde_json::Value::Array(denials);
        }
        value["principals"][fs_principal_index]["floor"]
            .as_array_mut()
            .unwrap()
            .extend(extra_floor);
        value["principals"][fs_principal_index]["escalationCeiling"]
            .as_array_mut()
            .unwrap()
            .extend(extra_escalation_ceiling);
        value["principals"][fs_principal_index]["floor"]
            .as_array_mut()
            .unwrap()
            .sort_by(|left, right| {
                let left = capsec_semantics::canonical::to_jcs_bytes(left).unwrap();
                let right = capsec_semantics::canonical::to_jcs_bytes(right).unwrap();
                left.cmp(&right)
            });
        value["principals"][fs_principal_index]["floor"]
            .as_array_mut()
            .unwrap()
            .dedup();
        mutate(&mut value);
        let digest = capsec_semantics::digest::compute_checked_contract_digest(
            capsec_semantics::digest::DigestKind::ArmedSnapshot,
            &value,
        )
        .unwrap();
        value["armedSnapshotDigest"] = serde_json::Value::String(digest.clone());
        let digest_at = |path: &[&str]| {
            let field = path
                .iter()
                .fold(&value, |current, segment| &current[*segment]);
            Digest::new(field.as_str().unwrap()).unwrap()
        };
        let expected = ExpectedArmingIdentity {
            profile: value["capsVocab"].as_str().unwrap().into(),
            semantic_core: value["semanticCore"].as_str().unwrap().into(),
            vocab_digest: digest_at(&["vocabDigest"]),
            registry_digest: digest_at(&["registryDigest"]),
            policy_digest: digest_at(&["policyDigest"]),
            armed_snapshot_digest: digest_at(&["armedSnapshotDigest"]),
            target: value["engine"]["target"].as_str().unwrap().into(),
            engine_binary_digest: digest_at(&["engine", "binaryDigest"]),
            features: value["engine"]["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feature| feature.as_str().unwrap().into())
                .collect(),
            package_graph_digest: digest_at(&["packageGraph", "digest"]),
            protected_artifacts: value["protectedObjects"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let role: capsec_semantics::arming::ProtectedArtifactRole =
                        serde_json::from_value(row["role"].clone()).unwrap();
                    let content_digest = match role {
                        capsec_semantics::arming::ProtectedArtifactRole::EngineBinary => {
                            digest_at(&["engine", "binaryDigest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::ExactOperationManifest => {
                            digest_at(&["exactEmbedder", "operationManifestDigest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::ArmedPolicy => {
                            digest_at(&["policyDigest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::PackageGraph => {
                            digest_at(&["packageGraph", "digest"])
                        }
                        capsec_semantics::arming::ProtectedArtifactRole::Registry => {
                            digest_at(&["registryDigest"])
                        }
                    };
                    capsec_semantics::arming::ExpectedProtectedArtifact {
                        role,
                        host_path: serde_json::from_value(serde_json::json!({
                            "root": "absolute",
                            "components": [
                                {"encoding": "utf8", "value": "fixture"},
                                {"encoding": "utf8", "value": row["role"].as_str().unwrap()}
                            ],
                            "hostBound": true
                        }))
                        .unwrap(),
                        object: serde_json::from_value(row["object"].clone()).unwrap(),
                        content_digest,
                    }
                })
                .collect(),
        };
        let snapshot =
            ArmedSnapshot::load(&serde_json::to_vec(&value).unwrap(), &expected).unwrap();
        let host = unsafe {
            crate::host::Host::new_armed_for_test(
                crate::host::HostConfig {
                    mode: crate::host::SecurityMode::Enforce,
                    ..Default::default()
                },
                Arc::new(snapshot),
            )
        }
        .unwrap();
        (host, digest)
    }

    struct HostResetGuard;

    impl Drop for HostResetGuard {
        fn drop(&mut self) {
            crate::host::abi::install_host(crate::host::Host::strict());
        }
    }

    fn install_test_host_with_allow(allow: &[&str]) -> HostResetGuard {
        crate::host::abi::install_host(crate::host::Host::new(crate::host::HostConfig {
            mode: crate::host::SecurityMode::Enforce,
            allow: allow
                .iter()
                .map(|capability| capability.to_string())
                .collect(),
            ..Default::default()
        }));
        HostResetGuard
    }

    static ABI_PROBE_SYNC_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static ABI_PROBE_ASYNC_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static EXACT_ABI_PROBE_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static EXACT_ABI_PROBE_OPERATION: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);
    static EXACT_ABI_PROBE_PAYLOAD_LEN: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    extern "C" fn abi_probe_sync_host_call(
        _op: *const std::os::raw::c_char,
        _args_json: *const std::os::raw::c_char,
    ) -> *mut std::os::raw::c_char {
        ABI_PROBE_SYNC_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        host_call_response(r#"+{"bridge":"sync"}"#.to_string())
    }

    extern "C" fn abi_probe_async_host_call(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        _op: *const std::os::raw::c_char,
        _args_json: *const std::os::raw::c_char,
    ) {
        ABI_PROBE_ASYNC_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let payload = b"+{\"bridge\":\"async\"}\0";
        unsafe {
            ex_hermes_resolve_host_call(runtime, call_id, payload.as_ptr().cast());
        }
    }

    extern "C" fn abi_probe_exact_host_call(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        operation_id: u32,
        payload: *const u8,
        payload_len: usize,
        _context: *mut std::ffi::c_void,
    ) {
        EXACT_ABI_PROBE_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_OPERATION.store(operation_id as usize, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_PAYLOAD_LEN.store(payload_len, std::sync::atomic::Ordering::SeqCst);
        if payload_len > 0 {
            assert!(!payload.is_null());
            let bytes = unsafe { std::slice::from_raw_parts(payload, payload_len) };
            assert_eq!(bytes, [1, 2, 3]);
        }
        let response = [9_u8, 8_u8];
        unsafe {
            ex_hermes_resolve_exact_host_call(
                runtime,
                call_id,
                0,
                response.as_ptr(),
                response.len(),
            );
            // Completion IDs are single-use capabilities. A replay must be a
            // no-op and cannot replace the first result.
            let replay = [7_u8];
            ex_hermes_resolve_exact_host_call(runtime, call_id, 0, replay.as_ptr(), replay.len());
        }
    }

    extern "C" fn abi_probe_exact_malformed_completion(
        runtime: *mut HermesRuntimeOpaque,
        call_id: u64,
        _operation_id: u32,
        _payload: *const u8,
        _payload_len: usize,
        _context: *mut std::ffi::c_void,
    ) {
        unsafe {
            ex_hermes_resolve_exact_host_call(runtime, call_id, 0, std::ptr::null(), 1);
        }
    }

    extern "C" fn abi_probe_exact_pending_call(
        _runtime: *mut HermesRuntimeOpaque,
        _call_id: u64,
        _operation_id: u32,
        _payload: *const u8,
        _payload_len: usize,
        _context: *mut std::ffi::c_void,
    ) {
    }

    #[tokio::test(flavor = "current_thread")]
    async fn off_owner_runtime_handle_drop_is_fail_safe_and_owner_can_reclaim() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = HostResetGuard;
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let handle = RuntimeHandle::new(None).expect("diagnostic runtime");
        let shared = handle.shared();

        std::thread::spawn(move || {
            assert!(
                handle.with_runtime(|_| ()).is_err(),
                "runtime-thread FFI must reject a non-owner caller"
            );
            drop(handle);
        })
        .join()
        .unwrap();
        let raw = shared.raw.load(Ordering::SeqCst);
        assert!(
            !raw.is_null(),
            "off-owner drop must retain the runtime pointer for its owner"
        );

        assert_eq!(shared.shutdown(), RuntimeShutdown::Destroyed);
        assert_eq!(shared.shutdown(), RuntimeShutdown::NotLive);
        assert!(shared.raw.load(Ordering::SeqCst).is_null());
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_creation_requires_exact_installed_snapshot_digest() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();

        let error = match SharedRuntime::new(Some("sha256:wrong")) {
            Ok(_) => panic!("mismatched digest must reject Hermes allocation"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("handshake was rejected"));

        let diagnostic_error = match SharedRuntime::new(None) {
            Ok(_) => panic!("diagnostic creation must not consume an armed Host context"),
            Err(error) => error,
        };
        assert!(diagnostic_error
            .to_string()
            .contains("Failed to create Hermes runtime"));

        let runtime =
            SharedRuntime::new(Some(&digest)).expect("matching digest must create Hermes");
        assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_creation_refuses_every_injected_startup_failure() {
        struct ResetInjectedFailure;
        impl Drop for ResetInjectedFailure {
            fn drop(&mut self) {
                unsafe { ibex_test_set_armed_startup_failure_stage(std::ptr::null()) };
            }
        }

        let _lock = hermes_engine_test_lock().lock().await;
        let _reset_failure = ResetInjectedFailure;
        for stage in [
            "install-globals",
            "module-loader",
            "process-setup",
            "capability-hardening",
            "eager-install-seal",
            "lockdown",
            "compartment-registry",
        ] {
            // A runtime claim consumes its installed host context even when
            // startup subsequently refuses, so each injected construction gets
            // an independently installed context just like a fresh launch.
            let (_reset_host, digest) = install_armed_test_host();
            let stage = CString::new(stage).unwrap();
            unsafe { ibex_test_set_armed_startup_failure_stage(stage.as_ptr()) };
            assert!(
                SharedRuntime::new(Some(&digest)).is_err(),
                "armed runtime survived injected startup failure at {}",
                stage.to_string_lossy()
            );
        }
        unsafe { ibex_test_set_armed_startup_failure_stage(std::ptr::null()) };
        let (_reset_host, digest) = install_armed_test_host();
        let runtime = SharedRuntime::new(Some(&digest))
            .expect("clearing injection must restore armed runtime creation");
        assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_random_bytes_is_a_zero_decision_non_capability() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let typed_before = crate::host::abi::installed_typed_decision_count();
        let legacy_before = crate::host::abi::installed_legacy_authorization_check_count();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "surface.native.op.exactrandombytes.non-capability"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  var bytes = __exactRandomBytes(16);
                  return String(bytes instanceof Uint8Array) + '/' + String(bytes.byteLength);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("true/16"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "random bytes must not consult the legacy oracle"
        );
        assert!(
            typed.is_empty(),
            "random bytes must not emit a typed decision"
        );
        assert_eq!(
            crate::host::abi::installed_legacy_authorization_check_count() - legacy_before,
            0
        );
        assert_eq!(
            crate::host::abi::installed_typed_decision_count() - typed_before,
            0
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_network_release_calls_require_only_ownership() {
        let _lock = hermes_engine_test_lock().lock().await;
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let floor = serde_json::json!({
            "cap": "network:connect",
            "resource": {
                "kind": "connect-endpoint",
                "transport": "tcp",
                "host": {"kind": "ip", "address": "127.0.0.1"},
                "port": {"kind": "exact", "value": port},
                "peerClasses": ["loopback"],
                "route": {"kind": "direct"}
            }
        });
        let (_reset, digest) = install_armed_test_host_at(None, false, false, false, vec![floor]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let setup = engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                  globalThis.__releaseClose = __exactTcpConnect('127.0.0.1', {port});
                  globalThis.__releaseReset = __exactTcpConnect('127.0.0.1', {port});
                  globalThis.__releaseShutdown = __exactTcpConnect('127.0.0.1', {port});
                  return 'ready';
                }})()"#
            ))
            .await
            .unwrap();
        assert_eq!(setup.as_deref(), Some("ready"));

        let typed_before = crate::host::abi::installed_typed_decision_count();
        let legacy_before = crate::host::abi::installed_legacy_authorization_check_count();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "surface.native.op.network.authority-release"
        ));
        let released = engine
            .eval_immediate(
                r#"(function() {
                  __exactTcpClose(globalThis.__releaseClose);
                  __exactTcpReset(globalThis.__releaseReset);
                  __exactTcpClose(globalThis.__releaseReset);
                  __exactTcpShutdown(globalThis.__releaseShutdown, 1);
                  __exactTcpClose(globalThis.__releaseShutdown);
                  return 'released';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(released.as_deref(), Some("released"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "release must not consult the legacy oracle"
        );
        assert!(typed.is_empty(), "release must not emit a typed decision");
        assert_eq!(
            crate::host::abi::installed_legacy_authorization_check_count() - legacy_before,
            0
        );
        assert_eq!(
            crate::host::abi::installed_typed_decision_count() - typed_before,
            0
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_exact_memory_sqlite_is_a_zero_decision_non_capability() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let prefixed_uri = engine
            .eval_immediate(
                r#"(function() {
                  try { __exactSqliteOpen('file::memory:?cache=shared', null); }
                  catch (_) { return 'denied'; }
                  return 'allowed';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(
            prefixed_uri.as_deref(),
            Some("denied"),
            "a URI-looking disk filename must not inherit the :memory: exemption"
        );

        let typed_before = crate::host::abi::installed_typed_decision_count();
        let legacy_before = crate::host::abi::installed_legacy_authorization_check_count();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "surface.native.op.sqlite.memory.non-capability"
        ));
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  var db = __exactSqliteOpen(':memory:', null);
                  var inTransaction = __exactSqliteInTransaction(db);
                  __exactSqliteClose(db);
                  return typeof inTransaction + '/' + String(inTransaction);
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("boolean/false"));

        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "in-memory SQLite must not consult the legacy oracle"
        );
        assert!(
            typed.is_empty(),
            "in-memory SQLite must not emit a typed decision"
        );
        assert_eq!(
            crate::host::abi::installed_legacy_authorization_check_count() - legacy_before,
            0
        );
        assert_eq!(
            crate::host::abi::installed_typed_decision_count() - typed_before,
            0
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_host_call_abi_rejects_post_lockdown_install_and_resolution() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        ABI_PROBE_SYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        ABI_PROBE_ASYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);

        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        assert_eq!(
            engine
                .eval_immediate("typeof __hostCall + '/' + typeof __hostCallAsync")
                .await
                .unwrap()
                .as_deref(),
            Some("undefined/undefined")
        );

        // The setters are invoked after armed creation has completed its
        // structural lockdown checks. Both replacement attempts and a forged
        // async completion must be silent no-ops at the native ABI boundary.
        let runtime = engine.ensure_runtime().await.unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                ex_hermes_set_host_call(raw, abi_probe_sync_host_call);
                ex_hermes_set_host_call_async(raw, abi_probe_async_host_call);
                let payload = b"+{\"forged\":true}\0";
                ex_hermes_resolve_host_call(raw, u64::MAX, payload.as_ptr().cast());
            })
            .unwrap();

        assert_eq!(
            engine
                .eval_immediate("typeof __hostCall + '/' + typeof __hostCallAsync")
                .await
                .unwrap()
                .as_deref(),
            Some("undefined/undefined")
        );
        assert_eq!(
            ABI_PROBE_SYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            ABI_PROBE_ASYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_exact_embedder_ingress_is_binary_endowed_and_single_use() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_exact_test_host();
        EXACT_ABI_PROBE_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_OPERATION.store(0, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_PAYLOAD_LEN.store(0, std::sync::atomic::Ordering::SeqCst);

        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32, 11_u32];
        let manifest_digest =
            std::ffi::CString::new("sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEA").unwrap();
        let wrong_manifest_digest =
            std::ffi::CString::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        wrong_manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -8,
                    "an armed runtime must reject the wrong manifest before JSI mutation"
                );
                let narrowed = [7_u32];
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        narrowed.as_ptr(),
                        narrowed.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -8,
                    "an armed runtime must reject a caller-selected endowment"
                );
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    0
                );
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        manifest_digest.as_ptr(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -5,
                    "an embedder cannot replace an installed endowment"
                );
            })
            .unwrap();

        assert_eq!(
            engine
                .eval_immediate(
                    "typeof __hostCall + '/' + typeof __hostCallAsync + '/' + \
                     typeof exact.invokeHostAsync",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("undefined/undefined/function")
        );
        assert_eq!(
            engine
                .eval_immediate(
                    "globalThis.__exactTypedResult = 'pending'; \
                     exact.invokeHostAsync(7, new Uint8Array([1,2,3])).then(\
                       function(value) { globalThis.__exactTypedResult = Array.from(value).join(','); },\
                       function(error) { globalThis.__exactTypedResult = 'rejected:' + error.message; }); \
                     'kicked'",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("kicked")
        );
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            engine
                .eval_immediate("globalThis.__exactTypedResult")
                .await
                .unwrap()
                .as_deref(),
            Some("9,8")
        );
        assert_eq!(
            engine
                .eval_immediate(
                    "try { exact.invokeHostAsync(7, {}); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("exact.invokeHostAsync payload must be an ArrayBuffer or view")
        );
        assert_eq!(
            engine
                .eval_immediate(
                    "try { exact.invokeHostAsync(8, new Uint8Array()); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("exact.invokeHostAsync operation is not endowed")
        );
        assert_eq!(
            EXACT_ABI_PROBE_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            EXACT_ABI_PROBE_OPERATION.load(std::sync::atomic::Ordering::SeqCst),
            7
        );
        assert_eq!(
            EXACT_ABI_PROBE_PAYLOAD_LEN.load(std::sync::atomic::Ordering::SeqCst),
            3
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_embedder_ingress_finalizes_immutable_package_capability() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let _compartments = TestEnvVar::set("IBEX_COMPARTMENTS", "1");
        EXACT_ABI_PROBE_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);

        let engine = HermesEngine::new().unwrap();
        // Touch the native runtime without running the CLI finalizer. This is
        // the embedder posture: the compartment hook is pending until the
        // typed ingress becomes the last package-visible native capability.
        assert!(engine.runtime_bundle_installed().await.unwrap());
        assert_eq!(
            engine
                .eval_immediate(
                    "typeof __ibexRefreshCompartmentBaseline + '/' + \
                     __ibexCompartmentBaselineFinalized",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("function/false")
        );

        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32];
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    0
                );
            })
            .unwrap();

        assert_eq!(
            engine
                .eval_immediate(
                    r#"(function () {
                      var a = __compartments['alpha@1.0.0'];
                      var b = __compartments['beta@1.0.0'];
                      var original = a.exact.invokeHostAsync;
                      try { a.exact.invokeHostAsync = function () { return 'intercepted'; }; }
                      catch (_) {}
                      try { delete a.exact.invokeHostAsync; } catch (_) {}
                      var descriptor = Object.getOwnPropertyDescriptor(
                        a.exact, 'invokeHostAsync'
                      );
                      return JSON.stringify([
                        typeof __ibexRefreshCompartmentBaseline,
                        __ibexCompartmentBaselineFinalized,
                        typeof a.exact.invokeHostAsync,
                        original === b.exact.invokeHostAsync,
                        descriptor.writable,
                        descriptor.configurable,
                        descriptor.enumerable
                      ]);
                    })()"#,
                )
                .await
                .unwrap()
                .as_deref(),
            Some(r#"["undefined",true,"function",true,false,false,false]"#)
        );

        engine
            .eval_immediate(
                "globalThis.__exactPackageResult = 'pending'; \
                 __compartments['alpha@1.0.0'].exact.invokeHostAsync(\
                   7, new Uint8Array([1,2,3])\
                 ).then(function(value) { \
                   globalThis.__exactPackageResult = Array.from(value).join(','); \
                 });",
            )
            .await
            .unwrap();
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            engine
                .eval_immediate("globalThis.__exactPackageResult")
                .await
                .unwrap()
                .as_deref(),
            Some("9,8")
        );
        assert_eq!(
            EXACT_ABI_PROBE_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_embedder_ingress_rolls_back_when_package_finalization_fails() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let _compartments = TestEnvVar::set("IBEX_COMPARTMENTS", "1");

        let engine = HermesEngine::new().unwrap();
        assert!(engine.runtime_bundle_installed().await.unwrap());
        engine
            .eval_immediate("delete globalThis.__ibexRefreshCompartmentBaseline")
            .await
            .unwrap();

        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32];
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -6
                );
            })
            .unwrap();

        assert_eq!(
            engine
                .eval_immediate(
                    "typeof exact.invokeHostAsync + '/' + \
                     __ibexCompartmentBaselineFinalized",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("undefined/false")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_embedder_ingress_rejects_malformed_completion_and_pending_flood() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);

        let malformed_engine = HermesEngine::new().unwrap();
        malformed_engine.load_runtime().await.unwrap();
        let malformed_runtime = malformed_engine.ensure_runtime().await.unwrap();
        let operations = [7_u32];
        malformed_runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_malformed_completion,
                        std::ptr::null_mut(),
                    ),
                    0
                );
            })
            .unwrap();
        malformed_engine
            .eval_immediate(
                "globalThis.__exactMalformed = 'pending'; \
                 exact.invokeHostAsync(7, new Uint8Array()).then(\
                   function() { globalThis.__exactMalformed = 'resolved'; },\
                   function(error) { globalThis.__exactMalformed = error.message; });",
            )
            .await
            .unwrap();
        malformed_engine.drive_event_loop().await.unwrap();
        assert_eq!(
            malformed_engine
                .eval_immediate("globalThis.__exactMalformed")
                .await
                .unwrap()
                .as_deref(),
            Some("Exact host operation completion payload is invalid or exceeds 16 MiB")
        );
        drop(malformed_runtime);
        drop(malformed_engine);

        let flood_engine = HermesEngine::new().unwrap();
        flood_engine.load_runtime().await.unwrap();
        let flood_runtime = flood_engine.ensure_runtime().await.unwrap();
        flood_runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_pending_call,
                        std::ptr::null_mut(),
                    ),
                    0
                );
            })
            .unwrap();
        flood_engine
            .eval_immediate(
                "globalThis.__exactFlood = 'pending'; \
                 for (var i = 0; i < 1025; i += 1) { \
                   exact.invokeHostAsync(7, new Uint8Array()).catch(\
                     function(error) { globalThis.__exactFlood = error.message; }); \
                 }",
            )
            .await
            .unwrap();
        flood_engine.drive_event_loop().await.unwrap();
        assert_eq!(
            flood_engine
                .eval_immediate("globalThis.__exactFlood")
                .await
                .unwrap()
                .as_deref(),
            Some("exact.invokeHostAsync pending-call budget exhausted")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn diagnostic_exact_embedder_ingress_exercises_binary_completion() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        EXACT_ABI_PROBE_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_OPERATION.store(0, std::sync::atomic::Ordering::SeqCst);
        EXACT_ABI_PROBE_PAYLOAD_LEN.store(0, std::sync::atomic::Ordering::SeqCst);

        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        let operations = [7_u32, 11_u32];
        runtime
            .with_runtime(|raw| unsafe {
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        operations.as_ptr(),
                        operations.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    0
                );
            })
            .unwrap();

        assert_eq!(
            engine
                .eval_immediate(
                    "globalThis.__exactTypedResult = 'pending'; \
                     exact.invokeHostAsync(7, new Uint8Array([1,2,3])).then(\
                       function(value) { globalThis.__exactTypedResult = Array.from(value).join(','); },\
                       function(error) { globalThis.__exactTypedResult = 'rejected:' + error.message; }); \
                     'kicked'",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("kicked")
        );
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            engine
                .eval_immediate("globalThis.__exactTypedResult")
                .await
                .unwrap()
                .as_deref(),
            Some("9,8")
        );
        assert_eq!(
            engine
                .eval_immediate(
                    "try { exact.invokeHostAsync(7, new Uint8Array(16777217)); 'allowed' } \
                     catch (error) { error.message }",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("exact.invokeHostAsync payload exceeds 16 MiB")
        );
        assert_eq!(
            EXACT_ABI_PROBE_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            EXACT_ABI_PROBE_OPERATION.load(std::sync::atomic::Ordering::SeqCst),
            7
        );
        assert_eq!(
            EXACT_ABI_PROBE_PAYLOAD_LEN.load(std::sync::atomic::Ordering::SeqCst),
            3
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_embedder_ingress_rejects_noncanonical_endowments() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                let raw_address = raw as usize;
                let off_owner = std::thread::spawn(move || {
                    let valid = [19_u32];
                    ex_hermes_set_exact_host_call_async(
                        raw_address as *mut HermesRuntimeOpaque,
                        1,
                        valid.as_ptr(),
                        valid.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    )
                })
                .join()
                .unwrap();
                assert_eq!(off_owner, -7);
                let unsorted = [11_u32, 7_u32];
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        1,
                        unsorted.as_ptr(),
                        unsorted.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -4
                );
                let zero = [0_u32];
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        2,
                        zero.as_ptr(),
                        zero.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -4
                );
                let valid = [19_u32];
                assert_eq!(
                    ex_hermes_set_exact_host_call_async(
                        raw,
                        99,
                        valid.as_ptr(),
                        valid.len(),
                        std::ptr::null(),
                        abi_probe_exact_host_call,
                        std::ptr::null_mut(),
                    ),
                    -3
                );
            })
            .unwrap();
        assert_eq!(
            engine
                .eval_immediate("typeof exact.invokeHostAsync")
                .await
                .unwrap()
                .as_deref(),
            Some("undefined")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn diagnostic_host_call_abi_allows_replacement_and_async_resolution() {
        let _lock = hermes_engine_test_lock().lock().await;
        let _reset = install_test_host_with_allow(&[]);
        ABI_PROBE_SYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
        ABI_PROBE_ASYNC_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);

        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let runtime = engine.ensure_runtime().await.unwrap();
        runtime
            .with_runtime(|raw| unsafe {
                ex_hermes_set_host_call(raw, abi_probe_sync_host_call);
                ex_hermes_set_host_call_async(raw, abi_probe_async_host_call);
            })
            .unwrap();

        assert_eq!(
            engine
                .eval_immediate("JSON.stringify(__hostCall('abi.sync', {value: 1}))")
                .await
                .unwrap()
                .as_deref(),
            Some(r#"{"bridge":"sync"}"#)
        );
        assert_eq!(
            engine
                .eval_immediate(
                    "globalThis.__abiAsync = 'pending'; \
                     __hostCallAsync('abi.async', {}).then(\
                       function(value) { globalThis.__abiAsync = value.bridge; },\
                       function() { globalThis.__abiAsync = 'rejected'; }); \
                     'kicked'",
                )
                .await
                .unwrap()
                .as_deref(),
            Some("kicked")
        );
        engine.drive_event_loop().await.unwrap();
        assert_eq!(
            engine
                .eval_immediate("globalThis.__abiAsync")
                .await
                .unwrap()
                .as_deref(),
            Some("async")
        );
        assert_eq!(
            ABI_PROBE_SYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            ABI_PROBE_ASYNC_CALLS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn capsec_conformance_adapter_is_direct_and_not_a_public_bridge_route() {
        let _lock = hermes_engine_test_lock().lock().await;
        let floor = serde_json::json!({
            "cap": "sys:read",
            "resource": {"kind": "system-info", "name": "platform"}
        });
        let (_reset, _digest) = install_armed_test_host_at(None, false, false, false, vec![floor]);
        let decision = serde_json::json!({
            "decisionSetSchema": "ibex/capsec-decision-set/1",
            "operationId": "conformance-sys-read",
            "atomicityGroup": "surface.native.op.exactarch.0djy1vp.decision",
            "combination": "conjunction",
            "context": {
                "stage": "delivery",
                "actor": {"kind": "root", "identity": "project-root"},
                "constrainedPrincipals": [
                    {"kind": "root", "identity": "project-root"}
                ],
                "presentedHandleIds": []
            },
            "effects": [{
                "cap": "sys:read",
                "effectOwner": {"kind": "root", "identity": "project-root"},
                "resource": {
                    "kind": "system-info-occurrence",
                    "requested": {"kind": "system-info", "name": "platform"}
                }
            }]
        });
        let gates = serde_json::json!([{
            "coverageEdgeId": "surface.native.op.exactarch.0djy1vp",
            "targetCell": "complete",
            "definitionAndEdgePredicatesSatisfied": true
        }]);
        let request = serde_json::json!({
            "terminalBranchId": "enforcement.test.exactarch",
            "decisionSetJson": serde_json::to_string(&decision).unwrap(),
            "gatesJson": serde_json::to_string(&gates).unwrap()
        });
        let result: serde_json::Value = serde_json::from_str(
            &evaluate_capsec_conformance_adapter(&serde_json::to_string(&request).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(result["adapter"]["decision"]["outcome"], "allow");
        assert_eq!(result["typedObservations"].as_array().unwrap().len(), 1);
        assert_eq!(
            result["typedObservations"][0]["terminalBranchId"],
            "enforcement.test.exactarch"
        );
        assert_eq!(
            result["typedObservations"][0]["decisionSet"]["effects"][0]["cap"],
            "sys:read"
        );
        assert_eq!(result["legacyObservations"], serde_json::json!([]));

        let operation = CString::new("capsec.conformance.evaluate").unwrap();
        let request = CString::new(serde_json::to_string(&request).unwrap()).unwrap();
        let generic_result = unsafe {
            CString::from_raw(exact_agent_host_call(operation.as_ptr(), request.as_ptr()))
        };
        assert!(
            generic_result
                .to_string_lossy()
                .contains("Unknown host call"),
            "the diagnostic adapter must not be reachable through the generic bridge"
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn public_os_reads_reach_their_exact_typed_native_gates() {
        let _lock = hermes_engine_test_lock().lock().await;
        let floors = [
            "architecture",
            "cpus",
            "hostname",
            "load-average",
            "memory",
            "network-interfaces",
            "os-release",
            "platform",
            "storage-paths",
            "uptime",
            "user",
            "cwd",
        ]
        .into_iter()
        .map(|name| {
            serde_json::json!({
                "cap": "sys:read",
                "resource": {"kind": "system-info", "name": name}
            })
        })
        .collect();
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, floors, None, |snapshot| {
                snapshot["principals"][0]["imports"]["builtins"] = serde_json::json!(["node:os"]);
            });
        assert_ne!(crate::host::abi::install_host(host), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        assert!(
            ibex_runtime::host::abi::begin_installed_conformance_observation(
                "public.node-os.native-readers"
            )
        );
        let value = engine
            .eval_immediate(
                "var os = require('node:os'); JSON.stringify([\
                   os.platform(), os.arch(), os.type(), os.release(),\
                   os.homedir(), os.tmpdir(), os.hostname(), os.cpus().length,\
                   os.totalmem(), os.freemem(), os.uptime(), os.endianness(),\
                   Object.keys(os.networkInterfaces()).length, os.loadavg().length,\
                   os.version(), os.machine(), os.availableParallelism(),\
                   typeof os.userInfo().username, __exactGetProcessRSS(), __exactGetCwd()])",
            )
            .await
            .unwrap();
        assert!(value.is_some(), "public os calls must return normally");
        let (legacy, observed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        assert!(
            legacy.is_empty(),
            "rev2 paths must not consult the legacy plane"
        );
        assert_eq!(
            observed.len(),
            40,
            "twenty reads must authorize two stages each"
        );

        let expected = [
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "platform",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "architecture",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "platform",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "os-release",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "storage-paths",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "storage-paths",
            ),
            ("surface.native.op.exactgethostname.01gi6am", "hostname"),
            ("surface.native.op.exactgetcpucount.1k05aty", "cpus"),
            ("surface.native.op.exactgettotalmem.0ziuv9c", "memory"),
            ("surface.native.op.exactgetfreemem.0dytp7m", "memory"),
            ("surface.native.op.exactgetuptime.0ydqt27", "uptime"),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "architecture",
            ),
            (
                "surface.native.op.exactgetnetworkinterfaces.15q8n2j",
                "network-interfaces",
            ),
            ("surface.native.op.exactgetloadavg.10t3k2t", "load-average"),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "os-release",
            ),
            (
                "surface.native.op.exactauthorizesysteminfo.0ii7nrh",
                "architecture",
            ),
            ("surface.native.op.exactgetcpucount.1k05aty", "cpus"),
            ("surface.native.op.exactgetuserinfo.027b1gs", "user"),
            ("surface.native.op.exactgetprocessrss.0o50wgs", "memory"),
            ("surface.native.op.exactgetcwd.1bhagb7", "cwd"),
        ];
        for (index, (edge, name)) in expected.into_iter().enumerate() {
            let requested = &observed[index * 2];
            let committed = &observed[index * 2 + 1];
            assert_eq!(
                requested.terminal_branch_id,
                "public.node-os.native-readers"
            );
            assert_eq!(
                requested.decision_set.context.stage,
                capsec_semantics::model::Stage::Requested
            );
            assert_eq!(
                committed.decision_set.context.stage,
                capsec_semantics::model::Stage::Commit
            );
            for decision in [requested, committed] {
                assert_eq!(decision.gates.len(), 1);
                assert_eq!(decision.gates[0].coverage_edge_id.as_str(), edge);
                assert_eq!(decision.decision_set.effects[0].action.as_str(), "sys:read");
                assert_eq!(
                    serde_json::to_value(&decision.decision_set.effects[0].resource).unwrap()
                        ["requested"]["name"],
                    name
                );
                assert_eq!(
                    decision.evidence.outcome,
                    capsec_semantics::decision::DecisionOutcome::Allow
                );
            }
        }
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn public_os_read_denial_stops_before_commit_and_data_access() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, vec![], None, |snapshot| {
                snapshot["principals"][0]["imports"]["builtins"] = serde_json::json!(["node:os"]);
                snapshot["principals"][0]["denials"] = serde_json::json!([
                    {
                        "cap": "sys:read",
                        "resource": {"kind": "system-info", "name": "cpus"}
                    },
                    {
                        "cap": "sys:read",
                        "resource": {"kind": "system-info", "name": "memory"}
                    },
                    {
                        "cap": "sys:read",
                        "resource": {"kind": "system-info", "name": "cwd"}
                    }
                ]);
            });
        assert_ne!(crate::host::abi::install_host(host), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        assert!(
            ibex_runtime::host::abi::begin_installed_conformance_observation(
                "public.node-os.cpus.denied"
            )
        );
        let value = engine
            .eval_immediate(
                r#"(function() {
                    var os = require('node:os');
                    var calls = [
                      function() { return os.cpus(); },
                      function() { return __exactGetProcessRSS(); },
                      function() { return __exactGetCwd(); }
                    ];
                    var denied = 0;
                    for (var i = 0; i < calls.length; i++) {
                      try { calls[i](); }
                      catch (error) {
                        if (String(error && error.message || error).indexOf('Permission denied') !== -1) denied++;
                      }
                    }
                    return String(denied);
                })()"#,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(value, "3", "all public reads must deny before data access");
        let (legacy, observed) = ibex_runtime::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert_eq!(
            observed.len(),
            3,
            "each denial must stop before Commit and read"
        );
        assert!(observed.iter().all(|decision| {
            decision.decision_set.context.stage == capsec_semantics::model::Stage::Requested
                && decision.evidence.outcome == capsec_semantics::decision::DecisionOutcome::Deny
        }));
        assert_eq!(
            observed
                .iter()
                .map(|decision| decision.gates[0].coverage_edge_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "surface.native.op.exactgetcpucount.1k05aty",
                "surface.native.op.exactgetprocessrss.0o50wgs",
                "surface.native.op.exactgetcwd.1bhagb7",
            ]
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_equal_digest_runtimes_claim_their_exact_installed_host() {
        let _lock = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let first_path = root.join("first-context.txt");
        let second_path = root.join("second-context.txt");
        fs::write(&first_path, b"first").unwrap();
        fs::write(&second_path, b"second").unwrap();
        let (first, first_digest) =
            build_armed_test_host_at(Some(&root), false, false, false, vec![]);
        let (second, second_digest) =
            build_armed_test_host_at(Some(&root), false, false, false, vec![]);
        assert_eq!(first_digest, second_digest, "snapshots intentionally match");
        let first_observer = first.clone();
        let second_observer = second.clone();

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let spawn = |host: crate::host::Host,
                     digest: String,
                     path: std::path::PathBuf,
                     barrier: Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                assert_ne!(crate::host::abi::install_host(host), 0);
                // Both equal-digest Hosts are published before either runtime
                // claims one. Digest-based newest-match selection can now swap
                // them; the pending token must bind this thread's exact Host.
                barrier.wait();
                let runtime = SharedRuntime::new(Some(&digest)).expect("armed runtime");
                let source = format!(
                    "if (typeof __exactEnsureFs === 'function') __exactEnsureFs(); \
                     try {{ __exactReadFile({path:?}); 'ALLOWED' }} \
                     catch (_) {{ 'denied' }}",
                    path = path.to_str().unwrap(),
                );
                let value = runtime
                    .with_runtime(|raw| unsafe {
                        let source_url = CString::new("host-context-binding-test.js").unwrap();
                        let mut output = std::ptr::null_mut();
                        let status = ex_hermes_eval(
                            raw,
                            source.as_ptr(),
                            source.len(),
                            source_url.as_ptr(),
                            0,
                            &mut output,
                        );
                        let value = if output.is_null() {
                            String::new()
                        } else {
                            let value = CStr::from_ptr(output).to_string_lossy().into_owned();
                            ex_hermes_free_string(output);
                            value
                        };
                        (status, value)
                    })
                    .unwrap();
                assert_eq!(runtime.shutdown(), RuntimeShutdown::Destroyed);
                value
            })
        };

        let first_thread = spawn(
            first,
            first_digest.clone(),
            first_path,
            Arc::clone(&barrier),
        );
        let second_thread = spawn(second, second_digest, second_path, barrier);
        assert_eq!(first_thread.join().unwrap(), (0, "denied".into()));
        assert_eq!(second_thread.join().unwrap(), (0, "denied".into()));

        let first_evidence = serde_json::to_string(&first_observer.typed_evidence()).unwrap();
        let second_evidence = serde_json::to_string(&second_observer.typed_evidence()).unwrap();
        assert!(
            first_evidence.contains("first-context.txt")
                && !first_evidence.contains("second-context.txt"),
            "first runtime decisions must stay on its exact Host: {first_evidence}"
        );
        assert!(
            second_evidence.contains("second-context.txt")
                && !second_evidence.contains("first-context.txt"),
            "second runtime decisions must stay on its exact Host: {second_evidence}"
        );
        crate::host::abi::install_host(crate::host::Host::strict());
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_reauthenticates_exact_package_source_after_creation() {
        use std::os::unix::fs::MetadataExt;

        let _lock = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let package_root = root.join("node_modules/pkg");
        fs::create_dir_all(&package_root).unwrap();
        fs::write(
            package_root.join("package.json"),
            r#"{"name":"pkg","version":"1.0.0","main":"index.js"}"#,
        )
        .unwrap();
        let source = package_root.join("index.js");
        fs::write(&source, "module.exports = 'authenticated';\n").unwrap();
        let integrity = crate::module_loader::package_tree_integrity(&package_root).unwrap();
        let metadata = fs::metadata(&package_root).unwrap();
        let package_components = package_root
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(value) => Some(serde_json::json!({
                    "encoding": "utf8",
                    "value": value.to_str().unwrap(),
                })),
                _ => None,
            })
            .collect::<Vec<_>>();
        let principal = serde_json::json!({
            "kind": "package",
            "name": "pkg",
            "integrity": integrity,
            "locator": "pkg@1.0.0",
        });
        let principal_for_snapshot = principal.clone();
        let (host, digest) = build_armed_test_host_custom(
            Some(&root),
            false,
            false,
            false,
            vec![],
            None,
            move |value| {
                value["principals"][0]["imports"]["packages"] = serde_json::json!(["pkg@1.0.0"]);
                value["principals"][1]["principal"] = principal_for_snapshot.clone();
                value["packageGraph"]["nodes"][0]["principal"] = principal_for_snapshot.clone();
                value["packageGraph"]["importEdges"][0]["imported"] =
                    principal_for_snapshot.clone();
                value["rootBindings"][0] = serde_json::json!({
                    "logicalRoot": "package",
                    "owner": principal_for_snapshot,
                    "hostPath": {
                        "root": "absolute",
                        "components": package_components,
                        "hostBound": true,
                    },
                    "object": {
                        "platform": if cfg!(any(target_os = "macos", target_os = "ios")) {
                            "apple"
                        } else {
                            "unix"
                        },
                        "volume": format!("dev:{}", metadata.dev()),
                        "file": format!("ino:{}", metadata.ino()),
                    },
                });
            },
        );
        assert_ne!(crate::host::abi::install_host(host), 0);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        // The Host and Hermes runtime are already armed. Replacing source now
        // must invalidate the package principal before any replacement bytes
        // reach compilation/evaluation.
        fs::write(
            &source,
            "globalThis.__packageMutationExecuted = true; module.exports = 'mutated';\n",
        )
        .unwrap();
        let outcome = engine
            .eval_immediate(
                r#"(function() {
                  try { require('pkg'); return 'ALLOWED'; }
                  catch (_) { return String(globalThis.__packageMutationExecuted === true); }
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("false"));
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_process_environment_and_signal_surfaces_stay_closed() {
        let _lock = hermes_engine_test_lock().lock().await;
        let original_cwd = std::env::current_dir().unwrap();
        let target = std::env::temp_dir();
        let marker = target.join(format!("ibex-armed-spawn-marker-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let script = format!(
            r#"(function() {{
                var denied = 0;
                if (Object.keys(__exactGetAllEnv()).length === 0) denied++;
                try {{ __exactSetCwd({target:?}); }} catch (_) {{ denied++; }}
                try {{ process.kill(process.pid, 0); }} catch (_) {{ denied++; }}
                try {{ __exactExecSync('touch ' + {marker:?}, '{{}}'); }} catch (_) {{ denied++; }}
                try {{ __exactSpawnSync('/usr/bin/touch', JSON.stringify([{marker:?}]), '{{}}'); }} catch (_) {{ denied++; }}
                try {{ __exactSpawn('/usr/bin/touch', JSON.stringify([{marker:?}]), '{{}}'); }} catch (_) {{ denied++; }}
                return String(denied);
            }})()"#,
            target = target.to_str().unwrap(),
            marker = marker.to_str().unwrap(),
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("6"));
        assert_eq!(std::env::current_dir().unwrap(), original_cwd);
        assert!(!marker.exists());
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_environment_enumeration_closes_without_any_authorization_oracle() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let typed_before = crate::host::abi::installed_typed_decision_count();
        let legacy_before = crate::host::abi::installed_legacy_authorization_check_count();
        assert!(crate::host::abi::begin_installed_conformance_observation(
            "enforcement.test.environment-enumeration-closed"
        ));
        let outcome = engine
            .eval_immediate("String(Object.keys(__exactGetAllEnv()).length)")
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("0"));
        let (legacy, typed) = crate::host::abi::take_installed_conformance_observations();
        assert!(legacy.is_empty());
        assert!(typed.is_empty());
        assert_eq!(
            crate::host::abi::installed_typed_decision_count() - typed_before,
            0
        );
        assert_eq!(
            crate::host::abi::installed_legacy_authorization_check_count() - legacy_before,
            0
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_authority_bridge_rejects_forged_principals_and_unknown_ids() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let script = r#"(function() {
            var forgedActorDenied = false;
            try {
              Ibex.authority.mintHandle({
                actor: {
                  kind: 'package',
                  name: 'image-lib',
                  integrity: 'sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA',
                  locator: 'image-lib@2.4.1'
                },
                holder: {
                  kind: 'package',
                  name: 'image-lib',
                  integrity: 'sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA',
                  locator: 'image-lib@2.4.1'
                },
                authority: {
                  cap: 'fs:read',
                  resource: {
                    kind: 'path-tree',
                    path: {
                      root: 'project',
                      components: [{encoding: 'utf8', value: 'images'}]
                    }
                  }
                }
              });
            } catch (_) { forgedActorDenied = true; }
            var unknownBearerDenied = false;
            try { Ibex.authority.revokeHandle('h-forged-not-issued'); }
            catch (_) { unknownBearerDenied = true; }
            var forgedGrantDenied = false;
            try {
              Ibex.permissions.requestTyped({
                grantId: 'forged-package-grant',
                principal: {
                  kind: 'package',
                  name: 'image-lib',
                  integrity: 'sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA',
                  locator: 'image-lib@2.4.1'
                },
                authority: {
                  cap: 'device:location',
                  resource: {
                    kind: 'device-location',
                    usage: 'foreground',
                    precision: 'coarse'
                  }
                }
              });
            } catch (_) { forgedGrantDenied = true; }
            var unknownGrantDenied = false;
            try { Ibex.permissions.revokeTyped('forged-grant-not-issued'); }
            catch (_) { unknownGrantDenied = true; }
            return JSON.stringify([
              forgedActorDenied,
              unknownBearerDenied,
              forgedGrantDenied,
              unknownGrantDenied
            ]);
        })()"#;
        let outcome = engine.eval_immediate(script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("[true,true,true,true]"));
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_tcp_connect_commits_and_rechecks_the_actual_peer() {
        use std::io::Read;
        use std::net::TcpListener;

        let _lock = hermes_engine_test_lock().lock().await;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut chunk = [0u8; 3];
                stream.read_exact(&mut chunk).unwrap();
                bytes.extend(chunk);
            }
            bytes
        });
        let floor = serde_json::json!({
            "cap": "network:connect",
            "resource": {
                "kind": "connect-endpoint",
                "transport": "tcp",
                "host": {"kind": "ip", "address": "127.0.0.1"},
                "port": {"kind": "exact", "value": port},
                "peerClasses": ["loopback"],
                "route": {"kind": "direct"}
            }
        });
        let (_reset, digest) = install_armed_test_host_at(None, false, false, false, vec![floor]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let before = crate::host::abi::installed_typed_decision_count();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                var socket = __exactTcpConnect('127.0.0.1', {port});
                if (__exactTcpWrite(socket, 'x') !== 1) throw new Error('write');
                if (__exactTcpWrite(socket, 'x') !== 1) throw new Error('write');
                if (__exactTcpWrite(socket, 'x') !== 1) throw new Error('write');
                __exactTcpClose(socket);
                var pending = __exactTcpConnectStart('127.0.0.1', {port});
                var pendingDenied = false;
                try {{ __exactTcpWrite(pending, 'z'); }} catch (_) {{ pendingDenied = true; }}
                if (!pendingDenied) throw new Error('pending socket gained write authority');
                var connected = false;
                for (var attempt = 0; attempt < 10000; attempt++) {{
                  if (__exactTcpConnectPoll(pending) === 1) {{ connected = true; break; }}
                }}
                if (!connected) throw new Error('pending connect did not complete');
                if (__exactTcpWrite(pending, 'y') !== 1) throw new Error('pending write');
                if (__exactTcpWrite(pending, 'y') !== 1) throw new Error('pending write');
                if (__exactTcpWrite(pending, 'y') !== 1) throw new Error('pending write');
                __exactTcpClose(pending);
                var metadataDenied = false;
                try {{ __exactTcpConnect('169.254.169.254', 80); }} catch (_) {{ metadataDenied = true; }}
                if (!metadataDenied) throw new Error('metadata peer was reachable');
                var mappedDenied = false;
                try {{ __exactTcpConnect('::ffff:127.0.0.1', {port}); }}
                catch (error) {{
                  mappedDenied = String(error && error.message || error).indexOf('not canonical') !== -1;
                }}
                if (!mappedDenied) throw new Error('mapped TCP literal was not rejected canonically');
                return 'ok';
            }})()"#
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("ok"));
        assert_eq!(server.join().unwrap(), b"xxxyyy");
        let decisions = crate::host::abi::installed_typed_decision_count() - before;
        assert!(
            (8..=10).contains(&decisions),
            "unexpected full network decision count: {decisions}"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn dual_stack_listener_reports_ipv4_peer_in_canonical_form() {
        use std::net::TcpStream;

        let _lock = hermes_engine_test_lock().lock().await;
        // networkEndpointCapability("network:listen", "::", 0)
        let _reset = install_test_host_with_allow(&["network:listen::::0"]);
        let engine = HermesEngine::new().unwrap();
        let setup = engine
            .eval_immediate(
                r#"(function() {
                    if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                    try {
                      var listener = __exactTcpListen('::', 0, 1, 0, 0);
                      var local = JSON.parse(__exactTcpLocalAddr(listener));
                      globalThis.__dualStackListener = listener;
                      return JSON.stringify({port: local.port, family: local.family});
                    } catch (error) {
                      return JSON.stringify({error: String(error && error.message || error)});
                    }
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        let setup: serde_json::Value = serde_json::from_str(&setup).unwrap();
        if let Some(error) = setup.get("error").and_then(serde_json::Value::as_str) {
            let unsupported = [
                "Address family not supported",
                "Protocol not available",
                "Cannot assign requested address",
                "ai_family not supported",
            ]
            .iter()
            .any(|marker| error.contains(marker));
            assert!(
                unsupported,
                "dual-stack listener failed for a reason other than platform support: {error}"
            );
            return;
        }
        assert_eq!(setup["family"], "IPv6");
        let port = setup["port"].as_u64().unwrap() as u16;
        let client = TcpStream::connect(("127.0.0.1", port))
            .expect("IPv4 must connect to the explicitly dual-stack IPv6 listener");
        let remote = engine
            .eval_immediate(
                r#"(function() {
                    var accepted = -1;
                    for (var attempt = 0; attempt < 10000 && accepted < 0; attempt++) {
                      accepted = __exactTcpAccept(globalThis.__dualStackListener);
                    }
                    if (accepted < 0) throw new Error('dual-stack connection was not accepted');
                    var remote = JSON.parse(__exactTcpRemoteAddr(accepted));
                    __exactTcpClose(accepted);
                    __exactTcpClose(globalThis.__dualStackListener);
                    delete globalThis.__dualStackListener;
                    return JSON.stringify(remote);
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        drop(client);
        let remote: serde_json::Value = serde_json::from_str(&remote).unwrap();
        assert_eq!(remote["address"], "127.0.0.1");
        assert_eq!(remote["family"], "IPv4");
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_udp_send_authorizes_each_literal_datagram_peer() {
        use std::net::UdpSocket;

        let _lock = hermes_engine_test_lock().lock().await;
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let port = receiver.local_addr().unwrap().port();
        let floor = serde_json::json!({
            "cap": "network:connect",
            "resource": {
                "kind": "connect-endpoint",
                "transport": "udp",
                "host": {"kind": "ip", "address": "127.0.0.1"},
                "port": {"kind": "exact", "value": port},
                "peerClasses": ["loopback"],
                "route": {"kind": "direct"}
            }
        });
        let (_reset, digest) = install_armed_test_host_at(None, false, false, false, vec![floor]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                var socket = __exactUdpSocket('udp4');
                var bindDenied = false;
                try {{ __exactUdpBind(socket, '127.0.0.1', 0); }} catch (_) {{ bindDenied = true; }}
                if (!bindDenied) throw new Error('send authority yielded UDP listen authority');
                var mappedDenied = false;
                try {{ __exactUdpSend(socket, 'm', {port}, '::ffff:127.0.0.1'); }}
                catch (error) {{
                  mappedDenied = String(error && error.message || error).indexOf('not canonical') !== -1;
                }}
                if (!mappedDenied) throw new Error('mapped UDP literal was not rejected canonically');
                if (__exactUdpSend(socket, 'u', {port}, '127.0.0.1') !== 1) throw new Error('send');
                __exactUdpClose(socket);
                var metadataDenied = false;
                var deniedSocket = __exactUdpSocket('udp4');
                try {{ __exactUdpSend(deniedSocket, 'x', 80, '169.254.169.254'); }} catch (_) {{ metadataDenied = true; }}
                __exactUdpClose(deniedSocket);
                if (!metadataDenied) throw new Error('metadata datagram was allowed');
                return 'ok';
            }})()"#
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("ok"));
        let mut byte = [0u8; 1];
        let (amount, _) = receiver.recv_from(&mut byte).unwrap();
        assert_eq!((amount, byte[0]), (1, b'u'));
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_udp_repeat_lease_is_bounded_and_generation_checked() {
        use std::net::UdpSocket;

        let _lock = hermes_engine_test_lock().lock().await;
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let port = receiver.local_addr().unwrap().port();
        let udp_floor = serde_json::json!({
            "cap": "network:connect",
            "resource": {
                "kind": "connect-endpoint",
                "transport": "udp",
                "host": {"kind": "ip", "address": "127.0.0.1"},
                "port": {"kind": "exact", "value": port},
                "peerClasses": ["loopback"],
                "route": {"kind": "direct"}
            }
        });
        let unrelated_dynamic = serde_json::json!({
            "cap": "device:location",
            "resource": {
                "kind": "device-location",
                "usage": "foreground",
                "precision": "coarse"
            }
        });
        let (host, digest) = build_armed_test_host_control(
            None,
            false,
            false,
            false,
            vec![udp_floor],
            vec![unrelated_dynamic.clone()],
            true,
            0,
            None,
            |_| {},
        );
        let control = host.clone();
        let root = control.typed_principal_for_module("0").unwrap();
        let grant_id =
            capsec_semantics::model::NonEmptyString::new("udp-lease-generation").unwrap();
        let selector: capsec_semantics::model::AuthoritySelector =
            serde_json::from_value(unrelated_dynamic).unwrap();
        assert!(control
            .grant_typed_dynamic(grant_id.clone(), root, selector)
            .unwrap());
        assert_ne!(crate::host::abi::install_host(host), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let before = control.typed_decision_count();

        let first = engine
            .eval_immediate(&format!(
                r#"(function() {{
                    if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                    var socket = __exactUdpSocket('udp4');
                    for (var i = 0; i < 16; i++) {{
                      if (__exactUdpSend(socket, 'a', {port}, '127.0.0.1') !== 1) {{
                        throw new Error('first send batch');
                      }}
                    }}
                    globalThis.__udpLeaseSocket = socket;
                    return 'first';
                }})()"#
            ))
            .await
            .unwrap();
        assert_eq!(first.as_deref(), Some("first"));
        assert_eq!(
            control.typed_decision_count() - before,
            3,
            "sixteen identical datagrams must share one three-stage decision lease"
        );

        assert!(control.revoke_typed_dynamic(&grant_id).unwrap());
        let second = engine
            .eval_immediate(&format!(
                r#"(function() {{
                    for (var i = 0; i < 16; i++) {{
                      if (__exactUdpSend(globalThis.__udpLeaseSocket, 'b', {port}, '127.0.0.1') !== 1) {{
                        throw new Error('second send batch');
                      }}
                    }}
                    __exactUdpClose(globalThis.__udpLeaseSocket);
                    delete globalThis.__udpLeaseSocket;
                    return 'second';
                }})()"#
            ))
            .await
            .unwrap();
        assert_eq!(second.as_deref(), Some("second"));
        assert_eq!(
            control.typed_decision_count() - before,
            6,
            "revocation generation change must force exactly one lease renewal"
        );

        let mut received = [0u8; 32];
        for expected in received.iter_mut().take(16) {
            let mut byte = [0u8; 1];
            let (amount, _) = receiver.recv_from(&mut byte).unwrap();
            assert_eq!(amount, 1);
            *expected = byte[0];
        }
        for expected in received.iter_mut().skip(16) {
            let mut byte = [0u8; 1];
            let (amount, _) = receiver.recv_from(&mut byte).unwrap();
            assert_eq!(amount, 1);
            *expected = byte[0];
        }
        assert_eq!(&received[..16], &[b'a'; 16]);
        assert_eq!(&received[16..], &[b'b'; 16]);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_unported_network_surfaces_refuse_before_external_effects() {
        let _lock = hermes_engine_test_lock().lock().await;
        let (_reset, digest) = install_armed_test_host();
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let socket_path = std::env::temp_dir().join(format!(
            "ibex-capsec-closed-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                var denied = 0;
                try {{ __nativeFetch('http://127.0.0.1:9/', {{}}); }} catch (_) {{ denied++; }}
                try {{ __exactDnsLookup('localhost', 4); }} catch (_) {{ denied++; }}
                try {{ __exactWsConnect('ws://127.0.0.1:9/', '', {{}}); }} catch (_) {{ denied++; }}
                var nulUrlRejected = false;
                try {{ __exactWsConnect('ws://127.0.0.1:9/\u0000suffix', '', {{}}); }}
                catch (error) {{
                  nulUrlRejected = String(error && error.message || error).indexOf('ASCII control') !== -1;
                }}
                if (!nulUrlRejected) throw new Error('NUL-bearing WebSocket URL was not rejected');
                try {{ __exactTcpListen('127.0.0.1', 0, 1, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactHttpServe(0, '127.0.0.1'); }} catch (_) {{ denied++; }}
                try {{ __exactUnixConnect({socket_path:?}); }} catch (_) {{ denied++; }}
                try {{ __exactUnixListen({socket_path:?}, 1); }} catch (_) {{ denied++; }}
                var udp = __exactUdpSocket('udp4');
                try {{ __exactUdpBind(udp, '127.0.0.1', 0); }} catch (_) {{ denied++; }}
                __exactUdpClose(udp);
                return String(denied);
            }})()"#,
            socket_path = socket_path.to_str().unwrap(),
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("8"));
        assert!(!socket_path.exists());
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_fs_open_authorizes_create_truncate_and_repeated_write() {
        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-open-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let existing = root.join("existing.txt");
        let created = root.join("created.txt");
        let async_created = root.join("async-created.txt");
        let async_whole = root.join("async-whole.txt");
        let whole_created = root.join("whole-created.txt");
        let directory_created = root.join("created-directory");
        let async_directory_created = root.join("async-created-directory");
        std::fs::write(&existing, b"old contents").unwrap();
        let link = root.join("existing-link");
        std::os::unix::fs::symlink(&existing, &link).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                var existing = __exactFsOpen({existing:?}, 'w');
                __exactFsWrite(existing, 'new', -1);
                __exactFsClose(existing);
                var created = __exactFsOpen({created:?}, 'w+');
                __exactFsWrite(created, 'made', -1);
                JSON.parse(__exactFsFstatSync(created));
                __exactFsFtruncateSync(created, 2);
                __exactFsFsyncSync(created);
                __exactFsClose(created);
                var reread = __exactReadFile({existing:?});
                if (String.fromCharCode.apply(null, reread) !== 'new') throw new Error('readFile');
                if (!JSON.parse(__exactStat({existing:?})).is_file) throw new Error('stat');
                if (!JSON.parse(__exactLstat({link:?})).is_symlink) throw new Error('lstat');
                if (__exactRealpath({existing:?}) !== {existing:?}) throw new Error('realpath');
                if (JSON.parse(__exactReaddir({root:?})).indexOf('existing.txt') < 0) throw new Error('readdir');
                __exactWriteFile({existing:?}, 'whole');
                __exactAppendFile({existing:?}, '+tail');
                __exactWriteFile({whole_created:?}, 'fresh');
                __exactMkdir({directory_created:?}, false);
                return 'ok';
            }})()"#,
            existing = existing.to_str().unwrap(),
            created = created.to_str().unwrap(),
            root = root.to_str().unwrap(),
            link = link.to_str().unwrap(),
            whole_created = whole_created.to_str().unwrap(),
            directory_created = directory_created.to_str().unwrap(),
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();

        assert_eq!(outcome.as_deref(), Some("ok"));
        assert_eq!(std::fs::read(&existing).unwrap(), b"whole+tail");
        assert_eq!(std::fs::read(&created).unwrap(), b"ma");
        assert_eq!(std::fs::read(&whole_created).unwrap(), b"fresh");
        assert!(directory_created.is_dir());

        let async_mkdir_script = format!(
            r#"globalThis.__armedAsyncMkdir = 'pending';
               __exactFsPathAsync('mkdir', {path:?}, '', 0, 0, 0).then(function() {{
                 globalThis.__armedAsyncMkdir = 'ok';
               }}, function(error) {{
                 globalThis.__armedAsyncMkdir = 'error:' + error.message;
               }});"#,
            path = async_directory_created.to_str().unwrap(),
        );
        engine.eval_immediate(&async_mkdir_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_mkdir = engine
            .eval_immediate("globalThis.__armedAsyncMkdir")
            .await
            .unwrap();
        assert_eq!(async_mkdir.as_deref(), Some("ok"));
        assert!(async_directory_created.is_dir());

        let async_script = format!(
            r#"globalThis.__armedAsyncOpen = 'pending';
               __exactFsOpenAsync({path:?}, 'w+').then(function(fd) {{
                 __exactFsWrite(fd, 'async', -1);
                 return __exactFsFdAsync('fsync', fd, 0, 0).then(function() {{
                   return __exactFsStatAsync(fd, 'fstat');
                 }}).then(function() {{
                   __exactFsClose(fd);
                   globalThis.__armedAsyncOpen = 'ok';
                 }});
               }}, function(error) {{
                 globalThis.__armedAsyncOpen = 'error:' + error.message;
               }});"#,
            path = async_created.to_str().unwrap(),
        );
        engine.eval_immediate(&async_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_outcome = engine
            .eval_immediate("globalThis.__armedAsyncOpen")
            .await
            .unwrap();
        assert_eq!(async_outcome.as_deref(), Some("ok"));
        assert_eq!(std::fs::read(&async_created).unwrap(), b"async");
        let async_read_script = format!(
            r#"globalThis.__armedAsyncRead = 'pending';
               __exactFsReadFileAsync({path:?}, 'r', 0).then(function(bytes) {{
                 globalThis.__armedAsyncRead = String.fromCharCode.apply(null, bytes);
               }}, function(error) {{
                 globalThis.__armedAsyncRead = 'error:' + error.message;
               }});"#,
            path = existing.to_str().unwrap(),
        );
        engine.eval_immediate(&async_read_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_read = engine
            .eval_immediate("globalThis.__armedAsyncRead")
            .await
            .unwrap();
        assert_eq!(async_read.as_deref(), Some("whole+tail"));
        let async_stat_script = format!(
            r#"globalThis.__armedAsyncStat = 'pending';
               __exactFsStatAsync({path:?}, 'stat').then(function(json) {{
                 globalThis.__armedAsyncStat = String(JSON.parse(json).is_file);
               }}, function(error) {{
                 globalThis.__armedAsyncStat = 'error:' + error.message;
               }});"#,
            path = existing.to_str().unwrap(),
        );
        engine.eval_immediate(&async_stat_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_stat = engine
            .eval_immediate("globalThis.__armedAsyncStat")
            .await
            .unwrap();
        assert_eq!(async_stat.as_deref(), Some("true"));
        let async_lstat_script = format!(
            r#"globalThis.__armedAsyncLstat = 'pending';
               __exactFsStatAsync({path:?}, 'lstat').then(function(json) {{
                 globalThis.__armedAsyncLstat = String(JSON.parse(json).is_symlink);
               }}, function(error) {{
                 globalThis.__armedAsyncLstat = 'error:' + error.message;
               }});"#,
            path = link.to_str().unwrap(),
        );
        engine.eval_immediate(&async_lstat_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_lstat = engine
            .eval_immediate("globalThis.__armedAsyncLstat")
            .await
            .unwrap();
        assert_eq!(async_lstat.as_deref(), Some("true"));
        let async_write_script = format!(
            r#"globalThis.__armedAsyncWrite = 'pending';
               __exactFsWriteFileAsync({path:?}, 'worker', 'w', 438, true).then(function() {{
                 globalThis.__armedAsyncWrite = 'ok';
               }}, function(error) {{
                 globalThis.__armedAsyncWrite = 'error:' + error.message;
               }});"#,
            path = async_whole.to_str().unwrap(),
        );
        engine.eval_immediate(&async_write_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_write = engine
            .eval_immediate("globalThis.__armedAsyncWrite")
            .await
            .unwrap();
        assert_eq!(async_write.as_deref(), Some("ok"));
        assert_eq!(std::fs::read(&async_whole).unwrap(), b"worker");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_large_reads_use_generation_checked_descriptor_leases() {
        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-large-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let large = root.join("large.bin");
        std::fs::write(&large, vec![0x5a; 4 * 1024 * 1024]).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let before = crate::host::abi::installed_typed_decision_count();
        for expected in ["first", "second"] {
            let script = format!(
                r#"(function() {{
                    if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                    var bytes = __exactReadFile({path:?});
                    if (bytes.length !== 4194304 || bytes[0] !== 90 || bytes[4194303] !== 90) {{
                      throw new Error('large read mismatch');
                    }}
                    return {expected:?};
                }})()"#,
                path = large.to_str().unwrap(),
            );
            let outcome = engine.eval_immediate(&script).await.unwrap();
            assert_eq!(outcome.as_deref(), Some(expected));
        }
        let decisions = crate::host::abi::installed_typed_decision_count() - before;
        // Each descriptor performs four full decisions: requested, discovery,
        // commit, and the first repeat. The remaining chunks recheck only the
        // three authority generations, and the lease does not survive into
        // the second descriptor operation.
        assert_eq!(
            decisions, 8,
            "two 4 MiB reads performed an unexpected number of full decisions"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_read_stops_after_dynamic_authority_is_revoked_mid_stream() {
        use std::os::unix::fs::MetadataExt;

        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-revoked-read-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let large = root.join("large.bin");
        let file = std::fs::File::create(&large).unwrap();
        file.set_len(128 * 1024 * 1024).unwrap();
        drop(file);
        let package = root.join("node_modules/image-lib");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
        )
        .unwrap();
        std::fs::write(
            package.join("index.js"),
            r#"module.exports = function(path) {
                try { require('node:fs').readFileSync(path); return 'completed'; }
                catch (error) { return String(error && error.message || error); }
            };"#,
        )
        .unwrap();
        let entry = root.join("app.js");
        std::fs::write(
            &entry,
            format!(
                "globalThis.__revokedReadOutcome = require('image-lib')({:?});\n",
                large.to_str().unwrap()
            ),
        )
        .unwrap();
        struct RestoreCwd(std::path::PathBuf);
        impl Drop for RestoreCwd {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.0);
            }
        }
        let cwd = RestoreCwd(std::env::current_dir().unwrap());
        std::env::set_current_dir(&root).unwrap();

        let read_authority = serde_json::json!({
            "cap":"fs:read",
            "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
        });
        let integrity = crate::module_loader::package_tree_integrity(&package).unwrap();
        let principal: capsec_semantics::model::Principal =
            serde_json::from_value(serde_json::json!({
                "kind":"package",
                "name":"image-lib",
                "integrity": integrity,
                "locator":"image-lib@2.4.1"
            }))
            .unwrap();
        let package_components = package
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(value) => Some(serde_json::json!({
                    "encoding": "utf8",
                    "value": value.to_str().unwrap(),
                })),
                _ => None,
            })
            .collect::<Vec<_>>();
        let package_metadata = std::fs::metadata(&package).unwrap();
        let principal_for_snapshot = serde_json::to_value(&principal).unwrap();
        let (host, digest) = build_armed_test_host_control(
            Some(&root),
            false,
            false,
            true,
            Vec::new(),
            vec![read_authority.clone()],
            false,
            1,
            None,
            move |value| {
                value["principals"][1]["principal"] = principal_for_snapshot.clone();
                value["packageGraph"]["nodes"][0]["principal"] = principal_for_snapshot.clone();
                value["packageGraph"]["importEdges"][0]["imported"] =
                    principal_for_snapshot.clone();
                value["rootBindings"][0] = serde_json::json!({
                    "logicalRoot": "package",
                    "owner": principal_for_snapshot,
                    "hostPath": {
                        "root": "absolute",
                        "components": package_components,
                        "hostBound": true,
                    },
                    "object": {
                        "platform": if cfg!(any(target_os = "macos", target_os = "ios")) {
                            "apple"
                        } else {
                            "unix"
                        },
                        "volume": format!("dev:{}", package_metadata.dev()),
                        "file": format!("ino:{}", package_metadata.ino()),
                    },
                });
            },
        );
        assert_ne!(
            crate::host::abi::install_host(host.clone()),
            0,
            "test Host context token allocation"
        );
        let _reset = HostResetGuard;
        let selector: capsec_semantics::model::AuthoritySelector =
            serde_json::from_value(read_authority).unwrap();
        let grant_id = capsec_semantics::model::NonEmptyString::new("stream-read-grant").unwrap();
        assert!(host
            .grant_typed_dynamic(grant_id.clone(), principal, selector)
            .unwrap());
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();
        let before = host.typed_decision_count();
        let control = host.clone();
        let revoked_id = grant_id.clone();
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let revoker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            // Wait through request/discovery/commit and the first repeat. The
            // read lease then covers chunks only while authority generations
            // remain unchanged, so revocation must stop a later chunk.
            while control.typed_decision_count() < before + 5 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "read never reached its first repeat decision"
                );
                std::thread::yield_now();
            }
            let revoked = control.revoke_typed_dynamic(&revoked_id).unwrap();
            sent.send(revoked).unwrap();
        });
        engine.run_file(entry.to_str().unwrap()).await.unwrap();
        let outcome = engine
            .eval_immediate("globalThis.__revokedReadOutcome")
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(
            received
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap(),
            "dynamic read grant was not revoked"
        );
        revoker.join().unwrap();
        assert!(
            outcome.to_ascii_lowercase().contains("permission denied"),
            "read continued after authority revocation: {outcome}"
        );
        assert!(host.typed_decision_count() >= before + 6);
        drop(cwd);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_fs_open_denial_cannot_truncate_or_create() {
        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-open-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let existing = root.join("existing.txt");
        let absent = root.join("absent.txt");
        let absent_directory = root.join("absent-directory");
        let async_absent_directory = root.join("async-absent-directory");
        let retained_directory = root.join("retained-directory");
        let renamed = root.join("renamed.txt");
        let copied = root.join("copied.txt");
        let symlinked = root.join("symlinked.txt");
        let hard_linked = root.join("hard-linked.txt");
        std::fs::write(&existing, b"must survive").unwrap();
        std::fs::create_dir(&retained_directory).unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                var denied = 0;
                try {{ __exactFsOpen({existing:?}, 'w'); }} catch (_) {{ denied++; }}
                try {{ __exactFsOpen({absent:?}, 'w'); }} catch (_) {{ denied++; }}
                try {{ __exactReadFile({existing:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsReadFileAsync({existing:?}, 'r', 0); }} catch (_) {{ denied++; }}
                try {{ __exactWriteFile({existing:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactWriteFile({absent:?}, 'created'); }} catch (_) {{ denied++; }}
                try {{ __exactAppendFile({existing:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactAppendFile({absent:?}, 'created'); }} catch (_) {{ denied++; }}
                try {{ __exactFsWriteFileAsync({absent:?}, 'created', 'w', 438, true); }} catch (_) {{ denied++; }}
                try {{ __exactMkdir({absent_directory:?}, false); }} catch (_) {{ denied++; }}
                try {{ __exactUnlink({existing:?}); }} catch (_) {{ denied++; }}
                try {{ __exactRmdir({retained_directory:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('unlink', {existing:?}, '', 0, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('rmdir', {retained_directory:?}, '', 0, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactRename({existing:?}, {renamed:?}); }} catch (_) {{ denied++; }}
                try {{ __exactCopyFile({existing:?}, {copied:?}); }} catch (_) {{ denied++; }}
                try {{ __exactSymlink({existing:?}, {symlinked:?}); }} catch (_) {{ denied++; }}
                try {{ __exactLink({existing:?}, {hard_linked:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('rename', {existing:?}, {renamed:?}, 0, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('copyfile', {existing:?}, {copied:?}, 0, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('symlink', {existing:?}, {symlinked:?}, 0, 0, 0); }} catch (_) {{ denied++; }}
                try {{ __exactFsPathAsync('link', {existing:?}, {hard_linked:?}, 0, 0, 0); }} catch (_) {{ denied++; }}
                return String(denied);
            }})()"#,
            existing = existing.to_str().unwrap(),
            absent = absent.to_str().unwrap(),
            absent_directory = absent_directory.to_str().unwrap(),
            retained_directory = retained_directory.to_str().unwrap(),
            renamed = renamed.to_str().unwrap(),
            copied = copied.to_str().unwrap(),
            symlinked = symlinked.to_str().unwrap(),
            hard_linked = hard_linked.to_str().unwrap(),
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();

        assert_eq!(outcome.as_deref(), Some("22"));
        assert_eq!(std::fs::read(&existing).unwrap(), b"must survive");
        assert!(!absent.exists());
        assert!(!absent_directory.exists());
        assert!(retained_directory.is_dir());
        assert!(!renamed.exists());
        assert!(!copied.exists());
        assert!(!symlinked.exists());
        assert!(!hard_linked.exists());

        let async_open_script = format!(
            r#"globalThis.__armedDeniedAsyncOpen = 'pending';
               var denied = 0;
               Promise.all([
                 __exactFsOpenAsync({existing:?}, 'w').then(function() {{
                   throw new Error('existing async open unexpectedly allowed');
                 }}, function() {{ denied++; }}),
                 __exactFsOpenAsync({absent:?}, 'w').then(function() {{
                   throw new Error('absent async open unexpectedly allowed');
                 }}, function() {{ denied++; }})
               ]).then(function() {{
                 globalThis.__armedDeniedAsyncOpen = String(denied);
               }}, function(error) {{
                 globalThis.__armedDeniedAsyncOpen = 'error:' + error.message;
               }});"#,
            existing = existing.to_str().unwrap(),
            absent = absent.to_str().unwrap(),
        );
        engine.eval_immediate(&async_open_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_open_outcome = engine
            .eval_immediate("globalThis.__armedDeniedAsyncOpen")
            .await
            .unwrap();
        assert_eq!(async_open_outcome.as_deref(), Some("2"));
        assert_eq!(std::fs::read(&existing).unwrap(), b"must survive");
        assert!(!absent.exists());

        let async_script = format!(
            r#"globalThis.__armedDeniedAsyncMkdir = 'pending';
               __exactFsPathAsync('mkdir', {path:?}, '', 0, 0, 0).then(function() {{
                 globalThis.__armedDeniedAsyncMkdir = 'unexpected-allow';
               }}, function() {{
                 globalThis.__armedDeniedAsyncMkdir = 'denied';
               }});"#,
            path = async_absent_directory.to_str().unwrap(),
        );
        engine.eval_immediate(&async_script).await.unwrap();
        engine.drive_event_loop().await.unwrap();
        let async_outcome = engine
            .eval_immediate("globalThis.__armedDeniedAsyncMkdir")
            .await
            .unwrap();
        assert_eq!(async_outcome.as_deref(), Some("denied"));
        assert!(!async_absent_directory.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_create_rollback_never_unlinks_a_racing_creator() {
        struct TestEnvironment;
        impl Drop for TestEnvironment {
            fn drop(&mut self) {
                std::env::remove_var("IBEX_TEST_ARMED_CREATE_PAUSE_MS");
                std::env::remove_var("IBEX_TEST_ARMED_DENY_OPEN_COMMIT");
            }
        }

        let _lock = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let target = root.join("raced-create.txt");
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, false, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        // Pause after the bridge observes absence, let an independent creator
        // publish the name, then force the post-open commit to deny. A racy
        // precheck implementation marks the competitor's object as "created"
        // and unlinks it during rollback; O_EXCL ownership must not.
        std::env::set_var("IBEX_TEST_ARMED_CREATE_PAUSE_MS", "250");
        std::env::set_var("IBEX_TEST_ARMED_DENY_OPEN_COMMIT", "1");
        let _environment = TestEnvironment;
        let competitor_target = target.clone();
        let competitor = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            fs::write(competitor_target, b"competitor-owned").unwrap();
        });

        let outcome = engine
            .eval_immediate(&format!(
                "if (typeof __exactEnsureFs === 'function') __exactEnsureFs(); \
                 try {{ __exactFsOpen({path:?}, 'w'); 'ALLOWED' }} \
                 catch (_) {{ 'denied' }}",
                path = target.to_str().unwrap(),
            ))
            .await
            .unwrap();
        competitor.join().unwrap();

        assert_eq!(outcome.as_deref(), Some("denied"));
        assert_eq!(fs::read(&target).unwrap(), b"competitor-owned");
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn all_protected_roles_deny_write_unlink_rename_and_replace_before_mutation() {
        use std::os::unix::fs::MetadataExt;

        let _lock = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let roles = ["armed-policy", "engine-binary", "package-graph", "registry"];
        let mut paths = Vec::new();
        let mut protected = Vec::new();
        for role in roles {
            let path = root.join(format!("{role}.artifact"));
            fs::write(&path, format!("original:{role}")).unwrap();
            fs::write(
                root.join(format!("{role}.artifact.replacement")),
                format!("replacement:{role}"),
            )
            .unwrap();
            let metadata = fs::metadata(&path).unwrap();
            protected.push(serde_json::json!({
                "role": role,
                "object": {
                    "platform": if cfg!(any(target_os = "macos", target_os = "ios")) {
                        "apple"
                    } else {
                        "unix"
                    },
                    "volume": format!("dev:{}", metadata.dev()),
                    "file": format!("ino:{}", metadata.ino()),
                },
                "deniedActions": ["fs:write"],
            }));
            paths.push(path);
        }
        let (host, digest) = build_armed_test_host_at_with_protected(
            Some(&root),
            true,
            true,
            true,
            vec![],
            Some(protected),
        );
        assert_ne!(crate::host::abi::install_host(host), 0);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let js_paths = serde_json::to_string(
            &paths
                .iter()
                .map(|path| path.to_str().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let outcome = engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  var paths = {js_paths};
                  var denied = 0;
                  for (var i = 0; i < paths.length; i++) {{
                    var path = paths[i];
                    try {{ __exactWriteFile(path, 'mutated'); }} catch (_) {{ denied++; }}
                    try {{ __exactUnlink(path); }} catch (_) {{ denied++; }}
                    try {{ __exactRename(path, path + '.moved'); }} catch (_) {{ denied++; }}
                    try {{ __exactRename(path + '.replacement', path); }} catch (_) {{ denied++; }}
                  }}
                  return String(denied);
                }})()"#,
            ))
            .await
            .unwrap();
        assert_eq!(outcome.as_deref(), Some("16"));
        for (role, path) in roles.into_iter().zip(paths) {
            assert_eq!(
                fs::read(&path).unwrap(),
                format!("original:{role}").as_bytes()
            );
            assert!(!path.with_extension("artifact.moved").exists());
            assert_eq!(
                fs::read(format!("{}.replacement", path.display())).unwrap(),
                format!("replacement:{role}").as_bytes()
            );
        }
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_fs_list_denial_prevents_metadata_and_directory_disclosure() {
        let _lock = hermes_engine_test_lock().lock().await;
        let root = std::env::temp_dir().join(format!(
            "ibex-capsec-list-deny-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let directory = root.join("directory");
        std::fs::create_dir_all(&directory).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let directory = root.join("directory");
        let file = directory.join("secret.txt");
        std::fs::write(&file, b"secret").unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, true, false, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                var denied = 0;
                try {{ __exactStat({file:?}); }} catch (_) {{ denied++; }}
                try {{ __exactReaddir({directory:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsStatAsync({file:?}, 'stat'); }} catch (_) {{ denied++; }}
                try {{ __exactRealpath({file:?}); }} catch (_) {{ denied++; }}
                try {{ __exactLstat({file:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsStatAsync({file:?}, 'lstat'); }} catch (_) {{ denied++; }}
                return String(denied);
            }})()"#,
            file = file.to_str().unwrap(),
            directory = directory.to_str().unwrap(),
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();

        assert_eq!(outcome.as_deref(), Some("6"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_fs_open_rejects_parent_and_final_symlink_escape() {
        use std::os::unix::fs::symlink;

        let _lock = hermes_engine_test_lock().lock().await;
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let root = std::env::temp_dir().join(format!("ibex-capsec-symlink-root-{nonce}"));
        let outside = std::env::temp_dir().join(format!("ibex-capsec-symlink-outside-{nonce}"));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let outside = std::fs::canonicalize(outside).unwrap();
        let outside_file = outside.join("protected.txt");
        std::fs::write(&outside_file, b"outside").unwrap();
        symlink(&outside, root.join("parent-link")).unwrap();
        symlink(&outside_file, root.join("final-link")).unwrap();
        let parent_escape = root.join("parent-link/protected.txt");
        let final_escape = root.join("final-link");
        let (_reset, digest) = install_armed_test_host_at(Some(&root), true, true, true, vec![]);
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                var denied = 0;
                try {{ __exactFsOpen({parent_escape:?}, 'w'); }} catch (_) {{ denied++; }}
                try {{ __exactFsOpen({final_escape:?}, 'w'); }} catch (_) {{ denied++; }}
                try {{ __exactReadFile({parent_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactReadFile({final_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactFsReadFileAsync({parent_escape:?}, 'r', 0); }} catch (_) {{ denied++; }}
                try {{ __exactFsReadFileAsync({final_escape:?}, 'r', 0); }} catch (_) {{ denied++; }}
                try {{ __exactStat({final_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactReaddir({parent_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactWriteFile({parent_escape:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactWriteFile({final_escape:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactAppendFile({parent_escape:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactAppendFile({final_escape:?}, 'lost'); }} catch (_) {{ denied++; }}
                try {{ __exactFsWriteFileAsync({parent_escape:?}, 'lost', 'w', 438, true); }} catch (_) {{ denied++; }}
                try {{ __exactFsWriteFileAsync({final_escape:?}, 'lost', 'w', 438, true); }} catch (_) {{ denied++; }}
                try {{ __exactFsStatAsync({parent_escape:?}, 'stat'); }} catch (_) {{ denied++; }}
                try {{ __exactFsStatAsync({final_escape:?}, 'stat'); }} catch (_) {{ denied++; }}
                try {{ __exactRealpath({parent_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactRealpath({final_escape:?}); }} catch (_) {{ denied++; }}
                try {{ __exactLstat({parent_escape:?}); }} catch (_) {{ denied++; }}
                if (!JSON.parse(__exactLstat({final_escape:?})).is_symlink) throw new Error('lstat-link');
                return String(denied);
            }})()"#,
            parent_escape = parent_escape.to_str().unwrap(),
            final_escape = final_escape.to_str().unwrap(),
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();

        assert_eq!(outcome.as_deref(), Some("19"));
        assert_eq!(std::fs::read(&outside_file).unwrap(), b"outside");
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_installs_typed_dynamic_permission_bridge() {
        let _lock = hermes_engine_test_lock().lock().await;
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();
        let result = engine
            .eval_immediate(
                "JSON.stringify([typeof Ibex.permissions.requestTyped, typeof Ibex.permissions.revokeTyped, typeof Ibex.authority.mintHandle, typeof Ibex.authority.revokeHandle])",
            )
            .await
            .unwrap();
        assert_eq!(
            result.as_deref(),
            Some("[\"function\",\"function\",\"function\",\"function\"]")
        );

        let malformed = engine
            .eval_immediate(
                "try { Ibex.permissions.requestTyped('fs:read:/tmp'); 'missed' } catch (e) { e.name }",
            )
            .await
            .unwrap();
        assert_eq!(malformed.as_deref(), Some("TypeError"));

        let malformed_handle = engine
            .eval_immediate(
                "try { Ibex.authority.mintHandle('fs:read:/tmp'); 'missed' } catch (e) { e.name }",
            )
            .await
            .unwrap();
        assert_eq!(malformed_handle.as_deref(), Some("TypeError"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retained_sqlite_statements_reuse_generation_checked_authorization() {
        let _lock = hermes_engine_test_lock().lock().await;
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("retained.sqlite");
        let database = database.to_str().unwrap();
        let fs_read = format!("fs:read:{database}");
        let fs_write = format!("fs:write:{database}");
        let _reset = install_test_host_with_allow(&["sqlite:write", &fs_read, &fs_write]);
        let engine = HermesEngine::new().unwrap();
        let before = crate::host::abi::installed_legacy_authorization_check_count();
        let script = format!(
            r#"(function() {{
                    if (typeof __exactEnsureSqlite === 'function') __exactEnsureSqlite();
                    var db = __exactSqliteOpen({database:?}, null);
                    __exactSqliteExec(db, 'CREATE TABLE t (n INTEGER)', null);
                    var prepared = __exactSqlitePrepare(db, 'INSERT INTO t VALUES (?)');
                    for (var i = 0; i < 256; i++) {{
                      __exactSqliteRun(prepared.handle, [i]);
                    }}
                    __exactSqliteFinalize(prepared.handle);
                    var query = __exactSqlitePrepare(db, 'SELECT count(*) AS n FROM t');
                    var result = __exactSqliteGet(query.handle, null);
                    __exactSqliteFinalize(query.handle);
                    __exactSqliteClose(db);
                    return String(result.row.n);
                }})()"#
        );
        let outcome = engine.eval_immediate(&script).await.unwrap();
        assert_eq!(outcome.as_deref(), Some("256"));
        let checks = crate::host::abi::installed_legacy_authorization_check_count() - before;
        assert!(
            (1..=3).contains(&checks),
            "259 retained SQLite operations performed {checks} full capability decisions"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn load_runtime_finalizes_preinstalled_compartment_baseline() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _lockdown_disabled = TestEnvVar::remove("IBEX_LOCKDOWN");
        let _compartments_disabled = TestEnvVar::remove("IBEX_COMPARTMENTS");
        let compartments_enabled = TestEnvVar::set("IBEX_COMPARTMENTS", "1");
        let engine = HermesEngine::new().unwrap();

        // HermesEngine::new is lazy; keep the flag set through the first native
        // runtime touch so C++ installs the compartment handshake.
        assert!(engine.runtime_bundle_installed().await.unwrap());
        // Mode selection belongs to native runtime creation. Removing the env
        // flag afterwards must not make Rust skip the already-installed hook.
        let pending = engine
            .eval_immediate(
                r#"JSON.stringify([
                  globalThis.__ibexCompartmentRegistryReady === true,
                  typeof globalThis.__ibexRefreshCompartmentBaseline,
                  typeof globalThis.__compartments,
                  globalThis.__ibexCompartmentBaselineFinalized
                ])"#,
            )
            .await
            .unwrap();
        assert_eq!(
            pending.as_deref(),
            Some(r#"[true,"function","object",false]"#)
        );
        drop(compartments_enabled);

        engine.load_runtime().await.unwrap();
        // Exercise the actual finalizer again, as Runtime::load_runtime does on
        // every Windows call instead of taking HermesEngine's loaded fast path.
        finalize_compartment_baseline(&engine).await.unwrap();
        // A second call takes the runtime_loaded fast path and must not require
        // the deliberately deleted one-shot hook again.
        engine.load_runtime().await.unwrap();

        let state = engine
            .eval_immediate(
                r#"JSON.stringify([
                  globalThis.__ibexCompartmentRegistryReady === true,
                  typeof globalThis.__ibexRefreshCompartmentBaseline,
                  typeof globalThis.__compartments,
                  globalThis.__ibexCompartmentBaselineFinalized
                ])"#,
            )
            .await
            .unwrap();
        assert_eq!(
            state.as_deref(),
            Some(r#"[true,"undefined","object",true]"#)
        );
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_endowment_json_cannot_inject_or_overwrite_locator_buckets() {
        let _guard = hermes_engine_test_lock().lock().await;
        let attacker_locator = "attacker@zz:fetch,Buffer;victim";
        let overwritten_locator = "attacker@zz";
        let victim_locator = "victim@1.0.0";
        let (host, digest) =
            build_armed_test_host_custom(None, false, false, false, Vec::new(), None, |snapshot| {
                let integrity = snapshot["principals"][1]["principal"]["integrity"].clone();
                let attacker = serde_json::json!({
                    "kind": "package",
                    "name": "attacker",
                    "integrity": integrity,
                    "locator": attacker_locator,
                });
                let overwritten = serde_json::json!({
                    "kind": "package",
                    "name": "overwritten",
                    "integrity": integrity,
                    "locator": overwritten_locator,
                });
                let victim = serde_json::json!({
                    "kind": "package",
                    "name": "victim",
                    "integrity": integrity,
                    "locator": victim_locator,
                });

                snapshot["principals"][0]["imports"]["packages"] =
                    serde_json::json!([overwritten_locator, attacker_locator, victim_locator]);
                snapshot["principals"][1]["principal"] = attacker.clone();
                snapshot["principals"][1]["endowments"] = serde_json::json!(["process"]);
                let mut overwritten_row = snapshot["principals"][1].clone();
                overwritten_row["principal"] = overwritten.clone();
                overwritten_row["endowments"] = serde_json::json!(["Bun"]);
                let mut victim_row = snapshot["principals"][1].clone();
                victim_row["principal"] = victim.clone();
                victim_row["endowments"] = serde_json::json!([]);
                snapshot["principals"]
                    .as_array_mut()
                    .unwrap()
                    .extend([overwritten_row, victim_row]);

                snapshot["packageGraph"]["nodes"] = serde_json::json!([
                    {"principal": attacker},
                    {"principal": overwritten},
                    {"principal": victim},
                ]);
                let root = snapshot["rootIdentity"].clone();
                snapshot["packageGraph"]["importEdges"] = serde_json::json!([
                    {"importer": root, "imported": attacker},
                    {"importer": root, "imported": overwritten},
                    {"importer": root, "imported": victim},
                ]);

                snapshot["rootBindings"][0]["owner"] = attacker;
                let mut overwritten_binding = snapshot["rootBindings"][0].clone();
                overwritten_binding["owner"] = overwritten;
                overwritten_binding["hostPath"]["components"]
                    .as_array_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap()["value"] = serde_json::json!("overwritten");
                overwritten_binding["object"]["file"] = serde_json::json!("file-201");
                let mut victim_binding = snapshot["rootBindings"][0].clone();
                victim_binding["owner"] = victim;
                victim_binding["hostPath"]["components"]
                    .as_array_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap()["value"] = serde_json::json!("victim");
                victim_binding["object"]["file"] = serde_json::json!("file-202");
                snapshot["rootBindings"]
                    .as_array_mut()
                    .unwrap()
                    .extend([overwritten_binding, victim_binding]);
            });
        assert_ne!(crate::host::abi::install_host(host), 0);
        let _reset = HostResetGuard;
        let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        engine.load_runtime().await.unwrap();

        let script = format!(
            r#"(function () {{
              var registry = globalThis.__compartments;
              var attacker = registry[{}];
              var overwritten = registry[{}];
              var victim = registry[{}];
              var injectedBare = registry['victim'];
              return JSON.stringify({{
                attackerOwnsOnlyProcess:
                  attacker.process === globalThis.process &&
                  attacker.fetch === undefined && attacker.Buffer === undefined &&
                  attacker.Bun === undefined,
                otherExactBucketNotOverwritten:
                  overwritten.Bun === globalThis.Bun &&
                  overwritten.fetch === undefined && overwritten.Buffer === undefined &&
                  overwritten.process === undefined,
                emptyExactBucketBlocksBareInjection:
                  victim.fetch === undefined && victim.Buffer === undefined &&
                  victim.process === undefined && victim.Bun === undefined,
                noInjectedBareBucket:
                  injectedBare.fetch === undefined && injectedBare.Buffer === undefined &&
                  injectedBare.process === undefined && injectedBare.Bun === undefined,
                wireDeleted: typeof globalThis.__ibexEndowRaw === 'undefined'
              }});
            }})()"#,
            serde_json::to_string(attacker_locator).unwrap(),
            serde_json::to_string(overwritten_locator).unwrap(),
            serde_json::to_string(victim_locator).unwrap(),
        );
        let encoded = engine.eval_immediate(&script).await.unwrap().unwrap();
        let result: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            result,
            serde_json::json!({
                "attackerOwnsOnlyProcess": true,
                "otherExactBucketNotOverwritten": true,
                "emptyExactBucketBlocksBareInjection": true,
                "noInjectedBareBucket": true,
                "wireDeleted": true,
            })
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn compartment_baseline_finalizer_accepts_disabled_and_rejects_partial_state() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _lockdown_disabled = TestEnvVar::remove("IBEX_LOCKDOWN");
        let _compartments_disabled = TestEnvVar::remove("IBEX_COMPARTMENTS");
        let engine = HermesEngine::new().unwrap();

        finalize_compartment_baseline(&engine)
            .await
            .expect("an entirely absent native handshake means compartments are disabled");
        engine
            .eval_immediate(
                r#"Object.defineProperty(
                  globalThis,
                  '__ibexCompartmentRegistryReady',
                  { value: true, configurable: true }
                )"#,
            )
            .await
            .unwrap();

        let error = finalize_compartment_baseline(&engine)
            .await
            .expect_err("a partial native handshake must fail closed");
        assert!(error.to_string().contains("malformed"), "{error:#}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn locked_baseline_rejects_prototype_and_contains_late_global_mutation() {
        let _guard = hermes_engine_test_lock().lock().await;
        // Structural lockdown is a constructor invariant. An ambient opt-out
        // must not restore the historical compartments-only mode where shared
        // prototypes and evaluator constructors remained mutable.
        // @ref LLP 0013#mechanism-1 — shared intrinsics are frozen and dynamic
        // evaluator constructors are tamed before application code executes.
        let _lockdown_cannot_disable = TestEnvVar::set("IBEX_LOCKDOWN", "0");
        let _compartments_enabled = TestEnvVar::set("IBEX_COMPARTMENTS", "1");
        let engine = HermesEngine::new().unwrap();
        engine.load_runtime().await.unwrap();

        let raw = engine
            .eval_immediate(
                r#"(function () {
                  var root = globalThis;
                  var O = Object;
                  var R = Reflect;
                  var J = JSON;
                  var originalProxy = root.Proxy;
                  var proxyDescriptor = O.getOwnPropertyDescriptor(root, 'Proxy');
                  var registry = root.__compartments;
                  var sessionSymbol = Symbol('ibex.session.prototype');
                  var getterRan = false;
                  var prototypeStringRejected = !R.defineProperty(
                    O.prototype,
                    'sessionPrototypeString',
                    { value: 'STRING-SECRET', configurable: true }
                  );
                  var prototypeSymbolRejected = !R.defineProperty(
                    O.prototype,
                    sessionSymbol,
                    { value: 'SYMBOL-SECRET', configurable: true }
                  );
                  var prototypeGetterRejected = !R.defineProperty(
                    O.prototype,
                    'sessionPrototypeGetter',
                    {
                      configurable: true,
                      get: function () {
                        getterRan = true;
                        return 'GETTER-SECRET';
                      }
                    }
                  );

                  O.freeze(registry);
                  // Lockdown freezes shared intrinsics, not the session's realm
                  // global. Late root bindings may exist for REPL/application
                  // use, but the finalized package baseline must not acquire
                  // them or a replacement constructor binding.
                  var sessionGlobalAdded = R.defineProperty(
                    root,
                    'sessionGlobalSecret',
                    { value: 'GLOBAL-SECRET', configurable: true }
                  );
                  var replacementProxy = function PoisonedProxy() {
                    throw new Error('live global Proxy must not create compartments');
                  };
                  var proxyReplaced =
                    R.set(root, 'Proxy', replacementProxy, root) &&
                    root.Proxy === replacementProxy;

                  // This key has not been requested before: creation must use
                  // the captured Proxy constructor and immutable baseline.
                  var compartment = registry['late-session-pkg@1.0.0'];
                  var cachesDescriptorBefore = O.getOwnPropertyDescriptor(root, 'caches');
                  var indexedDBDescriptorBefore = O.getOwnPropertyDescriptor(root, 'indexedDB');

                  // Root-first and package-first access must converge on each
                  // lazy global's single shared memo without replacing a value
                  // that the other side has already observed.
                  var rootCaches = root.caches;
                  var packageCaches = compartment.caches;
                  var packageIndexedDB = compartment.indexedDB;
                  var rootIndexedDB = root.indexedDB;
                  var result = {
                    freshProxy: compartment !== root,
                    aliasesSelf: compartment.globalThis === compartment &&
                      compartment.global === compartment &&
                      compartment.self === compartment &&
                      compartment.window === compartment,
                    prototypeStringRejected: prototypeStringRejected,
                    prototypeSymbolRejected: prototypeSymbolRejected,
                    prototypeGetterRejected: prototypeGetterRejected,
                    sessionGlobalAdded: sessionGlobalAdded,
                    sessionGlobalType: typeof compartment.sessionGlobalSecret,
                    sessionGlobalHas: R.has(compartment, 'sessionGlobalSecret'),
                    proxyReplaced: proxyReplaced,
                    stringType: typeof compartment.sessionPrototypeString,
                    stringHas: R.has(compartment, 'sessionPrototypeString'),
                    symbolType: typeof compartment[sessionSymbol],
                    symbolHas: R.has(compartment, sessionSymbol),
                    getterType: typeof compartment.sessionPrototypeGetter,
                    getterHas: R.has(compartment, 'sessionPrototypeGetter'),
                    getterRan: getterRan,
                    toStringType: typeof compartment.toString,
                    registryFrozen: O.isFrozen(registry),
                    capturedProxy: compartment.Proxy === originalProxy,
                    lazyGlobalsPending:
                      !!cachesDescriptorBefore &&
                      typeof cachesDescriptorBefore.get === 'function' &&
                      !!indexedDBDescriptorBefore &&
                      typeof indexedDBDescriptorBefore.get === 'function',
                    cachesIdentity: rootCaches === packageCaches,
                    cachesRootStable: root.caches === rootCaches,
                    cachesInstalled:
                      O.getOwnPropertyDescriptor(root, 'caches').value === rootCaches,
                    indexedDBIdentity: packageIndexedDB === rootIndexedDB,
                    indexedDBRootStable: root.indexedDB === rootIndexedDB,
                    indexedDBPackageStable:
                      compartment.indexedDB === packageIndexedDB,
                    indexedDBInstalled:
                      O.getOwnPropertyDescriptor(root, 'indexedDB').value === rootIndexedDB,
                    lockedDown: root.__ibexLockedDown === true
                  };

                  R.deleteProperty(root, 'sessionGlobalSecret');
                  R.defineProperty(root, 'Proxy', proxyDescriptor);

                  return J.stringify(result);
                })()"#,
            )
            .await
            .unwrap()
            .expect("baseline regression probe should return JSON");
        let state: serde_json::Value = serde_json::from_str(&raw).unwrap();

        for field in [
            "freshProxy",
            "aliasesSelf",
            "prototypeStringRejected",
            "prototypeSymbolRejected",
            "prototypeGetterRejected",
            "sessionGlobalAdded",
            "proxyReplaced",
            "registryFrozen",
            "capturedProxy",
            "lazyGlobalsPending",
            "cachesIdentity",
            "cachesRootStable",
            "cachesInstalled",
            "indexedDBIdentity",
            "indexedDBRootStable",
            "indexedDBPackageStable",
            "indexedDBInstalled",
            "lockedDown",
        ] {
            assert_eq!(state[field], true, "{field} failed: {state}");
        }
        for field in [
            "sessionGlobalHas",
            "stringHas",
            "symbolHas",
            "getterHas",
            "getterRan",
        ] {
            assert_eq!(state[field], false, "{field} leaked: {state}");
        }
        for field in [
            "sessionGlobalType",
            "stringType",
            "symbolType",
            "getterType",
        ] {
            assert_eq!(state[field], "undefined", "{field} leaked: {state}");
        }
        assert_eq!(state["toStringType"], "function", "{state}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fresh_runtime_preinstalls_shared_runtime_bundle() {
        // The C Hermes host callbacks are process-global in the test binary.
        // Keep engine-owning tests serial so the Rust test harness cannot
        // overlap bridge teardown with another runtime's event-loop pump.
        let _guard = hermes_engine_test_lock().lock().await;
        let engine = HermesEngine::new().unwrap();
        assert!(engine.runtime_bundle_installed().await.unwrap());

        let installed = engine
            .eval_immediate(
                r#"(function() {
                    return (
                      globalThis.__exactRuntimeLoaded === true &&
                      typeof globalThis.ExactBundle === 'object' &&
                      globalThis.ExactBundle !== null &&
                      typeof globalThis.__exactRuntime === 'object'
                    ) ? 'true' : 'false';
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        assert_eq!(installed.trim(), "true");

        let bootstrap_surface = engine
            .eval_immediate(
                r#"(function() {
                    var text = globalThis.Exact.unsafe.arrayBufferToString(new Uint8Array([104, 105]));
                    return JSON.stringify({
                      hasBunUnsafe: !!globalThis.Exact.unsafe,
                      hasPeekStatus: typeof globalThis.Exact.peek.status === 'function',
                      noAmbientBun: typeof globalThis.Bun === 'undefined',
                      text: text,
                      hasGetRandomValues: typeof globalThis.crypto.getRandomValues === 'function',
                      hasRandomUUID: typeof globalThis.crypto.randomUUID === 'function'
                    });
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(bootstrap_surface.contains(r#""hasBunUnsafe":true"#));
        assert!(bootstrap_surface.contains(r#""noAmbientBun":true"#));
        assert!(bootstrap_surface.contains(r#""hasPeekStatus":true"#));
        assert!(bootstrap_surface.contains(r#""text":"hi""#));
        assert!(bootstrap_surface.contains(r#""hasGetRandomValues":true"#));
        assert!(bootstrap_surface.contains(r#""hasRandomUUID":true"#));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_byte_and_fetch_boundaries_reject_forged_inputs() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["network:fetch:127.0.0.1"]);
        let engine = HermesEngine::new().unwrap();

        let outcome = engine
            .eval_immediate(
                r#"(function() {
                    var out = [];
                    var forged = { buffer: new ArrayBuffer(4), byteOffset: 3, byteLength: 4 };
                    try {
                      __nativeFetch('http://127.0.0.1:9/', {
                        headers: [['x-test', 'ok\r\nInjected: yes']]
                      });
                      out.push('headers:ALLOWED');
                    } catch (e) {
                      out.push(String(e && e.message || e).indexOf('invalid header') !== -1
                        ? 'headers:DENIED' : 'headers:ERR');
                    }
                    try {
                      __exactBytesToUtf8String(forged);
                      out.push('utf8:ALLOWED');
                    } catch (e) {
                      out.push(String(e && e.message || e).indexOf('out of bounds') !== -1
                        ? 'utf8:DENIED' : 'utf8:ERR');
                    }
                    try {
                      __nativeFetch('http://127.0.0.1:9/', { method: 'POST', headers: [] }, forged);
                      out.push('fetch-body:ALLOWED');
                    } catch (e) {
                      out.push(String(e && e.message || e).indexOf('out of bounds') !== -1
                        ? 'fetch-body:DENIED' : 'fetch-body:ERR');
                    }
                    return out.join(' ');
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();

        assert_eq!(
            outcome.trim(),
            "headers:DENIED utf8:DENIED fetch-body:DENIED"
        );
    }

    #[cfg(feature = "host-http-server")]
    #[tokio::test(flavor = "current_thread")]
    async fn native_http_response_body_rejects_forged_view_bounds() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["network:listen:127.0.0.1:0"]);
        let engine = HermesEngine::new().unwrap();

        let outcome = engine
            .eval_immediate(
                r#"(function() {
                    if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
                    var server = JSON.parse(__exactHttpServe(0, '127.0.0.1'));
                    if (server.error) return 'setup:' + server.error;
                    __exactHttpSetRef(server.id, 0);
                    var forged = { buffer: new ArrayBuffer(4), byteOffset: 3, byteLength: 4 };
                    try {
                      __exactHttpRespond(server.id, 1, 200, '[]', forged);
                      return 'http-body:ALLOWED';
                    } catch (e) {
                      return String(e && e.message || e).indexOf('out of bounds') !== -1
                        ? 'http-body:DENIED' : 'http-body:ERR';
                    } finally {
                      __exactHttpClose(server.id, 1);
                    }
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();

        assert_eq!(outcome.trim(), "http-body:DENIED");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_call_async_resolves_and_rejects_through_the_promise_channel() {
        let _guard = hermes_engine_test_lock().lock().await;
        let engine = HermesEngine::new().unwrap();

        let kicked = engine
            .eval_immediate(
                r#"(function() {
                    globalThis.__hcAsync = {
                      resolve: 'pending', reject: 'pending', numOp: 'pending'
                    };
                    __hostCallAsync('agent.captureScreenshot', '{}').then(
                      function(r) {
                        globalThis.__hcAsync.resolve =
                          'ok:' + (r && typeof r.error === 'string');
                      },
                      function() { globalThis.__hcAsync.resolve = 'rejected'; });
                    __hostCallAsync('selftest.unknown-op', '{}').then(
                      function() { globalThis.__hcAsync.reject = 'resolved'; },
                      function(e) {
                        globalThis.__hcAsync.reject =
                          (e && typeof e.message === 'string' &&
                           e.message.indexOf('Unknown host call') !== -1)
                            ? 'rejected-with-message' : 'rejected-odd';
                      });
                    // ENG-22982: a non-string op must not sync-throw before the
                    // promise exists. It is coerced (12345 -> "12345"), reaches
                    // the host, and settles as a rejection like any unknown op —
                    // the kick itself must NOT throw.
                    try {
                      __hostCallAsync(12345, '{}').then(
                        function() { globalThis.__hcAsync.numOp = 'resolved'; },
                        function(e) {
                          globalThis.__hcAsync.numOp =
                            (e && typeof e.message === 'string' &&
                             e.message.indexOf('Unknown host call') !== -1)
                              ? 'rejected-with-message' : 'rejected-odd';
                        });
                    } catch (e) {
                      globalThis.__hcAsync.numOp = 'threw:' + (e && e.message);
                    }
                    return 'kicked';
                })()"#,
            )
            .await
            .unwrap()
            .unwrap_or_default();
        assert_eq!(kicked.trim(), "kicked");

        engine.drive_event_loop().await.unwrap();

        let outcome = engine
            .eval_immediate("JSON.stringify(globalThis.__hcAsync)")
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(outcome.contains(r#""resolve":"ok:true""#), "{outcome}");
        assert!(
            outcome.contains(r#""reject":"rejected-with-message""#),
            "{outcome}"
        );
        assert!(
            outcome.contains(r#""numOp":"rejected-with-message""#),
            "{outcome}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fs_positional_read_does_not_move_the_file_offset() {
        // ENG-22982: __exactFsRead with a numeric position is a *positional*
        // read (pread) that leaves the fd's current offset unchanged, matching
        // Node's readSync. The old lseek+read moved the cursor, so a fixed
        // header read followed by a sequential read returned the wrong bytes.
        let _guard = hermes_engine_test_lock().lock().await;

        let path = std::env::temp_dir().join(format!(
            "ibex-eng-22982-positional-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, b"abcdefghij").unwrap();
        let path_str = path.to_str().unwrap().to_string();
        let cap = format!("fs:read:{path_str}");
        let _host_guard = install_test_host_with_allow(&[cap.as_str()]);

        let engine = HermesEngine::new().unwrap();

        let script = format!(
            r#"(function() {{
                if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                function b2s(a) {{ return String.fromCharCode.apply(null, a); }}
                // The POSIX fs bridge is installed lazily on first use.
                var fd = __exactFsOpen({path_str:?}, 'r');
                // Positional read at offset 5 -> "fg". This must NOT advance the
                // fd cursor, so the following sequential read starts from 0.
                var positional = b2s(__exactFsRead(fd, 2, 5));
                var sequential = b2s(__exactFsRead(fd, 2, -1));
                __exactFsClose(fd);
                return JSON.stringify({{
                    positional: positional, sequential: sequential
                }});
            }})()"#
        );

        let outcome = engine
            .eval_immediate(&script)
            .await
            .unwrap()
            .unwrap_or_default();

        let _ = fs::remove_file(&path);

        let parsed: serde_json::Value = serde_json::from_str(&outcome)
            .unwrap_or_else(|_| panic!("fs positional read eval returned non-JSON: {outcome}"));
        assert_eq!(parsed["positional"], "fg", "{outcome}");
        // Pre-fix (lseek+read) this returned "hi" because the positional read
        // moved the cursor to offset 7; pread leaves it at 0 -> "ab".
        assert_eq!(parsed["sequential"], "ab", "{outcome}");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn stale_fd_number_reuse_never_authorizes_the_replacement_object() {
        use std::os::fd::AsRawFd;

        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let first = tempdir.path().join("first.txt");
        let replacement = tempdir.path().join("replacement.txt");
        fs::write(&first, b"AAAA").unwrap();
        fs::write(&replacement, b"BBBB").unwrap();
        let first_path = first.to_str().unwrap();
        let read_cap = format!("fs:read:{first_path}");
        let _host_guard = install_test_host_with_allow(&[&read_cap]);
        let engine = HermesEngine::new().unwrap();

        let opened = engine
            .eval_immediate(&format!(
                "if (typeof __exactEnsureFs === 'function') __exactEnsureFs(); \
                 String(__exactFsOpen({first_path:?}, 'r'))"
            ))
            .await
            .unwrap()
            .unwrap();
        let fd: i32 = opened.trim().parse().expect("numeric native fd");

        assert_eq!(unsafe { libc::close(fd) }, 0);
        let replacement_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&replacement)
            .unwrap();
        let replacement_source_fd = replacement_file.as_raw_fd();
        if replacement_source_fd != fd {
            assert_eq!(unsafe { libc::dup2(replacement_source_fd, fd) }, fd);
        }

        let outcome = engine
            .eval_immediate(&format!(
                r#"(function(fd) {{
                  function denied(operation) {{
                    try {{
                      operation();
                      return 'ALLOWED';
                    }} catch (error) {{
                      return String(error && error.message || error);
                    }}
                  }}
                  return JSON.stringify([
                    denied(function() {{ __exactFsRead(fd, 1, -1); }}),
                    denied(function() {{ __exactFsFstatSync(fd); }}),
                    denied(function() {{ __exactFsWrite(fd, new Uint8Array([88]), 0); }}),
                    denied(function() {{ __exactFsReadAsync(fd, 1, -1); }}),
                    denied(function() {{ __exactFsWriteAsync(fd, new Uint8Array([88]), 0); }}),
                    denied(function() {{ __exactFsClose(fd); }}),
                    denied(function() {{ __exactFsCloseAsync(fd); }})
                  ]);
                }})({fd})"#
            ))
            .await
            .unwrap()
            .unwrap();
        let denials: Vec<String> = serde_json::from_str(&outcome).unwrap();
        assert_eq!(denials.len(), 7);
        assert!(
            denials
                .iter()
                .all(|message| message.contains("bad file descriptor")),
            "every stale sync/async operation must fail as EBADF: {denials:?}"
        );

        let mut bytes = [0u8; 4];
        assert_eq!(
            unsafe { libc::pread(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) },
            4,
            "denied close must leave the replacement descriptor open"
        );
        assert_eq!(&bytes, b"BBBB", "denied writes must not mutate replacement");

        drop(engine);
        if replacement_source_fd != fd {
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
        drop(replacement_file);
        assert_eq!(fs::read(&replacement).unwrap(), b"BBBB");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn runtime_cleanup_never_closes_a_reused_descriptor_number() {
        use std::os::fd::AsRawFd;

        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let owned_path = tempdir.path().join("owned.txt");
        let replacement_path = tempdir.path().join("replacement.txt");
        fs::write(&owned_path, b"owned").unwrap();
        fs::write(&replacement_path, b"replacement").unwrap();
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let engine = HermesEngine::new().unwrap();
        let fd = engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  return String(__exactFsOpen({:?}, 'r'));
                }})()"#,
                owned_path.to_str().unwrap()
            ))
            .await
            .unwrap()
            .unwrap()
            .parse::<i32>()
            .unwrap();

        assert_eq!(unsafe { libc::close(fd) }, 0);
        let replacement = std::fs::File::open(&replacement_path).unwrap();
        let replacement_source_fd = replacement.as_raw_fd();
        if replacement_source_fd != fd {
            assert_eq!(unsafe { libc::dup2(replacement_source_fd, fd) }, fd);
        }

        drop(engine);
        let mut bytes = [0u8; 11];
        assert_eq!(
            unsafe { libc::pread(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) },
            bytes.len() as isize
        );
        assert_eq!(&bytes, b"replacement");
        if replacement_source_fd != fd {
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
    }

    #[cfg(unix)]
    async fn run_bounded_owner_thread_teardown_probe(
        child_env: &str,
        exact_test_name: &str,
    ) -> bool {
        if std::env::var(child_env).as_deref() == Ok("1") {
            return false;
        }

        let mut command = Command::new(std::env::current_exe().expect("current test binary"));
        command
            .arg(exact_test_name)
            .arg("--exact")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(child_env, "1")
            .env_remove("IBEX_TEST_FS_WORKER_THROW_ENQUEUE");
        let label = format!("owner-thread teardown probe {exact_test_name}");
        let output = output_with_timeout(&mut command, std::time::Duration::from_secs(10), &label)
            .await
            .unwrap_or_else(|error| panic!("{error:#}"));
        assert!(
            output.status.success(),
            "{label} failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        true
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_destroy_waits_for_an_inflight_fs_worker_pin() {
        use std::io::Write as _;

        const CHILD_ENV: &str = "IBEX_TEST_INFLIGHT_FS_PIN_TEARDOWN_CHILD";
        const TEST_NAME: &str =
            "engine::hermes::tests::concurrent_destroy_waits_for_an_inflight_fs_worker_pin";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let fifo = tempdir.path().join("blocked-read.fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let engine = HermesEngine::new().unwrap();
        let started = engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__blockedRead = __exactFsReadFileAsync({:?}, 'r', 0);
                  return 'started';
                }})()"#,
                fifo.to_str().unwrap()
            ))
            .await
            .unwrap();
        assert_eq!(started.as_deref(), Some("started"));
        let shared = engine.runtime.lock().await.as_ref().unwrap().shared();
        let fifo_for_writer = fifo.clone();
        let shutdown_returned = Arc::new(AtomicBool::new(false));
        let shutdown_returned_for_writer = Arc::clone(&shutdown_returned);
        let raw_for_writer = shared.raw.load(Ordering::SeqCst) as usize;
        let runtime_nonce =
            unsafe { ex_hermes_runtime_nonce(raw_for_writer as *mut HermesRuntimeOpaque) };
        assert_ne!(runtime_nonce, 0);
        let writer = std::thread::spawn(move || {
            // The nonce API returns zero once the native registry leaves
            // Running, so this cannot be satisfied merely by Rust swapping its
            // pointer before entering the C++ destructor.
            while unsafe { ex_hermes_runtime_nonce(raw_for_writer as *mut HermesRuntimeOpaque) }
                == runtime_nonce
            {
                std::thread::yield_now();
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            let returned_before_release = shutdown_returned_for_writer.load(Ordering::Acquire);
            let mut writer = std::fs::OpenOptions::new()
                .write(true)
                .open(fifo_for_writer)
                .unwrap();
            writer.write_all(b"release").unwrap();
            assert!(
                !returned_before_release,
                "owner-thread destroy returned while the worker still held a runtime lifetime pin"
            );
        });

        // JSI/Hermes destruction is owner-thread-only. Release the blocked
        // worker from another thread while shutdown waits on this thread.
        let started_waiting = std::time::Instant::now();
        assert_eq!(shared.shutdown(), RuntimeShutdown::Destroyed);
        shutdown_returned.store(true, Ordering::Release);
        writer.join().unwrap();
        assert!(
            started_waiting.elapsed() >= std::time::Duration::from_millis(100),
            "destroy must wait while the worker owns a runtime lifetime pin"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn fs_enqueue_exception_releases_runtime_pin_before_destroy() {
        const CHILD_ENV: &str = "IBEX_TEST_FS_ENQUEUE_SHUTDOWN_CHILD";
        const TEST_NAME: &str =
            "engine::hermes::tests::fs_enqueue_exception_releases_runtime_pin_before_destroy";
        if run_bounded_owner_thread_teardown_probe(CHILD_ENV, TEST_NAME).await {
            return;
        }

        struct EnvReset;
        impl Drop for EnvReset {
            fn drop(&mut self) {
                std::env::remove_var("IBEX_TEST_FS_WORKER_THROW_ENQUEUE");
            }
        }

        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let file = tempdir.path().join("read.txt");
        fs::write(&file, b"data").unwrap();
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let engine = HermesEngine::new().unwrap();
        // The closed-startup check has already run. This control exists only
        // for deterministic post-construction native failure injection.
        std::env::set_var("IBEX_TEST_FS_WORKER_THROW_ENQUEUE", "1");
        let _reset = EnvReset;
        engine
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  globalThis.__enqueueFailure = 'pending';
                  __exactFsReadFileAsync({:?}, 'r', 0).then(
                    function() {{ globalThis.__enqueueFailure = 'unexpected-success'; }},
                    function() {{ globalThis.__enqueueFailure = 'rejected'; }}
                  );
                  return 'started';
                }})()"#,
                file.to_str().unwrap()
            ))
            .await
            .unwrap();
        std::env::remove_var("IBEX_TEST_FS_WORKER_THROW_ENQUEUE");
        let shared = engine.runtime.lock().await.as_ref().unwrap().shared();
        // Shutdown executes on the runtime owner thread. The parent test
        // process supplies the deadline so a leaked pin cannot hang this suite.
        assert_eq!(shared.shutdown(), RuntimeShutdown::Destroyed);
    }

    #[cfg(all(unix, feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn diagnostic_allow_all_cannot_use_or_close_an_armed_runtime_fd_or_socket() {
        let _guard = hermes_engine_test_lock().lock().await;
        let tempdir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tempdir.path()).unwrap();
        let file = root.join("armed-owned.txt");
        fs::write(&file, b"armed").unwrap();
        let (_reset, digest) = install_armed_test_host_at(Some(&root), false, true, true, vec![]);
        let armed = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let handles = armed
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                  return JSON.stringify({{
                    fd: __exactFsOpen({path:?}, 'r'),
                    socket: __exactUdpSocket('udp4')
                  }});
                }})()"#,
                path = file.to_str().unwrap(),
            ))
            .await
            .unwrap()
            .unwrap();
        let handles: serde_json::Value = serde_json::from_str(&handles).unwrap();
        let fd = handles["fd"].as_i64().unwrap();
        let socket = handles["socket"].as_i64().unwrap();

        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let diagnostic = HermesEngine::new().unwrap();
        let denied = diagnostic
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureFs === 'function') __exactEnsureFs();
                  if (typeof __exactEnsureNet === 'function') __exactEnsureNet();
                  var denied = 0;
                  try {{ __exactFsRead({fd}, 1, -1); }} catch (_) {{ denied++; }}
                  try {{ __exactFsClose({fd}); }} catch (_) {{ denied++; }}
                  try {{ __exactUdpClose({socket}); }} catch (_) {{ denied++; }}
                  return String(denied);
                }})()"#,
            ))
            .await
            .unwrap();
        assert_eq!(denied.as_deref(), Some("3"));

        let owner_result = armed
            .eval_immediate(&format!(
                r#"(function() {{
                  var text = String.fromCharCode.apply(null, __exactFsRead({fd}, 5, -1));
                  __exactFsClose({fd});
                  __exactUdpClose({socket});
                  return text;
                }})()"#,
            ))
            .await
            .unwrap();
        assert_eq!(owner_result.as_deref(), Some("armed"));
    }

    #[cfg(feature = "capsec-conformance-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_cannot_use_or_close_diagnostic_sqlite_handles() {
        let _guard = hermes_engine_test_lock().lock().await;
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let owner = HermesEngine::new().unwrap();
        let handles = owner
            .eval_immediate(
                r#"(function() {
                  if (typeof __exactEnsureSqlite === 'function') __exactEnsureSqlite();
                  var db = __exactSqliteOpen(':memory:', null);
                  var statement = __exactSqlitePrepare(db, 'SELECT 1 AS value');
                  globalThis.__ownedSqliteDb = db;
                  globalThis.__ownedSqliteStatement = statement.handle;
                  return JSON.stringify({ db: db, statement: statement.handle });
                })()"#,
            )
            .await
            .unwrap()
            .unwrap();
        let handles: serde_json::Value = serde_json::from_str(&handles).unwrap();
        let db = handles["db"].as_u64().unwrap();
        let statement = handles["statement"].as_u64().unwrap();

        let (_reset, digest) = install_armed_test_host();
        let intruder = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let denied = intruder
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureSqlite === 'function') __exactEnsureSqlite();
                  var denied = 0;
                  try {{ __exactSqliteInTransaction({db}); }} catch (_) {{ denied++; }}
                  try {{ __exactSqliteExpandedSql({statement}); }} catch (_) {{ denied++; }}
                  try {{ __exactSqliteFinalize({statement}); }} catch (_) {{ denied++; }}
                  try {{ __exactSqliteClose({db}); }} catch (_) {{ denied++; }}
                  return String(denied);
                }})()"#
            ))
            .await
            .unwrap();
        assert_eq!(denied.as_deref(), Some("4"));

        let owner_result = owner
            .eval_immediate(
                r#"(function() {
                  var sql = __exactSqliteExpandedSql(globalThis.__ownedSqliteStatement);
                  __exactSqliteFinalize(globalThis.__ownedSqliteStatement);
                  __exactSqliteClose(globalThis.__ownedSqliteDb);
                  return sql;
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(owner_result.as_deref(), Some("SELECT 1 AS value"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelling_one_runtime_fetch_never_cancels_another_runtime_request() {
        let _guard = hermes_engine_test_lock().lock().await;

        struct HeldServer {
            url: String,
            accepted: std::sync::mpsc::Receiver<()>,
            release: std::sync::mpsc::Sender<()>,
            join: std::thread::JoinHandle<()>,
        }
        fn held_server(body: &'static str) -> HeldServer {
            use std::io::{Read as _, Write as _};
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let port = listener.local_addr().unwrap().port();
            let (accepted_tx, accepted) = std::sync::mpsc::channel();
            let (release, release_rx) = std::sync::mpsc::channel();
            let join = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                accepted_tx.send(()).unwrap();
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).unwrap();
            });
            HeldServer {
                url: format!("http://127.0.0.1:{port}/"),
                accepted,
                release,
                join,
            }
        }

        let first_server = held_server("first");
        let second_server = held_server("second");
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let first = HermesEngine::new().unwrap();
        assert_ne!(
            crate::host::abi::install_host(crate::host::Host::default_legacy()),
            0
        );
        let second = HermesEngine::new().unwrap();

        for (engine, url, name) in [
            (&first, first_server.url.as_str(), "first"),
            (&second, second_server.url.as_str(), "second"),
        ] {
            let started = engine
                .eval_immediate(&format!(
                    r#"globalThis.__fetchState = 'pending';
                       globalThis.__fetchPromise = __nativeFetch({url:?}, {{}});
                       globalThis.__fetchPromise.then(
                         function(response) {{ globalThis.__fetchState = 'ok:' + response.status; }},
                         function(error) {{ globalThis.__fetchState = 'error:' + String(error); }}
                       );
                       {name:?};"#
                ))
                .await
                .unwrap();
            assert_eq!(started.as_deref(), Some(name));
        }
        first_server
            .accepted
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        second_server
            .accepted
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();

        first
            .eval_immediate("globalThis.__fetchPromise.__exactCancel(); 'cancelled';")
            .await
            .unwrap();
        second_server.release.send(()).unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let second_state = loop {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(100),
                second.drive_event_loop(),
            )
            .await;
            let state = second
                .eval_immediate("globalThis.__fetchState")
                .await
                .unwrap()
                .unwrap_or_default();
            if state != "pending" || std::time::Instant::now() >= deadline {
                break state;
            }
        };
        assert_eq!(second_state, "ok:200");

        first_server.release.send(()).unwrap();
        first_server.join.join().unwrap();
        second_server.join.join().unwrap();
    }

    #[cfg(all(feature = "host-http-server", feature = "capsec-conformance-observer"))]
    #[tokio::test(flavor = "current_thread")]
    async fn armed_runtime_cannot_use_or_close_diagnostic_http_server() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["network:listen:127.0.0.1:0"]);
        let owner = HermesEngine::new().unwrap();
        let server = eval_json(
            &owner,
            r#"(function() {
              if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
              var result = JSON.parse(__exactHttpServe(0, '127.0.0.1'));
              globalThis.__ownedHttpServer = result.id;
              return JSON.stringify(result);
            })()"#,
        )
        .await;
        let server_id = server["id"].as_u64().unwrap();

        let (_reset, digest) = install_armed_test_host();
        let intruder = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
        let denied = intruder
            .eval_immediate(&format!(
                r#"(function() {{
                  if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
                  var denied = 0;
                  try {{ __exactHttpAddress({server_id}); }} catch (_) {{ denied++; }}
                  try {{ __exactHttpSetRef({server_id}, 0); }} catch (_) {{ denied++; }}
                  try {{ __exactHttpClose({server_id}, 1); }} catch (_) {{ denied++; }}
                  return String(denied);
                }})()"#
            ))
            .await
            .unwrap();
        assert_eq!(denied.as_deref(), Some("3"));

        let owner_result = owner
            .eval_immediate(
                r#"(function() {
                  var address = __exactHttpAddress(globalThis.__ownedHttpServer);
                  __exactHttpClose(globalThis.__ownedHttpServer, 1);
                  return address === null ? 'missing' : 'closed';
                })()"#,
            )
            .await
            .unwrap();
        assert_eq!(owner_result.as_deref(), Some("closed"));
    }

    #[cfg(feature = "host-http-server")]
    #[tokio::test(flavor = "current_thread")]
    async fn http_wait_timeout_is_not_starved_by_existing_waiters() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["network:listen:127.0.0.1:0"]);
        let _idle_delay = TestEnvVar::set("IBEX_TEST_HTTP_WAIT_IDLE_DELAY_MS", "250");
        let engine = HermesEngine::new().unwrap();

        let setup = eval_json(
            &engine,
            r#"(function() {
                if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
                var result = JSON.parse(__exactHttpServe(0, '127.0.0.1'));
                if (result.error) {
                  return JSON.stringify({ error: result.error });
                }
                __exactHttpSetRef(result.id, 0);
                globalThis.__exactWaitServerId = result.id;
                globalThis.__exactWaitStatus = 'pending';
                __exactHttpWait(result.id, 10).then(function(value) {
                  globalThis.__exactWaitStatus = value === null ? 'warm' : 'request';
                }).catch(function(err) {
                  globalThis.__exactWaitStatus =
                    'error:' + String(err && err.message ? err.message : err);
                });
                return JSON.stringify({ ok: true });
            })()"#,
        )
        .await;

        assert!(setup.get("error").is_none(), "server setup failed: {setup}");
        let warmed = wait_for_exact_wait_status(&engine).await;
        assert_eq!(
            warmed.get("status").and_then(serde_json::Value::as_str),
            Some("warm"),
            "warm-up wait should create an idle native worker: {warmed}",
        );

        // Let the completed worker return to the pool's idle wait before the
        // synchronous burst below. This is the state that used to strand the
        // finite wait behind the first unbounded wait: every enqueue observed
        // one idle worker even though that worker was already owed to an older
        // queued task.
        sleep(Duration::from_millis(25)).await;
        let burst = eval_json(
            &engine,
            r#"(function() {
                globalThis.__exactWaitStatus = 'pending';
                globalThis.__exactWaitKeepAlive = [
                  __exactHttpWait(globalThis.__exactWaitServerId, 0),
                  __exactHttpWait(globalThis.__exactWaitServerId, 0),
                  __exactHttpWait(globalThis.__exactWaitServerId, 0),
                  __exactHttpWait(globalThis.__exactWaitServerId, 0)
                ];
                __exactHttpWait(globalThis.__exactWaitServerId, 50).then(function(value) {
                  globalThis.__exactWaitStatus = value === null ? 'timeout' : 'request';
                }).catch(function(err) {
                  globalThis.__exactWaitStatus =
                    'error:' + String(err && err.message ? err.message : err);
                });
                return JSON.stringify({ ok: true });
            })()"#,
        )
        .await;

        assert_eq!(
            burst.get("ok").and_then(serde_json::Value::as_bool),
            Some(true)
        );

        // CI runners can start the native wait task after the fixed pre-sleep,
        // so observe the JS-visible terminal state instead of assuming a
        // single pump has already crossed the native timeout.
        let status = wait_for_exact_wait_status(&engine).await;
        close_server(&engine, "__exactWaitServerId").await;

        assert_eq!(
            status.get("status").and_then(serde_json::Value::as_str),
            Some("timeout"),
            "timed wait should resolve even while other waits are parked: {status}",
        );
    }

    #[cfg(feature = "host-http-server")]
    #[tokio::test(flavor = "current_thread")]
    async fn native_http_bridge_round_trips_wait_request_and_response() {
        let _guard = hermes_engine_test_lock().lock().await;
        let _host_guard = install_test_host_with_allow(&["network:listen:127.0.0.1:0"]);
        let engine = HermesEngine::new().unwrap();

        let setup = eval_json(
            &engine,
            r#"(function() {
                if (typeof __exactEnsureHttp === 'function') __exactEnsureHttp();
                var result = JSON.parse(__exactHttpServe(0, '127.0.0.1'));
                if (result.error) {
                  return JSON.stringify({ error: result.error });
                }
                __exactHttpSetRef(result.id, 0);
                globalThis.__bridgeServerId = result.id;
                globalThis.__bridgeServerPort = result.port;
                globalThis.__bridgeLastRequest = null;
                globalThis.__bridgePumpOnce = function() {
                  return __exactHttpWait(result.id, 1000).then(function(json) {
                    if (!json) {
                      return 'timeout';
                    }
                    var request = JSON.parse(json);
                    globalThis.__bridgeLastRequest = request.url;
                    __exactHttpRespondString(
                      result.id,
                      request.id,
                      200,
                      JSON.stringify({ 'content-type': 'text/plain; charset=utf-8' }),
                      'bridge-ok'
                    );
                    return 'responded';
                  });
                };
                return JSON.stringify({ id: result.id, port: result.port });
            })()"#,
        )
        .await;

        assert!(setup.get("error").is_none(), "server setup failed: {setup}");
        let server_id = setup
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .expect("server setup should return a server id");
        let port = setup
            .get("port")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .expect("server setup should return a port");

        let wait_deadline = Instant::now() + StdDuration::from_secs(1);
        while Instant::now() < wait_deadline {
            if crate::host::http_server::is_server_listening(server_id) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(
            crate::host::http_server::is_server_listening(server_id),
            "server should reach LISTENING before the bridge round-trip test starts",
        );

        engine
            .eval_immediate("globalThis.__bridgePumpOnce()")
            .await
            .expect("wait pump should start");

        let (response_tx, response_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = response_tx.send(blocking_http_get_with_retry(port, "/agent/onboarding", 10));
        });

        let deadline = Instant::now() + StdDuration::from_secs(2);
        let response = loop {
            if let Ok(result) = response_rx.try_recv() {
                break result;
            }

            if let Ok(result) = timeout(Duration::from_millis(250), engine.drive_event_loop()).await
            {
                result.expect("event loop pump should succeed");
            }

            if Instant::now() >= deadline {
                panic!("timed out waiting for Hermes HTTP bridge response");
            }
        };

        let state = eval_json(
            &engine,
            r#"(function() {
                return JSON.stringify({ lastRequest: globalThis.__bridgeLastRequest });
            })()"#,
        )
        .await;

        let response = response.unwrap_or_else(|err| {
            panic!("HTTP request should succeed: {err}; bridge state: {state}")
        });

        assert!(
            response.contains("HTTP/1.1 200 OK"),
            "expected a 200 response, got: {response}",
        );
        assert!(
            response.contains("bridge-ok"),
            "expected response body to contain bridge-ok, got: {response}",
        );

        assert_eq!(
            state.get("lastRequest").and_then(serde_json::Value::as_str),
            Some("/agent/onboarding"),
            "wait handler should receive the queued request path: {state}",
        );

        close_server(&engine, "__bridgeServerId").await;
    }
}
