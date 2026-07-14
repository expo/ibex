//! Engine support utilities
//!
//! The C++ Hermes adapter (`hermes_runtime.cc`) is compiled by build.rs and
//! linked into this crate. It exposes C functions (`ex_hermes_create`,
//! `ex_hermes_eval`, `ex_hermes_poll`, etc.) that can be called from both
//! Rust (via the CLI's hermes.rs wrapper) and Swift (via the bridging header).
//!
//! This module provides supporting utilities like source map handling.

pub mod sourcemap;
// Native TLS bridge engine for the `tls` builtin (ENG-23492/ENG-23526).
// Platform-specific TCP host functions provide the transport; the Rust engine
// itself is sans-I/O and shared across Unix and Windows.
pub mod tls_bridge;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

extern "C" {
    fn ex_hermes_bytecode_version() -> u32;
    fn ex_hermes_engine_binary_path(out: *mut std::ffi::c_char, out_len: usize) -> i32;
    #[cfg(target_os = "macos")]
    fn ex_hermes_engine_mapped_object(out_device: *mut u64, out_inode: *mut u64) -> i32;
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadedEngineBinaryIdentity {
    pub engine_artifact_path: std::path::PathBuf,
    pub kind: String,
    pub binary_digest: String,
    pub object: capsec_semantics::model::ObjectIdentity,
    pub target_architecture: String,
    pub structural_features: Vec<String>,
}

fn loaded_engine_identity() -> &'static std::result::Result<LoadedEngineBinaryIdentity, String> {
    static IDENTITY: OnceLock<std::result::Result<LoadedEngineBinaryIdentity, String>> =
        OnceLock::new();
    IDENTITY.get_or_init(|| {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
        use std::io::Read as _;

        let mut buffer = vec![0u8; 32 * 1024];
        let length =
            unsafe { ex_hermes_engine_binary_path(buffer.as_mut_ptr().cast(), buffer.len()) };
        if length <= 0 {
            return Err("failed to identify the loaded Hermes engine artifact".into());
        }
        buffer.truncate(length as usize);
        let text = std::str::from_utf8(&buffer)
            .map_err(|_| "loaded Hermes path is not UTF-8".to_owned())?;
        let path = std::fs::canonicalize(text).map_err(|error| {
            format!("failed to authenticate loaded Hermes artifact {text}: {error}")
        })?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
        }
        let mut file = options.open(&path).map_err(|error| {
            format!(
                "failed to pin loaded Hermes artifact {}: {error}",
                path.display()
            )
        })?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("failed to inspect loaded Hermes artifact: {error}"))?;
        if !metadata.is_file() {
            return Err("loaded Hermes artifact is not a regular file".into());
        }
        verify_loaded_mapping_object(&metadata)?;
        let object = engine_object_identity(&metadata)?;
        let mut hash = Sha256::new();
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut chunk)
                .map_err(|error| format!("failed to hash loaded Hermes artifact: {error}"))?;
            if read == 0 {
                break;
            }
            hash.update(&chunk[..read]);
        }
        let after = file
            .metadata()
            .map_err(|error| format!("failed to revalidate loaded Hermes artifact: {error}"))?;
        if engine_object_identity(&after)? != object || after.len() != metadata.len() {
            return Err("loaded Hermes artifact changed while it was authenticated".into());
        }
        let digest = format!("sha256-{}", URL_SAFE_NO_PAD.encode(hash.finalize()));
        Ok(LoadedEngineBinaryIdentity {
            engine_artifact_path: path,
            kind: "hermes".into(),
            binary_digest: digest,
            object,
            target_architecture: std::env::consts::ARCH.to_owned(),
            structural_features: loaded_engine_structural_features(),
        })
    })
}

pub fn loaded_engine_structural_features() -> Vec<String> {
    if cfg!(exact_frame_attribution) {
        vec![
            "hermes-frame-attribution".into(),
            "native-compartments".into(),
            "native-lockdown".into(),
        ]
    } else {
        Vec::new()
    }
}

fn engine_object_identity(
    metadata: &std::fs::Metadata,
) -> Result<capsec_semantics::model::ObjectIdentity, String> {
    #[cfg(unix)]
    {
        use capsec_semantics::model::{NonEmptyString, ObjectIdentity, ObjectPlatform};
        use std::os::unix::fs::MetadataExt;
        Ok(ObjectIdentity {
            platform: if cfg!(any(target_os = "macos", target_os = "ios")) {
                ObjectPlatform::Apple
            } else if cfg!(target_os = "android") {
                ObjectPlatform::Android
            } else {
                ObjectPlatform::Unix
            },
            volume: NonEmptyString::new(format!("dev:{}", metadata.dev()))?,
            file: NonEmptyString::new(format!("ino:{}", metadata.ino()))?,
        })
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        Err(
            "Windows cannot derive a stable loaded-engine object identity on this build; refusing pathname-only identity"
                .into(),
        )
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn verify_loaded_mapping_object(metadata: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let address = ex_hermes_engine_binary_path as usize;
    let maps = std::fs::read_to_string("/proc/self/maps")
        .map_err(|error| format!("failed to inspect loaded Hermes mapping: {error}"))?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else { continue };
        let _permissions = fields.next();
        let _offset = fields.next();
        let Some(device) = fields.next() else {
            continue;
        };
        let Some(inode) = fields.next() else { continue };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start, 16),
            usize::from_str_radix(end, 16),
        ) else {
            continue;
        };
        if !(start..end).contains(&address) {
            continue;
        }
        let mapped_inode = inode
            .parse::<u64>()
            .map_err(|_| "loaded Hermes mapping has an invalid inode".to_owned())?;
        let Some((major, minor)) = device.split_once(':') else {
            return Err("loaded Hermes mapping has an invalid device".into());
        };
        let major = u64::from_str_radix(major, 16)
            .map_err(|_| "loaded Hermes mapping has an invalid device major".to_owned())?;
        let minor = u64::from_str_radix(minor, 16)
            .map_err(|_| "loaded Hermes mapping has an invalid device minor".to_owned())?;
        let mapped_device = libc::makedev(major as _, minor as _) as u64;
        if mapped_inode != metadata.ino() || mapped_device != metadata.dev() {
            return Err(
                "loaded Hermes path names a different object than the executable mapping".into(),
            );
        }
        return Ok(());
    }
    Err("could not locate the loaded Hermes executable mapping".into())
}

#[cfg(target_os = "macos")]
fn verify_loaded_mapping_object(metadata: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let mut device = 0u64;
    let mut inode = 0u64;
    if unsafe { ex_hermes_engine_mapped_object(&mut device, &mut inode) } != 1 {
        return Err("failed to identify the mapped Hermes vnode".into());
    }
    if device != metadata.dev() || inode != metadata.ino() {
        return Err(
            "loaded Hermes path names a different object than the mapped Mach-O image".into(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn verify_loaded_mapping_object(_metadata: &std::fs::Metadata) -> Result<(), String> {
    Err(
        "Windows cannot attest the loaded Hermes section's file identity on this build; refusing pathname-only identity"
            .into(),
    )
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
fn verify_loaded_mapping_object(_metadata: &std::fs::Metadata) -> Result<(), String> {
    Err("this target cannot attest the loaded Hermes image object".into())
}

/// Identity of the artifact that supplied the linked Hermes runtime factory.
/// The multi-megabyte digest is cached because the loaded artifact cannot
/// change within the process execution it identifies.
pub fn loaded_engine_binary_path() -> Result<std::path::PathBuf, String> {
    loaded_engine_identity()
        .as_ref()
        .map(|identity| identity.engine_artifact_path.clone())
        .map_err(Clone::clone)
}

pub fn loaded_engine_binary_digest() -> Result<String, String> {
    loaded_engine_identity()
        .as_ref()
        .map(|identity| identity.binary_digest.clone())
        .map_err(Clone::clone)
}

pub fn loaded_engine_binary_identity() -> Result<LoadedEngineBinaryIdentity, String> {
    loaded_engine_identity()
        .as_ref()
        .cloned()
        .map_err(Clone::clone)
}

/// HBC version accepted by the mapped Hermes engine. This deliberately does
/// not consult a separately discovered CLI binary.
pub fn loaded_engine_bytecode_version() -> Result<u32, String> {
    let version = unsafe { ex_hermes_bytecode_version() };
    (version != 0)
        .then_some(version)
        .ok_or_else(|| "loaded Hermes engine did not expose its bytecode version".into())
}

pub fn verify_loaded_engine_binary_identity(
    expected: &LoadedEngineBinaryIdentity,
) -> Result<LoadedEngineBinaryIdentity, String> {
    let actual = loaded_engine_binary_identity()?;
    if &actual != expected {
        return Err("loaded Hermes identity differs from the expected artifact".into());
    }
    Ok(actual)
}

/// Flag set when a background callback is pushed.
/// iOS polls this to know when to wake up the event loop.
static CALLBACK_PENDING: AtomicBool = AtomicBool::new(false);

/// Host wake hook (exact LLP 0297 W4b/B8): a wake-driven host executor
/// parks its runtime thread on a condition variable instead of polling the
/// pending flag, so it needs a push notification when a cross-thread
/// callback lands. Stored as raw words so invocation from arbitrary
/// threads is lock-free. Registration is expected once at host boot;
/// re-registration is not synchronized against a concurrent notify (a
/// racing reader may pair the new fn with the old context).
static HOST_WAKE_HOOK_FN: AtomicUsize = AtomicUsize::new(0);
static HOST_WAKE_HOOK_CTX: AtomicUsize = AtomicUsize::new(0);

/// Register (or clear, with `None`) the host wake hook invoked whenever a
/// background thread pushes a runtime callback. The hook runs on the
/// pushing thread and must only do cheap, bounded work (enqueue + signal a
/// condvar). The one library-owned notify symbol always invokes this hook;
/// CLI profiles register their tokio wake function through it at runtime.
#[no_mangle]
pub extern "C" fn ex_hermes_set_host_wake_hook(
    hook: Option<extern "C" fn(*mut std::ffi::c_void)>,
    context: *mut std::ffi::c_void,
) {
    HOST_WAKE_HOOK_CTX.store(context as usize, Ordering::Release);
    HOST_WAKE_HOOK_FN.store(hook.map_or(0, |f| f as usize), Ordering::Release);
}

fn invoke_host_wake_hook() {
    let raw_fn = HOST_WAKE_HOOK_FN.load(Ordering::Acquire);
    if raw_fn == 0 {
        return;
    }
    let context = HOST_WAKE_HOOK_CTX.load(Ordering::Acquire) as *mut std::ffi::c_void;
    // SAFETY: raw_fn was stored from a valid `extern "C" fn(*mut c_void)`
    // in ex_hermes_set_host_wake_hook and is only transmuted back to that
    // exact type.
    let hook: extern "C" fn(*mut std::ffi::c_void) = unsafe { std::mem::transmute(raw_fn) };
    hook(context);
}

/// Default implementation of ex_hermes_notify_callback for iOS/standalone use.
/// This is called from C++ (hermes_runtime.cc) when async callbacks are pushed
/// from background threads.
///
/// This symbol is deliberately owned by the library in every feature profile.
/// A binary that needs a specialized wake mechanism registers it through
/// `ex_hermes_set_host_wake_hook`; defining a replacement global symbol made
/// `cli-notify` integration-test link units fail when the CLI object was absent
/// (ENG-24265).
#[no_mangle]
pub extern "C" fn ex_hermes_notify_callback() {
    CALLBACK_PENDING.store(true, Ordering::Release);
    invoke_host_wake_hook();
}

/// Check and clear the callback pending flag.
/// Called from the event loop polling code.
pub fn take_callback_pending() -> bool {
    CALLBACK_PENDING.swap(false, Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use std::ffi::{c_void, CStr, CString};
    use std::os::raw::c_char;

    #[test]
    fn loaded_engine_identity_attests_the_mapped_artifact() {
        let identity = super::loaded_engine_binary_identity().unwrap();
        assert_eq!(identity.kind, "hermes");
        assert!(identity.engine_artifact_path.is_absolute());
        assert!(identity.binary_digest.starts_with("sha256-"));
        assert_eq!(identity.target_architecture, std::env::consts::ARCH);
        assert!(super::loaded_engine_bytecode_version().unwrap() > 0);
        assert_eq!(
            super::verify_loaded_engine_binary_identity(&identity).unwrap(),
            identity
        );
    }

    #[repr(C)]
    struct HermesRuntimeOpaque {
        _private: [u8; 0],
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(C)]
    struct WorkletSharedValueHandle {
        slot: u32,
        generation: u32,
        epoch: u32,
    }

    const WORKLET_CAPTURE_F32: u32 = 1;
    const WORKLET_CAPTURE_BOOL: u32 = 2;
    const WORKLET_CAPTURE_SHARED_VALUE: u32 = 3;
    const WORKLET_INSTALL_SOURCE_UTF8: u32 = 1;
    const WORKLET_RUN_ON_JS_SLOTS: usize = 8;

    #[derive(Clone, Copy)]
    #[repr(C)]
    struct WorkletCapture {
        kind: u32,
        scalar: f32,
        shared_value: WorkletSharedValueHandle,
    }

    #[derive(Clone, Copy, Debug)]
    #[repr(C)]
    struct WorkletScheduledCall {
        source_identity: u64,
        source_sequence: u64,
        generation: u64,
        callback_identity: u32,
        argument_count: u32,
        arguments: [f32; WORKLET_RUN_ON_JS_SLOTS],
    }

    impl Default for WorkletScheduledCall {
        fn default() -> Self {
            Self {
                source_identity: 0,
                source_sequence: 0,
                generation: 0,
                callback_identity: 0,
                argument_count: 0,
                arguments: [0.0; WORKLET_RUN_ON_JS_SLOTS],
            }
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    #[repr(C)]
    struct WorkletInstallMetrics {
        source_install_count: u64,
        reused_install_count: u64,
        source_install_total_ns: u64,
        source_install_max_ns: u64,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6EvidenceSource {
        path: String,
        sha256: String,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6Transaction {
        epoch: u32,
        motion_seq: String,
        root_instance: u32,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6CaptureEvidence {
        kind: String,
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        descriptor_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generation: Option<u32>,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6CallbackEvidence {
        identity: u32,
        action: String,
        payload_keys: Vec<String>,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6ArtifactEvidence {
        schema_version: u32,
        descriptor_id: String,
        node_id: u32,
        phase: String,
        generation: u64,
        compiler_id: String,
        install_format: String,
        source: String,
        source_identity: String,
        callback_identity: String,
        captures: Vec<MotionM6CaptureEvidence>,
        input_slots: Vec<String>,
        output_slots: Vec<String>,
        callbacks: Vec<MotionM6CallbackEvidence>,
        source_sha256: String,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6TierEvidence {
        tier: String,
        root_id: u32,
        transaction: MotionM6Transaction,
        artifacts: Vec<MotionM6ArtifactEvidence>,
    }

    #[derive(Clone, Debug, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct MotionM6GeneratedEvidence {
        schema_version: u32,
        generated_at_unix_ms: u64,
        generator: String,
        sources: Vec<MotionM6EvidenceSource>,
        tiers: Vec<MotionM6TierEvidence>,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct MotionM6EvidenceFile {
        schema_version: u32,
        generated_at_unix_ms: u64,
        generator: String,
        sources: Vec<MotionM6EvidenceSource>,
        tiers: Vec<MotionM6TierEvidence>,
        evidence_sha256: String,
    }

    #[derive(Clone, Copy, Debug)]
    #[repr(C)]
    struct MotionRatedPublishSample {
        channel_identity: u64,
        dirty_generation: u64,
        sample_time_ns: u64,
        value_count: u32,
        flags: u32,
        values: [f32; WORKLET_RUN_ON_JS_SLOTS],
    }

    type WorkletSharedValueReadCallback =
        extern "C" fn(WorkletSharedValueHandle, *mut f32, *mut c_void) -> u32;
    type WorkletSharedValueWriteCallback =
        extern "C" fn(WorkletSharedValueHandle, f32, *mut c_void) -> u32;

    extern "C" {
        fn ex_hermes_create() -> *mut HermesRuntimeOpaque;
        fn ex_hermes_create_diagnostic() -> *mut HermesRuntimeOpaque;
        fn ex_hermes_destroy(runtime: *mut HermesRuntimeOpaque);
        fn ex_hermes_eval(
            runtime: *mut HermesRuntimeOpaque,
            data: *const u8,
            len: usize,
            source_url: *const c_char,
            is_bytecode: i32,
            out_value: *mut *mut c_char,
        ) -> i32;
        #[cfg(target_os = "windows")]
        fn ex_host_install();
        fn ex_hermes_free_string(value: *mut c_char);
        fn ex_hermes_get_gc_stats(runtime: *mut HermesRuntimeOpaque) -> *mut c_char;
        fn ex_hermes_poll(runtime: *mut HermesRuntimeOpaque, now_ms: u64) -> i32;
        fn ex_hermes_set_keep_alive_on_async_error(runtime: *mut HermesRuntimeOpaque, enabled: i32);
        fn ex_hermes_next_timer(runtime: *mut HermesRuntimeOpaque) -> i64;
        fn ex_hermes_now_ms() -> u64;
        fn ex_hermes_callback_backlog(runtime: *mut HermesRuntimeOpaque) -> u32;
        fn ex_hermes_runtime_nonce(runtime: *mut HermesRuntimeOpaque) -> u64;
        fn ex_hermes_schedule_watchdog_heartbeat(
            runtime: *mut HermesRuntimeOpaque,
            callback: extern "C" fn(*mut std::ffi::c_void),
            context: *mut std::ffi::c_void,
        );
        fn ex_hermes_schedule_watchdog_heartbeat_for_generation(
            runtime: *mut HermesRuntimeOpaque,
            runtime_nonce: u64,
            callback: extern "C" fn(*mut std::ffi::c_void),
            context: *mut std::ffi::c_void,
        );
        fn ex_worklet_create() -> *mut HermesRuntimeOpaque;
        fn ex_worklet_destroy(runtime: *mut HermesRuntimeOpaque);
        fn ex_worklet_set_generation(runtime: *mut HermesRuntimeOpaque, generation: u64);
        fn ex_worklet_install(
            runtime: *mut HermesRuntimeOpaque,
            worklet_id: *const c_char,
            source: *const u8,
            source_len: usize,
            generation: u64,
            out_error: *mut *mut c_char,
        ) -> i32;
        fn ex_worklet_invoke(
            runtime: *mut HermesRuntimeOpaque,
            worklet_id: *const c_char,
            args_json: *const c_char,
            out_result_json: *mut *mut c_char,
        ) -> i32;
        fn ex_worklet_install_typed(
            runtime: *mut HermesRuntimeOpaque,
            install_format: u32,
            artifact: *const u8,
            artifact_len: usize,
            captures: *const WorkletCapture,
            capture_count: u32,
            generation: u64,
            out_identity: *mut u64,
            out_error: *mut *mut c_char,
        ) -> i32;
        fn ex_worklet_invoke_typed(
            runtime: *mut HermesRuntimeOpaque,
            identity: u64,
            inputs: *const f32,
            input_count: u32,
            outputs: *mut f32,
            output_capacity: u32,
            out_output_count: *mut u32,
        ) -> i32;
        fn ex_worklet_install_metrics(
            runtime: *mut HermesRuntimeOpaque,
            out_metrics: *mut WorkletInstallMetrics,
        ) -> i32;
        fn ex_worklet_drain_scheduled_typed(
            runtime: *mut HermesRuntimeOpaque,
            out_calls: *mut WorkletScheduledCall,
            capacity: u32,
        ) -> u32;
        fn ex_worklet_take_scheduled_drop_count(runtime: *mut HermesRuntimeOpaque) -> u64;
        fn ex_hermes_dispatch_worklet_calls(
            runtime: *mut HermesRuntimeOpaque,
            calls: *const WorkletScheduledCall,
            count: u32,
            out_delivered: *mut u32,
        ) -> i32;
        fn ex_hermes_dispatch_worklet_json_batch(
            runtime: *mut HermesRuntimeOpaque,
            batch_json: *const u8,
            batch_len: usize,
            generation: u64,
        ) -> i32;
        fn ex_hermes_dispatch_motion_rated_publish(
            runtime: *mut HermesRuntimeOpaque,
            sample: *const MotionRatedPublishSample,
        ) -> i32;
        fn ex_worklet_bind_shared_value_accessors(
            runtime: *mut HermesRuntimeOpaque,
            read_callback: Option<WorkletSharedValueReadCallback>,
            write_callback: Option<WorkletSharedValueWriteCallback>,
            context: *mut c_void,
        ) -> i32;
    }

    #[derive(Debug)]
    struct SharedValueHost {
        expected: WorkletSharedValueHandle,
        value: f32,
        reads: u32,
        writes: u32,
        rejected_reads: u32,
        rejected_writes: u32,
    }

    extern "C" fn read_shared_value(
        handle: WorkletSharedValueHandle,
        out_value: *mut f32,
        context: *mut c_void,
    ) -> u32 {
        if context.is_null() || out_value.is_null() {
            return 2;
        }
        // SAFETY: the test keeps the boxed host alive until after it unbinds
        // the callbacks and destroys the single-owner worklet runtime.
        let host = unsafe { &mut *context.cast::<SharedValueHost>() };
        if handle != host.expected {
            host.rejected_reads += 1;
            return 1;
        }
        host.reads += 1;
        // SAFETY: the C++ bridge supplies a non-null pointer to one float.
        unsafe { *out_value = host.value };
        0
    }

    extern "C" fn write_shared_value(
        handle: WorkletSharedValueHandle,
        value: f32,
        context: *mut c_void,
    ) -> u32 {
        if context.is_null() {
            return 2;
        }
        // SAFETY: see read_shared_value; callback invocation is synchronous.
        let host = unsafe { &mut *context.cast::<SharedValueHost>() };
        if handle != host.expected {
            host.rejected_writes += 1;
            return 1;
        }
        host.writes += 1;
        host.value = value;
        0
    }

    fn install_worklet(
        runtime: *mut HermesRuntimeOpaque,
        id: &CString,
        source: &str,
        generation: u64,
    ) {
        let mut error = std::ptr::null_mut();
        let status = unsafe {
            ex_worklet_install(
                runtime,
                id.as_ptr(),
                source.as_ptr(),
                source.len(),
                generation,
                &mut error,
            )
        };
        let message = if error.is_null() {
            None
        } else {
            let text = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe { ex_hermes_free_string(error) };
            Some(text)
        };
        assert_eq!(status, 0, "worklet install failed: {message:?}");
    }

    fn invoke_worklet(runtime: *mut HermesRuntimeOpaque, id: &CString) -> String {
        let mut result = std::ptr::null_mut();
        let status =
            unsafe { ex_worklet_invoke(runtime, id.as_ptr(), std::ptr::null(), &mut result) };
        assert_eq!(status, 0, "worklet invoke failed");
        assert!(!result.is_null(), "worklet result must be JSON encoded");
        let text = unsafe { CStr::from_ptr(result) }
            .to_string_lossy()
            .into_owned();
        unsafe { ex_hermes_free_string(result) };
        text
    }

    unsafe fn install_typed_worklet(
        runtime: *mut HermesRuntimeOpaque,
        source: &str,
        captures: &[WorkletCapture],
        generation: u64,
    ) -> u64 {
        let mut identity = 0;
        let mut error = std::ptr::null_mut();
        let status = ex_worklet_install_typed(
            runtime,
            WORKLET_INSTALL_SOURCE_UTF8,
            source.as_ptr(),
            source.len(),
            captures.as_ptr(),
            captures.len() as u32,
            generation,
            &mut identity,
            &mut error,
        );
        let message = if error.is_null() {
            None
        } else {
            let text = CStr::from_ptr(error).to_string_lossy().into_owned();
            ex_hermes_free_string(error);
            Some(text)
        };
        assert_eq!(status, 0, "typed worklet install failed: {message:?}");
        assert_ne!(identity, 0);
        identity
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        format!("{:x}", Sha256::digest(bytes))
    }

    fn load_motion_m6_evidence() -> Option<MotionM6GeneratedEvidence> {
        let evidence_path = std::env::var_os("EXACT_MOTION_M6_ARTIFACTS")?;
        let bytes = std::fs::read(&evidence_path).unwrap_or_else(|error| {
            panic!(
                "failed to read EXACT_MOTION_M6_ARTIFACTS {}: {error}",
                std::path::Path::new(&evidence_path).display(),
            )
        });
        let evidence: MotionM6EvidenceFile =
            serde_json::from_slice(&bytes).expect("Motion M6 evidence must be strict JSON");
        let generated = MotionM6GeneratedEvidence {
            schema_version: evidence.schema_version,
            generated_at_unix_ms: evidence.generated_at_unix_ms,
            generator: evidence.generator,
            sources: evidence.sources,
            tiers: evidence.tiers,
        };
        assert_eq!(
            generated.schema_version, 1,
            "unsupported Motion M6 evidence schema"
        );
        assert_eq!(
            generated.generator, "scripts/check-motion-m6-authoring.ts",
            "Motion M6 evidence must come from the registered authoring twin",
        );
        let canonical_bytes =
            serde_json::to_vec(&generated).expect("Motion M6 evidence must reserialize");
        assert_eq!(
            sha256_hex(&canonical_bytes),
            evidence.evidence_sha256,
            "Motion M6 evidence digest does not authenticate the generated payload",
        );

        let max_age_ms = std::env::var("EXACT_MOTION_M6_ARTIFACT_MAX_AGE_MS")
            .unwrap_or_else(|_| "300000".to_owned())
            .parse::<u64>()
            .expect("EXACT_MOTION_M6_ARTIFACT_MAX_AGE_MS must be a u64");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_millis() as u64;
        assert!(
            generated.generated_at_unix_ms <= now_ms.saturating_add(10_000),
            "Motion M6 evidence timestamp is implausibly in the future",
        );
        assert!(
            now_ms.saturating_sub(generated.generated_at_unix_ms) <= max_age_ms,
            "Motion M6 evidence is stale (generated={}, now={}, maxAgeMs={})",
            generated.generated_at_unix_ms,
            now_ms,
            max_age_ms,
        );

        const EXPECTED_SOURCES: [&str; 5] = [
            "scripts/check-motion-m6-authoring.ts",
            "tests/motion/m6-authoring-twin.contract",
            "tests/motion/m6-authoring-twin.react.ts",
            "packages/exact-contract/src/compiler/motion-worklet-source.ts",
            "packages/exact-devtools/src/worklet-source-plugin.ts",
        ];
        assert_eq!(
            generated
                .sources
                .iter()
                .map(|source| source.path.as_str())
                .collect::<Vec<_>>(),
            EXPECTED_SOURCES,
            "Motion M6 provenance source set drifted",
        );
        let exact_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("Ibex must be vendored under Exact/vendor");
        for source in &generated.sources {
            let source_bytes =
                std::fs::read(exact_root.join(&source.path)).unwrap_or_else(|error| {
                    panic!("failed to read provenance source {}: {error}", source.path)
                });
            assert_eq!(
                sha256_hex(&source_bytes),
                source.sha256,
                "Motion M6 provenance source {} changed after evidence generation",
                source.path,
            );
        }

        assert_eq!(
            generated.tiers.len(),
            2,
            "expected Contract and React evidence"
        );
        assert_eq!(generated.tiers[0].tier, "contract");
        assert_eq!(generated.tiers[0].root_id, 2_470_401);
        assert_eq!(generated.tiers[1].tier, "react");
        assert_eq!(generated.tiers[1].root_id, 2_470_402);
        for tier in &generated.tiers {
            assert!(tier.transaction.epoch > 0);
            assert!(tier.transaction.root_instance > 0);
            assert!(
                tier.transaction
                    .motion_seq
                    .parse::<u64>()
                    .is_ok_and(|sequence| sequence > 0),
                "{} Motion transaction sequence must be positive",
                tier.tier,
            );
            assert_eq!(
                tier.artifacts.len(),
                4,
                "{} must emit four artifacts",
                tier.tier
            );
            let phase_count = |phase: &str| {
                tier.artifacts
                    .iter()
                    .filter(|artifact| artifact.phase == phase)
                    .count()
            };
            assert_eq!(
                phase_count("derive"),
                2,
                "{} must emit two projections",
                tier.tier
            );
            assert_eq!(
                phase_count("update"),
                1,
                "{} must emit one update",
                tier.tier
            );
            assert_eq!(
                phase_count("end"),
                1,
                "{} must emit one terminal callback",
                tier.tier
            );
            for artifact in &tier.artifacts {
                assert_eq!(artifact.schema_version, 2);
                assert_eq!(artifact.install_format, "source-utf8");
                assert!(artifact.node_id > 0);
                assert!(artifact.generation > 0);
                assert!(!artifact.compiler_id.is_empty());
                assert!(
                    artifact
                        .descriptor_id
                        .parse::<u64>()
                        .is_ok_and(|identity| identity > 0),
                    "{} descriptor identity must be a positive u64",
                    artifact.compiler_id,
                );
                assert!(artifact.source_identity.parse::<u64>().is_ok());
                assert!(artifact.callback_identity.parse::<u64>().is_ok());
                assert_eq!(
                    sha256_hex(artifact.source.as_bytes()),
                    artifact.source_sha256,
                    "{} artifact source digest mismatch",
                    artifact.compiler_id,
                );
                assert!(artifact.input_slots.len() <= 16);
                assert!(artifact.output_slots.len() <= 16);
                match artifact.phase.as_str() {
                    "derive" => {
                        assert!(artifact.input_slots.is_empty());
                        assert_eq!(artifact.output_slots, ["return.value"]);
                        assert_eq!(artifact.captures.len(), 1);
                        assert!(artifact.callbacks.is_empty());
                    }
                    "update" => {
                        assert_eq!(artifact.input_slots.len(), 1);
                        assert!(artifact.output_slots.is_empty());
                        assert_eq!(artifact.captures.len(), 1);
                        assert!(artifact.callbacks.is_empty());
                    }
                    "end" => {
                        assert_eq!(artifact.input_slots.len(), 2);
                        assert!(artifact.output_slots.is_empty());
                        assert!(artifact.captures.is_empty());
                        assert_eq!(artifact.callbacks.len(), 1);
                        assert_eq!(artifact.callbacks[0].action, "observe");
                        assert_eq!(artifact.callbacks[0].payload_keys, ["x", "velocity"]);
                    }
                    other => panic!("unexpected Motion M6 artifact phase {other}"),
                }
            }
        }
        Some(generated)
    }

    unsafe fn worklet_total_allocated_bytes(runtime: *mut HermesRuntimeOpaque) -> u64 {
        let stats = ex_hermes_get_gc_stats(runtime);
        assert!(!stats.is_null(), "Hermes GC stats must be available");
        let text = CStr::from_ptr(stats).to_string_lossy().into_owned();
        ex_hermes_free_string(stats);
        let marker = "\"totalAllocatedBytes\":";
        let cursor = text
            .find(marker)
            .map(|offset| offset + marker.len())
            .expect("Hermes GC stats must include totalAllocatedBytes");
        let digits = text[cursor..]
            .trim_start()
            .bytes()
            .take_while(u8::is_ascii_digit)
            .collect::<Vec<_>>();
        assert!(!digits.is_empty(), "totalAllocatedBytes must be an integer");
        std::str::from_utf8(&digits)
            .expect("allocation counter digits must be UTF-8")
            .parse::<u64>()
            .expect("totalAllocatedBytes must fit in u64")
    }

    unsafe fn invoke_typed_repeatedly(
        runtime: *mut HermesRuntimeOpaque,
        identity: u64,
        input_count: usize,
        output_capacity: usize,
        expected_output_count: u32,
        sample_count: u64,
    ) {
        let inputs = vec![2.0_f32; input_count];
        let mut outputs = vec![0.0_f32; output_capacity];
        let input_ptr = if inputs.is_empty() {
            std::ptr::null()
        } else {
            inputs.as_ptr()
        };
        let output_ptr = if outputs.is_empty() {
            std::ptr::null_mut()
        } else {
            outputs.as_mut_ptr()
        };
        for _ in 0..sample_count {
            let mut output_count = 0;
            assert_eq!(
                ex_worklet_invoke_typed(
                    runtime,
                    identity,
                    input_ptr,
                    input_count as u32,
                    output_ptr,
                    output_capacity as u32,
                    &mut output_count,
                ),
                0,
            );
            assert_eq!(output_count, expected_output_count);
        }
    }

    unsafe fn typed_allocation_slope(
        runtime: *mut HermesRuntimeOpaque,
        identity: u64,
        input_count: usize,
        output_capacity: usize,
        expected_output_count: u32,
        sample_count: u64,
    ) -> u64 {
        let before = worklet_total_allocated_bytes(runtime);
        invoke_typed_repeatedly(
            runtime,
            identity,
            input_count,
            output_capacity,
            expected_output_count,
            sample_count,
        );
        let after = worklet_total_allocated_bytes(runtime);
        assert!(
            after >= before,
            "Hermes' cumulative allocation counter must be monotonic"
        );
        after - before
    }

    fn motion_m6_worklet_captures(
        artifact: &MotionM6ArtifactEvidence,
        epoch: u32,
    ) -> Vec<WorkletCapture> {
        artifact
            .captures
            .iter()
            .map(|capture| match capture.kind.as_str() {
                "f32" => {
                    assert!(capture.descriptor_id.is_none());
                    assert!(capture.generation.is_none());
                    let value = capture
                        .value
                        .as_ref()
                        .and_then(serde_json::Value::as_f64)
                        .expect("f32 capture must carry a numeric value");
                    assert!(value.is_finite());
                    assert!(value >= f32::MIN as f64 && value <= f32::MAX as f64);
                    WorkletCapture {
                        kind: WORKLET_CAPTURE_F32,
                        scalar: value as f32,
                        shared_value: WorkletSharedValueHandle {
                            slot: 0,
                            generation: 0,
                            epoch: 0,
                        },
                    }
                }
                "bool" => {
                    assert!(capture.descriptor_id.is_none());
                    assert!(capture.generation.is_none());
                    WorkletCapture {
                        kind: WORKLET_CAPTURE_BOOL,
                        scalar: if capture
                            .value
                            .as_ref()
                            .and_then(serde_json::Value::as_bool)
                            .expect("bool capture must carry a boolean value")
                        {
                            1.0
                        } else {
                            0.0
                        },
                        shared_value: WorkletSharedValueHandle {
                            slot: 0,
                            generation: 0,
                            epoch: 0,
                        },
                    }
                }
                "sharedValue" => {
                    assert!(capture.value.is_none());
                    let descriptor_id = capture
                        .descriptor_id
                        .as_deref()
                        .expect("SharedValue capture must carry descriptorId")
                        .parse::<u64>()
                        .expect("SharedValue descriptorId must fit u64");
                    assert!(descriptor_id > 0);
                    let folded_slot = (descriptor_id ^ (descriptor_id >> 32)) as u32;
                    WorkletCapture {
                        kind: WORKLET_CAPTURE_SHARED_VALUE,
                        scalar: 0.0,
                        shared_value: WorkletSharedValueHandle {
                            slot: folded_slot.max(1),
                            generation: capture
                                .generation
                                .expect("SharedValue capture must carry generation"),
                            epoch,
                        },
                    }
                }
                other => panic!("unsupported Motion M6 capture kind {other}"),
            })
            .collect()
    }

    fn motion_m6_matched_control(artifact: &MotionM6ArtifactEvidence) -> String {
        match artifact.phase.as_str() {
            "derive" if artifact.source.contains("worklet.clamp") => {
                "(function(){worklet.output(0,worklet.clamp((Math.abs(worklet.captureGet(0))/320),0,1));})".to_owned()
            }
            "derive" if artifact.source.contains("Math.max") => {
                "()=>{worklet.output(0,Math.max(0,Math.min(1,Math.abs(worklet.captureGet(0))/320)));return;}".to_owned()
            }
            "derive" if artifact.source.starts_with("()=>") => {
                "()=>{worklet.output(0,worklet.captureGet(0)+0);return;}".to_owned()
            }
            "derive" => {
                "(function(){worklet.output(0,worklet.captureGet(0)+0);})".to_owned()
            }
            "update" if artifact.source.contains("=>") => {
                "__exactInput0=>{worklet.captureSet(0,__exactInput0+0);}".to_owned()
            }
            "update" => {
                "(function(__exactInput0){worklet.captureSet(0,__exactInput0+0);})".to_owned()
            }
            "end" if artifact.source.contains("=>") => {
                "(__exactInput0,__exactInput1)=>{worklet.runOnJS(1,__exactInput0,__exactInput1);}".to_owned()
            }
            "end" => {
                "(function(__exactInput0,__exactInput1){worklet.runOnJS(1,__exactInput0,__exactInput1);})".to_owned()
            }
            other => panic!("unsupported Motion M6 artifact phase {other}"),
        }
    }

    unsafe fn measure_motion_m6_tier(tier: &MotionM6TierEvidence) {
        const WARMUP: u64 = 128;
        const SAMPLES: u64 = 2_048;
        let generation = tier.artifacts[0].generation;
        assert!(tier
            .artifacts
            .iter()
            .all(|artifact| artifact.generation == generation));

        let captures = tier
            .artifacts
            .iter()
            .map(|artifact| {
                (
                    artifact,
                    motion_m6_worklet_captures(artifact, tier.transaction.epoch),
                )
            })
            .collect::<Vec<_>>();
        let mut shared_handles = captures
            .iter()
            .flat_map(|(_, captures)| captures)
            .filter(|capture| capture.kind == WORKLET_CAPTURE_SHARED_VALUE)
            .map(|capture| capture.shared_value)
            .collect::<Vec<_>>();
        shared_handles.dedup();
        assert_eq!(
            shared_handles.len(),
            1,
            "{} fixture must project one SharedValue identity",
            tier.tier,
        );

        let runtime = ex_worklet_create();
        assert!(!runtime.is_null());
        let mut host = Box::new(SharedValueHost {
            expected: shared_handles[0],
            value: 80.0,
            reads: 0,
            writes: 0,
            rejected_reads: 0,
            rejected_writes: 0,
        });
        let context = (&mut *host as *mut SharedValueHost).cast::<c_void>();
        assert_eq!(
            ex_worklet_bind_shared_value_accessors(
                runtime,
                Some(read_shared_value),
                Some(write_shared_value),
                context,
            ),
            0,
        );
        ex_worklet_set_generation(runtime, generation);

        for (artifact, captures) in &captures {
            let candidate =
                install_typed_worklet(runtime, &artifact.source, captures, artifact.generation);
            let control = install_typed_worklet(
                runtime,
                &motion_m6_matched_control(artifact),
                captures,
                artifact.generation,
            );
            invoke_typed_repeatedly(
                runtime,
                candidate,
                artifact.input_slots.len(),
                artifact.output_slots.len(),
                artifact.output_slots.len() as u32,
                WARMUP,
            );
            invoke_typed_repeatedly(
                runtime,
                control,
                artifact.input_slots.len(),
                artifact.output_slots.len(),
                artifact.output_slots.len() as u32,
                WARMUP,
            );
            let candidate_bytes = typed_allocation_slope(
                runtime,
                candidate,
                artifact.input_slots.len(),
                artifact.output_slots.len(),
                artifact.output_slots.len() as u32,
                SAMPLES,
            );
            let control_bytes = typed_allocation_slope(
                runtime,
                control,
                artifact.input_slots.len(),
                artifact.output_slots.len(),
                artifact.output_slots.len() as u32,
                SAMPLES,
            );
            eprintln!(
                concat!(
                    "motion-worklet-generated-artifact: tier={} compiler={} phase={} ",
                    "samples={} raw-control={} raw-candidate={} semantic-excess={}",
                ),
                tier.tier,
                artifact.compiler_id,
                artifact.phase,
                SAMPLES,
                control_bytes,
                candidate_bytes,
                candidate_bytes.saturating_sub(control_bytes),
            );
            assert!(control_bytes > 0, "retain raw Hermes ABI allocation truth");
            assert_eq!(
                candidate_bytes, control_bytes,
                "{} {} generated artifact must have zero semantic/excess allocation bytes",
                tier.tier, artifact.compiler_id,
            );
        }

        let (derive, derive_captures) = captures
            .iter()
            .find(|(artifact, _)| {
                artifact.phase == "derive"
                    && !artifact.source.contains("worklet.clamp")
                    && !artifact.source.contains("Math.max")
            })
            .expect("Motion M6 evidence must include the direct scalar projection");
        let negative = install_typed_worklet(
            runtime,
            "(function(){var box={value:worklet.captureGet(0)};worklet.output(0,box.value);})",
            derive_captures,
            derive.generation,
        );
        let control = install_typed_worklet(
            runtime,
            &motion_m6_matched_control(derive),
            derive_captures,
            derive.generation,
        );
        invoke_typed_repeatedly(runtime, negative, 0, 1, 1, WARMUP);
        invoke_typed_repeatedly(runtime, control, 0, 1, 1, WARMUP);
        let negative_bytes = typed_allocation_slope(runtime, negative, 0, 1, 1, SAMPLES);
        let control_bytes = typed_allocation_slope(runtime, control, 0, 1, 1, SAMPLES);
        assert!(
            negative_bytes > control_bytes,
            "{} negative object-allocation control must exceed its matched control",
            tier.tier,
        );
        eprintln!(
            "motion-worklet-generated-negative: tier={} samples={} raw-control={} raw-negative={} semantic-excess={}",
            tier.tier,
            SAMPLES,
            control_bytes,
            negative_bytes,
            negative_bytes.saturating_sub(control_bytes),
        );

        assert_eq!(host.rejected_reads, 0);
        assert_eq!(host.rejected_writes, 0);
        assert_eq!(
            ex_worklet_bind_shared_value_accessors(runtime, None, None, std::ptr::null_mut()),
            0,
        );
        ex_worklet_destroy(runtime);
    }

    /// LLP 0099 M6 forbids object/string allocation in the hot math path; it
    /// does not pretend Hermes' fixed JSI call cells disappear. Compare raw
    /// cumulative slopes in one warmed runtime with identical input/output
    /// host-call shapes, and require zero candidate excess. The allocating
    /// control proves that this counter detects the object-literal regression
    /// the compiler is required to exclude.
    #[test]
    fn motion_worklet_semantic_allocation_slope_is_flat() {
        if let Some(evidence) = load_motion_m6_evidence() {
            unsafe {
                for tier in &evidence.tiers {
                    measure_motion_m6_tier(tier);
                }
            }
            return;
        }

        // The standalone Ibex suite has no Exact authoring toolchain. Retain
        // one local source-shape sentinel there; the registered Exact M6
        // acceptance wrapper always supplies authenticated generated evidence
        // and therefore takes the branch above.
        unsafe {
            const WARMUP: u64 = 128;
            const SAMPLES: u64 = 2_048;
            let runtime = ex_worklet_create();
            assert!(!runtime.is_null());
            ex_worklet_set_generation(runtime, 1);

            let control = install_typed_worklet(
                runtime,
                "(function (input) { worklet.output(0, input); })",
                &[],
                1,
            );
            let candidate = install_typed_worklet(
                runtime,
                "(function (input) { worklet.output(0, input * 2 + 1); })",
                &[],
                1,
            );
            let allocating_control = install_typed_worklet(
                runtime,
                "(function (input) { var box = { value: input * 2 + 1 }; worklet.output(0, box.value); })",
                &[],
                1,
            );

            for identity in [control, candidate, allocating_control] {
                invoke_typed_repeatedly(runtime, identity, 1, 1, 1, WARMUP);
            }

            let control_bytes = typed_allocation_slope(runtime, control, 1, 1, 1, SAMPLES);
            let candidate_bytes = typed_allocation_slope(runtime, candidate, 1, 1, 1, SAMPLES);
            let allocating_bytes =
                typed_allocation_slope(runtime, allocating_control, 1, 1, 1, SAMPLES);

            eprintln!(
                concat!(
                    "motion-worklet-allocation: samples={} raw-control={} ",
                    "raw-candidate={} semantic-excess={} allocating-control={}",
                ),
                SAMPLES,
                control_bytes,
                candidate_bytes,
                candidate_bytes.saturating_sub(control_bytes),
                allocating_bytes,
            );

            assert!(control_bytes > 0, "retain raw Hermes ABI allocation truth");
            assert_eq!(
                candidate_bytes, control_bytes,
                "scalar math must have zero semantic/excess allocation bytes"
            );
            assert!(
                allocating_bytes > control_bytes,
                "the paired counter must detect an object-literal allocation"
            );
            ex_worklet_destroy(runtime);
        }
    }

    fn eval(runtime: *mut HermesRuntimeOpaque, source: &str) -> (i32, Option<String>) {
        let url = std::ffi::CString::new("r1-test.js").expect("source url");
        let mut out: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_eval(
                runtime,
                source.as_ptr(),
                source.len(),
                url.as_ptr(),
                0,
                &mut out,
            )
        };
        let value = if out.is_null() {
            None
        } else {
            let text = unsafe { std::ffi::CStr::from_ptr(out) }
                .to_string_lossy()
                .into_owned();
            unsafe { ex_hermes_free_string(out) };
            Some(text)
        };
        (status, value)
    }

    /// Restricted worklets must cross the SharedValue boundary with the full
    /// typed identity. Stale identities are host-rejected no-ops, and values
    /// that cannot be represented as finite f32 never reach the host callback.
    #[test]
    fn worklet_shared_values_use_validating_typed_accessors() {
        unsafe {
            let runtime = ex_worklet_create();
            assert!(!runtime.is_null());

            let mut host = Box::new(SharedValueHost {
                expected: WorkletSharedValueHandle {
                    slot: 2,
                    generation: 7,
                    epoch: 3,
                },
                value: 41.0,
                reads: 0,
                writes: 0,
                rejected_reads: 0,
                rejected_writes: 0,
            });
            let context = (&mut *host as *mut SharedValueHost).cast::<c_void>();
            assert_eq!(
                ex_worklet_bind_shared_value_accessors(
                    runtime,
                    Some(read_shared_value),
                    Some(write_shared_value),
                    context,
                ),
                0
            );
            ex_worklet_set_generation(runtime, 1);

            let live_id = CString::new("typed-live").expect("worklet id");
            install_worklet(
                runtime,
                &live_id,
                "(function () { var s = worklet.sharedValue(2, 7, 3); s.set(s.get() + 1); return s.get(); })",
                1,
            );
            assert_eq!(invoke_worklet(runtime, &live_id), "42");
            assert_eq!(host.value, 42.0);
            assert_eq!((host.reads, host.writes), (2, 1));

            let stale_id = CString::new("typed-stale").expect("worklet id");
            install_worklet(
                runtime,
                &stale_id,
                "(function () { var s = worklet.sharedValue(2, 8, 3); s.set(99); return s.get() === undefined; })",
                1,
            );
            assert_eq!(invoke_worklet(runtime, &stale_id), "true");
            assert_eq!(host.value, 42.0, "stale write must be a no-op");
            assert_eq!((host.rejected_reads, host.rejected_writes), (1, 1));

            // A durable handle keeps its last successfully observed value
            // when the host later rejects that same typed identity. The raw
            // accessor still fails closed; only the language handle owns the
            // stale shadow required by LLP 0099 M1.
            let shadow_id = CString::new("typed-stale-shadow").expect("worklet id");
            install_worklet(
                runtime,
                &shadow_id,
                "(function () { var s = worklet.sharedValue(2, 7, 3); return function () { return s.get(); }; })()",
                1,
            );
            assert_eq!(invoke_worklet(runtime, &shadow_id), "42");
            host.expected.generation = 8;
            assert_eq!(invoke_worklet(runtime, &shadow_id), "42");
            assert_eq!(host.rejected_reads, 2);
            host.expected.generation = 7;

            let non_finite_id = CString::new("typed-non-finite").expect("worklet id");
            install_worklet(
                runtime,
                &non_finite_id,
                "(function () { worklet.sharedValue(2, 7, 3).set(Infinity); return 1; })",
                1,
            );
            assert_eq!(invoke_worklet(runtime, &non_finite_id), "1");
            assert_eq!(host.writes, 1, "non-finite value must not reach the host");
            assert_eq!(host.value, 42.0);

            assert_eq!(
                ex_worklet_bind_shared_value_accessors(runtime, None, None, std::ptr::null_mut(),),
                0
            );
            ex_worklet_destroy(runtime);
        }
    }

    /// LLP 0099 M6: the hot Motion worklet ABI is fixed f32 slots, captures
    /// are install-time scalars or full SharedValue identities, unchanged
    /// artifacts retain a stable callback identity, and runOnJS uses a
    /// bounded drop-oldest ring drained on the app runtime.
    #[test]
    fn motion_worklet_typed_abi_captures_and_run_on_js_are_bounded() {
        unsafe {
            let runtime = ex_worklet_create();
            assert!(!runtime.is_null());
            let mut host = Box::new(SharedValueHost {
                expected: WorkletSharedValueHandle {
                    slot: 3,
                    generation: 9,
                    epoch: 4,
                },
                value: 41.0,
                reads: 0,
                writes: 0,
                rejected_reads: 0,
                rejected_writes: 0,
            });
            let context = (&mut *host as *mut SharedValueHost).cast::<c_void>();
            assert_eq!(
                ex_worklet_bind_shared_value_accessors(
                    runtime,
                    Some(read_shared_value),
                    Some(write_shared_value),
                    context,
                ),
                0
            );
            ex_worklet_set_generation(runtime, 7);
            let captures = [
                WorkletCapture {
                    kind: WORKLET_CAPTURE_F32,
                    scalar: 2.0,
                    shared_value: WorkletSharedValueHandle {
                        slot: 0,
                        generation: 0,
                        epoch: 0,
                    },
                },
                WorkletCapture {
                    kind: WORKLET_CAPTURE_BOOL,
                    scalar: 1.0,
                    shared_value: WorkletSharedValueHandle {
                        slot: 0,
                        generation: 0,
                        epoch: 0,
                    },
                },
                WorkletCapture {
                    kind: WORKLET_CAPTURE_SHARED_VALUE,
                    scalar: 0.0,
                    shared_value: host.expected,
                },
            ];
            let source = r#"(function (input) {
              var shared = worklet.captureGet(2);
              worklet.output(0, input * worklet.capture(0));
              worklet.output(1, shared);
              worklet.output(2, worklet.capture(1) ? 1 : 0);
              worklet.captureSet(2, shared + 1);
              worklet.runOnJS(77, input, shared);
            })"#;
            let identity = install_typed_worklet(runtime, source, &captures, 7);
            assert_eq!(
                install_typed_worklet(runtime, source, &captures, 7),
                identity,
                "content + capture identity must be stable across re-renders"
            );

            let mut output = [f32::NAN; 3];
            let input = [3.0_f32];
            let mut output_count = 0;
            assert_eq!(
                ex_worklet_invoke_typed(
                    runtime,
                    identity,
                    input.as_ptr(),
                    input.len() as u32,
                    output.as_mut_ptr(),
                    output.len() as u32,
                    &mut output_count,
                ),
                0
            );
            assert_eq!(output_count, 3);
            assert_eq!(output, [6.0, 41.0, 1.0]);
            assert_eq!(host.value, 42.0);

            // The install-time SharedValue capture owns the same stale shadow
            // contract as worklet.sharedValue(...). A host-rejected handle
            // reads its last observed value and rejects the write.
            host.expected.generation = 10;
            assert_eq!(
                ex_worklet_invoke_typed(
                    runtime,
                    identity,
                    input.as_ptr(),
                    1,
                    output.as_mut_ptr(),
                    3,
                    &mut output_count,
                ),
                0
            );
            assert_eq!(output[1], 42.0);
            assert_eq!(host.rejected_reads, 1);
            assert_eq!(host.rejected_writes, 1);
            host.expected.generation = 9;

            // Fill past the fixed ring. The oldest four calls are evicted;
            // per-source sequence remains monotonic and makes the gap clear.
            for _ in 0..254 {
                assert_eq!(
                    ex_worklet_invoke_typed(
                        runtime,
                        identity,
                        input.as_ptr(),
                        1,
                        output.as_mut_ptr(),
                        3,
                        &mut output_count,
                    ),
                    0
                );
            }
            let mut calls = [WorkletScheduledCall::default(); 256];
            assert_eq!(
                ex_worklet_drain_scheduled_typed(runtime, calls.as_mut_ptr(), 256),
                256
            );
            assert_eq!(ex_worklet_take_scheduled_drop_count(runtime), 0);
            // Two calls occurred before the 254-fill loop: the stale-shadow
            // invocation is still a valid runOnJS enqueue, so capacity is
            // reached exactly without a drop.
            assert_eq!(calls[0].source_sequence, 1);
            assert_eq!(calls[255].source_sequence, 256);
            assert!(calls.iter().all(|call| {
                call.source_identity == identity
                    && call.generation == 7
                    && call.callback_identity == 77
                    && call.argument_count == 2
            }));
            for _ in 0..260 {
                assert_eq!(
                    ex_worklet_invoke_typed(
                        runtime,
                        identity,
                        input.as_ptr(),
                        1,
                        output.as_mut_ptr(),
                        3,
                        &mut output_count,
                    ),
                    0
                );
            }
            assert_eq!(
                ex_worklet_drain_scheduled_typed(runtime, calls.as_mut_ptr(), 256),
                256
            );
            assert_eq!(ex_worklet_take_scheduled_drop_count(runtime), 4);
            assert_eq!(calls[0].source_sequence, 261);
            assert_eq!(calls[255].source_sequence, 516);

            let app = ex_hermes_create_diagnostic();
            assert!(!app.is_null());
            assert_eq!(
                eval(
                    app,
                    "globalThis.__runOnJSSeen=[]; globalThis.__exactRunOnJS=function(id,meta,a,b){ __runOnJSSeen.push([id,meta.sourceSequence,a,b]); }; 'ready'",
                )
                .0,
                0
            );
            let mut delivered = 0;
            assert_eq!(
                ex_hermes_dispatch_worklet_calls(
                    app,
                    calls.as_ptr(),
                    calls.len() as u32,
                    &mut delivered,
                ),
                0
            );
            assert_eq!(delivered, 256);
            assert_eq!(
                eval(
                    app,
                    "JSON.stringify([__runOnJSSeen.length,__runOnJSSeen[0],__runOnJSSeen[255]])",
                )
                .1
                .as_deref(),
                Some("[256,[77,\"261\",3,300],[77,\"516\",3,555]]")
            );

            let mut metrics = WorkletInstallMetrics::default();
            assert_eq!(ex_worklet_install_metrics(runtime, &mut metrics), 0);
            assert_eq!(metrics.source_install_count, 1);
            assert_eq!(metrics.reused_install_count, 1);
            assert!(metrics.source_install_total_ns > 0);
            assert!(metrics.source_install_max_ns > 0);

            ex_hermes_destroy(app);
            assert_eq!(
                ex_worklet_bind_shared_value_accessors(runtime, None, None, std::ptr::null_mut(),),
                0
            );
            ex_worklet_destroy(runtime);
        }
    }

    /// The source-install choice is deliberate for M6: the shipped build
    /// plugin already emits function-expression source, and warm installs
    /// must remain immaterial beside the 1ms per-frame execution budget.
    #[test]
    fn motion_worklet_source_install_p95_is_measured() {
        unsafe {
            let runtime = ex_worklet_create();
            assert!(!runtime.is_null());
            ex_worklet_set_generation(runtime, 1);
            let mut samples = Vec::new();
            for index in 0..64_u32 {
                let source =
                    format!("(function (value) {{ worklet.output(0, value + {index}); }})");
                let started = std::time::Instant::now();
                let _ = install_typed_worklet(runtime, &source, &[], 1);
                samples.push(started.elapsed().as_nanos() as u64);
            }
            samples.sort_unstable();
            let p50 = samples[samples.len() / 2];
            let p95 = samples[(samples.len() * 95 / 100).min(samples.len() - 1)];
            eprintln!(
                "M6 source install: p50={:.3}ms p95={:.3}ms",
                p50 as f64 / 1_000_000.0,
                p95 as f64 / 1_000_000.0,
            );
            assert!(
                p95 < 5_000_000,
                "warm source install p95 must stay below the 5ms mount-time ceiling"
            );
            ex_worklet_destroy(runtime);
        }
    }

    #[test]
    fn legacy_unarmed_constructor_is_non_executable() {
        unsafe {
            assert!(ex_hermes_create().is_null());
        }
    }

    extern "C" fn count_watchdog_heartbeat(context: *mut std::ffi::c_void) {
        let count = unsafe { &*(context.cast::<std::sync::atomic::AtomicUsize>()) };
        count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// A watchdog executor retains its runtime identity across threads. If the
    /// handle address is recycled, an old heartbeat must not be relabelled with
    /// the new runtime's nonce and admitted into that runtime.
    #[test]
    fn watchdog_heartbeat_rejects_a_stale_generation_at_a_reused_address() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());

        unsafe {
            let stale_runtime = ex_hermes_create_diagnostic();
            assert!(!stale_runtime.is_null());
            let stale_nonce = ex_hermes_runtime_nonce(stale_runtime);
            assert_ne!(stale_nonce, 0);
            ex_hermes_destroy(stale_runtime);

            let replacement = ex_hermes_create_diagnostic();
            assert!(!replacement.is_null());

            let replacement_nonce = ex_hermes_runtime_nonce(replacement);
            assert_ne!(replacement_nonce, 0);
            assert_ne!(replacement_nonce, stale_nonce);
            let count = std::sync::atomic::AtomicUsize::new(0);
            let context = (&count as *const std::sync::atomic::AtomicUsize)
                .cast_mut()
                .cast::<std::ffi::c_void>();

            ex_hermes_schedule_watchdog_heartbeat(replacement, count_watchdog_heartbeat, context);
            assert_eq!(ex_hermes_callback_backlog(replacement), 0);
            assert_eq!(ex_hermes_poll(replacement, ex_hermes_now_ms()), 0);
            assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 0);

            // Force the exact identity pair seen after address reuse: the
            // address now names B, while the producer still carries A's
            // captured nonce. Physical allocator reuse is irrelevant to the
            // registry operation and would make this test nondeterministic.
            ex_hermes_schedule_watchdog_heartbeat_for_generation(
                replacement,
                stale_nonce,
                count_watchdog_heartbeat,
                context,
            );
            assert_eq!(ex_hermes_callback_backlog(replacement), 0);
            assert_eq!(ex_hermes_poll(replacement, ex_hermes_now_ms()), 0);
            assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 0);

            ex_hermes_schedule_watchdog_heartbeat_for_generation(
                replacement,
                replacement_nonce,
                count_watchdog_heartbeat,
                context,
            );
            assert_eq!(ex_hermes_callback_backlog(replacement), 1);
            assert_eq!(ex_hermes_poll(replacement, ex_hermes_now_ms()), 1);
            assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 1);
            ex_hermes_destroy(replacement);
        }
    }

    /// Frame attribution must inspect the runtime being evaluated, not merely
    /// the last runtime created on this thread. Snapback nests a mutation
    /// runtime inside an action runtime; the stale thread-local used to make
    /// the outer continuation look like it had no user principal and falsely
    /// deny its explicitly granted fetch capability (ENG-24219).
    #[test]
    fn capability_attribution_tracks_the_eval_target_across_two_runtimes() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::strict();
        host.capabilities().grant("*", "network:fetch", None);
        crate::host::abi::install_host(host);

        unsafe {
            let outer = ex_hermes_create_diagnostic();
            let nested = ex_hermes_create_diagnostic();
            assert!(!outer.is_null());
            assert!(!nested.is_null());

            let (status, value) = eval(
                outer,
                "__exactCapabilityCheck('network:fetch:127.0.0.1') ? 'allowed' : 'denied'",
            );
            assert_eq!(status, 0, "outer eval failed: {value:?}");
            assert_eq!(value.as_deref(), Some("allowed"));

            ex_hermes_destroy(nested);
            ex_hermes_destroy(outer);
        }
    }

    #[test]
    fn native_owner_hosts_reject_non_integral_or_unsafe_numeric_selectors() {
        let _host_guard = crate::host::abi::host_test_lock();
        crate::host::abi::install_host(crate::host::Host::strict());

        unsafe {
            #[cfg(target_os = "windows")]
            ex_host_install();
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());

            let (status, value) = eval(
                runtime,
                r#"
                (function() {
                  var invalid = [
                    NaN, Infinity, -Infinity, 0, -1, 1.5,
                    9007199254740992, undefined, '1'
                  ];
                  var httpRejected = invalid.every(function(value) {
                    return __exactHttpOwner(value) === false;
                  });
                  var stamp = __exactNetOwner('new');
                  __exactNetOwner('assert', stamp);
                  var stampsRejected = invalid.every(function(value) {
                    try {
                      __exactNetOwner('assert', value);
                      return false;
                    } catch (_) {
                      return true;
                    }
                  });
                  var invalidHandles = [
                    NaN, Infinity, -Infinity, 0, -1, 1.5,
                    9007199254740992, '1'
                  ];
                  var handlesRejected = invalidHandles.every(function(value) {
                    try {
                      __exactNetOwner('assert', stamp, value);
                      return false;
                    } catch (_) {
                      return true;
                    }
                  });
                  return String(httpRejected) + ':' +
                    String(stampsRejected) + ':' + String(handlesRejected);
                })()
                "#,
            );
            assert_eq!(status, 0, "owner-host selector probe failed: {value:?}");
            assert_eq!(value.as_deref(), Some("true:true:true"));
            ex_hermes_destroy(runtime);
        }
    }

    #[test]
    fn schedule_on_app_runtime_json_dispatches_on_app_runtime() {
        unsafe {
            let app = ex_hermes_create_diagnostic();
            assert!(!app.is_null());
            assert_eq!(
                eval(
                    app,
                    "globalThis.__scheduled=null; globalThis.__exactScheduleOnAppRuntime=function(batch,generation){ __scheduled=[batch,generation]; }; 'ready'",
                )
                .0,
                0
            );
            let batch = br#"[{"name":"refreshBadge","args":{"count":3}}]"#;
            assert_eq!(
                ex_hermes_dispatch_worklet_json_batch(app, batch.as_ptr(), batch.len(), 11,),
                0
            );
            assert_eq!(
                eval(app, "JSON.stringify(__scheduled)").1.as_deref(),
                Some("[[{\"name\":\"refreshBadge\",\"args\":{\"count\":3}}],11]")
            );
            ex_hermes_destroy(app);
        }
    }

    #[test]
    fn motion_rated_publish_dispatches_fixed_sample_on_app_runtime() {
        unsafe {
            let app = ex_hermes_create_diagnostic();
            assert!(!app.is_null());
            assert_eq!(
                eval(
                    app,
                    "globalThis.__rated=null; globalThis.__exactMotionRatedPublish=function(id,values,metadata){ __rated=[id,values,metadata]; }; 'ready'",
                )
                .0,
                0
            );
            let sample = MotionRatedPublishSample {
                channel_identity: 91,
                dirty_generation: 7,
                sample_time_ns: 123_456,
                value_count: 2,
                flags: 3,
                values: [4.5, -2.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            };
            assert_eq!(ex_hermes_dispatch_motion_rated_publish(app, &sample), 0);
            assert_eq!(
                eval(app, "JSON.stringify(__rated)").1.as_deref(),
                Some(
                    "[\"91\",[4.5,-2],{\"dirtyGeneration\":\"7\",\"sampleTimeNs\":\"123456\",\"heartbeat\":true,\"programmatic\":true}]"
                )
            );

            let mut invalid = sample;
            invalid.values[0] = f32::NAN;
            assert_eq!(ex_hermes_dispatch_motion_rated_publish(app, &invalid), 1);
            ex_hermes_destroy(app);
        }
    }

    #[test]
    fn host_policy_is_pinned_to_each_runtime_context() {
        let _host_guard = crate::host::abi::host_test_lock();
        let allow = crate::host::Host::strict();
        allow.capabilities().grant("*", "network:fetch", None);
        crate::host::abi::install_host(allow);
        let first = unsafe { ex_hermes_create_diagnostic() };
        assert!(!first.is_null());

        let deny = crate::host::Host::strict();
        deny.capabilities().deny("*", "network:fetch", None);
        crate::host::abi::install_host(deny);
        let second = unsafe { ex_hermes_create_diagnostic() };
        assert!(!second.is_null());

        let source = "__exactCapabilityCheck('network:fetch:example.com') ? 'allowed' : 'denied'";
        let (first_status, first_value) = eval(first, source);
        let (second_status, second_value) = eval(second, source);
        assert_eq!((first_status, first_value.as_deref()), (0, Some("allowed")));
        assert_eq!(
            (second_status, second_value.as_deref()),
            (0, Some("denied"))
        );

        unsafe {
            ex_hermes_destroy(second);
            ex_hermes_destroy(first);
        }
    }

    /// Native TLS engine handles are process-global numbers at the JS ABI, but
    /// authority must remain scoped to the creating runtime. Two runtimes can
    /// use the same principal ids, so principal-only ownership lets one guess,
    /// inspect, or close the other's TLS session. Runtime destruction must also
    /// retire only that runtime's engines.
    #[test]
    fn tls_engine_handles_are_isolated_and_cleaned_per_runtime() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::strict();
        crate::host::abi::install_host(host);

        unsafe {
            let first = ex_hermes_create_diagnostic();
            let second = ex_hermes_create_diagnostic();
            assert!(!first.is_null());
            assert!(!second.is_null());

            let (status, first_id_text) =
                eval(first, "__exactTlsEngineNew('{\"host\":\"localhost\"}')");
            assert_eq!(
                status, 0,
                "first TLS engine creation failed: {first_id_text:?}"
            );
            let first_id: u64 = first_id_text
                .expect("first engine id")
                .parse()
                .expect("numeric first engine id");

            let (status, second_id_text) =
                eval(second, "__exactTlsEngineNew('{\"host\":\"localhost\"}')");
            assert_eq!(
                status, 0,
                "second TLS engine creation failed: {second_id_text:?}"
            );
            let second_id: u64 = second_id_text
                .expect("second engine id")
                .parse()
                .expect("numeric second engine id");

            let (status, value) = eval(
                second,
                &format!(
                    "try {{ __exactTlsEngineStatus({first_id}); 'leaked' }} \
                     catch (error) {{ String(error).includes('belongs to another runtime or principal') ? 'isolated' : String(error) }}"
                ),
            );
            assert_eq!(status, 0, "cross-runtime probe failed: {value:?}");
            assert_eq!(value.as_deref(), Some("isolated"));

            ex_hermes_destroy(first);

            let (status, value) = eval(
                second,
                &format!(
                    "try {{ __exactTlsEngineStatus({first_id}); 'retained' }} \
                     catch (error) {{ String(error).includes('unknown engine handle') ? 'cleaned' : String(error) }}"
                ),
            );
            assert_eq!(
                status, 0,
                "destroyed-runtime cleanup probe failed: {value:?}"
            );
            assert_eq!(value.as_deref(), Some("cleaned"));

            let (status, value) = eval(
                second,
                &format!(
                    "JSON.parse(__exactTlsEngineStatus({second_id})).handshaking ? 'alive' : 'alive'"
                ),
            );
            assert_eq!(
                status, 0,
                "surviving runtime lost its TLS engine: {value:?}"
            );
            assert_eq!(value.as_deref(), Some("alive"));

            ex_hermes_destroy(second);
        }
    }

    /// A one-shot timer whose callback throws must be retired before the
    /// error propagates out of `ex_hermes_poll`; before the fix it stayed
    /// due and refired on every subsequent poll. @ref LLP 0006#degrade-diagnostics-never-the-caller
    #[test]
    fn throwing_one_shot_timer_does_not_refire() {
        unsafe {
            std::env::set_var("IBEX_SUPPRESS_CONSOLE_MIRROR", "1");
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());

            let (status, value) = eval(
                runtime,
                "globalThis.__r1Count = 0;\n\
                 setTimeout(function () { globalThis.__r1Count++; throw new Error('boom'); }, 0);\n\
                 'armed';",
            );
            assert_eq!(status, 0, "arming eval failed: {value:?}");

            // Timer due_ms is monotonic-ms since process start; a huge `now`
            // guarantees the timer is due on the first poll.
            let now = u64::MAX / 2;
            let first = ex_hermes_poll(runtime, now);
            assert_eq!(first, -1, "throwing timer should surface a poll error");

            let second = ex_hermes_poll(runtime, now + 1_000);
            assert_eq!(second, 0, "retired one-shot timer must not refire");
            let third = ex_hermes_poll(runtime, now + 2_000);
            assert_eq!(third, 0, "retired one-shot timer must not refire");

            let (status, value) = eval(runtime, "String(globalThis.__r1Count)");
            assert_eq!(status, 0);
            assert_eq!(value.as_deref(), Some("1"));

            ex_hermes_destroy(runtime);
        }
    }

    /// Embedded hosts opt into report-and-continue behavior for errors escaping
    /// async callbacks. A `nextTick` queued by a timer is drained from
    /// `ex_hermes_poll`, not the arming eval, so this directly pins the
    /// keep-alive policy at the poll-time nextTick drain. @ref LLP 0003#the-event-loop
    #[test]
    fn keep_alive_policy_continues_after_poll_time_next_tick_throw() {
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            ex_hermes_set_keep_alive_on_async_error(runtime, 1);

            let (status, value) = eval(
                runtime,
                "globalThis.__r1TickOrder = [];\n\
                 setTimeout(function () {\n\
                   process.nextTick(function () {\n\
                     globalThis.__r1TickOrder.push('threw');\n\
                     throw new Error('keep-alive-next-tick');\n\
                   });\n\
                   process.nextTick(function () {\n\
                     globalThis.__r1TickOrder.push('continued');\n\
                   });\n\
                 }, 0);\n\
                 'armed';",
            );
            assert_eq!(status, 0, "arming eval failed: {value:?}");

            let poll_status = ex_hermes_poll(runtime, u64::MAX / 2);
            let (state_status, state) = eval(runtime, "globalThis.__r1TickOrder.join(',')");
            ex_hermes_destroy(runtime);

            assert_eq!(
                poll_status, 1,
                "keep-alive nextTick throw must not make the observing poll fatal"
            );
            assert_eq!(
                state_status, 0,
                "runtime must remain evaluable after the throw"
            );
            assert_eq!(
                state.as_deref(),
                Some("threw,continued"),
                "the nextTick drain must continue after the throwing callback"
            );
        }
    }

    /// The native signal watcher delivers through `pushRuntimeCallback`, the
    /// same cross-thread callback queue used by HTTP, WebSocket, DNS, and fs.
    /// Replacing its JS dispatcher with a throwing function makes the throw
    /// escape the queued callback itself, exercising `drainCallbackQueue`
    /// without a network race or a test-only production hook. @ref LLP 0003#the-event-loop
    #[cfg(unix)]
    #[test]
    fn keep_alive_policy_continues_after_cross_thread_callback_throw() {
        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            ex_hermes_set_keep_alive_on_async_error(runtime, 1);

            let signal = libc::SIGUSR2;
            let (status, value) = eval(
                runtime,
                &format!(
                    "globalThis.__r1CrossThreadRuns = 0;\n\
                     globalThis.__exactDispatchPendingSignals = function () {{\n\
                       globalThis.__r1CrossThreadRuns++;\n\
                       throw new Error('keep-alive-cross-thread');\n\
                     }};\n\
                     __exactTrapSignal({signal});\n\
                     'armed';"
                ),
            );
            assert_eq!(status, 0, "signal callback setup failed: {value:?}");
            assert_eq!(
                libc::raise(signal),
                0,
                "failed to raise trapped test signal"
            );

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let mut backlog = ex_hermes_callback_backlog(runtime);
            while backlog == 0 && std::time::Instant::now() < deadline {
                std::thread::yield_now();
                backlog = ex_hermes_callback_backlog(runtime);
            }

            let poll_status = if backlog == 0 {
                None
            } else {
                Some(ex_hermes_poll(runtime, ex_hermes_now_ms()))
            };
            let (state_status, state) = eval(runtime, "String(globalThis.__r1CrossThreadRuns)");
            // Restore the process-wide disposition before assertions can panic.
            let _ = eval(runtime, &format!("__exactResetSignal({signal}); 'reset'"));
            ex_hermes_destroy(runtime);

            assert!(
                backlog > 0,
                "signal watcher did not enqueue its runtime callback"
            );
            assert_eq!(
                poll_status,
                Some(0),
                "keep-alive cross-thread throw must not make the observing poll fatal"
            );
            assert_eq!(
                state_status, 0,
                "runtime must remain evaluable after the throw"
            );
            assert_eq!(state.as_deref(), Some("1"));
        }
    }

    #[test]
    fn self_clearing_interval_keeps_captured_principals_alive_through_callback() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::strict();
        host.capabilities()
            .grant("*", "network:fetch:self-clear.invalid", None);
        assert_ne!(crate::host::abi::install_host(host), 0);

        unsafe {
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());
            let (status, value) = eval(
                runtime,
                "globalThis.__selfClearCount = 0;\n\
                 globalThis.__selfClearAllowed = false;\n\
                 var interval = setInterval(function () {\n\
                   clearInterval(interval);\n\
                   globalThis.__selfClearCount++;\n\
                   globalThis.__selfClearAllowed =\n\
                     __exactCapabilityCheck('network:fetch:self-clear.invalid');\n\
                 }, 0);\n\
                 'armed';",
            );
            assert_eq!(status, 0, "interval setup failed: {value:?}");

            assert_eq!(
                ex_hermes_poll(runtime, u64::MAX / 2),
                1,
                "self-clearing callback should complete after erasing its timer record"
            );
            assert_eq!(ex_hermes_poll(runtime, u64::MAX / 2 + 1), 0);
            let (status, value) = eval(
                runtime,
                "String(globalThis.__selfClearCount) + ':' + \
                 String(globalThis.__selfClearAllowed)",
            );
            assert_eq!((status, value.as_deref()), (0, Some("1:true")));
            ex_hermes_destroy(runtime);
        }
    }

    /// setTimeout/setInterval store `due_ms = nowMs() + delay` on a MONOTONIC
    /// clock, and the Rust event loop reads that same clock via
    /// `ex_hermes_now_ms()` for the `now` it feeds to `ex_hermes_poll`. A large
    /// numeric delay lets us confirm both sides share one clock domain: due_ms
    /// minus a freshly-read now must be ~= the delay (not wildly off, as it
    /// would be if the two used different clock epochs).
    #[test]
    fn timer_due_time_shares_monotonic_clock_domain() {
        unsafe {
            std::env::set_var("IBEX_SUPPRESS_CONSOLE_MIRROR", "1");
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());

            let t0 = ex_hermes_now_ms();
            let (status, _) = eval(
                runtime,
                "globalThis.__c = 0; setTimeout(function () { globalThis.__c++; }, 100000); 'ok';",
            );
            assert_eq!(status, 0);

            let due = ex_hermes_next_timer(runtime);
            assert!(
                due >= 0,
                "an armed timer must report a non-negative due time"
            );
            let rel = (due as u64).saturating_sub(t0);
            assert!(
                (90_000..=110_000).contains(&rel),
                "due_ms - ex_hermes_now_ms() = {rel}ms, expected ~100000ms; \
                 the Rust loop clock and the C++ timer clock must be the same domain",
            );

            // Passing that due time straight to poll fires the timer.
            let fired = ex_hermes_poll(runtime, due as u64);
            assert!(fired >= 1, "timer should fire once its due time is reached");
            let (_, value) = eval(runtime, "String(globalThis.__c)");
            assert_eq!(value.as_deref(), Some("1"));

            ex_hermes_destroy(runtime);
        }
    }

    /// setTimeout/setInterval must (a) ToNumber-coerce a non-number delay like
    /// `'100000'` instead of silently treating it as 0, and (b) clamp negative
    /// and NaN delays to 0. Before the fix the delay went through
    /// `static_cast<uint64_t>(asNumber())`: strings became 0, and negative/NaN
    /// were UB — on x86_64 they cast to 0x8000000000000000, so `nowMs() + delay`
    /// landed ~292M years out and the callback NEVER fired.
    #[test]
    fn timer_delay_is_coerced_and_clamped() {
        unsafe {
            std::env::set_var("IBEX_SUPPRESS_CONSOLE_MIRROR", "1");
            let runtime = ex_hermes_create_diagnostic();
            assert!(!runtime.is_null());

            // (a) A string delay is coerced via ToNumber, so a '100000' timer is
            // due ~100s out — not immediately (which is what treating it as 0
            // would produce).
            let t0 = ex_hermes_now_ms();
            let (status, _) = eval(
                runtime,
                "globalThis.__s = 0; setTimeout(function () { globalThis.__s++; }, '100000'); 'ok';",
            );
            assert_eq!(status, 0);
            let due = ex_hermes_next_timer(runtime);
            assert!(due >= 0);
            let rel = (due as u64).saturating_sub(t0);
            assert!(
                rel >= 90_000,
                "string delay '100000' must coerce to ~100000ms, got {rel}ms \
                 (a non-coerced delay would be ~0)",
            );
            // Retire it so it doesn't interfere with the clamp cases below.
            ex_hermes_poll(runtime, due as u64);
            let (_, value) = eval(runtime, "String(globalThis.__s)");
            assert_eq!(value.as_deref(), Some("1"));
            assert_eq!(ex_hermes_next_timer(runtime), -1);

            // (b) Negative, NaN, non-coercible-object, and missing delays all
            // clamp to 0: each timer is due ~immediately (a small offset, NOT a
            // ~292M-year deadline) and fires on the next poll.
            let cases = [
                ("neg", "setTimeout(function () { globalThis.__f++; }, -1);"),
                ("nan", "setTimeout(function () { globalThis.__f++; }, NaN);"),
                ("obj", "setTimeout(function () { globalThis.__f++; }, {});"),
                ("none", "setTimeout(function () { globalThis.__f++; });"),
            ];
            for (label, arm) in cases {
                let base = ex_hermes_now_ms();
                let (status, _) = eval(runtime, &format!("globalThis.__f = 0; {arm} 'ok';"));
                assert_eq!(status, 0, "{label}: setTimeout must not throw");
                let due = ex_hermes_next_timer(runtime);
                assert!(
                    due >= 0,
                    "{label}: delay must not become a far-future deadline"
                );
                let rel = (due as u64).saturating_sub(base);
                assert!(
                    rel <= 1_000,
                    "{label}: delay must clamp to ~0ms, got {rel}ms (bogus deadline?)",
                );
                // now >= due, so the timer is due and fires.
                let fired = ex_hermes_poll(runtime, ex_hermes_now_ms());
                assert!(fired >= 1, "{label}: clamped-to-0 timer must fire");
                let (_, value) = eval(runtime, "String(globalThis.__f)");
                assert_eq!(
                    value.as_deref(),
                    Some("1"),
                    "{label}: callback should run once"
                );
                assert_eq!(
                    ex_hermes_next_timer(runtime),
                    -1,
                    "{label}: one-shot retired"
                );
            }

            ex_hermes_destroy(runtime);
        }
    }

    /// DNS and filesystem pool jobs retain JSI promise callbacks off-thread.
    /// Destroy must enter Closing, wait for those producers to publish their
    /// callbacks, and discard the captures on this owner thread before Hermes
    /// is deleted. Recreating immediately exercises allocator address reuse.
    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn destroy_drains_delayed_dns_and_fs_producers_before_recreate() {
        let _host_guard = crate::host::abi::host_test_lock();
        let temp = std::env::temp_dir().join(format!(
            "ibex-runtime-lifetime-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&temp, b"lifetime").expect("write async lifetime fixture");

        let host = crate::host::Host::strict();
        host.capabilities()
            .grant("*", &format!("fs:read:{}", temp.display()), None);
        host.capabilities()
            .grant("*", "network:resolve:localhost", None);
        crate::host::abi::install_host(host);
        std::env::set_var("IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS", "100");

        unsafe {
            let first = ex_hermes_create_diagnostic();
            assert!(!first.is_null());
            let path = serde_json::to_string(&temp.to_string_lossy()).unwrap();
            let (status, value) = eval(
                first,
                &format!("require('fs'); __exactFsReadFileAsync({path}); 'fs-queued'"),
            );
            assert_eq!((status, value.as_deref()), (0, Some("fs-queued")));
            let started = std::time::Instant::now();
            ex_hermes_destroy(first);
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(60),
                "destroy returned before the pinned filesystem worker drained"
            );

            let second = ex_hermes_create_diagnostic();
            assert!(!second.is_null());
            let (status, value) = eval(
                second,
                "require('dns'); __exactDnsLookupAsync('localhost', 4); 'dns-queued'",
            );
            assert_eq!((status, value.as_deref()), (0, Some("dns-queued")));
            let started = std::time::Instant::now();
            ex_hermes_destroy(second);
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(60),
                "destroy returned before the pinned DNS worker drained"
            );

            let third = ex_hermes_create_diagnostic();
            assert!(!third.is_null());
            assert_eq!(
                eval(third, "'fresh-runtime'").1.as_deref(),
                Some("fresh-runtime")
            );
            ex_hermes_destroy(third);
        }

        std::env::remove_var("IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS");
        let _ = std::fs::remove_file(temp);
    }

    /// Fetch backends may complete after cancellation. The native callback
    /// takes its nonce-bearing target before this injected delay; destroy and
    /// immediate recreate must make the later pin fail instead of delivering
    /// old-runtime JSI handles into a reused address.
    #[cfg(feature = "capsec-conformance-observer")]
    #[test]
    fn delayed_fetch_completion_cannot_enter_recreated_runtime() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let _host_guard = crate::host::abi::host_test_lock();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fetch lifetime server");
        let port = listener.local_addr().unwrap().port();
        let (responded_tx, responded_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept fetch lifetime request");
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .expect("write fetch lifetime response");
            let _ = stream.flush();
            responded_tx.send(()).unwrap();
        });

        let host = crate::host::Host::strict();
        host.capabilities()
            .grant("*", "network:fetch:127.0.0.1", None);
        crate::host::abi::install_host(host);
        std::env::set_var("IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS", "150");

        unsafe {
            let first = ex_hermes_create_diagnostic();
            assert!(!first.is_null());
            let source = format!(
                "__nativeFetch('http://127.0.0.1:{port}/', {{method:'GET'}}, null); 'fetch-queued'"
            );
            assert_eq!(eval(first, &source).1.as_deref(), Some("fetch-queued"));
            responded_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("native fetch reached local server");
            std::thread::sleep(std::time::Duration::from_millis(25));
            ex_hermes_destroy(first);

            let second = ex_hermes_create_diagnostic();
            assert!(!second.is_null());
            std::thread::sleep(std::time::Duration::from_millis(200));
            assert_eq!(
                eval(second, "'fresh-after-fetch'").1.as_deref(),
                Some("fresh-after-fetch")
            );
            ex_hermes_destroy(second);
        }

        server.join().expect("fetch lifetime server thread");
        std::env::remove_var("IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS");
    }

    #[cfg(all(feature = "host-http-server", feature = "capsec-conformance-observer"))]
    #[test]
    fn destroy_cancels_and_drains_delayed_http_wait_before_recreate() {
        let _host_guard = crate::host::abi::host_test_lock();
        let host = crate::host::Host::strict();
        host.capabilities()
            .grant("*", "network:listen:127.0.0.1:0", None);
        crate::host::abi::install_host(host);
        std::env::set_var("IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS", "100");

        unsafe {
            let first = ex_hermes_create_diagnostic();
            assert!(!first.is_null());
            let (status, value) = eval(
                first,
                "require('http'); var __lifeServer = JSON.parse(__exactHttpServe(0, '127.0.0.1')); __exactHttpWait(__lifeServer.id, 5000); 'http-queued'",
            );
            assert_eq!((status, value.as_deref()), (0, Some("http-queued")));
            let started = std::time::Instant::now();
            ex_hermes_destroy(first);
            assert!(
                started.elapsed() >= std::time::Duration::from_millis(60),
                "destroy returned before the pinned HTTP waiter drained"
            );

            let second = ex_hermes_create_diagnostic();
            assert!(!second.is_null());
            assert_eq!(
                eval(second, "'fresh-after-http'").1.as_deref(),
                Some("fresh-after-http")
            );
            ex_hermes_destroy(second);
        }
        std::env::remove_var("IBEX_TEST_RUNTIME_CALLBACK_DELAY_MS");
    }

    #[cfg(target_os = "windows")]
    mod windows_native_smoke {
        use super::*;
        use base64::{engine::general_purpose, Engine as _};
        use sha1::{Digest, Sha1};
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::{Duration, Instant};

        struct RuntimeGuard(*mut HermesRuntimeOpaque);

        impl RuntimeGuard {
            fn new() -> Self {
                unsafe {
                    ex_host_install();
                    let runtime = ex_hermes_create_diagnostic();
                    assert!(!runtime.is_null());
                    Self(runtime)
                }
            }

            fn as_ptr(&self) -> *mut HermesRuntimeOpaque {
                self.0
            }
        }

        impl Drop for RuntimeGuard {
            fn drop(&mut self) {
                unsafe { ex_hermes_destroy(self.0) };
            }
        }

        fn eval_ok(runtime: *mut HermesRuntimeOpaque, source: &str) -> Option<String> {
            let (status, value) = eval(runtime, source);
            assert_eq!(status, 0, "eval failed: {value:?}");
            value
        }

        fn eval_ok_with_permissive_host(
            runtime: *mut HermesRuntimeOpaque,
            source: &str,
        ) -> Option<String> {
            unsafe { ex_host_install() };
            let (mut status, mut value) = eval(runtime, source);
            if status != 0
                && value
                    .as_deref()
                    .is_some_and(|message| message.contains("Permission denied"))
            {
                unsafe { ex_host_install() };
                (status, value) = eval(runtime, source);
            }
            assert_eq!(status, 0, "eval failed: {value:?}");
            value
        }

        fn json_string(value: &str) -> String {
            serde_json::to_string(value).expect("JSON string")
        }

        fn install_ascii_text_encoder(runtime: *mut HermesRuntimeOpaque) {
            let value = eval_ok(
                runtime,
                r#"
                if (typeof TextEncoder === 'undefined') {
                  globalThis.TextEncoder = function TextEncoder() {};
                  TextEncoder.prototype.encode = function(value) {
                    var text = String(value);
                    var out = new Uint8Array(text.length);
                    for (var i = 0; i < text.length; i++) {
                      out[i] = text.charCodeAt(i) & 255;
                    }
                    return out;
                  };
                }
                'text-encoder-ready';
                "#,
            );
            assert_eq!(value.as_deref(), Some("text-encoder-ready"));
        }

        fn wait_for_js_result(runtime: *mut HermesRuntimeOpaque, expression: &str) -> String {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut tick = u64::MAX / 4;
            while Instant::now() < deadline {
                let poll_status = unsafe { ex_hermes_poll(runtime, tick) };
                assert!(
                    poll_status >= 0,
                    "Hermes poll failed while waiting for {expression}"
                );
                tick = tick.saturating_add(20);

                let value = eval_ok(runtime, expression).unwrap_or_default();
                if !value.is_empty() {
                    return value;
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!("timed out waiting for {expression}");
        }

        fn read_http_headers(stream: &mut TcpStream) -> String {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let mut request = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let read = stream.read(&mut buf).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            String::from_utf8_lossy(&request).into_owned()
        }

        fn spawn_http_server() -> (String, thread::JoinHandle<()>) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind HTTP server");
            let port = listener.local_addr().expect("HTTP local addr").port();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept HTTP client");
                let request = read_http_headers(&mut stream);
                assert!(request.starts_with("GET /native-fetch "));
                let body = b"ibex-winhttp-fetch";
                let response = format!(
                    "HTTP/1.1 203 Non-Authoritative Information\r\n\
                     Content-Length: {}\r\n\
                     Content-Type: text/plain\r\n\
                     X-Ibex-Backend: winhttp\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write HTTP headers");
                stream.write_all(body).expect("write HTTP body");
            });
            (format!("http://127.0.0.1:{port}/native-fetch"), handle)
        }

        fn websocket_accept_key(client_key: &str) -> String {
            let mut sha = Sha1::new();
            sha.update(client_key.as_bytes());
            sha.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            general_purpose::STANDARD.encode(sha.finalize())
        }

        fn read_websocket_text_frame(stream: &mut TcpStream) -> String {
            let mut header = [0u8; 2];
            stream
                .read_exact(&mut header)
                .expect("read WebSocket frame header");
            assert_eq!(header[0] & 0x0f, 0x1, "expected text frame");
            let masked = (header[1] & 0x80) != 0;
            assert!(masked, "client WebSocket frames must be masked");
            let mut len = (header[1] & 0x7f) as usize;
            if len == 126 {
                let mut ext = [0u8; 2];
                stream
                    .read_exact(&mut ext)
                    .expect("read extended frame length");
                len = u16::from_be_bytes(ext) as usize;
            } else if len == 127 {
                let mut ext = [0u8; 8];
                stream
                    .read_exact(&mut ext)
                    .expect("read extended frame length");
                len = u64::from_be_bytes(ext) as usize;
            }
            let mut mask = [0u8; 4];
            stream.read_exact(&mut mask).expect("read frame mask");
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).expect("read frame payload");
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
            String::from_utf8(payload).expect("text frame utf8")
        }

        fn write_websocket_text_frame(stream: &mut TcpStream, text: &str) {
            let payload = text.as_bytes();
            let mut frame = vec![0x81];
            if payload.len() < 126 {
                frame.push(payload.len() as u8);
            } else {
                frame.push(126);
                frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            }
            frame.extend_from_slice(payload);
            stream
                .write_all(&frame)
                .expect("write WebSocket text frame");
        }

        fn spawn_websocket_echo_server() -> (String, thread::JoinHandle<()>) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind WebSocket server");
            let port = listener.local_addr().expect("WebSocket local addr").port();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept WebSocket client");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set WebSocket timeout");
                let request = read_http_headers(&mut stream);
                let key = request
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if name.eq_ignore_ascii_case("sec-websocket-key") {
                            Some(value.trim().to_string())
                        } else {
                            None
                        }
                    })
                    .expect("Sec-WebSocket-Key header");
                let accept = websocket_accept_key(&key);
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write WebSocket handshake");
                let message = read_websocket_text_frame(&mut stream);
                assert_eq!(message, "ibex-winhttp-websocket");
                write_websocket_text_frame(&mut stream, "winhttp-websocket-echo");
                thread::sleep(Duration::from_millis(250));
                let _ = stream.write_all(&[0x88, 0x02, 0x03, 0xe8]);
            });
            (format!("ws://127.0.0.1:{port}/native-websocket"), handle)
        }

        fn spawn_tcp_echo_server() -> (u16, thread::JoinHandle<()>) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind TCP server");
            let port = listener.local_addr().expect("TCP local addr").port();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept TCP client");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("set TCP timeout");
                let mut buf = [0u8; 64];
                let read = stream.read(&mut buf).expect("read TCP payload");
                assert_eq!(&buf[..read], b"ibex-winsock-tcp");
                stream
                    .write_all(b"winsock-tcp-echo")
                    .expect("write TCP echo");
            });
            (port, handle)
        }

        #[test]
        fn windows_runtime_uses_native_platform_backends() {
            let _host_guard = crate::host::abi::host_test_lock();
            let runtime = RuntimeGuard::new();
            install_ascii_text_encoder(runtime.as_ptr());

            let tempdir = tempfile::tempdir().expect("tempdir");
            let file = tempdir.path().join("native-fs.txt");
            let file_js = json_string(file.to_str().expect("utf8 temp path"));
            let sync_source = format!(
                r#"(function() {{
                  var crypto = require('crypto');
                  var fs = require('fs');
                  var os = require('os');
                  var cp = require('child_process');
                  var file = {file_js};
                  fs.writeFileSync(file, 'ibex-windows-fs');
                  var fsText = fs.readFileSync(file, 'utf8');
                  var hash = crypto.createHash('sha256').update('abc').digest('hex');
                  var hmac = crypto.createHmac('sha256', 'key').update('abc').digest('hex');
                  var spawn = cp.spawnSync('cmd.exe', ['/d', '/c', 'echo ibex-windows-spawn']);
                  var stdout = spawn.stdout && typeof spawn.stdout.toString === 'function'
                    ? spawn.stdout.toString()
                    : String(spawn.stdout || '');
                  return [
                    process.platform,
                    os.platform(),
                    String(os.totalmem() > 0),
                    hash,
                    hmac,
                    fsText,
                    String(fs.statSync(file).isFile()),
                    String(spawn.status),
                    stdout.replace(/\s+$/, '')
                  ].join('|');
                }})()"#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &sync_source).as_deref(),
                Some(
                    "win32|win32|true|\
                     ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad|\
                     9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab|\
                     ibex-windows-fs|true|0|ibex-windows-spawn"
                )
            );

            let (fetch_url, fetch_server) = spawn_http_server();
            let fetch_url_js = json_string(&fetch_url);
            let fetch_source = format!(
                r#"
                globalThis.__windowsNativeFetch = {{ done: false, result: '' }};
                fetch({fetch_url_js}).then(function(response) {{
                  return response.text().then(function(text) {{
                    globalThis.__windowsNativeFetch.result =
                      String(response.status) + ':' + response.headers.get('x-ibex-backend') + ':' + text;
                    globalThis.__windowsNativeFetch.done = true;
                  }});
                }}, function(error) {{
                  globalThis.__windowsNativeFetch.result = 'ERR:' + (error && error.message || String(error));
                  globalThis.__windowsNativeFetch.done = true;
                }});
                'armed';
                "#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &fetch_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeFetch.done ? globalThis.__windowsNativeFetch.result : ''",
                ),
                "203:winhttp:ibex-winhttp-fetch"
            );
            fetch_server.join().expect("HTTP server thread");

            let (ws_url, ws_server) = spawn_websocket_echo_server();
            let ws_url_js = json_string(&ws_url);
            let ws_source = format!(
                r#"
                globalThis.__windowsNativeWs = {{ done: false, result: '' }};
                var ws = new WebSocket({ws_url_js});
                ws.onopen = function() {{
                  ws.send('ibex-winhttp-websocket');
                }};
                ws.onmessage = function(event) {{
                  globalThis.__windowsNativeWs.result = 'ws:' + event.data;
                  globalThis.__windowsNativeWs.done = true;
                  ws.close(1000, 'done');
                }};
                ws.onerror = function(event) {{
                  globalThis.__windowsNativeWs.result = 'ERR:' + (event && event.message || 'websocket error');
                  globalThis.__windowsNativeWs.done = true;
                }};
                'armed';
                "#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &ws_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeWs.done ? globalThis.__windowsNativeWs.result : ''",
                ),
                "ws:winhttp-websocket-echo"
            );
            ws_server.join().expect("WebSocket server thread");

            let dns_source = r#"
              globalThis.__windowsNativeDns = { done: false, result: '' };
              require('dns').lookup('localhost', { family: 4 }, function(error, address, family) {
                var normalizedFamily = family === 'IPv4' ? 4 : family;
                globalThis.__windowsNativeDns.result = error
                  ? 'ERR:' + (error.code || error.message)
                  : 'dns:' + String(normalizedFamily) + ':' + String(!!address);
                globalThis.__windowsNativeDns.done = true;
              });
              'armed';
            "#;
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), dns_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeDns.done ? globalThis.__windowsNativeDns.result : ''",
                ),
                "dns:4:true"
            );

            let (tcp_port, tcp_server) = spawn_tcp_echo_server();
            let tcp_source = format!(
                r#"
                globalThis.__windowsNativeTcp = {{ done: false, result: '' }};
                __exactEnsureNet();
                var tcpHandle = __exactTcpConnect('127.0.0.1', {tcp_port}, null, null);
                __exactTcpWrite(tcpHandle, 'ibex-winsock-tcp');
                function __tcpBytesToText(bytes) {{
                  if (bytes === null || bytes === '') return '';
                  var out = '';
                  for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
                  return out;
                }}
                function __pollTcp() {{
                  try {{
                    var chunk = __exactTcpRead(tcpHandle, 65536);
                    if (chunk === '') {{
                      setTimeout(__pollTcp, 5);
                      return;
                    }}
                    if (chunk === null) {{
                      globalThis.__windowsNativeTcp.result = 'ERR:closed';
                      globalThis.__windowsNativeTcp.done = true;
                      return;
                    }}
                    globalThis.__windowsNativeTcp.result = 'tcp:' + __tcpBytesToText(chunk);
                    globalThis.__windowsNativeTcp.done = true;
                    __exactTcpClose(tcpHandle);
                  }} catch (error) {{
                    globalThis.__windowsNativeTcp.result = 'ERR:' + (error && error.message || String(error));
                    globalThis.__windowsNativeTcp.done = true;
                  }}
                }}
                __pollTcp();
                'armed';
                "#
            );
            assert_eq!(
                eval_ok_with_permissive_host(runtime.as_ptr(), &tcp_source).as_deref(),
                Some("armed")
            );
            assert_eq!(
                wait_for_js_result(
                    runtime.as_ptr(),
                    "globalThis.__windowsNativeTcp.done ? globalThis.__windowsNativeTcp.result : ''",
                ),
                "tcp:winsock-tcp-echo"
            );
            tcp_server.join().expect("TCP server thread");
        }
    }
}
