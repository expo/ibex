//! Runtime-only module loading and loop-driving ABI.

use ibex2::{
    boundary::HostValue,
    boundary_abi::{AbiValue, TAG_UNDEFINED},
    grant::GrantSet,
    task::RuntimeState,
};
use std::{
    collections::HashMap,
    ffi::{c_char, c_int, CStr},
    sync::{Arc, Mutex},
};

/// Where the owning runtime reads modules and what authority each receives.
#[derive(Debug)]
pub(crate) struct LoaderConfig {
    pub root: crate::loader::Root,
    pub grants: crate::loader::ModuleGrants,
    pub compiler: Option<crate::bytecode::Compiler>,
    pub precompiled_only: bool,
    pub manifest: Option<crate::bytecode::Manifest>,
    pub cache: crate::loader::ResolveCache,
    pub bundle: Option<crate::bytecode::Bundle>,
}

#[derive(Default)]
pub(crate) struct LoaderState {
    config: Mutex<Option<LoaderConfig>>,
    interned_grants: Mutex<HashMap<GrantSet, Arc<GrantSet>>>,
}

impl LoaderState {
    pub(crate) fn set(&self, config: LoaderConfig) {
        *self.config.lock().expect("loader poisoned") = Some(config);
    }

    fn load_module(&self, from: &str, specifier: &str) -> Result<(String, Vec<u8>), String> {
        let guard = self.config.lock().expect("loader poisoned");
        let config = guard.as_ref().ok_or("no loader configured")?;
        let resolved = match config
            .manifest
            .as_ref()
            .and_then(|manifest| manifest.edge(from, specifier))
        {
            Some(resolved) => resolved.to_string(),
            None => crate::loader::resolve_in(&config.cache, &config.root, from, specifier)?,
        };

        if let (Some(compiler), Some(manifest)) = (&config.compiler, &config.manifest) {
            if let Some(key) = manifest.get(&resolved) {
                if let Some(bytes) = config.bundle.as_ref().and_then(|bundle| bundle.get(key)) {
                    return Ok((resolved, bytes.to_vec()));
                }
                let bytes = compiler
                    .by_key(key)
                    .map_err(|error| format!("{resolved}: {error}"))?;
                return Ok((resolved, bytes));
            }
            if config.precompiled_only {
                return Err(format!("{resolved}: not in the build manifest"));
            }
        }

        #[cfg(not(feature = "loader"))]
        #[allow(clippy::needless_return)]
        {
            return Err(format!(
                "{resolved}: not in the build manifest, and this build has no loader — it runs precompiled artifacts only"
            ));
        }
        #[cfg(feature = "loader")]
        {
            let path = config.root.join(resolved.trim_start_matches("./"));
            let source = std::fs::read_to_string(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            let wrapped = crate::loader::lower_and_wrap(&source, &resolved)?;
            match &config.compiler {
                Some(compiler) => {
                    let bytes = if config.precompiled_only {
                        compiler.cached_only(&wrapped)
                    } else {
                        compiler.compile(&wrapped)
                    }
                    .map_err(|error| format!("{resolved}: {error}"))?;
                    Ok((resolved, bytes))
                }
                None => Ok((resolved, wrapped.into_bytes())),
            }
        }
    }

    fn grants_for(&self, specifier: &str) -> Arc<GrantSet> {
        let guard = self.config.lock().expect("loader poisoned");
        let set = match guard.as_ref() {
            Some(config) => config.grants.for_module(specifier).clone(),
            None => GrantSet::none(),
        };
        let mut interned = self
            .interned_grants
            .lock()
            .expect("interned grants poisoned");
        if let Some(existing) = interned.get(&set) {
            return Arc::clone(existing);
        }
        let shared = Arc::new(set.clone());
        interned.insert(set, Arc::clone(&shared));
        shared
    }
}

fn undefined() -> AbiValue {
    AbiValue {
        tag: TAG_UNDEFINED,
        number: 0.0,
        data: std::ptr::null(),
        len: 0,
    }
}

unsafe fn text(raw: *const c_char) -> String {
    if raw.is_null() {
        String::new()
    } else {
        CStr::from_ptr(raw).to_string_lossy().into_owned()
    }
}

/// Resolve a module through runtime-owned loader state.
#[no_mangle]
pub unsafe extern "C" fn ibex2_runtime_loader_load(
    loader: *const LoaderState,
    from: *const c_char,
    specifier: *const c_char,
    out_resolved: *mut AbiValue,
    out_source: *mut AbiValue,
) -> c_int {
    if loader.is_null() || out_resolved.is_null() || out_source.is_null() {
        return 1;
    }
    *out_resolved = undefined();
    *out_source = undefined();
    match (*loader).load_module(&text(from), &text(specifier)) {
        Ok((resolved, bytes)) => {
            *out_resolved = ibex2::boundary_abi::leak_value(HostValue::Str(resolved));
            *out_source = ibex2::boundary_abi::leak_value(HostValue::Bytes(bytes));
            0
        }
        Err(message) => {
            *out_resolved = ibex2::boundary_abi::leak_value(HostValue::Str(message));
            1
        }
    }
}

/// Return the interned authority for one loaded module.
#[no_mangle]
pub unsafe extern "C" fn ibex2_runtime_loader_grants_for(
    loader: *const LoaderState,
    specifier: *const c_char,
) -> *const GrantSet {
    if loader.is_null() {
        return std::ptr::null();
    }
    Arc::into_raw((*loader).grants_for(&text(specifier)))
}

#[no_mangle]
pub unsafe extern "C" fn ibex2_runtime_millis_until_next_timer(state: *const RuntimeState) -> f64 {
    ibex2::task::borrow_state(state)
        .and_then(RuntimeState::millis_until_next_timer)
        .unwrap_or(-1.0)
}

#[no_mangle]
pub unsafe extern "C" fn ibex2_runtime_wait_for_completion(
    state: *const RuntimeState,
    timeout_ms: u64,
) -> c_int {
    ibex2::task::borrow_state(state).map_or(0, |state| {
        i32::from(
            state
                .queue
                .wait(std::time::Duration::from_millis(timeout_ms)),
        )
    })
}

#[no_mangle]
pub unsafe extern "C" fn ibex2_runtime_admit_due_timers(state: *const RuntimeState) -> c_int {
    ibex2::task::borrow_state(state).map_or(0, |state| state.admit_due_timers() as c_int)
}

#[no_mangle]
pub unsafe extern "C" fn ibex2_runtime_begin_drive(state: *const RuntimeState) -> c_int {
    ibex2::task::borrow_state(state).map_or(0, |state| c_int::from(state.begin_drive()))
}

#[no_mangle]
pub unsafe extern "C" fn ibex2_runtime_end_drive(state: *const RuntimeState) {
    if let Some(state) = ibex2::task::borrow_state(state) {
        state.end_drive();
    }
}
