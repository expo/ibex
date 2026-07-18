//! Process and environment operations for the Host ABI
//!
//! These operations are gated by the env and spawn capabilities.
//! Note: spawn is not available on iOS (no child processes).

use anyhow::Result;
use capsec_semantics::model::EnvironmentName;
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

type EnvOverlay = HashMap<String, Option<String>>;

static COMPILED_ENVIRONMENT_BASE: OnceLock<CompiledEnvironmentBase> = OnceLock::new();

fn env_overlay() -> &'static RwLock<EnvOverlay> {
    static OVERLAY: OnceLock<RwLock<EnvOverlay>> = OnceLock::new();
    OVERLAY.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Immutable compiled-application broker base. Installation is process-wide
/// and one-shot because a compiled image owns exactly one captured launch
/// environment; individual reads are still authorized against the active
/// principal stack by the native adapter before these bytes are disclosed.
/// @ref LLP 0029#4-compiled-mode-authority
#[derive(Debug)]
pub struct CompiledEnvironmentBase {
    entries: BTreeMap<EnvironmentName, Vec<u8>>,
}

impl CompiledEnvironmentBase {
    pub fn new(entries: Vec<(EnvironmentName, Vec<u8>)>) -> Result<Self> {
        let mut ordered = BTreeMap::new();
        for (name, value) in entries {
            if ordered.insert(name, value).is_some() {
                anyhow::bail!("compiled environment broker base contains a duplicate name");
            }
        }
        Ok(Self { entries: ordered })
    }

    fn value(&self, key: &str) -> Option<&[u8]> {
        let name = EnvironmentName::new(key).ok()?;
        self.entries.get(&name).map(Vec::as_slice)
    }

    fn key(&self, index: usize) -> Option<&str> {
        self.entries.keys().nth(index).map(EnvironmentName::as_str)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn compiled_environment_base() -> Option<&'static CompiledEnvironmentBase> {
    COMPILED_ENVIRONMENT_BASE.get()
}

pub fn install_compiled_environment_base(base: CompiledEnvironmentBase) -> Result<()> {
    COMPILED_ENVIRONMENT_BASE
        .set(base)
        .map_err(|_| anyhow::anyhow!("compiled environment broker base is already installed"))
}

pub fn compiled_environment_value(key: &str) -> Option<Option<Vec<u8>>> {
    compiled_environment_base().map(|base| base.value(key).map(<[u8]>::to_vec))
}

pub fn compiled_environment_key_count() -> Option<usize> {
    compiled_environment_base().map(CompiledEnvironmentBase::len)
}

pub fn compiled_environment_key(index: usize) -> Option<&'static str> {
    compiled_environment_base()?.key(index)
}

/// Get the current working directory
pub fn cwd() -> Result<PathBuf> {
    std::env::current_dir().map_err(|e| anyhow::anyhow!("Failed to get cwd: {}", e))
}

/// Change the current working directory
pub fn chdir(path: &std::path::Path) -> Result<()> {
    std::env::set_current_dir(path)
        .map_err(|e| anyhow::anyhow!("Failed to change directory: {}", e))
}

/// Get an environment variable
pub fn env_get(key: &str) -> Option<String> {
    if let Some(value) = env_overlay()
        .read()
        .ok()
        .and_then(|overlay| overlay.get(key).cloned())
    {
        return value;
    }

    std::env::var(key).ok()
}

/// Set an environment variable
pub fn env_set(key: &str, value: &str) {
    if let Ok(mut overlay) = env_overlay().write() {
        overlay.insert(key.to_string(), Some(value.to_string()));
    }
}

/// Remove an environment variable
pub fn env_remove(key: &str) {
    if let Ok(mut overlay) = env_overlay().write() {
        overlay.insert(key.to_string(), None);
    }
}

/// Get all environment variables
pub fn env_all() -> HashMap<String, String> {
    let mut all = std::env::vars().collect::<HashMap<_, _>>();
    if let Ok(overlay) = env_overlay().read() {
        for (key, value) in overlay.iter() {
            match value {
                Some(value) => {
                    all.insert(key.clone(), value.clone());
                }
                None => {
                    all.remove(key);
                }
            }
        }
    }
    all
}

/// Get the command line arguments
pub fn argv() -> Vec<String> {
    std::env::args().collect()
}

/// Get the process ID
pub fn pid() -> u32 {
    std::process::id()
}

/// Get the platform name
pub fn platform() -> &'static str {
    #[cfg(target_os = "macos")]
    return "darwin";
    #[cfg(target_os = "android")]
    return "android";
    #[cfg(target_os = "linux")]
    return "linux";
    #[cfg(target_os = "windows")]
    return "win32";
    #[cfg(target_os = "ios")]
    return "ios";
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "linux",
        target_os = "android",
        target_os = "windows"
    )))]
    return "unknown";
}

/// Get the CPU architecture
pub fn arch() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    return "x64";
    #[cfg(target_arch = "aarch64")]
    return "arm64";
    #[cfg(target_arch = "x86")]
    return "x86";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
    return "unknown";
}

/// Exit the process with a status code
pub fn exit(code: i32) -> ! {
    std::process::exit(code)
}

/// Result of spawning a process
#[derive(Debug)]
pub struct SpawnResult {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Get system information
pub fn system_info() -> SystemInfo {
    SystemInfo {
        platform: platform().to_string(),
        arch: arch().to_string(),
        hostname: std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "localhost".to_string()),
        cpus: std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1),
    }
}

/// System information
#[derive(Debug)]
pub struct SystemInfo {
    pub platform: String,
    pub arch: String,
    pub hostname: String,
    pub cpus: usize,
}

#[cfg(test)]
mod compiled_environment_tests {
    use super::*;

    #[test]
    fn compiled_environment_base_is_canonical_and_byte_preserving() {
        let base = CompiledEnvironmentBase::new(vec![
            (EnvironmentName::new("ZED").unwrap(), vec![0xff, 0x00]),
            (EnvironmentName::new("ALPHA").unwrap(), b"value".to_vec()),
        ])
        .unwrap();
        assert_eq!(base.len(), 2);
        assert_eq!(base.key(0), Some("ALPHA"));
        assert_eq!(base.key(1), Some("ZED"));
        assert_eq!(base.value("ALPHA"), Some(b"value".as_slice()));
        assert_eq!(base.value("lowercase"), None);
    }

    #[test]
    fn compiled_environment_base_refuses_duplicate_names() {
        let duplicate = EnvironmentName::new("DUPLICATE").unwrap();
        assert!(CompiledEnvironmentBase::new(vec![
            (duplicate.clone(), b"first".to_vec()),
            (duplicate, b"second".to_vec()),
        ])
        .is_err());
    }
}
