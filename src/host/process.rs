//! Process and environment operations for the Host ABI
//!
//! These operations are gated by the env and spawn capabilities.
//! Note: spawn is not available on iOS (no child processes).

use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;

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
    std::env::var(key).ok()
}

/// Set an environment variable
pub fn env_set(key: &str, value: &str) {
    std::env::set_var(key, value);
}

/// Remove an environment variable
pub fn env_remove(key: &str) {
    std::env::remove_var(key);
}

/// Get all environment variables
pub fn env_all() -> HashMap<String, String> {
    std::env::vars().collect()
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
