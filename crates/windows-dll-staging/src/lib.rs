//! Race-safe publication of the Windows Hermes runtime DLL bundle.
//!
//! This crate is intentionally independent from the Ibex runtime build so its
//! filesystem behavior can run on Windows CI without first locating or linking
//! Hermes. The build script supplies the real profile and Hermes `bin` paths.

use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const PUBLISH_LOCK_FILE: &str = ".ibex-hermes-dll-publish.lock";
const PUBLISH_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(20);
static TEMP_FILE_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub struct StagingReport {
    pub dll_count: usize,
    pub published_files: usize,
    pub reused_files: usize,
    pub bundle_digest: String,
    pub source_paths: Vec<PathBuf>,
}

/// Publish every DLL from `hermes_bin_dir` into the Cargo profile root and its
/// `deps` directory as one interprocess-serialized bundle.
///
/// Content digests, never length or timestamps, decide whether a destination
/// may be reused. Changed files are copied to a unique sibling and atomically
/// renamed into place; a loaded/locked mismatched DLL therefore fails the build
/// instead of retaining stale runtime code.
///
/// @ref LLP 0005#c-compilation — a successful Windows build must execute the
/// exact Hermes runtime artifact selected by that build.
pub fn stage_runtime_dlls(profile_dir: &Path, hermes_bin_dir: &Path) -> io::Result<StagingReport> {
    fs::create_dir_all(profile_dir)?;
    let deps_dir = profile_dir.join("deps");
    fs::create_dir_all(&deps_dir)?;

    // Hold one lock across discovery, hashing, and both destinations. Without
    // this bundle-wide boundary, concurrent builds using different Hermes
    // sources can publish a profile/deps mixture that matches neither source.
    let _publish_lock =
        PublishLock::acquire(&profile_dir.join(PUBLISH_LOCK_FILE), PUBLISH_LOCK_TIMEOUT)?;

    let mut source_paths = dll_paths(hermes_bin_dir)?;
    source_paths.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    if source_paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "no Windows runtime DLLs found in {}",
                hermes_bin_dir.display()
            ),
        ));
    }

    let mut bundle_hasher = Sha256::new();
    let mut published_files = 0usize;
    let mut reused_files = 0usize;
    for source in &source_paths {
        let file_name = source.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Windows runtime DLL has no file name: {}", source.display()),
            )
        })?;
        let source_digest = file_sha256(source)?;
        let file_name_bytes = file_name.to_string_lossy();
        bundle_hasher.update((file_name_bytes.len() as u64).to_le_bytes());
        bundle_hasher.update(file_name_bytes.as_bytes());
        bundle_hasher.update(source_digest);

        for destination_dir in [profile_dir, deps_dir.as_path()] {
            let destination = destination_dir.join(file_name);
            if file_digest_matches(&destination, source_digest) {
                reused_files += 1;
                continue;
            }
            publish_file(source, &destination, source_digest)?;
            published_files += 1;
        }
    }

    Ok(StagingReport {
        dll_count: source_paths.len(),
        published_files,
        reused_files,
        bundle_digest: format!("sha256-{:x}", bundle_hasher.finalize()),
        source_paths,
    })
}

fn dll_paths(directory: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension.to_string_lossy().eq_ignore_ascii_case("dll"))
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn publish_file(source: &Path, destination: &Path, expected_digest: [u8; 32]) -> io::Result<()> {
    let file_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "staging destination has no file name: {}",
                destination.display()
            ),
        )
    })?;
    let nonce = TEMP_FILE_NONCE.fetch_add(1, Ordering::Relaxed);
    let temporary = destination.with_file_name(format!(
        ".{}.ibex-stage-{}-{nonce}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut cleanup = TemporaryFile::new(temporary.clone());

    fs::copy(source, &temporary).map_err(|error| {
        contextual_error(
            error,
            format!(
                "failed to copy Windows runtime DLL {} to temporary {}",
                source.display(),
                temporary.display()
            ),
        )
    })?;
    if !file_digest_matches(&temporary, expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "temporary Windows runtime DLL {} does not match source {}",
                temporary.display(),
                source.display()
            ),
        ));
    }

    fs::rename(&temporary, destination).map_err(|error| {
        contextual_error(
            error,
            format!(
                "failed to atomically publish Windows runtime DLL {} into {} (the destination may be locked by a running process)",
                source.display(),
                destination.display()
            ),
        )
    })?;
    cleanup.published = true;

    if !file_digest_matches(destination, expected_digest) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "published Windows runtime DLL {} does not match source {}",
                destination.display(),
                source.display()
            ),
        ));
    }
    Ok(())
}

fn contextual_error(error: io::Error, context: String) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

fn file_sha256(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn file_digest_matches(path: &Path, expected: [u8; 32]) -> bool {
    matches!(file_sha256(path), Ok(actual) if actual == expected)
}

struct PublishLock {
    file: Option<File>,
}

impl PublishLock {
    fn acquire(path: &Path, timeout: Duration) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|error| {
                contextual_error(
                    error,
                    format!("failed to open staging lock {}", path.display()),
                )
            })?;
        let started = Instant::now();
        loop {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => {
                    file.set_len(0)?;
                    if let Err(error) = writeln!(file, "pid={}", std::process::id()) {
                        return Err(contextual_error(
                            error,
                            format!("failed to initialize staging lock {}", path.display()),
                        ));
                    }
                    return Ok(Self { file: Some(file) });
                }
                Err(error) if lock_is_contended(&error) => {
                    if started.elapsed() >= timeout {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "timed out waiting for Windows runtime DLL staging lock {}; another build is still publishing",
                                path.display()
                            ),
                        ));
                    }
                    thread::sleep(LOCK_RETRY_INTERVAL);
                }
                Err(error) => {
                    return Err(contextual_error(
                        error,
                        format!("failed to acquire staging lock {}", path.display()),
                    ));
                }
            }
        }
    }
}

fn lock_is_contended(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        // fs2 reports Windows ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION
        // as raw OS errors rather than mapping them to WouldBlock.
        || (cfg!(windows) && matches!(error.raw_os_error(), Some(32 | 33)))
}

impl Drop for PublishLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = fs2::FileExt::unlock(&file);
        }
    }
}

struct TemporaryFile {
    path: PathBuf,
    published: bool,
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            published: false,
        }
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::time::SystemTime;
    use tempfile::TempDir;

    fn write_bundle(root: &Path, marker: &str) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("hermes.dll"), format!("hermes-{marker}")).unwrap();
        fs::write(root.join("icu.dll"), format!("icu----{marker}")).unwrap();
    }

    #[test]
    fn same_length_tamper_with_future_clock_is_repaired_by_digest() {
        let temporary = TempDir::new().unwrap();
        let source = temporary.path().join("source");
        let profile = temporary.path().join("profile");
        write_bundle(&source, "trusted");
        stage_runtime_dlls(&profile, &source).unwrap();

        let destination = profile.join("hermes.dll");
        let original = fs::read(&destination).unwrap();
        let tampered = vec![b'X'; original.len()];
        fs::write(&destination, &tampered).unwrap();
        let future = SystemTime::now() + Duration::from_secs(86_400);
        File::options()
            .write(true)
            .open(&destination)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(future))
            .unwrap();

        let report = stage_runtime_dlls(&profile, &source).unwrap();
        assert!(report.published_files >= 1);
        assert_eq!(fs::read(&destination).unwrap(), original);
    }

    #[test]
    fn concurrent_different_sources_never_publish_a_mixed_bundle() {
        let temporary = TempDir::new().unwrap();
        let source_a = temporary.path().join("source-a");
        let source_b = temporary.path().join("source-b");
        let profile = temporary.path().join("profile");
        write_bundle(&source_a, "AAAAAAA");
        write_bundle(&source_b, "BBBBBBB");
        let barrier = Arc::new(Barrier::new(3));

        let handles: Vec<_> = [source_a.clone(), source_b.clone()]
            .into_iter()
            .map(|source| {
                let profile = profile.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    stage_runtime_dlls(&profile, &source)
                })
            })
            .collect();
        barrier.wait();
        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        let hermes = fs::read_to_string(profile.join("hermes.dll")).unwrap();
        let icu = fs::read_to_string(profile.join("icu.dll")).unwrap();
        let profile_marker = hermes.strip_prefix("hermes-").unwrap();
        let deps_hermes = fs::read_to_string(profile.join("deps/hermes.dll")).unwrap();
        let deps_icu = fs::read_to_string(profile.join("deps/icu.dll")).unwrap();
        assert_eq!(icu.strip_prefix("icu----").unwrap(), profile_marker);
        assert_eq!(deps_hermes.strip_prefix("hermes-").unwrap(), profile_marker);
        assert_eq!(deps_icu.strip_prefix("icu----").unwrap(), profile_marker);
    }

    #[test]
    fn an_empty_source_directory_fails_loudly() {
        let temporary = TempDir::new().unwrap();
        let source = temporary.path().join("source");
        let profile = temporary.path().join("profile");
        fs::create_dir_all(&source).unwrap();
        let error = stage_runtime_dlls(&profile, &source).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[cfg(windows)]
    #[test]
    fn a_locked_mismatched_destination_fails_without_reusing_it() {
        use std::os::windows::fs::OpenOptionsExt;

        let temporary = TempDir::new().unwrap();
        let source = temporary.path().join("source");
        let profile = temporary.path().join("profile");
        write_bundle(&source, "old----");
        stage_runtime_dlls(&profile, &source).unwrap();
        let destination = profile.join("hermes.dll");
        let old_bytes = fs::read(&destination).unwrap();
        write_bundle(&source, "new----");

        let locked = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&destination)
            .unwrap();
        let error = stage_runtime_dlls(&profile, &source).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        drop(locked);
        assert_eq!(fs::read(&destination).unwrap(), old_bytes);
    }
}
