use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

pub(crate) const RELEASE_TAG: &str = "hermes-vanilla-d412d3bd8512-v1";
const DEFAULT_RELEASE_BASE_URL: &str = "https://github.com/expo/ibex/releases/download";
const CACHE_DIGEST_RECORD: &str = ".hermes-lean-sys-archive-sha256";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BundlePin {
    pub target: &'static str,
    pub asset: &'static str,
    pub sha256: &'static str,
}

// @ref LLP 0057.000#l1--the-bindings-door — this table is the trust root for
// the compiler/VM identity shared by the bindings and the owning runtime.
// L1d placeholders are replaced after the immutable release and its Sigstore
// attestations have been verified; see scripts/update-hermes-lean-sys-pins.mjs.
pub(crate) const PINNED_BUNDLES: &[BundlePin] = &[
    BundlePin {
        target: "aarch64-apple-darwin",
        asset: "hermes-vanilla-aarch64-apple-darwin.tar.gz",
        sha256: "TODO_L1D_SHA256_AARCH64_APPLE_DARWIN",
    },
    BundlePin {
        target: "x86_64-apple-darwin",
        asset: "hermes-vanilla-x86_64-apple-darwin.tar.gz",
        sha256: "TODO_L1D_SHA256_X86_64_APPLE_DARWIN",
    },
    BundlePin {
        target: "aarch64-apple-ios",
        asset: "hermes-vanilla-aarch64-apple-ios.tar.gz",
        sha256: "TODO_L1D_SHA256_AARCH64_APPLE_IOS",
    },
    BundlePin {
        target: "aarch64-apple-ios-sim",
        asset: "hermes-vanilla-universal-apple-ios-simulator.tar.gz",
        sha256: "TODO_L1D_SHA256_UNIVERSAL_APPLE_IOS_SIMULATOR",
    },
    BundlePin {
        target: "x86_64-apple-ios",
        asset: "hermes-vanilla-universal-apple-ios-simulator.tar.gz",
        sha256: "TODO_L1D_SHA256_UNIVERSAL_APPLE_IOS_SIMULATOR",
    },
    BundlePin {
        target: "x86_64-unknown-linux-gnu",
        asset: "hermes-vanilla-x86_64-unknown-linux-gnu.tar.gz",
        sha256: "TODO_L1D_SHA256_X86_64_UNKNOWN_LINUX_GNU",
    },
    BundlePin {
        target: "aarch64-unknown-linux-gnu",
        asset: "hermes-vanilla-aarch64-unknown-linux-gnu.tar.gz",
        sha256: "TODO_L1D_SHA256_AARCH64_UNKNOWN_LINUX_GNU",
    },
    BundlePin {
        target: "x86_64-pc-windows-msvc",
        asset: "hermes-vanilla-x86_64-pc-windows-msvc.tar.gz",
        sha256: "TODO_L1D_SHA256_X86_64_PC_WINDOWS_MSVC",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallOrigin {
    Override,
    Repository,
    Bundle,
}

#[derive(Debug)]
struct InstallLayout {
    root: PathBuf,
    include_dir: PathBuf,
    lib_root: PathBuf,
    vm_archive: PathBuf,
    origin: InstallOrigin,
    requires_receipt: bool,
}

#[derive(Debug)]
pub(crate) struct EngineInstall {
    pub root: PathBuf,
    pub include_dir: PathBuf,
    pub lib_root: PathBuf,
    pub vm_archive: PathBuf,
    pub hermesc: PathBuf,
}

#[derive(Debug)]
pub(crate) struct DownloadOptions {
    pub cache_root: PathBuf,
    pub release_base_url: String,
    pub offline: bool,
}

#[derive(Deserialize)]
struct Receipt {
    #[serde(default)]
    schema: Option<String>,
    engine: ReceiptEngine,
    #[serde(default)]
    compiler: Option<ReceiptCompiler>,
    #[serde(default)]
    bytecode: Option<ReceiptBytecode>,
}

#[derive(Deserialize)]
struct ReceiptEngine {
    binary: String,
    #[serde(rename = "binaryDigest")]
    binary_digest: String,
}

#[derive(Deserialize)]
struct ReceiptCompiler {
    #[serde(default)]
    digest: Option<String>,
}

#[derive(Deserialize)]
struct ReceiptBytecode {
    version: serde_json::Value,
}

pub(crate) fn pin_for_target(target: &str) -> Result<&'static BundlePin, String> {
    PINNED_BUNDLES
        .iter()
        .find(|pin| pin.target == target)
        .ok_or_else(|| {
            format!(
                "unsupported Hermes target {target}; set HERMES_LEAN_SYS_DIR to a complete local install"
            )
        })
}

pub(crate) fn parse_pin_sha256(value: &str) -> Result<String, String> {
    if value.starts_with("TODO_L1D_SHA256_") {
        return Err(format!(
            "the Hermes bundle digest pin {value} is awaiting publication; set HERMES_LEAN_SYS_DIR to a complete local install"
        ));
    }
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid pinned Hermes archive SHA-256 {value:?}; expected 64 hexadecimal digits"
        ));
    }
    Ok(value.to_ascii_lowercase())
}

pub(crate) fn download_options_from_env() -> Result<DownloadOptions, String> {
    let cargo_home = match env::var_os("CARGO_HOME") {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => default_cargo_home()?,
    };
    Ok(DownloadOptions {
        cache_root: cargo_home.join("hermes-lean-sys"),
        release_base_url: env::var("HERMES_LEAN_SYS_MIRROR")
            .unwrap_or_else(|_| DEFAULT_RELEASE_BASE_URL.to_owned()),
        offline: env_truthy("CARGO_NET_OFFLINE") || env_truthy("HERMES_LEAN_SYS_OFFLINE"),
    })
}

fn default_cargo_home() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .filter(|path| !path.is_empty())
        .or_else(|| env::var_os("USERPROFILE").filter(|path| !path.is_empty()))
        .map(|home| PathBuf::from(home).join(".cargo"))
        .ok_or_else(|| {
            "cannot determine Cargo home; set CARGO_HOME or HERMES_LEAN_SYS_DIR".to_owned()
        })
}

fn env_truthy(name: &str) -> bool {
    env::var(name)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub(crate) fn resolve_engine_directory(
    repo_root: &Path,
    target: &str,
    host: &str,
) -> Result<EngineInstall, String> {
    let target_layout = if let Some(overridden) = env::var_os("HERMES_LEAN_SYS_DIR") {
        install_layout(PathBuf::from(overridden), target, InstallOrigin::Override)
    } else {
        let pin = pin_for_target(target)?;
        if let Some(root) = repository_install_root(repo_root, target) {
            install_layout(root, target, InstallOrigin::Repository)
        } else {
            let options = download_options_from_env()?;
            let root = acquire_bundle(pin, &options)?;
            install_layout(root, target, InstallOrigin::Bundle)
        }
    };

    validate_layout(&target_layout)?;
    let (hermesc, bytecode_version) = if target != host {
        let host_pin = pin_for_target(host).map_err(|_| {
            format!(
                "unsupported Hermes compiler host {host}; set HERMES_LEAN_SYS_DIR cannot replace the required pinned host compiler bundle for cross compilation"
            )
        })?;
        let options = download_options_from_env()?;
        let host_root = acquire_bundle(host_pin, &options)?;
        let host_layout = install_layout(host_root, host, InstallOrigin::Bundle);
        validate_layout(&host_layout)?;
        let compiler = compiler_in_bundle_or_install(&host_layout.root, host);
        let version = validate_compiler_bundle(&host_layout, &compiler)?;
        (compiler, version)
    } else if target_layout.origin == InstallOrigin::Repository {
        let compiler = repository_hermesc(repo_root, host)?;
        let version = validate_compiler_bundle(&target_layout, &compiler)?;
        (compiler, version)
    } else {
        let local = compiler_in_bundle_or_install(&target_layout.root, host);
        let compiler = if local.is_file() || target_layout.origin != InstallOrigin::Override {
            local
        } else if repository_install_root(repo_root, target)
            .as_deref()
            .is_some_and(|repository_root| same_location(repository_root, &target_layout.root))
        {
            repository_hermesc(repo_root, host)?
        } else {
            local
        };
        let version = validate_compiler_bundle(&target_layout, &compiler)?;
        (compiler, version)
    };

    if !hermesc.is_file() {
        return Err(format!(
            "hermesc not found at {}; set HERMES_LEAN_SYS_DIR to a complete local install",
            hermesc.display()
        ));
    }
    let engine_digest = digest_file(&target_layout.vm_archive)?;
    validate_receipt(
        &target_layout,
        &hermesc,
        target == host,
        &engine_digest,
        &bytecode_version,
    )?;

    Ok(EngineInstall {
        root: target_layout.root,
        include_dir: target_layout.include_dir,
        lib_root: target_layout.lib_root,
        vm_archive: target_layout.vm_archive,
        hermesc,
    })
}

fn repository_install_root(repo_root: &Path, target: &str) -> Option<PathBuf> {
    let root = if target.contains("-apple-") {
        repo_root.join("ios/Frameworks-vanilla")
    } else if target.ends_with("-pc-windows-msvc") {
        let arch = if target.starts_with("x86_64-") {
            "x64"
        } else if target.starts_with("aarch64-") {
            "arm64"
        } else {
            return None;
        };
        repo_root.join(format!("tools/hermes-vanilla/windows-{arch}"))
    } else if target.ends_with("-unknown-linux-gnu") {
        repo_root.join("linux/Frameworks-vanilla")
    } else {
        return None;
    };
    root.is_dir().then_some(root)
}

fn install_layout(root: PathBuf, target: &str, origin: InstallOrigin) -> InstallLayout {
    let bundle_layout = root.join("include").is_dir() || root.join("lib").is_dir();
    let (include_dir, lib_root) = if bundle_layout {
        (root.join("include"), root.join("lib"))
    } else {
        let lib_dir = if target.contains("-apple-") {
            "macos-static"
        } else if target.ends_with("-pc-windows-msvc") {
            "windows-static"
        } else {
            "linux-static"
        };
        (root.join("hermes-headers"), root.join(lib_dir))
    };
    let archive = if target.ends_with("-pc-windows-msvc") {
        "hermesvm_a.lib"
    } else {
        "libhermesvm_a.a"
    };
    InstallLayout {
        root,
        include_dir,
        vm_archive: lib_root.join(archive),
        lib_root,
        origin,
        requires_receipt: bundle_layout,
    }
}

fn repository_hermesc(repo_root: &Path, host: &str) -> Result<PathBuf, String> {
    let (os, arch, suffix) = if host == "aarch64-apple-darwin" {
        ("macos", "arm64", "")
    } else if host == "x86_64-apple-darwin" {
        ("macos", "x64", "")
    } else if host == "aarch64-unknown-linux-gnu" {
        ("linux", "arm64", "")
    } else if host == "x86_64-unknown-linux-gnu" {
        ("linux", "x64", "")
    } else if host == "x86_64-pc-windows-msvc" {
        ("windows", "x64", ".exe")
    } else {
        return Err(format!(
            "unsupported Hermes compiler host {host}; set HERMES_LEAN_SYS_DIR does not change which host can execute hermesc"
        ));
    };
    Ok(repo_root
        .join("tools/hermes-vanilla")
        .join(format!("hermesc-{os}-{arch}{suffix}")))
}

fn compiler_in_bundle_or_install(root: &Path, host: &str) -> PathBuf {
    let name = if host.ends_with("-pc-windows-msvc") {
        "hermesc.exe"
    } else {
        "hermesc"
    };
    [root.join("bin").join(name), root.join(name)]
        .into_iter()
        .find(|path| path.is_file())
        .unwrap_or_else(|| root.join("bin").join(name))
}

fn same_location(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn validate_layout(layout: &InstallLayout) -> Result<(), String> {
    for (label, path, want_dir) in [
        ("Hermes headers", &layout.include_dir, true),
        ("Hermes library directory", &layout.lib_root, true),
        ("Hermes VM archive", &layout.vm_archive, false),
    ] {
        let exists = if want_dir {
            path.is_dir()
        } else {
            path.is_file()
        };
        if !exists {
            return Err(format!(
                "{label} not found at {}; set HERMES_LEAN_SYS_DIR to a complete local install or populate the pinned bundle cache",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_compiler_bundle(layout: &InstallLayout, compiler: &Path) -> Result<String, String> {
    if !compiler.is_file() {
        return Err(format!("hermesc not found at {}", compiler.display()));
    }
    authenticate_compiler(layout, compiler)?;
    let engine_digest = digest_file(&layout.vm_archive)?;
    let bytecode_version = hermesc_bytecode_version(compiler)?;
    validate_receipt(layout, compiler, true, &engine_digest, &bytecode_version)?;
    Ok(bytecode_version)
}

fn authenticate_compiler(layout: &InstallLayout, compiler: &Path) -> Result<(), String> {
    let receipt_path = layout.root.join("hermes-input-receipt.json");
    if !receipt_path.is_file() {
        if layout.requires_receipt {
            return Err(format!(
                "pinned Hermes bundle is missing {}",
                receipt_path.display()
            ));
        }
        return Ok(());
    }
    let bytes = fs::read(&receipt_path)
        .map_err(|error| format!("cannot read {}: {error}", receipt_path.display()))?;
    let receipt: Receipt = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {}: {error}", receipt_path.display()))?;
    if layout.requires_receipt
        && receipt.schema.as_deref() != Some("ibex/hermes-upstream-pinned-receipt/2")
    {
        return Err(format!(
            "pinned Hermes bundle receipt {} is not schema ibex/hermes-upstream-pinned-receipt/2",
            receipt_path.display()
        ));
    }
    let expected = receipt
        .compiler
        .and_then(|compiler| compiler.digest)
        .ok_or_else(|| {
            format!(
                "{} has no compiler digest, so {} cannot be authenticated before execution",
                receipt_path.display(),
                compiler.display()
            )
        })?;
    let actual = digest_file(compiler)?;
    if expected != actual {
        return Err(format!(
            "{} records compiler digest {}, but selected hermesc {} has {}; refusing to execute an unauthenticated compiler",
            receipt_path.display(),
            expected,
            compiler.display(),
            actual
        ));
    }
    Ok(())
}

fn validate_receipt(
    layout: &InstallLayout,
    compiler: &Path,
    validate_compiler_digest: bool,
    engine_digest: &str,
    bytecode_version: &str,
) -> Result<(), String> {
    let receipt_path = layout.root.join("hermes-input-receipt.json");
    if !receipt_path.is_file() {
        if layout.requires_receipt {
            return Err(format!(
                "pinned Hermes bundle is missing {}",
                receipt_path.display()
            ));
        }
        return Ok(());
    }
    let bytes = fs::read(&receipt_path)
        .map_err(|error| format!("cannot read {}: {error}", receipt_path.display()))?;
    let receipt: Receipt = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot parse {}: {error}", receipt_path.display()))?;
    if layout.requires_receipt
        && receipt.schema.as_deref() != Some("ibex/hermes-upstream-pinned-receipt/2")
    {
        return Err(format!(
            "pinned Hermes bundle receipt {} is not schema ibex/hermes-upstream-pinned-receipt/2",
            receipt_path.display()
        ));
    }
    let receipt_archive = safe_relative_path(&layout.root, Path::new(&receipt.engine.binary))?;
    let selected_archive = fs::canonicalize(&layout.vm_archive).map_err(|error| {
        format!(
            "cannot resolve selected Hermes archive {}: {error}",
            layout.vm_archive.display()
        )
    })?;
    let described_archive = fs::canonicalize(&receipt_archive).map_err(|error| {
        format!(
            "receipt engine archive {} does not exist: {error}",
            receipt_archive.display()
        )
    })?;
    if selected_archive != described_archive {
        return Err(format!(
            "{} describes engine archive {}, but hermes-lean-sys selected {}",
            receipt_path.display(),
            receipt.engine.binary,
            layout.vm_archive.display()
        ));
    }
    if receipt.engine.binary_digest != engine_digest {
        return Err(format!(
            "{} records engine digest {}, but ENGINE_DIGEST is {}",
            receipt_path.display(),
            receipt.engine.binary_digest,
            engine_digest
        ));
    }
    if validate_compiler_digest {
        if let Some(compiler_digest) = receipt.compiler.and_then(|compiler| compiler.digest) {
            let selected_compiler_digest = digest_file(compiler)?;
            if compiler_digest != selected_compiler_digest {
                return Err(format!(
                    "{} records compiler digest {}, but selected hermesc {} has {}; the receipt describes a different compiler than this build uses",
                    receipt_path.display(),
                    compiler_digest,
                    compiler.display(),
                    selected_compiler_digest
                ));
            }
        }
    }
    if let Some(receipt_bytecode) = receipt.bytecode {
        let receipt_version = match receipt_bytecode.version {
            serde_json::Value::Number(number) => number.to_string(),
            serde_json::Value::String(text) => text,
            other => {
                return Err(format!(
                    "{} has invalid bytecode.version {other}",
                    receipt_path.display()
                ))
            }
        };
        if receipt_version != bytecode_version {
            return Err(format!(
                "{} records HBC bytecode version {}, but selected hermesc {} reports {}",
                receipt_path.display(),
                receipt_version,
                compiler.display(),
                bytecode_version
            ));
        }
    }
    Ok(())
}

fn safe_relative_path(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(format!(
            "unsafe absolute or empty path in Hermes receipt: {}",
            relative.display()
        ));
    }
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(format!(
                "unsafe path in Hermes receipt: {}",
                relative.display()
            ));
        }
    }
    Ok(root.join(relative))
}

pub(crate) fn digest_file(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut DigestWriter(&mut digest))
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
    Ok(format!("sha256-{:x}", digest.finalize()))
}

struct DigestWriter<'a>(&'a mut Sha256);

impl Write for DigestWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn hermesc_bytecode_version(hermesc: &Path) -> Result<String, String> {
    let output = std::process::Command::new(hermesc)
        .arg("-version")
        .output()
        .map_err(|error| format!("cannot run {}: {error}", hermesc.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} -version failed with {}",
            hermesc.display(),
            output.status
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    text.lines()
        .find_map(|line| line.trim().strip_prefix("HBC bytecode version:"))
        .map(str::trim)
        .filter(|version| !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()))
        .map(str::to_owned)
        .ok_or_else(|| {
            format!(
                "{} did not report an HBC bytecode version",
                hermesc.display()
            )
        })
}

pub(crate) fn acquire_bundle(
    pin: &BundlePin,
    options: &DownloadOptions,
) -> Result<PathBuf, String> {
    let expected_digest = parse_pin_sha256(pin.sha256)?;
    let entry = options.cache_root.join(RELEASE_TAG).join(&expected_digest);
    if entry.exists() {
        return validate_cache_record(&entry, &expected_digest).map(|()| entry);
    }
    if options.offline {
        return Err(format!(
            "Hermes bundle {} is not cached at {} and offline mode is enabled; pre-populate the cache while online or set HERMES_LEAN_SYS_DIR to a complete local install",
            pin.asset,
            entry.display()
        ));
    }

    let tag_dir = options.cache_root.join(RELEASE_TAG);
    fs::create_dir_all(&tag_dir)
        .map_err(|error| format!("cannot create Hermes cache {}: {error}", tag_dir.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(".download-")
        .tempdir_in(&tag_dir)
        .map_err(|error| format!("cannot create a Hermes cache staging directory: {error}"))?;
    let archive_path = staging.path().join(pin.asset);
    let url = format!(
        "{}/{}/{}",
        options.release_base_url.trim_end_matches('/'),
        RELEASE_TAG,
        pin.asset
    );
    download_archive(&url, &archive_path, &expected_digest)?;

    let extracted = staging.path().join("install");
    fs::create_dir(&extracted)
        .map_err(|error| format!("cannot create {}: {error}", extracted.display()))?;
    extract_archive_safely(&archive_path, &extracted)?;
    fs::write(
        extracted.join(CACHE_DIGEST_RECORD),
        format!("{expected_digest}\n"),
    )
    .map_err(|error| format!("cannot record the cached Hermes digest: {error}"))?;

    match fs::rename(&extracted, &entry) {
        Ok(()) => Ok(entry),
        Err(error) if entry.exists() => validate_cache_record(&entry, &expected_digest)
            .map(|()| entry)
            .map_err(|cache_error| {
                format!(
                    "parallel Hermes cache install lost a race ({error}), and the winning entry is invalid: {cache_error}"
                )
            }),
        Err(error) => Err(format!(
            "cannot atomically install Hermes bundle into {}: {error}",
            entry.display()
        )),
    }
}

fn validate_cache_record(entry: &Path, expected_digest: &str) -> Result<(), String> {
    let record = entry.join(CACHE_DIGEST_RECORD);
    let recorded = fs::read_to_string(&record).map_err(|error| {
        format!(
            "refusing cached Hermes bundle {} because its digest record {} cannot be read: {error}",
            entry.display(),
            record.display()
        )
    })?;
    if recorded.trim() != expected_digest {
        return Err(format!(
            "refusing cached Hermes bundle {}: recorded archive digest {:?} does not match pinned digest {}",
            entry.display(),
            recorded.trim(),
            expected_digest
        ));
    }
    Ok(())
}

fn download_archive(url: &str, destination: &Path, expected_digest: &str) -> Result<(), String> {
    let response = ureq::get(url)
        .call()
        .map_err(|error| format!("cannot download pinned Hermes bundle {url}: {error}"))?;
    let mut reader = response.into_body().into_reader();
    let mut output = File::create(destination)
        .map_err(|error| format!("cannot create {}: {error}", destination.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| format!("cannot read pinned Hermes bundle {url}: {error}"))?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|error| format!("cannot write {}: {error}", destination.display()))?;
        digest.update(&buffer[..count]);
    }
    output
        .sync_all()
        .map_err(|error| format!("cannot finish {}: {error}", destination.display()))?;
    let actual = format!("{:x}", digest.finalize());
    if actual != expected_digest {
        return Err(format!(
            "refusing Hermes bundle from {url}: SHA-256 mismatch (pinned {expected_digest}, downloaded {actual}); nothing was extracted"
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn verify_and_extract_archive(
    archive_path: &Path,
    expected_digest: &str,
    destination: &Path,
) -> Result<(), String> {
    let expected_digest = parse_pin_sha256(expected_digest)?;
    let actual = digest_file(archive_path)?
        .strip_prefix("sha256-")
        .expect("digest_file prefixes SHA-256")
        .to_owned();
    if actual != expected_digest {
        return Err(format!(
            "refusing Hermes bundle {}: SHA-256 mismatch (pinned {}, downloaded {}); nothing was extracted",
            archive_path.display(),
            expected_digest,
            actual
        ));
    }
    extract_archive_safely(archive_path, destination)
}

fn extract_archive_safely(archive_path: &Path, destination: &Path) -> Result<(), String> {
    validate_archive_entries(archive_path)?;
    let file = File::open(archive_path)
        .map_err(|error| format!("cannot open {}: {error}", archive_path.display()))?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    let entries = archive
        .entries()
        .map_err(|error| format!("cannot read {}: {error}", archive_path.display()))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| {
            format!(
                "cannot read an entry from {}: {error}",
                archive_path.display()
            )
        })?;
        let path = entry
            .path()
            .map_err(|error| format!("invalid tar path in {}: {error}", archive_path.display()))?
            .into_owned();
        let output_path = safe_relative_path(destination, &path)
            .expect("archive paths were validated before extraction");
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            fs::create_dir_all(&output_path).map_err(|error| {
                format!(
                    "cannot create extracted directory {}: {error}",
                    output_path.display()
                )
            })?;
        } else if entry_type.is_file() {
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "cannot create extracted directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
            entry.unpack(&output_path).map_err(|error| {
                format!(
                    "cannot extract regular file {}: {error}",
                    output_path.display()
                )
            })?;
        } else {
            unreachable!("archive entry types were validated before extraction");
        }
    }
    Ok(())
}

fn validate_archive_entries(archive_path: &Path) -> Result<(), String> {
    let file = File::open(archive_path)
        .map_err(|error| format!("cannot open {}: {error}", archive_path.display()))?;
    let decoder = GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| format!("cannot read {}: {error}", archive_path.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "cannot read an entry from {}: {error}",
                archive_path.display()
            )
        })?;
        let path = entry
            .path()
            .map_err(|error| format!("invalid tar path in {}: {error}", archive_path.display()))?
            .into_owned();
        safe_relative_path(Path::new("."), &path)
            .map_err(|error| format!("refusing unsafe tar entry {}: {error}", path.display()))?;
        let entry_type = entry.header().entry_type();
        if !entry_type.is_dir() && !entry_type.is_file() {
            return Err(format!(
                "refusing non-file tar entry {} (type {:?}); links and special files are forbidden",
                path.display(),
                entry_type
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod internal_tests {
    use super::*;

    #[test]
    fn published_layout_requires_a_v2_receipt_even_for_an_override() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path();
        fs::create_dir_all(root.join("include")).expect("include directory");
        fs::create_dir_all(root.join("lib")).expect("lib directory");
        fs::write(root.join("lib/libhermesvm_a.a"), b"engine").expect("engine archive");
        let layout = install_layout(
            root.to_path_buf(),
            "aarch64-apple-darwin",
            InstallOrigin::Override,
        );

        let error = validate_receipt(
            &layout,
            &root.join("bin/hermesc"),
            true,
            "sha256-unused",
            "96",
        )
        .expect_err("published layout without a receipt must fail");
        assert!(error.contains("missing"), "{error}");
    }

    #[test]
    fn receipt_refuses_a_different_selected_compiler() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path();
        fs::create_dir_all(root.join("include")).expect("include directory");
        fs::create_dir_all(root.join("lib")).expect("lib directory");
        fs::create_dir_all(root.join("bin")).expect("bin directory");
        fs::write(root.join("lib/libhermesvm_a.a"), b"engine").expect("engine archive");
        fs::write(root.join("bin/hermesc"), b"selected compiler").expect("compiler");
        let engine_digest = digest_file(&root.join("lib/libhermesvm_a.a")).expect("digest");
        fs::write(
            root.join("hermes-input-receipt.json"),
            format!(
                r#"{{"schema":"ibex/hermes-upstream-pinned-receipt/2","engine":{{"binary":"lib/libhermesvm_a.a","binaryDigest":"{engine_digest}"}},"compiler":{{"digest":"sha256-{}"}},"bytecode":{{"version":96}}}}"#,
                "0".repeat(64)
            ),
        )
        .expect("receipt");
        let layout = install_layout(
            root.to_path_buf(),
            "aarch64-apple-darwin",
            InstallOrigin::Bundle,
        );

        let error = validate_receipt(
            &layout,
            &root.join("bin/hermesc"),
            true,
            &engine_digest,
            "96",
        )
        .expect_err("compiler mismatch must fail");
        assert!(error.contains("different compiler"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn compiler_digest_is_checked_before_hermesc_executes() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path();
        fs::create_dir_all(root.join("include")).expect("include directory");
        fs::create_dir_all(root.join("lib")).expect("library directory");
        fs::create_dir_all(root.join("bin")).expect("compiler directory");
        fs::write(root.join("lib/libhermesvm_a.a"), b"engine").expect("engine archive");
        let marker = root.join("executed");
        let compiler = root.join("bin/hermesc");
        fs::write(
            &compiler,
            format!(
                "#!/bin/sh\ntouch '{}'\necho 'HBC bytecode version: 96'\n",
                marker.display()
            ),
        )
        .expect("compiler script");
        let mut permissions = fs::metadata(&compiler).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&compiler, permissions).expect("executable compiler");
        let engine_digest = digest_file(&root.join("lib/libhermesvm_a.a")).expect("digest");
        fs::write(
            root.join("hermes-input-receipt.json"),
            format!(
                r#"{{"schema":"ibex/hermes-upstream-pinned-receipt/2","engine":{{"binary":"lib/libhermesvm_a.a","binaryDigest":"{engine_digest}"}},"compiler":{{"digest":"sha256-{}"}},"bytecode":{{"version":96}}}}"#,
                "0".repeat(64)
            ),
        )
        .expect("receipt");
        let layout = install_layout(
            root.to_path_buf(),
            "aarch64-apple-darwin",
            InstallOrigin::Bundle,
        );

        let error = validate_compiler_bundle(&layout, &compiler)
            .expect_err("unauthenticated compiler must fail");
        assert!(error.contains("refusing to execute"), "{error}");
        assert!(
            !marker.exists(),
            "hermesc ran before its digest was authenticated"
        );
    }

    #[test]
    fn receipt_requires_the_selected_engine_archive() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path();
        fs::create_dir_all(root.join("lib")).expect("lib directory");
        fs::create_dir_all(root.join("bin")).expect("bin directory");
        fs::write(root.join("lib/libhermesvm_a.a"), b"selected").expect("selected archive");
        fs::write(root.join("lib/decoy.a"), b"decoy").expect("decoy archive");
        fs::write(root.join("bin/hermesc"), b"compiler").expect("compiler");
        let engine_digest = digest_file(&root.join("lib/libhermesvm_a.a")).expect("digest");
        fs::write(
            root.join("hermes-input-receipt.json"),
            format!(r#"{{"schema":"ibex/hermes-upstream-pinned-receipt/2","engine":{{"binary":"lib/decoy.a","binaryDigest":"{engine_digest}"}}}}"#),
        )
        .expect("receipt");
        let layout = install_layout(
            root.to_path_buf(),
            "aarch64-apple-darwin",
            InstallOrigin::Bundle,
        );

        let error = validate_receipt(
            &layout,
            &root.join("bin/hermesc"),
            true,
            &engine_digest,
            "96",
        )
        .expect_err("decoy archive must fail");
        assert!(error.contains("selected"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn cross_bundle_pairing_uses_the_host_compiler_receipt_and_hbc_version() {
        use std::os::unix::fs::PermissionsExt;

        fn bundle(root: &Path, compiler: &[u8], version: u64) -> (InstallLayout, PathBuf) {
            fs::create_dir_all(root.join("include")).expect("include directory");
            fs::create_dir_all(root.join("lib")).expect("library directory");
            fs::create_dir_all(root.join("bin")).expect("compiler directory");
            fs::write(
                root.join("lib/libhermesvm_a.a"),
                root.as_os_str().as_encoded_bytes(),
            )
            .expect("engine archive");
            let compiler_path = root.join("bin/hermesc");
            fs::write(&compiler_path, compiler).expect("compiler");
            let mut permissions = fs::metadata(&compiler_path)
                .expect("metadata")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&compiler_path, permissions).expect("executable compiler");
            let engine_digest =
                digest_file(&root.join("lib/libhermesvm_a.a")).expect("engine digest");
            let compiler_digest = digest_file(&compiler_path).expect("compiler digest");
            fs::write(
                root.join("hermes-input-receipt.json"),
                format!(
                    r#"{{"schema":"ibex/hermes-upstream-pinned-receipt/2","engine":{{"binary":"lib/libhermesvm_a.a","binaryDigest":"{engine_digest}"}},"compiler":{{"digest":"{compiler_digest}"}},"bytecode":{{"version":{version}}}}}"#
                ),
            )
            .expect("receipt");
            (
                install_layout(
                    root.to_path_buf(),
                    "aarch64-apple-darwin",
                    InstallOrigin::Bundle,
                ),
                compiler_path,
            )
        }

        let temporary = tempfile::tempdir().expect("temporary directory");
        let target_script = b"#!/bin/sh\necho 'HBC bytecode version: 96'\n# target compiler\n";
        let host_script =
            b"#!/bin/sh\necho 'HBC bytecode version: 96'\n# different host compiler\n";
        let (target, _) = bundle(&temporary.path().join("target"), target_script, 96);
        let (host, host_compiler) = bundle(&temporary.path().join("host"), host_script, 96);

        let host_version = validate_compiler_bundle(&host, &host_compiler)
            .expect("host compiler is authenticated by the host receipt");
        assert_ne!(
            digest_file(&temporary.path().join("target/bin/hermesc")).unwrap(),
            digest_file(&host_compiler).unwrap(),
            "fixture compiler digests must differ"
        );
        let target_engine_digest = digest_file(&target.vm_archive).expect("target engine digest");
        validate_receipt(
            &target,
            &host_compiler,
            false,
            &target_engine_digest,
            &host_version,
        )
        .expect("matching HBC versions permit a cross-bundle pairing");

        let mismatched = fs::read_to_string(target.root.join("hermes-input-receipt.json"))
            .expect("target receipt")
            .replace(r#""version":96"#, r#""version":97"#);
        fs::write(target.root.join("hermes-input-receipt.json"), mismatched)
            .expect("mismatched target receipt");
        let error = validate_receipt(
            &target,
            &host_compiler,
            false,
            &target_engine_digest,
            &host_version,
        )
        .expect_err("different HBC versions must fail");
        assert!(error.contains("HBC bytecode version"), "{error}");
    }
}
