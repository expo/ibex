//! Resolve and link the repository's local vanilla-Hermes lean install.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const LINUX_ICU_I18N: &str = "icui18n";
const LINUX_ICU_UC: &str = "icuuc";
const LINUX_ICU_DATA: &str = "icudata";

struct EngineInstall {
    root: PathBuf,
    include_dir: PathBuf,
    lib_root: PathBuf,
    vm_archive: PathBuf,
    hermesc: PathBuf,
}

fn main() {
    println!("cargo:rerun-if-env-changed=HERMES_LEAN_SYS_DIR");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the repository root");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
    let target_arch = cargo_arch("CARGO_CFG_TARGET_ARCH");
    let host = std::env::var("HOST").expect("Cargo supplies HOST");
    let links_runtime = std::env::var_os("CARGO_FEATURE_LINK").is_some();

    let install =
        resolve_engine_directory(repo_root, &target_os, &target_vendor, target_arch, &host);
    validate_install(&install);

    println!("cargo:rerun-if-changed={}", install.vm_archive.display());
    println!("cargo:rerun-if-changed={}", install.hermesc.display());

    let engine_digest = digest_file(&install.vm_archive);
    let bytecode_version = hermesc_bytecode_version(&install.hermesc);
    metadata("include_dir", &install.include_dir.display().to_string());
    metadata("hermesc_path", &install.hermesc.display().to_string());
    metadata("lib_root", &install.lib_root.display().to_string());
    metadata("archive", &install.vm_archive.display().to_string());
    metadata("engine_digest", &engine_digest);
    metadata("bytecode_version", &bytecode_version);
    metadata("engine_dir", &install.root.display().to_string());
    if target_os == "linux" {
        metadata("icu_lib_dir", &install.lib_root.display().to_string());
        metadata("icu_i18n", LINUX_ICU_I18N);
        metadata("icu_uc", LINUX_ICU_UC);
        metadata("icu_data", LINUX_ICU_DATA);
    }
    println!("cargo:rustc-env=HERMES_LEAN_ENGINE_DIGEST={engine_digest}");
    println!(
        "cargo:rustc-env=HERMES_LEAN_ARCHIVE={}",
        install.vm_archive.display()
    );
    println!("cargo:rustc-env=HERMES_LEAN_BYTECODE_VERSION={bytecode_version}");

    if links_runtime {
        emit_link_lines(
            &target_os,
            &target_vendor,
            &install.lib_root,
            &install.vm_archive,
        );
    }
}

/// The single local-engine resolution seam. L1c replaces the fallback side
/// with verified pinned-release acquisition while preserving the override.
// TODO(L1c): resolve a verified cached/downloaded bundle when no local install is supplied.
fn resolve_engine_directory(
    repo_root: &Path,
    target_os: &str,
    target_vendor: &str,
    target_arch: &str,
    host: &str,
) -> EngineInstall {
    let overridden = std::env::var_os("HERMES_LEAN_SYS_DIR").map(PathBuf::from);
    let root = overridden.clone().unwrap_or_else(|| {
        if target_vendor == "apple" {
            repo_root.join("ios/Frameworks-vanilla")
        } else if target_os == "windows" {
            repo_root.join(format!("tools/hermes-vanilla/windows-{target_arch}"))
        } else if target_os == "linux" {
            repo_root.join("linux/Frameworks-vanilla")
        } else {
            panic!("unsupported Hermes target OS: {target_os}");
        }
    });
    let include_dir = root.join("hermes-headers");
    let lib_root = root.join(if target_vendor == "apple" {
        "macos-static"
    } else if target_os == "windows" {
        "windows-static"
    } else {
        "linux-static"
    });
    // This repository's owning runtime evaluates source at its host entrance,
    // so every feature context names the full VM archive. In particular,
    // resolver-v2 build and normal dependencies must export one identity even
    // when only the latter enables link-line emission.
    let vm_archive = lib_root.join(if target_os == "windows" {
        "hermesvm_a.lib"
    } else {
        "libhermesvm_a.a"
    });
    let hermesc = if overridden.is_some() {
        find_first(&[
            root.join(executable("hermesc", target_os)),
            root.join("bin").join(executable("hermesc", target_os)),
        ])
        .unwrap_or_else(|| root.join(executable("hermesc", target_os)))
    } else {
        let (host_os, host_arch) = host_platform(host);
        repo_root.join("tools/hermes-vanilla").join(format!(
            "hermesc-{host_os}-{host_arch}{}",
            if host_os == "windows" { ".exe" } else { "" }
        ))
    };
    EngineInstall {
        root,
        include_dir,
        lib_root,
        vm_archive,
        hermesc,
    }
}

fn cargo_arch(name: &str) -> &'static str {
    match std::env::var(name).as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x64",
        other => panic!("unsupported Hermes architecture: {other:?}"),
    }
}

fn host_platform(host: &str) -> (&'static str, &'static str) {
    let os = if host.contains("apple-darwin") {
        "macos"
    } else if host.contains("windows") {
        "windows"
    } else if host.contains("linux") {
        "linux"
    } else {
        panic!("unsupported Hermes compiler host: {host}");
    };
    let arch = if host.starts_with("aarch64-") {
        "arm64"
    } else if host.starts_with("x86_64-") {
        "x64"
    } else {
        panic!("unsupported Hermes compiler host architecture: {host}");
    };
    (os, arch)
}

fn executable(name: &str, target_os: &str) -> String {
    format!("{name}{}", if target_os == "windows" { ".exe" } else { "" })
}

fn find_first(paths: &[PathBuf]) -> Option<PathBuf> {
    paths.iter().find(|path| path.is_file()).cloned()
}

fn validate_install(install: &EngineInstall) {
    for (label, path) in [
        ("Hermes headers", &install.include_dir),
        ("Hermes library directory", &install.lib_root),
        ("Hermes VM archive", &install.vm_archive),
        ("hermesc", &install.hermesc),
    ] {
        assert!(
            path.exists(),
            "{label} not found at {}\nset HERMES_LEAN_SYS_DIR to a complete local install or build the repository's vanilla Hermes artifacts",
            path.display()
        );
    }
}

fn digest_file(path: &Path) -> String {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let digest = Sha256::digest(bytes);
    format!("sha256-{digest:x}")
}

fn hermesc_bytecode_version(hermesc: &Path) -> String {
    let output = std::process::Command::new(hermesc)
        .arg("-version")
        .output()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", hermesc.display()));
    assert!(
        output.status.success(),
        "{} -version failed with {}",
        hermesc.display(),
        output.status
    );
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    text.lines()
        .find_map(|line| line.trim().strip_prefix("HBC bytecode version:"))
        .map(str::trim)
        .filter(|version| !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()))
        .map(str::to_owned)
        .unwrap_or_else(|| {
            panic!(
                "{} did not report an HBC bytecode version",
                hermesc.display()
            )
        })
}

fn metadata(key: &str, value: &str) {
    println!("cargo::metadata={key}={value}");
}

fn emit_link_lines(target_os: &str, target_vendor: &str, lib_root: &Path, vm_archive: &Path) {
    println!("cargo:rustc-link-search=native={}", lib_root.display());
    let vm = vm_archive
        .file_stem()
        .and_then(|name| name.to_str())
        .expect("Hermes archive has a UTF-8 stem")
        .trim_start_matches("lib");
    println!("cargo:rustc-link-lib=static={vm}");
    println!("cargo:rustc-link-lib=static=jsi");
    println!("cargo:rustc-link-lib=static=boost_context");
    if target_vendor == "apple" {
        println!("cargo:rustc-link-lib=c++");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Foundation");
    } else if target_os == "windows" {
        println!("cargo:rustc-link-lib=icuuc");
        println!("cargo:rustc-link-lib=icuin");
        println!("cargo:rustc-link-lib=dbghelp");
        println!("cargo:rustc-link-lib=version");
        println!("cargo:rustc-link-lib=psapi");
        println!("cargo:rustc-link-lib=winmm");
    } else {
        println!("cargo:rustc-link-lib=static={LINUX_ICU_I18N}");
        println!("cargo:rustc-link-lib=static={LINUX_ICU_UC}");
        println!("cargo:rustc-link-lib=static={LINUX_ICU_DATA}");
        println!("cargo:rustc-link-lib=static=tinfo");
        println!("cargo:rustc-link-lib=stdc++");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
    }
}
