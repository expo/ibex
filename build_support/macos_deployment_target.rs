//! Align every native object with the deployment target selected by Rust.
//! @ref LLP 0005#c-compilation — SDK version is not the consumer's minimum OS.

/// Call once at build-script entry, before any threads or `cc::Build` instances.
/// This changes only the build script's environment and its compiler children;
/// Cargo's Rust invocations already select this same effective target.
pub fn align() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    println!("cargo:rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo:rerun-if-env-changed=RUSTC");
    let rustc = std::env::var_os("RUSTC").expect("Cargo supplies RUSTC");
    let target = std::env::var_os("TARGET").expect("Cargo supplies TARGET");
    // Inherit MACOSX_DEPLOYMENT_TARGET: rustc owns both its architecture-specific
    // default and the interpretation (including minimums) of an explicit value.
    let output = std::process::Command::new(rustc)
        .arg("--target")
        .arg(target)
        .args(["--print", "deployment-target"])
        .output()
        .expect("query rustc's macOS deployment target");
    assert!(
        output.status.success(),
        "rustc could not select the macOS deployment target: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("rustc deployment target is UTF-8");
    let version = stdout
        .trim()
        .strip_prefix("MACOSX_DEPLOYMENT_TARGET=")
        .filter(|version| {
            !version.is_empty()
                && version
                    .split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .unwrap_or_else(|| panic!("unexpected rustc deployment target: {stdout:?}"));
    // SAFETY: both entrypoints call this before spawning threads or compiling.
    // Setting the variable before cc reads it also covers its compiler probes,
    // C, C++, Objective-C++ and archives without conflicting -m flags.
    unsafe { std::env::set_var("MACOSX_DEPLOYMENT_TARGET", version) };
}
