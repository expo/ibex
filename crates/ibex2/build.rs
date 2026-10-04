//! Build the engine-free Rust library and, when requested, its JSI bindings.

use std::path::{Path, PathBuf};

fn main() {
    let target_vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let is_apple = target_vendor == "apple";

    build_platform_backends(is_apple);
    if std::env::var_os("CARGO_FEATURE_BINDINGS").is_none() {
        return;
    }

    let headers = required_path("DEP_HERMES_LEAN_INCLUDE_DIR");
    println!("cargo:rerun-if-changed=src/bindings/install.cc");
    println!("cargo:rerun-if-changed=include/ibex2_jsi.h");
    let mut installer = cc::Build::new();
    installer
        .cpp(true)
        .file("src/bindings/install.cc")
        .include(&headers)
        .std("c++17");
    if target_os == "windows" {
        installer.flag("/EHsc").define("NOMINMAX", None);
    }
    if target_os == "linux" {
        for source in [
            "src/bindings/intl_number_format.cc",
            "src/bindings/intl_icu.cc",
            "src/bindings/intl_case_icu.cc",
            "src/bindings/intl_datetime_icu.cc",
        ] {
            println!("cargo:rerun-if-changed={source}");
            installer.file(source);
        }
        installer.define("IBEX2_JSI_HAS_INTL", None);
    }
    if is_apple {
        installer.flag("-stdlib=libc++");
    }
    installer.compile("ibex2_bindings_install");

    let hermesc = required_path("DEP_HERMES_LEAN_HERMESC_PATH");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let mut scripts = vec![
        "headers",
        "timers",
        "url",
        "domexception",
        "crypto",
        "events",
        "abort",
        "websocket",
        "blob",
        "fetch",
        "sqlite",
    ];
    if target_os == "linux" {
        scripts.extend(["intl_number_format", "intl_case", "intl_datetime"]);
    }
    scripts.push("structured_clone");
    for name in scripts {
        let source = format!("src/bindings/{name}.js");
        println!("cargo:rerun-if-changed={source}");
        compile_javascript(
            &hermesc,
            Path::new(&source),
            &out_dir.join(format!("{name}.hbc")),
        );
    }

    // Hardening is runtime bootstrap, but Decision C makes the same source
    // and bytecode part of the borrowed-runtime contract. Its source remains
    // physically with ibex2-runtime and its compiled artifact is exported here.
    let harden_source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ibex2-runtime/src/bindings/harden.js");
    println!("cargo:rerun-if-changed={}", harden_source.display());
    let harden_bytecode = out_dir.join("harden.hbc");
    compile_javascript(&hermesc, &harden_source, &harden_bytecode);
    println!(
        "cargo:rustc-env=IBEX2_HARDEN_SOURCE_PATH={}",
        harden_source.display()
    );
    println!(
        "cargo:rustc-env=IBEX2_HARDEN_BYTECODE_PATH={}",
        harden_bytecode.display()
    );
    println!(
        "cargo:rustc-env=IBEX2_BINDINGS_ENGINE_DIGEST={}",
        required("DEP_HERMES_LEAN_ENGINE_DIGEST")
    );
    println!(
        "cargo:rustc-env=IBEX2_BINDINGS_BYTECODE_VERSION={}",
        required("DEP_HERMES_LEAN_BYTECODE_VERSION")
    );
}

fn build_platform_backends(is_apple: bool) {
    if !is_apple {
        return;
    }
    for source in [
        "src/transport/darwin_http.mm",
        "src/secrets/darwin_keychain.mm",
    ] {
        println!("cargo:rerun-if-changed={source}");
        compile_objc(source);
    }
    if std::env::var_os("CARGO_FEATURE_WEBSOCKET").is_some() {
        let source = "src/transport/darwin_websocket.mm";
        println!("cargo:rerun-if-changed={source}");
        compile_objc(source);
    }
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
}

fn compile_objc(source: &str) {
    let stem = Path::new(source)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("Objective-C++ source has a stem");
    cc::Build::new()
        .cpp(true)
        .file(source)
        .flag("-std=c++17")
        .flag("-stdlib=libc++")
        .flag("-fobjc-arc")
        .flag("-x")
        .flag("objective-c++")
        .compile(&format!("ibex2_{stem}"));
}

fn compile_javascript(hermesc: &Path, source: &Path, output: &Path) {
    let status = std::process::Command::new(hermesc)
        .args(["-emit-binary", "-O", "-Xes6-block-scoping", "-out"])
        .arg(output)
        .arg(source)
        .status()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", hermesc.display()));
    assert!(status.success(), "hermesc failed on {}", source.display());
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} was not exported by hermes-lean-sys"))
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(required(name))
}
