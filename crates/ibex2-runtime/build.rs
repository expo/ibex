use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/engine/hermes_shim.cc");
    println!("cargo:rerun-if-changed=tests/embedding.cc");
    println!("cargo:rerun-if-changed=src/bindings/esm.js");

    let headers = required_path("DEP_HERMES_LEAN_INCLUDE_DIR");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();

    let mut shim = cc::Build::new();
    shim.cpp(true)
        .file("src/engine/hermes_shim.cc")
        .file("tests/embedding.cc")
        .include(&headers)
        .include("../ibex2/include")
        .std("c++17");
    if target_os == "windows" {
        shim.flag("/EHsc").define("NOMINMAX", None);
    }
    if target_vendor == "apple" {
        shim.flag("-stdlib=libc++");
    }
    shim.compile("ibex2_runtime_hermes_shim");

    let hermesc = required_path("DEP_HERMES_LEAN_HERMESC_PATH");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    compile_javascript(&hermesc, "src/bindings/esm.js", &out_dir.join("esm.hbc"));

    let engine_digest = required("DEP_HERMES_LEAN_ENGINE_DIGEST");
    let bytecode_version = required("DEP_HERMES_LEAN_BYTECODE_VERSION");
    let engine_dir = required("DEP_HERMES_LEAN_ENGINE_DIR");
    println!("cargo:rustc-env=IBEX2_LINKED_ENGINE_DIGEST={engine_digest}");
    println!("cargo:rustc-env=IBEX2_LINKED_BYTECODE_VERSION={bytecode_version}");
    println!("cargo:rustc-env=IBEX2_HERMESC_PATH={}", hermesc.display());
    println!("cargo:rustc-env=IBEX2_ENGINE_DIR={engine_dir}");
}

fn compile_javascript(hermesc: &std::path::Path, source: &str, output: &std::path::Path) {
    let status = std::process::Command::new(hermesc)
        .args(["-emit-binary", "-O", "-Xes6-block-scoping", "-out"])
        .arg(output)
        .arg(source)
        .status()
        .unwrap_or_else(|error| panic!("cannot run {}: {error}", hermesc.display()));
    assert!(status.success(), "hermesc failed on {source}");
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} was not exported by hermes-lean-sys"))
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(required(name))
}
