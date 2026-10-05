use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/lean_embedding.cc");
    println!("cargo:rerun-if-changed=tests/app.js");

    let headers = required_path("DEP_HERMES_LEAN_INCLUDE_DIR");
    let mut bridge = cc::Build::new();
    bridge
        .cpp(true)
        .file("src/lean_embedding.cc")
        .include(&headers)
        .include("../ibex2/include")
        .std("c++17");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        bridge.flag("-stdlib=libc++");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        bridge.flag("/EHsc").define("NOMINMAX", None);
    }
    bridge.compile("ibex2_lean_embedding");

    let full_hbc = required("DEP_HERMES_LEAN_BYTECODE_VERSION");
    let lean_hbc = required("DEP_HERMES_LEAN_LEAN_BYTECODE_VERSION");
    assert_eq!(
        full_hbc, lean_hbc,
        "full and lean Hermes VMs from one source commit must consume one HBC version"
    );

    let app_bytecode = PathBuf::from(required("OUT_DIR")).join("lean-app.hbc");
    let status = std::process::Command::new(required_path("DEP_HERMES_LEAN_HERMESC_PATH"))
        .args(["-emit-binary", "-O", "-Xes6-block-scoping", "-out"])
        .arg(&app_bytecode)
        .arg(Path::new("tests/app.js"))
        .status()
        .expect("run authenticated hermesc");
    assert!(status.success(), "hermesc failed on tests/app.js");
    println!(
        "cargo:rustc-env=IBEX2_LEAN_APP_BYTECODE={}",
        app_bytecode.display()
    );
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} was not exported by hermes-lean-sys"))
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(required(name))
}
