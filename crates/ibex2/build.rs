//! Build the Ibex 2 spike against **vanilla** Hermes.
//!
//! The engine is opt-in behind the `hermes` feature so the workspace stays
//! green on a machine that has not built one. Produce it with:
//!
//!     ./scripts/build-hermes.sh --vanilla
//!
//! This deliberately points at `ios/Frameworks-vanilla/`, never
//! `ios/Frameworks/`. Linking the reviewed patched engine here would silently
//! reintroduce the fork LLP 0060 D3 retires, and the whole value of the spike
//! is that it cannot compile against anything the patch series adds.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=src/engine/hermes_shim.cc");
    println!("cargo:rerun-if-env-changed=IBEX2_VANILLA_HERMES_DIR");

    if std::env::var("CARGO_FEATURE_HERMES").is_err() {
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("crate lives two levels below the repo root");

    let engine_dir = std::env::var("IBEX2_VANILLA_HERMES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join("ios/Frameworks-vanilla"));

    let headers = engine_dir.join("hermes-headers");
    let static_dir = engine_dir.join("macos-static");

    // Fail loud rather than emitting a link line that dies at the last step
    // with an unresolved-symbol wall: the actionable message is here.
    for required in [&headers, &static_dir] {
        assert!(
            required.exists(),
            "vanilla Hermes not found at {}\n\
             build it with: ./scripts/build-hermes.sh --vanilla\n\
             (or point IBEX2_VANILLA_HERMES_DIR at an existing one)",
            required.display()
        );
    }

    cc::Build::new()
        .cpp(true)
        .file("src/engine/hermes_shim.cc")
        .include(&headers)
        .flag("-std=c++17")
        .flag("-stdlib=libc++")
        .compile("ibex2_hermes_shim");

    // The Apple platform transport (LLP 0057 §3). Objective-C++ with ARC, so
    // NSURLSession manages its own object graph and this file does not.
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rerun-if-changed=src/engine/darwin_http.mm");
        cc::Build::new()
            .cpp(true)
            .file("src/engine/darwin_http.mm")
            .flag("-std=c++17")
            .flag("-stdlib=libc++")
            .flag("-fobjc-arc")
            .flag("-x")
            .flag("objective-c++")
            .compile("ibex2_darwin_http");
    }

    println!("cargo:rustc-link-search=native={}", static_dir.display());
    println!("cargo:rustc-link-lib=static=hermesvm_a");
    println!("cargo:rustc-link-lib=static=jsi");
    println!("cargo:rustc-link-lib=static=boost_context");
    println!("cargo:rustc-link-lib=c++");
    // Hermes's Apple platform-unicode path (PlatformUnicodeCF.cpp) calls
    // CFLocale/CFString directly for case conversion and normalization, and its
    // Intl implementation is Foundation-backed (NSNumberFormatter and kin) —
    // which is how this build satisfies LLP 0059 Tier E's ICU-bearing
    // requirement without a separate ICU.
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    println!("cargo:rustc-link-lib=framework=Foundation");
}
