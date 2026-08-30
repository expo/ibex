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

    // The Apple platform transport (LLP 0057 §3). Objective-C++ with ARC, so
    //
    // Compiled whether or not there is an engine: a Rust consumer of the
    // standard library (LLP 0068) has no engine in the process and still
    // needs the platform's `fetch` underneath it.
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
    // The Keychain behind `SecretStore` (LLP 0069 §3): the same shape, one
    // more framework.
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rerun-if-changed=src/engine/darwin_keychain.mm");
        cc::Build::new()
            .cpp(true)
            .file("src/engine/darwin_keychain.mm")
            .flag("-std=c++17")
            .flag("-stdlib=libc++")
            .flag("-fobjc-arc")
            .flag("-x")
            .flag("objective-c++")
            .compile("ibex2_darwin_keychain");
    }
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=Security");
    }

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

    // The engine this binary links, as a digest baked into it. Artifacts are
    // keyed by it at build time and the manifest is checked against it at run
    // time, so the runtime never hashes anything to know which engine it is —
    // the previous design SHA-256'd the framework dylib on disk at every start,
    // 25 ms of a 30 ms budget, to verify a file it does not even run
    // (issues/20260829-run-hashes-the-engine-on-every-start.md). Hashed here,
    // once per link, of the archive actually linked.
    let archive = static_dir.join("libhermesvm_a.a");
    println!("cargo:rerun-if-changed={}", archive.display());
    let archive_bytes = std::fs::read(&archive)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", archive.display()));
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&archive_bytes);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    println!("cargo:rustc-env=IBEX2_LINKED_ENGINE_DIGEST=sha256-{hex}");

    // The runtime's own JavaScript — the ESM helpers, Headers, timers, URL,
    // and the freeze — compiled to bytecode here so a runtime never parses
    // them: rules/RULES.md says the boot path compiles nothing, and that was
    // true of application code while the bindings were still evaluated from
    // source at every start (~0.7 ms of a 1.8 ms floor, LLP 0063 §2). The
    // hermesc is the one beside the vanilla engine, from the same install as
    // the archive linked above, so the bytecode version matches the VM.
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        _ => "x64",
    };
    println!("cargo:rerun-if-env-changed=IBEX2_HERMESC");
    let hermesc = std::env::var("IBEX2_HERMESC")
        .map(PathBuf::from)
        .unwrap_or_else(|_| repo_root.join(format!("tools/hermes-vanilla/hermesc-macos-{arch}")));
    assert!(
        hermesc.exists(),
        "hermesc not found at {}\n\
         build it with: ./scripts/build-hermes.sh --vanilla\n\
         (or point IBEX2_HERMESC at one)",
        hermesc.display()
    );
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    for name in ["esm", "headers", "timers", "url", "fetch", "harden"] {
        let source = format!("src/bindings/{name}.js");
        println!("cargo:rerun-if-changed={source}");
        let artifact = out_dir.join(format!("{name}.hbc"));
        let status = std::process::Command::new(&hermesc)
            .args(["-emit-binary", "-O", "-out"])
            .arg(&artifact)
            .arg(&source)
            .status()
            .unwrap_or_else(|e| panic!("cannot run {}: {e}", hermesc.display()));
        assert!(status.success(), "hermesc failed on {source}");
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
