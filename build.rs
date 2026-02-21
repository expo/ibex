use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("Failed to resolve repo root");

    let hermes_headers = repo_root.join("ios").join("Frameworks").join("hermes-headers");
    let hermes_frameworks = repo_root.join("ios").join("Frameworks");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    println!("cargo:rerun-if-changed=src/engine/hermes_runtime.cc");
    println!("cargo:rerun-if-changed=src/engine/native_fetch_macos.mm");
    println!("cargo:rerun-if-changed=src/engine/native_websocket_macos.mm");
    println!("cargo:rerun-if-env-changed=HERMES_ENABLE_DEBUGGER");
    println!("cargo:rustc-check-cfg=cfg(hermes_debugger)");

    // Compile hermes_runtime.cc
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file("src/engine/hermes_runtime.cc")
        .include(&hermes_headers)
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-stdlib=libc++");

    // Set minimum deployment targets to match Xcode project settings.
    // This avoids "was built for newer version" linker warnings for our C++ files.
    // Note: bundled C deps (e.g. rusqlite's sqlite3) need the env var set before
    // cargo runs — see build-kernel.sh which exports MACOSX_DEPLOYMENT_TARGET.
    match target_os.as_str() {
        "macos" => { build.flag("-mmacosx-version-min=14.0"); }
        "ios" => { build.flag("-mios-version-min=17.0"); }
        _ => {}
    }

    // Platform-specific includes and defines
    match target_os.as_str() {
        "macos" => {
            // OpenSSL include path from vendored openssl-sys crate
            if let Ok(openssl_include) = std::env::var("DEP_OPENSSL_INCLUDE") {
                build.include(&openssl_include);
            }

            // Brotli include path from vendored source
            let brotli_include = manifest_dir.join("vendor").join("brotli").join("include");
            build.include(&brotli_include);
        }
        "ios" => {
            // On iOS, CommonCrypto is available via the SDK (no OpenSSL needed)
            // Brotli is not available on iOS by default, so we disable it
            build.define("EXACT_NO_BROTLI", None);
            build.define("EXACT_NO_OPENSSL", None);
            build.define("EXACT_PLATFORM_IOS", None);
        }
        _ => {}
    }

    // Debugger support (disabled on iOS by default — Hermes xcframework needs matching debugger build)
    // Set HERMES_ENABLE_DEBUGGER=1 to enable for CDP DevTools support
    let enable_debugger = if target_os == "ios" {
        std::env::var("HERMES_ENABLE_DEBUGGER")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    } else {
        std::env::var("HERMES_ENABLE_DEBUGGER")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(true)
    };

    if enable_debugger {
        build.define("HERMES_ENABLE_DEBUGGER", None);
        println!("cargo:rustc-cfg=hermes_debugger");
    }

    build.compile("exact_hermes_runtime");

    // Compile native fetch and websocket (Objective-C++ using NSURLSession)
    // These work on both macOS and iOS since they use Foundation
    if target_os == "macos" || target_os == "ios" {
        let mut fetch_build = cc::Build::new();
        fetch_build
            .file("src/engine/native_fetch_macos.mm")
            .flag("-fobjc-arc")
            .flag("-std=c++17")
            .flag("-stdlib=libc++");
        if target_os == "macos" {
            fetch_build.flag("-mmacosx-version-min=14.0");
        } else {
            fetch_build.flag("-mios-version-min=17.0");
        }
        fetch_build.compile("exact_native_fetch");

        let mut ws_build = cc::Build::new();
        ws_build
            .file("src/engine/native_websocket_macos.mm")
            .flag("-fobjc-arc")
            .flag("-std=c++17")
            .flag("-stdlib=libc++");
        if target_os == "macos" {
            ws_build.flag("-mmacosx-version-min=14.0");
        } else {
            ws_build.flag("-mios-version-min=17.0");
        }
        ws_build
            .compile("exact_native_websocket");

        // Link frameworks
        if target_os == "macos" {
            println!("cargo:rustc-link-search=framework={}", hermes_frameworks.display());
            println!("cargo:rustc-link-lib=framework=hermesvm");
            println!("cargo:rustc-link-arg=-Wl,-rpath,{}", hermes_frameworks.display());
        }
        // On iOS, Hermes is linked by Xcode (via hermes.xcframework dependency)

        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=c++");
        println!("cargo:rustc-link-lib=z");

        if target_os == "macos" {
            // Link vendored OpenSSL (compiled by openssl-sys crate)
            // We must emit link directives here to ensure correct link order,
            // since hermes_runtime.cc references OpenSSL symbols directly.
            if let Ok(lib_dir) = std::env::var("DEP_OPENSSL_LIB_DIR") {
                println!("cargo:rustc-link-search=native={}", lib_dir);
            }
            println!("cargo:rustc-link-lib=static=ssl");
            println!("cargo:rustc-link-lib=static=crypto");
            // Link libresolv for DNS res_query()
            println!("cargo:rustc-link-lib=resolv");

            // Compile vendored Brotli from source
            let brotli_dir = manifest_dir.join("vendor").join("brotli");
            let mut brotli_build = cc::Build::new();
            brotli_build
                .include(brotli_dir.join("include"))
                .flag("-mmacosx-version-min=14.0");

            // Add all brotli C sources
            for subdir in &["common", "dec", "enc"] {
                let dir = brotli_dir.join(subdir);
                for entry in std::fs::read_dir(&dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.extension().map_or(false, |e| e == "c") {
                        brotli_build.file(&path);
                    }
                }
            }
            brotli_build.compile("brotli");
        }

        if target_os == "ios" {
            // Link libresolv for DNS on iOS too
            println!("cargo:rustc-link-lib=resolv");
        }
    }
}
