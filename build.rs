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
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

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

    // Platform-specific includes and defines
    match target_os.as_str() {
        "macos" => {
            // OpenSSL include path for Ed25519/X25519/ECDSA operations
            let openssl_paths = [
                "/opt/homebrew/opt/openssl/include",
                "/opt/homebrew/opt/openssl@3/include",
                "/usr/local/opt/openssl/include",
                "/usr/local/opt/openssl@3/include",
            ];
            for path in &openssl_paths {
                if std::path::Path::new(path).exists() {
                    build.include(path);
                    break;
                }
            }

            // Brotli include path
            let brotli_include_paths = [
                "/opt/homebrew/opt/brotli/include",
                "/opt/homebrew/include",
                "/usr/local/opt/brotli/include",
                "/usr/local/include",
            ];
            for path in &brotli_include_paths {
                if std::path::Path::new(path).join("brotli").join("encode.h").exists() {
                    build.include(path);
                    break;
                }
            }
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

    // Debugger support (disabled on iOS by default)
    let enable_debugger = if target_os == "ios" {
        false // Debugger adds significant binary size on iOS
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
        cc::Build::new()
            .file("src/engine/native_fetch_macos.mm")
            .flag("-fobjc-arc")
            .flag("-std=c++17")
            .flag("-stdlib=libc++")
            .compile("exact_native_fetch");

        cc::Build::new()
            .file("src/engine/native_websocket_macos.mm")
            .flag("-fobjc-arc")
            .flag("-std=c++17")
            .flag("-stdlib=libc++")
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
            // Link OpenSSL on macOS
            let openssl_lib_paths = [
                "/opt/homebrew/opt/openssl/lib",
                "/opt/homebrew/opt/openssl@3/lib",
                "/usr/local/opt/openssl/lib",
                "/usr/local/opt/openssl@3/lib",
            ];
            for path in &openssl_lib_paths {
                if std::path::Path::new(path).exists() {
                    println!("cargo:rustc-link-search=native={}", path);
                    break;
                }
            }
            println!("cargo:rustc-link-lib=ssl");
            println!("cargo:rustc-link-lib=crypto");
            // Link libresolv for DNS res_query()
            println!("cargo:rustc-link-lib=resolv");

            // Link Brotli
            let brotli_lib_paths = [
                "/opt/homebrew/opt/brotli/lib",
                "/opt/homebrew/lib",
                "/usr/local/opt/brotli/lib",
                "/usr/local/lib",
            ];
            for path in &brotli_lib_paths {
                if std::path::Path::new(path).join("libbrotlienc.a").exists() {
                    println!("cargo:rustc-link-search=native={}", path);
                    break;
                }
            }
            println!("cargo:rustc-link-lib=brotlienc");
            println!("cargo:rustc-link-lib=brotlidec");
            println!("cargo:rustc-link-lib=brotlicommon");
        }

        if target_os == "ios" {
            // Link libresolv for DNS on iOS too
            println!("cargo:rustc-link-lib=resolv");
        }
    }
}
