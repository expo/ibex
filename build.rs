use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("Failed to resolve repo root");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let default_ios_headers = repo_root
        .join("ios")
        .join("Frameworks")
        .join("hermes-headers");
    let default_linux_headers = repo_root.join("linux").join("hermes-headers");
    let hermes_include_dir = std::env::var("HERMES_INCLUDE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if target_os == "linux" && default_linux_headers.exists() {
                default_linux_headers.clone()
            } else {
                default_ios_headers.clone()
            }
        });
    let default_ios_lib = repo_root.join("ios").join("Frameworks");
    let default_linux_lib = repo_root.join("linux").join("lib");
    let hermes_lib_dir = std::env::var("HERMES_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if target_os == "linux" && default_linux_lib.exists() {
                default_linux_lib.clone()
            } else {
                default_ios_lib.clone()
            }
        });

    println!("cargo:rerun-if-changed=src/engine/hermes_runtime.cc");
    println!("cargo:rerun-if-changed=src/engine/native_fetch_macos.mm");
    println!("cargo:rerun-if-changed=src/engine/native_websocket_macos.mm");
    println!("cargo:rerun-if-changed=src/engine/native_fetch_linux.cc");
    println!("cargo:rerun-if-changed=src/engine/native_websocket_linux.cc");
    println!("cargo:rerun-if-changed=src/engine/bootstrap");
    println!("cargo:rerun-if-changed=src/builtins");
    println!("cargo:rerun-if-env-changed=HERMES_ENABLE_DEBUGGER");
    println!("cargo:rerun-if-env-changed=HERMES_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=HERMES_LIB_DIR");
    println!("cargo:rerun-if-env-changed=HERMES_LINK_STATIC");
    println!("cargo:rustc-check-cfg=cfg(hermes_debugger)");
    let allow_fallback = matches!(
        std::env::var("EXACT_ALLOW_FALLBACK")
            .ok()
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    );

    // --- Build builtin JS modules via rolldown ---
    // Compiles src/builtins/*.js through the shared Hermes transforms and
    // writes the output to $OUT_DIR/builtins/ for include_str!() in mod.rs.
    let builtins_src = manifest_dir.join("src").join("builtins");
    let builtins_out = out_dir.join("builtins");
    if builtins_src.exists() {
        let build_script = repo_root
            .join("js")
            .join("scripts")
            .join("build-builtins.mjs");
        if build_script.exists() {
            // Try bun first, fall back to node
            let runner = which_js_runner();
            if let Some(runner_path) = runner {
                let status = std::process::Command::new(&runner_path)
                    .arg(&build_script)
                    .arg("--src-dir")
                    .arg(&builtins_src)
                    .arg("--out-dir")
                    .arg(&builtins_out)
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        eprintln!(
                            "cargo:warning=Built builtin modules → {}",
                            builtins_out.display()
                        );
                    }
                    Ok(s) => {
                        if !allow_fallback {
                            panic!(
                                "build-builtins.mjs failed with status {s} and EXACT_ALLOW_FALLBACK is not set"
                            );
                        }
                        eprintln!("cargo:warning=build-builtins.mjs exited with status {}, copying source files as fallback", s);
                        copy_builtins_fallback(&builtins_src, &builtins_out);
                    }
                    Err(e) => {
                        if !allow_fallback {
                            panic!(
                                "Failed to run build-builtins.mjs ({e}); build aborted because EXACT_ALLOW_FALLBACK is not set"
                            );
                        }
                        eprintln!("cargo:warning=Failed to run build-builtins.mjs: {}, copying source files as fallback", e);
                        copy_builtins_fallback(&builtins_src, &builtins_out);
                    }
                }
            } else {
                if !allow_fallback {
                    panic!("Neither bun nor node found and EXACT_ALLOW_FALLBACK is not set");
                }
                eprintln!(
                    "cargo:warning=Neither bun nor node found, copying builtin sources as-is"
                );
                copy_builtins_fallback(&builtins_src, &builtins_out);
            }
        } else {
            if !allow_fallback {
                panic!("build-builtins.mjs not found and EXACT_ALLOW_FALLBACK is not set");
            }
            eprintln!("cargo:warning=build-builtins.mjs not found, copying builtin sources as-is");
            copy_builtins_fallback(&builtins_src, &builtins_out);
        }
    }

    // --- Precompile bootstrap JS to Hermes bytecode (HBC) ---
    // If hermesc is available, compile each bootstrap .js file to .hbc and
    // generate a C++ header (bootstrap_bytecode.h) with static byte arrays.
    // This makes JS startup ~10x faster (bytecode loading vs source parsing).
    let hermesc = repo_root.join("tools").join("hermes").join("hermesc");
    let bootstrap_dir = manifest_dir.join("src").join("engine").join("bootstrap");

    let bootstrap_files = [
        ("module-loader.js", "MODULE_LOADER"),
        ("bootstrap-globals.js", "BOOTSTRAP_GLOBALS"),
        ("console-enhance.js", "CONSOLE_ENHANCE"),
        ("stream-enhance.js", "STREAM_ENHANCE"),
        ("web-crypto.js", "WEB_CRYPTO"),
        ("web-storage.js", "WEB_STORAGE"),
        ("form-data.js", "FORM_DATA"),
        ("lazy-getters.js", "LAZY_GETTERS"),
        ("compat-polyfills.js", "COMPAT_POLYFILLS"),
        ("web-streams-polyfill.js", "WEB_STREAMS_POLYFILL"),
        ("exact-global.js", "EXACT_GLOBAL"),
        ("process-compat-fix.js", "PROCESS_COMPAT_FIX"),
    ];

    if hermesc.exists() {
        let mut header = String::from(
            "// Auto-generated by build.rs — do not edit\n\
             #pragma once\n\n",
        );
        let mut all_ok = true;

        for (js_file, array_name) in &bootstrap_files {
            let js_path = bootstrap_dir.join(js_file);
            let hbc_path = out_dir.join(js_file.replace(".js", ".hbc"));

            if !js_path.exists() {
                if !allow_fallback {
                    panic!(
                        "Bootstrap JS file not found: {} and EXACT_ALLOW_FALLBACK is not set",
                        js_path.display()
                    );
                }
                eprintln!(
                    "cargo:warning=Bootstrap JS file not found: {}",
                    js_path.display()
                );
                all_ok = false;
                break;
            }

            let status = std::process::Command::new(&hermesc)
                .arg("-emit-binary")
                .arg("-O")
                .arg("-out")
                .arg(&hbc_path)
                .arg(&js_path)
                .status();

            match status {
                Ok(s) if s.success() => {
                    let bytes = std::fs::read(&hbc_path).unwrap();
                    header.push_str(&format!(
                        "alignas(8) static const uint8_t {}_HBC[] = {{\n",
                        array_name
                    ));
                    for (i, byte) in bytes.iter().enumerate() {
                        if i % 16 == 0 && i > 0 {
                            header.push('\n');
                        }
                        header.push_str(&format!("0x{:02X},", byte));
                    }
                    header.push_str(&format!(
                        "\n}};\nstatic const size_t {}_HBC_LEN = sizeof({}_HBC);\n\n",
                        array_name, array_name
                    ));
                }
                _ => {
                    if !allow_fallback {
                        panic!(
                            "hermesc failed for {} and EXACT_ALLOW_FALLBACK is not set",
                            js_file
                        );
                    }
                    eprintln!("cargo:warning=hermesc failed for {}", js_file);
                    all_ok = false;
                    break;
                }
            }
        }

        if all_ok {
            let header_path = out_dir.join("bootstrap_bytecode.h");
            std::fs::write(&header_path, &header).unwrap();
            eprintln!("cargo:warning=Generated bootstrap_bytecode.h with precompiled HBC");
        } else {
            if !allow_fallback {
                panic!("HBC precompilation failed and EXACT_ALLOW_FALLBACK is not set");
            }
            eprintln!("cargo:warning=HBC precompilation failed, falling back to source parsing");
        }
    } else if !allow_fallback {
        panic!(
            "hermesc not found at {} and EXACT_ALLOW_FALLBACK is not set",
            hermesc.display()
        );
    } else {
        eprintln!(
            "cargo:warning=hermesc not found at {}, skipping HBC precompilation",
            hermesc.display()
        );
    }

    // --- Generate bootstrap_source.h with JS source as C++ string literals ---
    // This eliminates inline JS from hermes_runtime.cc — the source comes from
    // the same .js files used for HBC compilation, ensuring they never drift.
    {
        let mut src_header = String::from(
            "// Auto-generated by build.rs — do not edit\n\
             #pragma once\n\n",
        );
        let mut all_ok = true;

        for (js_file, const_name) in &bootstrap_files {
            let js_path = bootstrap_dir.join(js_file);
            if !js_path.exists() {
                if !allow_fallback {
                    panic!(
                        "Bootstrap JS file not found for source header: {} and EXACT_ALLOW_FALLBACK is not set",
                        js_path.display()
                    );
                }
                eprintln!(
                    "cargo:warning=Bootstrap JS file not found for source header: {}",
                    js_path.display()
                );
                all_ok = false;
                break;
            }

            let source = std::fs::read_to_string(&js_path).unwrap();
            src_header.push_str(&format!(
                "static const char* {}_SRC = R\"JSSRC(\n{})JSSRC\";\n\n",
                const_name, source
            ));
        }

        if all_ok {
            let header_path = out_dir.join("bootstrap_source.h");
            std::fs::write(&header_path, &src_header).unwrap();
            eprintln!("cargo:warning=Generated bootstrap_source.h with JS source literals");
        } else {
            if !allow_fallback {
                panic!(
                    "bootstrap_source.h generation failed because EXACT_ALLOW_FALLBACK is not set"
                );
            }
            eprintln!("cargo:warning=bootstrap_source.h generation failed — missing JS files");
        }
    }

    // Compile hermes_runtime.cc
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file("src/engine/hermes_runtime.cc")
        .include(&hermes_include_dir)
        .include(&out_dir) // For bootstrap_bytecode.h
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-stdlib=libc++")
        .flag_if_supported("-fPIC");

    // Set minimum deployment targets to match Xcode project settings.
    // This avoids "was built for newer version" linker warnings for our C++ files.
    // Note: bundled C deps (e.g. rusqlite's sqlite3) need the env var set before
    // cargo runs — see build-kernel.sh which exports MACOSX_DEPLOYMENT_TARGET.
    match target_os.as_str() {
        "macos" => {
            build.flag("-mmacosx-version-min=14.0");
        }
        "ios" => {
            build.flag("-mios-version-min=17.0");
        }
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
        "linux" => {
            if let Ok(openssl_include) = std::env::var("DEP_OPENSSL_INCLUDE") {
                build.include(&openssl_include);
            }
            let brotli_include = manifest_dir.join("vendor").join("brotli").join("include");
            build.include(&brotli_include);
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
        ws_build.compile("exact_native_websocket");

        // Link frameworks
        if target_os == "macos" {
            println!(
                "cargo:rustc-link-search=framework={}",
                hermes_lib_dir.display()
            );
            println!("cargo:rustc-link-lib=framework=hermesvm");
            println!(
                "cargo:rustc-link-arg=-Wl,-rpath,{}",
                hermes_lib_dir.display()
            );
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
                    if path.extension().is_some_and(|e| e == "c") {
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

    if target_os == "linux" {
        let mut fetch_build = cc::Build::new();
        fetch_build
            .cpp(true)
            .file("src/engine/native_fetch_linux.cc")
            .flag_if_supported("-std=c++17")
            .flag_if_supported("-fPIC");
        fetch_build.compile("exact_native_fetch");

        let mut ws_build = cc::Build::new();
        ws_build
            .cpp(true)
            .file("src/engine/native_websocket_linux.cc")
            .flag_if_supported("-std=c++17")
            .flag_if_supported("-fPIC");
        ws_build.compile("exact_native_websocket");

        println!(
            "cargo:rustc-link-search=native={}",
            hermes_lib_dir.display()
        );
        let static_link = std::env::var("HERMES_LINK_STATIC")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        if static_link {
            println!("cargo:rustc-link-lib=static=hermesvm");
        } else {
            println!("cargo:rustc-link-lib=dylib=hermesvm");
            println!(
                "cargo:rustc-link-arg=-Wl,-rpath,{}",
                hermes_lib_dir.display()
            );
        }

        if let Ok(lib_dir) = std::env::var("DEP_OPENSSL_LIB_DIR") {
            println!("cargo:rustc-link-search=native={}", lib_dir);
        }
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=stdc++");
        println!("cargo:rustc-link-lib=z");
        println!("cargo:rustc-link-lib=resolv");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");

        let brotli_dir = manifest_dir.join("vendor").join("brotli");
        let mut brotli_build = cc::Build::new();
        brotli_build
            .include(brotli_dir.join("include"))
            .flag_if_supported("-fPIC");
        for subdir in &["common", "dec", "enc"] {
            let dir = brotli_dir.join(subdir);
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|e| e == "c") {
                    brotli_build.file(&path);
                }
            }
        }
        brotli_build.compile("brotli");
    }
}

fn which_js_runner() -> Option<PathBuf> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    let dirs: Vec<&str> = if cfg!(target_os = "windows") {
        path_var.split(';').collect()
    } else {
        path_var.split(':').collect()
    };
    for name in &["bun", "node"] {
        for dir in &dirs {
            let candidate = PathBuf::from(dir).join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn copy_builtins_fallback(src: &std::path::Path, dst: &std::path::Path) {
    let _ = std::fs::create_dir_all(dst);
    if let Ok(entries) = std::fs::read_dir(src) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "js" || e == "ts") {
                let dest = dst.join(path.file_name().unwrap());
                let _ = std::fs::copy(&path, &dest);
            }
        }
    }
}
