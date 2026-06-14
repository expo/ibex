use std::io::{BufRead, BufReader, ErrorKind};
use std::path::Path;
use std::path::PathBuf;

fn env_path(var: &str) -> PathBuf {
    match std::env::var(var) {
        Ok(value) => PathBuf::from(value),
        Err(error) => panic!("Required environment variable {var} is not set: {error}"),
    }
}

fn optional_env_path(vars: &[&str]) -> Option<PathBuf> {
    vars.iter()
        .find_map(|var| std::env::var_os(var).map(PathBuf::from))
}

fn target_arch_to_hermes_dir(arch: &str) -> String {
    match arch {
        "x86_64" => "x64".to_string(),
        "aarch64" => "arm64".to_string(),
        "x86" | "i686" => "x86".to_string(),
        _ => arch.to_string(),
    }
}

fn target_arch_to_android_abi(arch: &str) -> &'static str {
    match arch {
        "aarch64" => "arm64-v8a",
        "arm" => "armeabi-v7a",
        "x86" | "i686" => "x86",
        "x86_64" => "x86_64",
        _ => panic!("Unsupported Android target architecture: {arch}"),
    }
}

fn android_prefab_module_root(root: &Path, module: &str) -> PathBuf {
    root.join("prefab").join("modules").join(module)
}

fn android_prefab_include_dir(root: &Path, module: &str) -> PathBuf {
    android_prefab_module_root(root, module).join("include")
}

fn android_prefab_lib_dir(root: &Path, module: &str, arch: &str) -> PathBuf {
    android_prefab_module_root(root, module)
        .join("libs")
        .join(format!("android.{}", target_arch_to_android_abi(arch)))
}

fn windows_hermes_root(repo_root: &Path, arch: &str) -> PathBuf {
    repo_root
        .join("tools")
        .join("hermes")
        .join(format!("windows-{}", target_arch_to_hermes_dir(arch)))
}

fn hermesc_path(repo_root: &Path, target_os: &str, target_arch: &str) -> PathBuf {
    if let Some(path) = optional_env_path(&["HERMESC", "HERMES_COMPILER"]) {
        return path;
    }
    if target_os == "windows" {
        return windows_hermes_root(repo_root, target_arch)
            .join("bin")
            .join("hermesc.exe");
    }
    let hermes_dir = repo_root.join("tools").join("hermes");
    // The standalone Ibex repo ships a platform-suffixed compiler
    // (e.g. hermesc-linux-x64); the monorepo layout uses the bare name.
    let suffixed = hermes_dir.join(format!(
        "hermesc-{}-{}",
        target_os,
        target_arch_to_hermes_dir(target_arch)
    ));
    let bare = hermes_dir.join("hermesc");
    if !bare.exists() && suffixed.exists() {
        return suffixed;
    }
    bare
}

fn hermes_cli_path(repo_root: &Path, target_os: &str, target_arch: &str) -> PathBuf {
    if let Some(path) = optional_env_path(&["HERMES_CLI", "HERMES_BINARY"]) {
        return path;
    }
    if target_os == "windows" {
        return windows_hermes_root(repo_root, target_arch)
            .join("bin")
            .join("hermes.exe");
    }
    let hermes_dir = repo_root.join("tools").join("hermes");
    let suffixed = hermes_dir.join(format!(
        "hermes-{}-{}",
        target_os,
        target_arch_to_hermes_dir(target_arch)
    ));
    let bare = hermes_dir.join("hermes");
    if !bare.exists() && suffixed.exists() {
        return suffixed;
    }
    bare
}

fn read_bytes_or_panic(path: &Path, context: &str) -> Vec<u8> {
    std::fs::read(path)
        .unwrap_or_else(|error| panic!("Failed to read {context} at {}: {error}", path.display()))
}

fn read_text_or_panic(path: &Path, context: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("Failed to read {context} at {}: {error}", path.display()))
}

fn write_file_or_panic(path: &Path, contents: impl AsRef<[u8]>, context: &str) {
    if let Err(error) = std::fs::write(path, contents) {
        panic!("Failed to write {context} at {}: {error}", path.display());
    }
}

fn read_dir_paths_or_panic(path: &Path, context: &str) -> Vec<PathBuf> {
    let entries = std::fs::read_dir(path).unwrap_or_else(|error| {
        panic!(
            "Failed to read directory for {context} at {}: {error}",
            path.display()
        )
    });
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "Failed to read directory entry for {context} under {}: {error}",
                path.display()
            )
        });
        paths.push(entry.path());
    }
    paths
}

fn main() {
    let manifest_dir = env_path("CARGO_MANIFEST_DIR");
    // Resolve the root that holds Hermes build inputs (linux/, tools/hermes/,
    // scripts/). Two supported layouts:
    //   - standalone ibex repo: the crate is the repo root.
    //   - legacy exact monorepo path: the crate is at packages/exact-runtime,
    //     so the root is two levels up.
    // Detect standalone by the presence of the Hermes build scripts at the
    // crate root; otherwise fall back to the legacy monorepo layout.
    let repo_root: PathBuf = if manifest_dir.join("scripts/build-hermes-linux.sh").exists()
        || manifest_dir.join("scripts/download-hermes.sh").exists()
    {
        manifest_dir.clone()
    } else {
        match manifest_dir.parent().and_then(|p| p.parent()) {
            Some(root) => root.to_path_buf(),
            None => panic!(
                "Failed to resolve repo root from CARGO_MANIFEST_DIR={}",
                manifest_dir.display()
            ),
        }
    };
    let repo_root = repo_root.as_path();

    let out_dir = env_path("OUT_DIR");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let default_ios_headers = repo_root
        .join("ios")
        .join("Frameworks")
        .join("hermes-headers");
    let default_linux_headers = repo_root.join("linux").join("hermes-headers");
    let default_android_hermes_root =
        optional_env_path(&["HERMES_ANDROID_DIR", "HERMES_ANDROID_ROOT"])
            .unwrap_or_else(|| repo_root.join("android").join("hermes-android"));
    let default_android_react_root =
        optional_env_path(&["REACT_ANDROID_DIR", "REACT_ANDROID_ROOT"])
            .unwrap_or_else(|| repo_root.join("android").join("react-android"));
    let default_android_hermes_headers =
        android_prefab_include_dir(&default_android_hermes_root, "hermesvm");
    let default_android_hermes_lib =
        android_prefab_lib_dir(&default_android_hermes_root, "hermesvm", &target_arch);
    let default_android_jsi_headers =
        android_prefab_include_dir(&default_android_react_root, "jsi");
    let default_android_jsi_lib =
        android_prefab_lib_dir(&default_android_react_root, "jsi", &target_arch);
    let default_windows_root = repo_root.join("tools").join("hermes").join(format!(
        "windows-{}",
        target_arch_to_hermes_dir(&target_arch)
    ));
    let default_windows_headers = default_windows_root.join("include");
    let hermes_include_dir = std::env::var("HERMES_INCLUDE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| match target_os.as_str() {
            "linux" => default_linux_headers.clone(),
            "android" => default_android_hermes_headers.clone(),
            "windows" => default_windows_headers.clone(),
            _ => default_ios_headers.clone(),
        });
    let jsi_include_dir = std::env::var("JSI_INCLUDE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if target_os == "android" {
                default_android_jsi_headers.clone()
            } else {
                hermes_include_dir.clone()
            }
        });
    let default_ios_lib = repo_root.join("ios").join("Frameworks");
    let default_linux_lib = repo_root.join("linux").join("lib");
    let default_windows_lib = default_windows_root.join("lib");
    let hermes_lib_dir = std::env::var("HERMES_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| match target_os.as_str() {
            "linux" => default_linux_lib.clone(),
            "android" => default_android_hermes_lib.clone(),
            "windows" => default_windows_lib.clone(),
            _ => default_ios_lib.clone(),
        });
    let jsi_lib_dir = std::env::var("JSI_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            if target_os == "android" {
                default_android_jsi_lib.clone()
            } else {
                hermes_lib_dir.clone()
            }
        });
    let hermes_framework_dir = if target_os == "macos" {
        let xcframework_macos = hermes_lib_dir
            .join("hermes.xcframework")
            .join("macos-arm64_x86_64");
        if xcframework_macos.exists() {
            xcframework_macos
        } else {
            hermes_lib_dir.clone()
        }
    } else {
        hermes_lib_dir.clone()
    };

    if target_os == "linux" {
        if !hermes_include_dir.exists() {
            panic!(
                "Linux Hermes headers not found at {}. Run ./scripts/build-hermes-linux.sh or set HERMES_INCLUDE_DIR.",
                hermes_include_dir.display()
            );
        }
        if !hermes_lib_dir.exists() {
            panic!(
                "Linux Hermes library dir not found at {}. Run ./scripts/build-hermes-linux.sh or set HERMES_LIB_DIR.",
                hermes_lib_dir.display()
            );
        }
    }
    if target_os == "android" {
        if !hermes_include_dir.join("hermes").join("hermes.h").exists() {
            panic!(
                "Android Hermes headers not found at {}. Run ./scripts/install-android-hermes.sh or set HERMES_INCLUDE_DIR.",
                hermes_include_dir.display()
            );
        }
        if !hermes_lib_dir.join("libhermesvm.so").exists() {
            panic!(
                "Android Hermes library not found at {}. Run ./scripts/install-android-hermes.sh or set HERMES_LIB_DIR.",
                hermes_lib_dir.display()
            );
        }
        if !jsi_include_dir.join("jsi").join("jsi.h").exists() {
            panic!(
                "Android JSI headers not found at {}. Run ./scripts/install-android-hermes.sh or set JSI_INCLUDE_DIR.",
                jsi_include_dir.display()
            );
        }
        if !jsi_lib_dir.join("libjsi.so").exists() {
            panic!(
                "Android JSI library not found at {}. Run ./scripts/install-android-hermes.sh or set JSI_LIB_DIR.",
                jsi_lib_dir.display()
            );
        }
    }
    if target_os == "windows" {
        if !hermes_include_dir.exists() {
            panic!(
                "Windows Hermes headers not found at {}. Run ./scripts/install-windows-hermes.ps1 or set HERMES_INCLUDE_DIR.",
                hermes_include_dir.display()
            );
        }
        if !hermes_lib_dir.exists() {
            panic!(
                "Windows Hermes library dir not found at {}. Run ./scripts/install-windows-hermes.ps1 or set HERMES_LIB_DIR.",
                hermes_lib_dir.display()
            );
        }
    }

    println!("cargo:rerun-if-changed=src/engine/hermes_runtime.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_bootstrap.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_utils.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_dns.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_crypto.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_crypto_windows.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_fs.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_fs_windows.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_process.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_net.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_http.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_sqlite.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_debugger.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_ios.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_console.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_timers.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_osinfo.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_process_setup.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_platform_windows.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_websocket.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_fetch.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_ipc.cc");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_templates.inl");
    println!("cargo:rerun-if-changed=src/engine/hermes_runtime_internal.h");
    println!("cargo:rerun-if-changed=src/host/mod.rs");
    println!("cargo:rerun-if-changed=src/sync.rs");
    println!("cargo:rerun-if-changed=src/cdp/mod.rs");
    println!("cargo:rerun-if-changed=src/cdp/network.rs");
    println!("cargo:rerun-if-changed=src/engine/native_fetch_macos.mm");
    println!("cargo:rerun-if-changed=src/engine/native_websocket_macos.mm");
    println!("cargo:rerun-if-changed=src/engine/native_fetch_linux.cc");
    println!("cargo:rerun-if-changed=src/engine/native_websocket_linux.cc");
    println!("cargo:rerun-if-changed=src/engine/native_fetch_windows.cc");
    println!("cargo:rerun-if-changed=src/engine/native_websocket_windows.cc");
    println!("cargo:rerun-if-changed=src/engine/bootstrap");
    println!("cargo:rerun-if-changed=src/builtins");
    println!(
        "cargo:rerun-if-changed={}",
        exact_devtools_script(repo_root, "build-builtins.mjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("modules.ts").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        exact_devtools_script(repo_root, "generate-module-manifest.ts").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        exact_devtools_script(repo_root, "transforms.mjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        exact_runtime_js_dir(repo_root).join("src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        exact_devtools_script(repo_root, "rolldown-bundle.mjs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repo_root
            .join("js")
            .join("vite.config.runtime.ts")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        exact_runtime_js_dir(repo_root)
            .join("package.json")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        exact_devtools_dir(repo_root).join("package.json").display()
    );
    println!("cargo:rerun-if-env-changed=HERMES_ENABLE_DEBUGGER");
    println!("cargo:rerun-if-env-changed=HERMESC");
    println!("cargo:rerun-if-env-changed=HERMES_COMPILER");
    println!("cargo:rerun-if-env-changed=HERMES_CLI");
    println!("cargo:rerun-if-env-changed=HERMES_BINARY");
    println!("cargo:rerun-if-env-changed=HERMES_ANDROID_DIR");
    println!("cargo:rerun-if-env-changed=HERMES_ANDROID_ROOT");
    println!("cargo:rerun-if-env-changed=HERMES_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=HERMES_LIB_DIR");
    println!("cargo:rerun-if-env-changed=HERMES_LINK_STATIC");
    println!("cargo:rerun-if-env-changed=REACT_ANDROID_DIR");
    println!("cargo:rerun-if-env-changed=REACT_ANDROID_ROOT");
    println!("cargo:rerun-if-env-changed=JSI_INCLUDE_DIR");
    println!("cargo:rerun-if-env-changed=JSI_LIB_DIR");
    println!("cargo:rerun-if-env-changed=IBEX_REGENERATE_RUNTIME");
    println!("cargo:rerun-if-env-changed=IBEX_UPDATE_VENDORED_GENERATED");
    println!("cargo:rerun-if-env-changed=IBEX_ALLOW_CURL_CLI_FALLBACK");
    println!("cargo:rustc-check-cfg=cfg(hermes_debugger)");
    let host_http_server_enabled = std::env::var_os("CARGO_FEATURE_HOST_HTTP_SERVER").is_some();
    let app_host_enabled = std::env::var_os("CARGO_FEATURE_APP_HOST").is_some();
    let openssl_crypto_enabled = std::env::var_os("CARGO_FEATURE_OPENSSL_CRYPTO").is_some();
    let hermes_macos_binary = if target_os == "macos" {
        let binary = find_macos_hermes_binary(&hermes_framework_dir)
            .or_else(|| find_macos_hermes_binary(&hermes_lib_dir));
        if let Some(path) = binary.as_ref() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
        binary
    } else {
        None
    };
    let allow_fallback = matches!(
        std::env::var("EXACT_ALLOW_FALLBACK")
            .ok()
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    );

    // Ibex keeps the default build hermetic: ordinary cargo builds copy the
    // committed generated JS artifacts from vendored-generated/. Native
    // regeneration is an explicit dev path, gated by IBEX_REGENERATE_RUNTIME=1.
    let vendored_generated_dir = manifest_dir.join("vendored-generated");
    let manifest_generator = exact_devtools_script(repo_root, "generate-module-manifest.ts");
    let regenerate_runtime = env_truthy("IBEX_REGENERATE_RUNTIME");
    let update_vendored_generated = env_truthy("IBEX_UPDATE_VENDORED_GENERATED");
    let standalone = !regenerate_runtime && vendored_generated_dir.exists();
    if standalone {
        eprintln!(
            "cargo:warning=Ibex build: using vendored generated artifacts from {}",
            vendored_generated_dir.display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            vendored_generated_dir.display()
        );
    } else if !regenerate_runtime {
        // The default ibex build is hermetic: it expects the committed
        // vendored-generated/ artifacts. If they are missing, fail loudly
        // rather than silently shelling out to the bun/node generators (which
        // now live in this repo, so `manifest_generator.exists()` would be true
        // and the build would quietly become non-hermetic). @ref LLP 0086 review F7
        panic!(
            "Ibex default build is hermetic but vendored generated artifacts are missing at {}. \
             Restore the committed artifacts, or set IBEX_REGENERATE_RUNTIME=1 to regenerate from JS sources (requires bun).",
            vendored_generated_dir.display()
        );
    } else if !manifest_generator.exists() {
        panic!(
            "IBEX_REGENERATE_RUNTIME=1 requested, but the module manifest generator was not found at {}",
            manifest_generator.display()
        );
    }

    generate_builtin_manifest(repo_root, &out_dir, standalone, &vendored_generated_dir);

    // --- Build builtin JS modules via rolldown ---
    // Compiles src/builtins/*.js through the shared Hermes transforms and
    // writes the output to $OUT_DIR/builtins/ for include_str!() in mod.rs.
    let builtins_src = manifest_dir.join("src").join("builtins");
    let builtins_out = out_dir.join("builtins");
    clear_dir_if_exists(&builtins_out, "generated builtins output");
    if standalone {
        // Copy the vendored (already-transformed) builtin modules into OUT_DIR
        // so the manifest's include_str!(OUT_DIR/builtins/*.js) calls resolve.
        let vendored_builtins = vendored_generated_dir.join("builtins");
        copy_dir_files(&vendored_builtins, &builtins_out, &["js"]);
        eprintln!(
            "cargo:warning=Copied vendored builtin modules → {}",
            builtins_out.display()
        );
    } else if builtins_src.exists() {
        let build_script = exact_devtools_script(repo_root, "build-builtins.mjs");
        if build_script.exists() {
            // Prefer bun when available, otherwise use node.
            let runner = which_js_runner();
            if let Some(runner_path) = runner {
                let runner_name = runner_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("js runner");
                let missing_js_deps_hint = missing_js_build_deps_hint(repo_root);
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
                        if try_build_builtins_via_primary_checkout(
                            repo_root,
                            &builtins_src,
                            &builtins_out,
                        ) {
                            eprintln!(
                                "cargo:warning=Built builtin modules via primary checkout toolchain → {}",
                                builtins_out.display()
                            );
                        } else {
                            if !allow_fallback {
                                panic!(
                                    "build-builtins.mjs failed with status {s} using {runner_name} and EXACT_ALLOW_FALLBACK is not set{missing_js_deps_hint}"
                                );
                            }
                            eprintln!("cargo:warning=build-builtins.mjs exited with status {}, copying source files as fallback", s);
                            copy_builtins_fallback(&builtins_src, &builtins_out);
                        }
                    }
                    Err(e) => {
                        if try_build_builtins_via_primary_checkout(
                            repo_root,
                            &builtins_src,
                            &builtins_out,
                        ) {
                            eprintln!(
                                "cargo:warning=Built builtin modules via primary checkout toolchain → {}",
                                builtins_out.display()
                            );
                        } else {
                            if !allow_fallback {
                                panic!(
                                    "Failed to run build-builtins.mjs with {runner_name} ({e}); build aborted because EXACT_ALLOW_FALLBACK is not set{missing_js_deps_hint}"
                                );
                            }
                            eprintln!("cargo:warning=Failed to run build-builtins.mjs: {}, copying source files as fallback", e);
                            copy_builtins_fallback(&builtins_src, &builtins_out);
                        }
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

    generate_runtime_bundle_source_header(
        repo_root,
        &out_dir,
        allow_fallback,
        standalone,
        &vendored_generated_dir,
    );
    if update_vendored_generated {
        if standalone {
            panic!(
                "IBEX_UPDATE_VENDORED_GENERATED=1 requires IBEX_REGENERATE_RUNTIME=1 so vendored artifacts come from a real regeneration"
            );
        }
        refresh_vendored_generated(&out_dir, &vendored_generated_dir);
    }

    // --- Precompile bootstrap JS to Hermes bytecode (HBC) ---
    // If hermesc is available and compatible, compile each bootstrap .js file to .hbc and
    // generate a C++ header (bootstrap_bytecode.h) with static byte arrays.
    // This makes JS startup faster by loading bytecode directly from static storage.
    let hermesc = hermesc_path(repo_root, &target_os, &target_arch);
    let hermes_binary = hermes_cli_path(repo_root, &target_os, &target_arch);
    let bootstrap_dir = manifest_dir.join("src").join("engine").join("bootstrap");
    println!("cargo:rerun-if-changed={}", hermesc.display());
    if hermes_binary.exists() {
        println!("cargo:rerun-if-changed={}", hermes_binary.display());
    }

    let bootstrap_hbc_header = out_dir.join("bootstrap_bytecode.h");
    let bootstrap_source_header = out_dir.join("bootstrap_source.h");
    safe_remove_file(&bootstrap_hbc_header);
    safe_remove_file(&bootstrap_source_header);

    let hermesc_hbc_version = extract_hbc_version(&hermesc);
    let runtime_hbc_version = if hermes_binary.exists() {
        extract_hbc_version(&hermes_binary)
    } else {
        None
    };
    let mut precompile_bootstrap_hbc = true;

    if !hermesc.exists() {
        precompile_bootstrap_hbc = false;
        if !allow_fallback {
            panic!(
                "hermesc not found at {} and EXACT_ALLOW_FALLBACK is not set",
                hermesc.display()
            );
        }
        eprintln!(
            "cargo:warning=hermesc not found at {}, skipping HBC precompilation",
            hermesc.display()
        );
    } else if hermesc_hbc_version.is_none() {
        precompile_bootstrap_hbc = false;
        if !allow_fallback {
            panic!("Failed to read hermesc HBC version and EXACT_ALLOW_FALLBACK is not set");
        }
        eprintln!(
            "cargo:warning=Cannot read hermesc HBC version; skipping bootstrap HBC precompilation"
        );
    } else if let (Some(compiler_version), Some(runtime_version)) =
        (hermesc_hbc_version, runtime_hbc_version)
    {
        if compiler_version != runtime_version {
            precompile_bootstrap_hbc = false;
            if !allow_fallback {
                panic!(
                    "Hermes bytecode version mismatch: hermesc {} vs hermes {} and EXACT_ALLOW_FALLBACK is not set",
                    compiler_version, runtime_version
                );
            }
            eprintln!(
                "cargo:warning=Skipping bootstrap HBC precompilation due version mismatch (hermesc {} vs hermes {})",
                compiler_version,
                runtime_version
            );
        }
    }

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
        ("ipc-listener.js", "IPC_LISTENER"),
    ];

    for (js_file, _) in &bootstrap_files {
        let js_path = bootstrap_dir.join(js_file);
        println!("cargo:rerun-if-changed={}", js_path.display());
    }

    if precompile_bootstrap_hbc {
        let mut header = String::from(
            "// Auto-generated by build.rs — do not edit\n\
             #pragma once\n\n",
        );
        let mut all_ok = true;
        let Some(expected_version) = hermesc_hbc_version else {
            panic!(
                "Internal build.rs invariant failed: missing hermesc HBC version after precompile_bootstrap_hbc gate"
            );
        };

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
                    match bytecode_file_version(&hermesc, &hbc_path) {
                        Some(actual_version) if actual_version == expected_version => {}
                        Some(actual_version) => {
                            if !allow_fallback {
                                panic!(
                                    "Bootstrap hbc version mismatch for {}: compiled {} expected {}",
                                    js_file, actual_version, expected_version
                                );
                            }
                            eprintln!(
                                "cargo:warning=Bootstrap hbc version mismatch for {}: compiled {} expected {}; skipping precompiled bootstrap",
                                js_file, actual_version, expected_version
                            );
                            all_ok = false;
                            break;
                        }
                        None => {
                            if !allow_fallback {
                                panic!(
                                    "Failed to read hbc version for {} and EXACT_ALLOW_FALLBACK is not set",
                                    js_file
                                );
                            }
                            eprintln!(
                                "cargo:warning=Cannot read hbc version for {}; skipping precompiled bootstrap",
                                js_file
                            );
                            all_ok = false;
                            break;
                        }
                    }

                    let bytes = read_bytes_or_panic(&hbc_path, "compiled bootstrap HBC");
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
            write_file_or_panic(&bootstrap_hbc_header, &header, "bootstrap_bytecode.h");
            eprintln!("cargo:warning=Generated bootstrap_bytecode.h with precompiled HBC");
        } else if !allow_fallback {
            panic!("HBC precompilation failed and EXACT_ALLOW_FALLBACK is not set");
        } else {
            eprintln!("cargo:warning=HBC precompilation failed, falling back to source parsing");
        }
    }
    if !bootstrap_hbc_header.exists() {
        write_empty_bootstrap_hbc_header(&bootstrap_hbc_header, &bootstrap_files);
    }

    // --- Generate bootstrap_source.h with JS source as C++ string literals ---
    // This keeps fallback loading aligned with the same bootstrap files used for HBC.
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

            let source = read_text_or_panic(&js_path, "bootstrap source");
            push_cpp_raw_string_literal(&mut src_header, &format!("{}_SRC", const_name), &source);
        }

        if all_ok {
            write_file_or_panic(&bootstrap_source_header, &src_header, "bootstrap_source.h");
            eprintln!("cargo:warning=Generated bootstrap_source.h with JS source literals");
        } else if !allow_fallback {
            panic!("bootstrap_source.h generation failed because EXACT_ALLOW_FALLBACK is not set");
        } else {
            eprintln!("cargo:warning=bootstrap_source.h generation failed — missing JS files");
        }
    }

    // Compile Hermes runtime adapter sources.
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .file("src/engine/hermes_runtime.cc")
        .file("src/engine/hermes_bootstrap.cc")
        .file("src/engine/hermes_runtime_utils.cc")
        .file("src/engine/hermes_runtime_sqlite.cc")
        .file("src/engine/hermes_runtime_console.cc")
        .file("src/engine/hermes_runtime_timers.cc")
        .file("src/engine/hermes_runtime_websocket.cc")
        .file("src/engine/hermes_runtime_fetch.cc")
        .file("src/engine/hermes_runtime_ipc.cc")
        .include(&hermes_include_dir)
        .include(&jsi_include_dir)
        .include(&out_dir); // For bootstrap_bytecode.h

    build.std("c++17");

    if target_os == "windows" {
        let hermes_jsi_cpp = hermes_include_dir.join("jsi").join("jsi.cpp");
        let hermes_jsilib_windows_cpp = hermes_include_dir.join("jsi").join("jsilib-windows.cpp");
        let hermes_rtti_cpp = hermes_include_dir
            .join("hermes")
            .join("Public")
            .join("rtti.cpp");

        if !hermes_jsi_cpp.exists() {
            panic!(
                "Windows Hermes package is missing {}; run scripts/install-windows-hermes.ps1",
                hermes_jsi_cpp.display()
            );
        }
        if !hermes_rtti_cpp.exists() {
            panic!(
                "Windows Hermes package is missing {}; run scripts/install-windows-hermes.ps1",
                hermes_rtti_cpp.display()
            );
        }

        build.file("src/engine/hermes_runtime_fs_windows.cc");
        build.file("src/engine/hermes_runtime_crypto_windows.cc");
        build.file("src/engine/hermes_runtime_http.cc");
        // Despite the historical filename, this file owns the platform-neutral
        // exact.dispatch/module/kernel C ABI that native hosts install.
        build.file("src/engine/hermes_runtime_ios.cc");
        build.file("src/engine/hermes_runtime_platform_windows.cc");
        build.file(&hermes_jsi_cpp);
        if hermes_jsilib_windows_cpp.exists() {
            build.file(&hermes_jsilib_windows_cpp);
        }
        build.file(&hermes_rtti_cpp);
        build.define("EXACT_PLATFORM_WINDOWS", None);
        build.define("EXACT_NO_OPENSSL", None);
        build.define("_WINDOWS", None);
        build.flag("/EHsc");
        build.flag("/Zc:__cplusplus");
    } else {
        build
            .file("src/engine/hermes_runtime_crypto.cc")
            .file("src/engine/hermes_runtime_dns.cc")
            .file("src/engine/hermes_runtime_fs.cc")
            .file("src/engine/hermes_runtime_process.cc")
            .file("src/engine/hermes_runtime_net.cc")
            .file("src/engine/hermes_runtime_http.cc")
            .file("src/engine/hermes_runtime_debugger.cc")
            .file("src/engine/hermes_runtime_ios.cc")
            .file("src/engine/hermes_runtime_osinfo.cc")
            .file("src/engine/hermes_runtime_process_setup.cc")
            .flag_if_supported("-stdlib=libc++")
            .flag_if_supported("-fPIC");
    }

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
        "android" => {
            build.flag_if_supported("-fexceptions");
            build.flag_if_supported("-frtti");
        }
        _ => {}
    }

    // Platform-specific includes and defines
    match target_os.as_str() {
        "macos" => {
            // OpenSSL include path from vendored openssl-sys crate
            if openssl_crypto_enabled {
                if let Ok(openssl_include) = std::env::var("DEP_OPENSSL_INCLUDE") {
                    build.include(&openssl_include);
                }
            } else {
                build.define("EXACT_NO_OPENSSL", None);
            }

            // Brotli include path from vendored source
            let brotli_include = manifest_dir.join("vendor").join("brotli").join("include");
            build.include(&brotli_include);
        }
        "windows" => {
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
            if openssl_crypto_enabled {
                if let Ok(openssl_include) = std::env::var("DEP_OPENSSL_INCLUDE") {
                    build.include(&openssl_include);
                }
            } else {
                build.define("EXACT_NO_OPENSSL", None);
            }
            let brotli_include = manifest_dir.join("vendor").join("brotli").join("include");
            build.include(&brotli_include);
        }
        "android" => {
            // @ref LLP 0001#2-the-axes-that-matter-beyond-os — Android's first
            // supported crypto profile is vendored OpenSSL until a native
            // Android backend exists.
            if !openssl_crypto_enabled {
                panic!(
                    "Android builds require --features openssl-crypto until Ibex has an Android-native crypto backend."
                );
            }
            let openssl_include = std::env::var("DEP_OPENSSL_INCLUDE").unwrap_or_else(|_| {
                panic!("Android openssl-crypto is enabled, but DEP_OPENSSL_INCLUDE was not set")
            });
            build.include(openssl_include);
            build.define("EXACT_PLATFORM_ANDROID", None);
            let brotli_include = manifest_dir.join("vendor").join("brotli").join("include");
            build.include(&brotli_include);
        }
        _ => {}
    }

    // App-host profile uses the same reduced crypto shape as Windows for now.
    if app_host_enabled && target_os != "android" {
        build.define("EXACT_NO_OPENSSL", None);
    }

    // Debugger support is auto-detected on macOS so we do not compile against
    // debugger APIs that are missing from the checked-in Hermes framework.
    let enable_debugger = target_os != "windows"
        && should_enable_hermes_debugger(&target_os, hermes_macos_binary.as_deref());

    if enable_debugger {
        build.define("HERMES_ENABLE_DEBUGGER", None);
        println!("cargo:rustc-cfg=hermes_debugger");
    }
    // Weak no-op `ex_host_http_*` stubs are compiled exactly when no real
    // implementation is linked, i.e. when the `host-http-server` feature is
    // off. Weak linkage keeps an externally provided strong implementation
    // authoritative if a host supplies one. Windows is excluded because MSVC
    // has no `__attribute__((weak))`; Windows builds must enable
    // `host-http-server`. @tactical @ref LLP 0159 P0-B (gate was inverted:
    // it previously keyed on cli-notify, so stub presence depended on cargo
    // feature unification).
    if !host_http_server_enabled && target_os != "windows" {
        build.define("EXACT_RUNTIME_USE_HTTP_STUBS", None);
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
                hermes_framework_dir.display()
            );
            println!("cargo:rustc-link-lib=framework=hermesvm");
            println!(
                "cargo:rustc-link-arg=-Wl,-rpath,{}",
                hermes_framework_dir.display()
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
            if openssl_crypto_enabled {
                println!("cargo:rustc-link-lib=static=ssl");
                println!("cargo:rustc-link-lib=static=crypto");
            }
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
                for path in read_dir_paths_or_panic(&dir, "vendored Brotli source discovery") {
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

    if target_os == "windows" {
        let mut fetch_build = cc::Build::new();
        fetch_build
            .cpp(true)
            .file("src/engine/native_fetch_windows.cc")
            .include(&hermes_include_dir)
            .include(&out_dir)
            .std("c++17")
            .flag("/EHsc")
            .flag("/Zc:__cplusplus");
        fetch_build.compile("exact_native_fetch");

        let mut ws_build = cc::Build::new();
        ws_build
            .cpp(true)
            .file("src/engine/native_websocket_windows.cc")
            .include(&hermes_include_dir)
            .include(&out_dir)
            .std("c++17")
            .flag("/EHsc")
            .flag("/Zc:__cplusplus");
        ws_build.compile("exact_native_websocket");

        println!(
            "cargo:rustc-link-search=native={}",
            hermes_lib_dir.display()
        );
        let hermes_lib_name =
            std::env::var("HERMES_LIB_NAME").unwrap_or_else(|_| "hermes".to_string());
        println!("cargo:rustc-link-lib=dylib={hermes_lib_name}");
        println!("cargo:rustc-link-lib=winhttp");
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=ncrypt");
        println!("cargo:rustc-link-lib=crypt32");
        println!("cargo:rustc-link-lib=ws2_32");
    }

    if target_os == "android" {
        let curl_include = std::env::var("DEP_CURL_INCLUDE").unwrap_or_else(|_| {
            panic!(
                "Android native networking requires curl-sys metadata, but DEP_CURL_INCLUDE was not set"
            )
        });

        let mut fetch_build = cc::Build::new();
        fetch_build
            .cpp(true)
            .file("src/engine/native_fetch_linux.cc")
            .include(&curl_include)
            .define("EXACT_HAS_CURL", None)
            .define("CURL_STATICLIB", None)
            .std("c++17")
            .flag_if_supported("-fPIC")
            .flag_if_supported("-fexceptions")
            .flag_if_supported("-frtti");
        fetch_build.compile("exact_native_fetch");

        let mut ws_build = cc::Build::new();
        ws_build
            .cpp(true)
            .file("src/engine/native_websocket_linux.cc")
            .include(&curl_include)
            .define("EXACT_HAS_CURL", None)
            .define("CURL_STATICLIB", None)
            .std("c++17")
            .flag_if_supported("-fPIC")
            .flag_if_supported("-fexceptions")
            .flag_if_supported("-frtti");
        ws_build.compile("exact_native_websocket");

        println!(
            "cargo:rustc-link-search=native={}",
            hermes_lib_dir.display()
        );
        println!("cargo:rustc-link-lib=dylib=hermesvm");
        println!("cargo:rustc-link-search=native={}", jsi_lib_dir.display());
        println!("cargo:rustc-link-lib=dylib=jsi");
        if let Ok(lib_dir) = std::env::var("DEP_OPENSSL_LIB_DIR") {
            println!("cargo:rustc-link-search=native={}", lib_dir);
        }
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
        println!("cargo:rustc-link-lib=c++_shared");
        println!("cargo:rustc-link-lib=z");
        println!("cargo:rustc-link-lib=log");
        println!("cargo:rustc-link-lib=android");
        println!("cargo:rustc-link-lib=dl");
        println!("cargo:rustc-link-lib=m");

        let brotli_dir = manifest_dir.join("vendor").join("brotli");
        let mut brotli_build = cc::Build::new();
        brotli_build
            .include(brotli_dir.join("include"))
            .flag_if_supported("-fPIC");
        for subdir in &["common", "dec", "enc"] {
            let dir = brotli_dir.join(subdir);
            for path in read_dir_paths_or_panic(&dir, "vendored Brotli source discovery") {
                if path.extension().is_some_and(|e| e == "c") {
                    brotli_build.file(&path);
                }
            }
        }
        brotli_build.compile("brotli");
    }

    if target_os == "linux" {
        const MIN_LIBCURL_VERSION: &str = "7.86.0";
        // @ref LLP 0008#linux-networking — libcurl is the supported Linux Fetch/WebSocket backend; the CLI fallback is explicit and degraded.
        let allow_curl_cli_fallback = std::env::var("IBEX_ALLOW_CURL_CLI_FALLBACK")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let detected_libcurl_version = std::process::Command::new("pkg-config")
            .args(["--modversion", "libcurl"])
            .output()
            .ok()
            .and_then(|out| {
                if out.status.success() {
                    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
                } else {
                    None
                }
            });
        let has_minimum_libcurl = std::process::Command::new("pkg-config")
            .args(["--atleast-version", MIN_LIBCURL_VERSION, "libcurl"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        let mut fetch_build = cc::Build::new();
        fetch_build
            .cpp(true)
            .file("src/engine/native_fetch_linux.cc")
            .flag_if_supported("-std=c++17")
            .flag_if_supported("-fPIC");
        if has_minimum_libcurl {
            fetch_build.define("EXACT_HAS_CURL", Some("1"));
        } else if allow_curl_cli_fallback {
            match detected_libcurl_version.as_deref() {
                Some(version) => println!(
                    "cargo:warning=libcurl {version} detected, but >= {MIN_LIBCURL_VERSION} is required for native Linux networking; using degraded curl CLI fetch fallback and disabling native websocket support because IBEX_ALLOW_CURL_CLI_FALLBACK=1"
                ),
                None => println!(
                    "cargo:warning=libcurl dev package not detected; using degraded curl CLI fetch fallback and disabling native websocket support because IBEX_ALLOW_CURL_CLI_FALLBACK=1"
                ),
            }
        } else {
            match detected_libcurl_version.as_deref() {
                Some(version) => panic!(
                    "Linux native networking requires libcurl >= {MIN_LIBCURL_VERSION}; detected {version}. Install a newer libcurl development package or set IBEX_ALLOW_CURL_CLI_FALLBACK=1 for a degraded fetch-only fallback."
                ),
                None => panic!(
                    "Linux native networking requires pkg-config and libcurl >= {MIN_LIBCURL_VERSION}. Install the libcurl development package (for example libcurl4-openssl-dev on Debian/Ubuntu) or set IBEX_ALLOW_CURL_CLI_FALLBACK=1 for a degraded fetch-only fallback."
                ),
            }
        }
        fetch_build.compile("exact_native_fetch");

        let mut ws_build = cc::Build::new();
        ws_build
            .cpp(true)
            .file("src/engine/native_websocket_linux.cc")
            .flag_if_supported("-std=c++17")
            .flag_if_supported("-fPIC");
        if has_minimum_libcurl {
            ws_build.define("EXACT_HAS_CURL", Some("1"));
        }
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

        if openssl_crypto_enabled {
            if let Ok(lib_dir) = std::env::var("DEP_OPENSSL_LIB_DIR") {
                println!("cargo:rustc-link-search=native={}", lib_dir);
            }
            println!("cargo:rustc-link-lib=static=ssl");
            println!("cargo:rustc-link-lib=static=crypto");
        }
        println!("cargo:rustc-link-lib=stdc++");
        println!("cargo:rustc-link-lib=z");
        if has_minimum_libcurl {
            println!("cargo:rustc-link-lib=curl");
        }
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
            for path in read_dir_paths_or_panic(&dir, "vendored Brotli source discovery") {
                if path.extension().is_some_and(|e| e == "c") {
                    brotli_build.file(&path);
                }
            }
        }
        brotli_build.compile("brotli");
    }
}

fn which_js_runner() -> Option<PathBuf> {
    let names: &[&str] = if cfg!(target_os = "windows") {
        &["node", "bun"]
    } else {
        &["bun", "node"]
    };
    for name in names {
        for candidate in js_runner_candidates(name) {
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn bun_runner() -> Option<PathBuf> {
    js_runner_candidates("bun")
        .into_iter()
        .find(|candidate| candidate.exists())
}

fn env_truthy(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn generate_builtin_manifest(
    repo_root: &Path,
    out_dir: &Path,
    standalone: bool,
    vendored_generated_dir: &Path,
) {
    let script = exact_devtools_script(repo_root, "generate-module-manifest.ts");
    if standalone {
        // Copy the vendored, pre-generated manifest into OUT_DIR so the
        // include!(OUT_DIR/builtin_manifest.generated.rs) in module_loader works.
        let vendored_manifest = vendored_generated_dir.join("builtin_manifest.generated.rs");
        let dest = out_dir.join("builtin_manifest.generated.rs");
        let contents = read_text_or_panic(&vendored_manifest, "vendored builtin manifest");
        write_file_or_panic(&dest, &contents, "builtin_manifest.generated.rs");
        eprintln!(
            "cargo:warning=Copied vendored builtin manifest → {}",
            dest.display()
        );
        return;
    }
    if !script.exists() {
        panic!(
            "Module manifest generator not found at {}",
            script.display()
        );
    }

    let Some(bun) = bun_runner() else {
        panic!(
            "bun is required to generate builtin module manifests from {}",
            script.display()
        );
    };

    let output = std::process::Command::new(&bun)
        .current_dir(repo_root)
        .arg(&script)
        .arg("--rust-out-dir")
        .arg(out_dir)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "Failed to run {} with {}: {error}",
                script.display(),
                bun.display()
            )
        });

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "Module manifest generator failed with status {}.\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        );
    }
}

fn js_runner_candidates(name: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    for env_var in js_runner_env_vars(name) {
        if let Ok(value) = std::env::var(env_var) {
            if !value.trim().is_empty() {
                push_js_runner_candidate(&mut candidates, PathBuf::from(value));
            }
        }
    }

    let path_var = std::env::var("PATH").unwrap_or_default();
    let path_entries: Vec<&str> = if cfg!(target_os = "windows") {
        path_var.split(';').collect()
    } else {
        path_var.split(':').collect()
    };
    for dir in path_entries {
        if dir.is_empty() {
            continue;
        }
        push_js_runner_candidate(&mut candidates, PathBuf::from(dir).join(name));
    }

    candidates.extend(common_js_runner_locations(name));
    dedupe_paths(candidates)
}

fn push_js_runner_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    candidates.push(path.clone());

    if cfg!(target_os = "windows") && path.extension().is_none() {
        for extension in ["exe", "cmd", "bat"] {
            candidates.push(path.with_extension(extension));
        }
    }
}

fn js_runner_env_vars(name: &str) -> &'static [&'static str] {
    match name {
        "bun" => &["EXACT_BUN", "BUN"],
        "node" => &["EXACT_NODE", "NODE"],
        _ => &[],
    }
}

fn common_js_runner_locations(name: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        push_js_runner_candidate(&mut candidates, home.join(".bun").join("bin").join(name));
        push_js_runner_candidate(&mut candidates, home.join(".volta").join("bin").join(name));
        push_js_runner_candidate(&mut candidates, home.join(".asdf").join("shims").join(name));

        if let Ok(nvm_bin) = std::env::var("NVM_BIN") {
            if !nvm_bin.trim().is_empty() {
                push_js_runner_candidate(&mut candidates, PathBuf::from(nvm_bin).join(name));
            }
        }

        if let Ok(asdf_dir) = std::env::var("ASDF_DIR") {
            if !asdf_dir.trim().is_empty() {
                push_js_runner_candidate(
                    &mut candidates,
                    PathBuf::from(asdf_dir).join("shims").join(name),
                );
            }
        }
    }

    push_js_runner_candidate(
        &mut candidates,
        PathBuf::from("/opt/homebrew/bin").join(name),
    );
    push_js_runner_candidate(&mut candidates, PathBuf::from("/usr/local/bin").join(name));

    candidates
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut unique = Vec::new();
    for path in paths {
        let key = path.as_os_str().to_os_string();
        if seen.insert(key) {
            unique.push(path);
        }
    }
    unique
}

fn exact_devtools_dir(repo_root: &Path) -> PathBuf {
    repo_root.join("packages").join("ibex-devtools")
}

fn exact_devtools_script(repo_root: &Path, script_name: &str) -> PathBuf {
    exact_devtools_dir(repo_root)
        .join("src")
        .join("scripts")
        .join(script_name)
}

fn exact_runtime_js_dir(repo_root: &Path) -> PathBuf {
    repo_root.join("packages").join("ibex-runtime-js")
}

fn generate_runtime_bundle_source_header(
    repo_root: &Path,
    out_dir: &Path,
    allow_fallback: bool,
    standalone: bool,
    vendored_generated_dir: &Path,
) {
    let devtools_dir = exact_devtools_dir(repo_root);
    let runtime_entry = exact_runtime_js_dir(repo_root)
        .join("src")
        .join("runtime-entry.ts");
    let build_script = exact_devtools_script(repo_root, "rolldown-bundle.mjs");
    let bundled_runtime = out_dir.join("embedded_runtime_bundle.js");
    let header_path = out_dir.join("runtime_bundle_source.h");
    let bytecode_header_path = out_dir.join("runtime_bundle_bytecode.h");
    safe_remove_file(&header_path);
    safe_remove_file(&bytecode_header_path);

    // Standalone: the monorepo runtime entry/bundler are absent. Use the
    // vendored pre-bundled runtime, emit the source header from it, and compile
    // bytecode via the present hermesc (same as the monorepo path's tail).
    if standalone {
        let vendored_bundle = vendored_generated_dir.join("embedded_runtime_bundle.js");
        let source = read_text_or_panic(&vendored_bundle, "vendored embedded_runtime_bundle.js");
        if !source.contains("ExactBundle") || !source.contains("__exactRuntimeLoaded") {
            panic!(
                "Vendored runtime bundle at {} does not look like an Exact runtime bundle",
                vendored_bundle.display()
            );
        }
        write_file_or_panic(&bundled_runtime, &source, "embedded_runtime_bundle.js");
        let mut header = String::from(
            "// Generated by build.rs from vendored-generated/embedded_runtime_bundle.js\n\
             // Do not edit by hand.\n",
        );
        push_cpp_raw_string_literal(&mut header, "SHARED_RUNTIME_BUNDLE_SRC", &source);
        write_file_or_panic(&header_path, header, "runtime_bundle_source.h");
        eprintln!("cargo:warning=Generated runtime_bundle_source.h from vendored runtime bundle");
        generate_runtime_bundle_bytecode_header(repo_root, out_dir, &bundled_runtime);
        return;
    }

    if !runtime_entry.exists() || !build_script.exists() {
        if !allow_fallback {
            panic!(
                "Runtime bundle source files are missing (expected {} and {}) and EXACT_ALLOW_FALLBACK is not set",
                runtime_entry.display(),
                build_script.display()
            );
        }
        eprintln!(
            "cargo:warning=Runtime bundle source files are missing; exact-runtime will keep the legacy bootstrap fallback"
        );
        return;
    }

    if !build_runtime_bundle_source(repo_root, &devtools_dir, &runtime_entry, &bundled_runtime) {
        let missing_js_deps_hint = missing_js_build_deps_hint(repo_root);
        if !allow_fallback {
            panic!(
                "Failed to build the shared runtime bundle for exact-runtime and EXACT_ALLOW_FALLBACK is not set{missing_js_deps_hint}"
            );
        }
        eprintln!(
            "cargo:warning=Failed to build the shared runtime bundle for exact-runtime; keeping the legacy bootstrap fallback"
        );
        return;
    }

    let source = match std::fs::read_to_string(&bundled_runtime) {
        Ok(source) => source,
        Err(err) => {
            if !allow_fallback {
                panic!(
                    "Failed to read shared runtime bundle {} ({}) and EXACT_ALLOW_FALLBACK is not set",
                    bundled_runtime.display(),
                    err
                );
            }
            eprintln!(
                "cargo:warning=Failed to read shared runtime bundle {}: {}",
                bundled_runtime.display(),
                err
            );
            return;
        }
    };

    if !source.contains("ExactBundle") || !source.contains("__exactRuntimeLoaded") {
        if !allow_fallback {
            panic!(
                "Shared runtime bundle at {} does not look like an Exact runtime bundle and EXACT_ALLOW_FALLBACK is not set",
                bundled_runtime.display()
            );
        }
        eprintln!(
            "cargo:warning=Shared runtime bundle at {} does not look like an Exact runtime bundle; keeping legacy bootstrap fallback",
            bundled_runtime.display()
        );
        return;
    }

    let mut header = String::from(
        "// Generated by build.rs from packages/ibex-runtime-js/src/runtime-entry.ts\n\
         // Do not edit by hand.\n",
    );
    push_cpp_raw_string_literal(&mut header, "SHARED_RUNTIME_BUNDLE_SRC", &source);
    write_file_or_panic(&header_path, header, "runtime_bundle_source.h");
    eprintln!("cargo:warning=Generated runtime_bundle_source.h from shared runtime bundle");

    generate_runtime_bundle_bytecode_header(repo_root, out_dir, &bundled_runtime);
}

fn build_runtime_bundle_source(
    repo_root: &Path,
    devtools_dir: &Path,
    runtime_entry: &Path,
    bundled_runtime: &Path,
) -> bool {
    let build_script = devtools_dir
        .join("src")
        .join("scripts")
        .join("rolldown-bundle.mjs");
    let Some(parent) = bundled_runtime.parent() else {
        return false;
    };
    let _ = std::fs::create_dir_all(parent);

    if let Some(runner_path) = which_js_runner() {
        let status = std::process::Command::new(&runner_path)
            .arg(&build_script)
            .arg("--entry")
            .arg(runtime_entry)
            .arg("--out")
            .arg(bundled_runtime)
            .arg("--format")
            .arg("iife")
            .current_dir(devtools_dir)
            .status();

        if matches!(status, Ok(result) if result.success()) {
            return true;
        }
    }

    try_build_runtime_bundle_via_primary_checkout(repo_root, runtime_entry, bundled_runtime)
}

fn push_cpp_raw_string_literal(out: &mut String, const_name: &str, source: &str) {
    const CHUNK_SIZE: usize = 16 * 1024;
    out.push_str(&format!("static const char* {const_name} =\n"));

    if source.is_empty() {
        out.push_str("R\"JSSRC()JSSRC\"");
    } else {
        let mut start = 0;
        while start < source.len() {
            let mut end = (start + CHUNK_SIZE).min(source.len());
            while end > start && !source.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                end = source.len();
            }
            out.push_str("R\"JSSRC(");
            out.push_str(&source[start..end]);
            out.push_str(")JSSRC\"");
            if end < source.len() {
                out.push('\n');
            }
            start = end;
        }
    }

    out.push_str(";\n\n");
}

fn write_empty_bootstrap_hbc_header(path: &Path, bootstrap_files: &[(&str, &str)]) {
    let mut header = String::from(
        "// Auto-generated by build.rs — empty fallback bytecode placeholders\n\
         #pragma once\n\n",
    );
    for (_, array_name) in bootstrap_files {
        header.push_str(&format!(
            "alignas(8) static const uint8_t {}_HBC[] = {{0}};\n\
             static const size_t {}_HBC_LEN = 0;\n\n",
            array_name, array_name
        ));
    }
    write_file_or_panic(path, header, "empty bootstrap_bytecode.h");
}

fn generate_runtime_bundle_bytecode_header(
    repo_root: &Path,
    out_dir: &Path,
    bundled_runtime: &Path,
) {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let hermesc = hermesc_path(repo_root, &target_os, &target_arch);
    let hermes_binary = hermes_cli_path(repo_root, &target_os, &target_arch);
    let bundled_runtime_hbc = out_dir.join("embedded_runtime_bundle.hbc");
    let header_path = out_dir.join("runtime_bundle_bytecode.h");

    safe_remove_file(&bundled_runtime_hbc);
    safe_remove_file(&header_path);

    if !hermesc.exists() {
        eprintln!(
            "cargo:warning=Skipping shared runtime bundle HBC generation: hermesc not found at {}",
            hermesc.display()
        );
        return;
    }

    let Some(compiler_version) = extract_hbc_version(&hermesc) else {
        eprintln!(
            "cargo:warning=Skipping shared runtime bundle HBC generation: could not read hermesc HBC version"
        );
        return;
    };

    let Some(runtime_version) = extract_hbc_version(&hermes_binary) else {
        eprintln!(
            "cargo:warning=Skipping shared runtime bundle HBC generation: could not read Hermes runtime HBC version"
        );
        return;
    };

    if compiler_version != runtime_version {
        eprintln!(
            "cargo:warning=Skipping shared runtime bundle HBC generation: hermesc HBC version {} != hermes HBC version {}",
            compiler_version,
            runtime_version
        );
        return;
    }

    let status = std::process::Command::new(&hermesc)
        .arg("-emit-binary")
        .arg("-O")
        .arg("-out")
        .arg(&bundled_runtime_hbc)
        .arg(bundled_runtime)
        .status();

    if !matches!(status, Ok(result) if result.success()) {
        eprintln!("cargo:warning=Skipping shared runtime bundle HBC generation: hermesc failed");
        safe_remove_file(&bundled_runtime_hbc);
        return;
    }

    match bytecode_file_version(&hermesc, &bundled_runtime_hbc) {
        Some(file_version) if file_version == compiler_version => {}
        Some(file_version) => {
            eprintln!(
                "cargo:warning=Skipping shared runtime bundle HBC generation: file HBC version {} != expected {}",
                file_version,
                compiler_version
            );
            safe_remove_file(&bundled_runtime_hbc);
            return;
        }
        None => {
            eprintln!(
                "cargo:warning=Skipping shared runtime bundle HBC generation: could not read generated HBC version"
            );
            safe_remove_file(&bundled_runtime_hbc);
            return;
        }
    }

    let bytes = read_bytes_or_panic(&bundled_runtime_hbc, "shared runtime bundle HBC");
    let mut header = String::from(
        "// Generated by build.rs from packages/ibex-runtime-js/src/runtime-entry.ts\n\
         // Do not edit by hand.\n\
         #pragma once\n\n\
         alignas(8) static const uint8_t SHARED_RUNTIME_BUNDLE_HBC[] = {\n",
    );

    for (index, byte) in bytes.iter().enumerate() {
        if index % 16 == 0 && index > 0 {
            header.push('\n');
        }
        header.push_str(&format!("0x{:02X},", byte));
    }

    header.push_str(
        "\n};\n\
         static const size_t SHARED_RUNTIME_BUNDLE_HBC_LEN = sizeof(SHARED_RUNTIME_BUNDLE_HBC);\n",
    );

    write_file_or_panic(&header_path, header, "runtime_bundle_bytecode.h");
    eprintln!("cargo:warning=Generated runtime_bundle_bytecode.h from shared runtime bundle");
}

fn try_build_builtins_via_primary_checkout(
    repo_root: &Path,
    builtins_src: &Path,
    builtins_out: &Path,
) -> bool {
    let Some(primary_root) = resolve_primary_worktree_root(repo_root) else {
        return false;
    };
    if primary_root == repo_root {
        return false;
    }

    let primary_devtools_dir = exact_devtools_dir(&primary_root);
    let primary_script = primary_devtools_dir
        .join("src")
        .join("scripts")
        .join("build-builtins.mjs");
    let primary_node_modules = primary_devtools_dir.join("node_modules");

    if !primary_script.exists() || !primary_node_modules.exists() || !builtins_src.exists() {
        return false;
    }

    let _ = std::fs::create_dir_all(builtins_out);
    let status = std::process::Command::new("node")
        .arg(primary_script)
        .arg("--src-dir")
        .arg(builtins_src)
        .arg("--out-dir")
        .arg(builtins_out)
        .current_dir(&primary_devtools_dir)
        .status();

    matches!(status, Ok(result) if result.success())
}

fn try_build_runtime_bundle_via_primary_checkout(
    repo_root: &Path,
    runtime_entry: &Path,
    bundled_runtime: &Path,
) -> bool {
    let Some(primary_root) = resolve_primary_worktree_root(repo_root) else {
        return false;
    };
    if primary_root == repo_root {
        return false;
    }

    let primary_devtools_dir = exact_devtools_dir(&primary_root);
    let primary_script = primary_devtools_dir
        .join("src")
        .join("scripts")
        .join("rolldown-bundle.mjs");
    let primary_node_modules = primary_devtools_dir.join("node_modules");

    if !primary_script.exists() || !primary_node_modules.exists() || !runtime_entry.exists() {
        return false;
    }

    if let Some(parent) = bundled_runtime.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let status = std::process::Command::new("node")
        .arg(primary_script)
        .arg("--entry")
        .arg(runtime_entry)
        .arg("--out")
        .arg(bundled_runtime)
        .arg("--format")
        .arg("iife")
        .current_dir(&primary_devtools_dir)
        .status();

    matches!(status, Ok(result) if result.success())
}

fn resolve_primary_worktree_root(repo_root: &Path) -> Option<PathBuf> {
    let dot_git_path = repo_root.join(".git");
    let dot_git_contents = std::fs::read_to_string(&dot_git_path).ok()?;
    let gitdir = dot_git_contents
        .lines()
        .find_map(|line| line.trim().strip_prefix("gitdir:"))
        .map(str::trim)?;
    let gitdir_path = resolve_git_path(repo_root, Path::new(gitdir));
    let commondir_contents = std::fs::read_to_string(gitdir_path.join("commondir")).ok()?;
    let commondir = commondir_contents.lines().next()?.trim();
    let common_git_dir = resolve_git_path(&gitdir_path, Path::new(commondir));
    common_git_dir.parent().map(|path| path.to_path_buf())
}

fn resolve_git_path(base: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_absolute() {
        return candidate.to_path_buf();
    }

    match std::fs::canonicalize(base.join(candidate)) {
        Ok(path) => path,
        Err(_) => base.join(candidate),
    }
}

fn missing_js_build_deps_hint(repo_root: &Path) -> String {
    let devtools_dir = exact_devtools_dir(repo_root);
    let node_modules_dir = devtools_dir.join("node_modules");
    let rolldown_dir = node_modules_dir.join("rolldown");
    let acorn_dir = node_modules_dir.join("acorn");

    if node_modules_dir.exists() && rolldown_dir.exists() && acorn_dir.exists() {
        String::new()
    } else {
        format!(
            "\nJS build dependencies look missing under {}.\nRun `bun install` from {} and retry.",
            node_modules_dir.display(),
            repo_root.display()
        )
    }
}

fn copy_builtins_fallback(src: &std::path::Path, dst: &std::path::Path) {
    let _ = std::fs::create_dir_all(dst);
    if let Ok(entries) = std::fs::read_dir(src) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "js" || e == "ts") {
                let Some(file_name) = path.file_name() else {
                    eprintln!(
                        "cargo:warning=Skipping builtin copy for {} because it has no file name",
                        path.display()
                    );
                    continue;
                };
                let dest = dst.join(file_name);
                let _ = std::fs::copy(&path, &dest);
            }
        }
    }
}

/// Copy every file in `src` whose extension is in `extensions` into `dst`,
/// creating `dst` if needed. Used to stage vendored generated artifacts into
/// OUT_DIR for the standalone Ibex build.
fn copy_dir_files(src: &Path, dst: &Path, extensions: &[&str]) {
    if let Err(error) = std::fs::create_dir_all(dst) {
        panic!("Failed to create OUT_DIR subdir {}: {error}", dst.display());
    }
    for path in read_dir_paths_or_panic(src, "vendored artifact copy") {
        let matches_ext = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| extensions.contains(&e));
        if !matches_ext {
            continue;
        }
        let Some(file_name) = path.file_name() else {
            continue;
        };
        let dest = dst.join(file_name);
        if let Err(error) = std::fs::copy(&path, &dest) {
            panic!(
                "Failed to copy vendored artifact {} -> {}: {error}",
                path.display(),
                dest.display()
            );
        }
    }
}

fn clear_dir_if_exists(path: &Path, context: &str) {
    if !path.exists() {
        return;
    }
    std::fs::remove_dir_all(path).unwrap_or_else(|error| {
        panic!(
            "Failed to clear {context} directory {}: {error}",
            path.display()
        )
    });
}

fn refresh_vendored_generated(out_dir: &Path, vendored_generated_dir: &Path) {
    if let Err(error) = std::fs::create_dir_all(vendored_generated_dir) {
        panic!(
            "Failed to create vendored generated dir {}: {error}",
            vendored_generated_dir.display()
        );
    }

    for file_name in [
        "builtin_manifest.generated.rs",
        "embedded_runtime_bundle.js",
    ] {
        let src = out_dir.join(file_name);
        let dst = vendored_generated_dir.join(file_name);
        let contents = read_bytes_or_panic(&src, file_name);
        write_file_or_panic(&dst, contents, file_name);
        eprintln!(
            "cargo:warning=Refreshed vendored artifact {}",
            dst.display()
        );
    }

    let src_builtins = out_dir.join("builtins");
    let dst_builtins = vendored_generated_dir.join("builtins");
    clear_dir_if_exists(&dst_builtins, "vendored builtins");
    copy_dir_files(&src_builtins, &dst_builtins, &["js"]);
    eprintln!(
        "cargo:warning=Refreshed vendored builtin modules in {}",
        dst_builtins.display()
    );
}

fn safe_remove_file(path: &Path) {
    if let Err(err) = std::fs::remove_file(path) {
        if err.kind() != ErrorKind::NotFound {
            eprintln!("cargo:warning=Failed to remove {}: {}", path.display(), err);
        }
    }
}

fn run_tool_output(path: &Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(path).args(args).output().ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    if text.trim().is_empty() {
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    if !output.status.success() {
        return None;
    }
    Some(text)
}

fn extract_u32_after_prefix(line_iter: &str, prefix: &str) -> Option<u32> {
    for line in line_iter.lines() {
        if let Some(rest) = line.trim().strip_prefix(prefix) {
            if let Ok(value) = rest.trim().parse::<u32>() {
                return Some(value);
            }
        }
    }
    None
}

fn extract_hbc_version(binary_path: &Path) -> Option<u32> {
    run_tool_output(binary_path, &["--version"])
        .and_then(|text| extract_u32_after_prefix(&text, "HBC bytecode version:"))
}

fn bytecode_file_version(hermesc: &Path, hbc_path: &Path) -> Option<u32> {
    let mut child = std::process::Command::new(hermesc)
        .arg("-dump-bytecode")
        .arg(hbc_path)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let mut reader = BufReader::new(stdout);

    for _ in 0..128 {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if let Some(version) =
                    extract_u32_after_prefix(line.trim(), "Bytecode version number:")
                {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Some(version);
                }
            }
            Err(_) => break,
        }
    }

    let _ = child.wait();
    None
}

fn parse_env_flag(name: &str) -> Option<bool> {
    std::env::var(name).ok().map(|value| {
        matches!(
            value.as_str(),
            "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
        )
    })
}

fn find_macos_hermes_binary(search_root: &Path) -> Option<PathBuf> {
    let candidates = [
        search_root
            .join("hermesvm.framework")
            .join("Versions")
            .join("Current")
            .join("hermesvm"),
        search_root
            .join("hermesvm.framework")
            .join("Versions")
            .join("1")
            .join("hermesvm"),
        search_root.join("hermesvm.framework").join("hermesvm"),
        search_root.join("hermesvm"),
    ];

    candidates.into_iter().find(|path| path.exists())
}

fn macos_hermes_has_debugger_symbols(binary_path: &Path) -> bool {
    let output = std::process::Command::new("nm")
        .args(["-gU", binary_path.to_string_lossy().as_ref()])
        .output()
        .or_else(|_| {
            std::process::Command::new("xcrun")
                .arg("nm")
                .arg("-gU")
                .arg(binary_path)
                .output()
        });

    let Ok(output) = output else {
        return false;
    };

    if !output.status.success() {
        return false;
    }

    String::from_utf8_lossy(&output.stdout).contains("AsyncDebuggerAPI")
}

fn should_enable_hermes_debugger(target_os: &str, hermes_macos_binary: Option<&Path>) -> bool {
    match parse_env_flag("HERMES_ENABLE_DEBUGGER") {
        Some(false) => false,
        Some(true) => {
            if target_os == "macos" {
                let Some(binary_path) = hermes_macos_binary else {
                    panic!(
                        "HERMES_ENABLE_DEBUGGER=1 was requested, but no macOS Hermes framework binary was found."
                    );
                };
                if !macos_hermes_has_debugger_symbols(binary_path) {
                    panic!(
                        "HERMES_ENABLE_DEBUGGER=1 was requested, but {} does not export Hermes debugger symbols. Rebuild Hermes with debugger support or unset HERMES_ENABLE_DEBUGGER.",
                        binary_path.display()
                    );
                }
            }
            true
        }
        None => match target_os {
            "ios" | "android" => false,
            "macos" => match hermes_macos_binary {
                Some(binary_path) if macos_hermes_has_debugger_symbols(binary_path) => true,
                Some(binary_path) => {
                    println!(
                        "cargo:warning=Hermes debugger disabled: {} does not export debugger symbols.",
                        binary_path.display()
                    );
                    false
                }
                None => {
                    println!(
                        "cargo:warning=Hermes debugger disabled: could not locate a macOS Hermes framework binary."
                    );
                    false
                }
            },
            _ => true,
        },
    }
}
