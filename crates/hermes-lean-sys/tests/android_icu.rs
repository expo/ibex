#![cfg(unix)]

#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

const TARGET: &str = "aarch64-linux-android";

// Run the actual build script in a child so Cargo feature environments cannot
// race other tests. The fixture compiler runs on the host; no NDK is needed.
#[test]
fn android_receipts_select_icu_data() {
    if std::env::var_os("IBEX_TEST_ANDROID_BUILD_SCRIPT").is_some() {
        build_script::main();
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    for tiers in [false, true] {
        let bundle = temporary.path().join(if tiers { "v6" } else { "v5" });
        write_bundle(&bundle, tiers);
        for feature in ["default", "intl", "intl-all-locales"] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", "android_receipts_select_icu_data", "--nocapture"])
                .env("IBEX_TEST_ANDROID_BUILD_SCRIPT", "1")
                .env("TARGET", TARGET)
                .env("HOST", TARGET)
                .env("CARGO_CFG_TARGET_OS", "android")
                .env("CARGO_CFG_TARGET_VENDOR", "unknown")
                .env("CARGO_FEATURE_LINK", "1")
                .env("CARGO_FEATURE_ICU", "1")
                .env_remove("CARGO_FEATURE_LINK_LEAN")
                .env_remove("CARGO_FEATURE_ICU_EN_DATA")
                .env_remove("CARGO_FEATURE_ICU_FULL_DATA")
                .env("HERMES_LEAN_SYS_DIR_aarch64_linux_android", &bundle)
                .env("OUT_DIR", temporary.path());
            if feature != "default" {
                command.env("CARGO_FEATURE_ICU_EN_DATA", "1");
            }
            if feature == "intl-all-locales" {
                command.env("CARGO_FEATURE_ICU_FULL_DATA", "1");
            }
            let output = command.output().unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(
                output.status.success(),
                "tiers={tiers}, {feature}: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let library = if !tiers {
                "icudata"
            } else if feature == "intl-all-locales" {
                "icudata-full"
            } else {
                "icudata-en"
            };
            let links: Vec<_> = stdout
                .lines()
                .filter_map(|line| line.strip_prefix("cargo:rustc-link-lib="))
                .collect();
            assert_eq!(
                links,
                [
                    "static=hermesvm_a",
                    "static=jsi",
                    "static=boost_context",
                    "static=icui18n",
                    "static=icuuc",
                    &format!("static={library}"),
                    "c++_static",
                    "c++abi",
                    "log",
                    "dl",
                    "m",
                ],
                "tiers={tiers}, {feature}: ICU must precede the NDK C++ runtime"
            );
            let archive = bundle.join(format!("lib/lib{library}.a"));
            assert!(stdout.contains(&format!(
                "cargo::metadata=linked_icu_data_archive={}\n",
                archive.display()
            )));
            assert!(stdout.contains(&format!(
                "cargo::metadata=linked_icu_data_digest={}\n",
                digest(&fs::read(archive).unwrap())
            )));
        }
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256-{:x}", Sha256::digest(bytes))
}

fn write_bundle(root: &Path, tiers: bool) {
    let mut receipt: Value =
        serde_json::from_str(include_str!("../testdata/receipt-v2-valid.json")).unwrap();
    receipt["target"] = TARGET.into();
    receipt["build"]["flags"] = json!([if tiers {
        "-DHERMES_ENABLE_INTL=true"
    } else {
        "-DHERMES_ENABLE_INTL=false"
    }]);
    let write = |path: &str, contents: &[u8]| {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
        digest(contents)
    };
    let compiler = "bin/hermesc";
    receipt["compiler"]["digest"] =
        write(compiler, b"#!/bin/sh\necho 'HBC bytecode version: 99'\n").into();
    fs::set_permissions(root.join(compiler), fs::Permissions::from_mode(0o755)).unwrap();
    receipt["headers"][0]["digest"] = write("include/jsi/jsi.h", b"// fixture header").into();
    let mut archives = vec![
        "lib/libhermesvm_a.a",
        "lib/libhermesvmlean_a.a",
        "lib/libjsi.a",
        "lib/libboost_context.a",
        "lib/libicui18n.a",
        "lib/libicuuc.a",
        "lib/libicudata.a",
    ];
    if tiers {
        archives.extend(["lib/libicudata-en.a", "lib/libicudata-full.a"]);
    }
    archives.sort();
    receipt["archives"] = archives
        .iter()
        .map(|path| json!({"path": path, "digest": write(path, path.as_bytes())}))
        .collect();
    receipt["engine"]["binaryDigest"] = digest(b"lib/libhermesvm_a.a").into();
    if tiers {
        let base_filter = "share/icu/filters-root-en.json";
        let en_filter = "share/icu/filters-en-intl.json";
        receipt["icu"] = json!({
            "upstream": {"artifact": "unicode-org/icu", "sourceCommit": "2d029329c82c7792b985024b2bdab5fc7278fbc8", "sourceRef": "release-74-2", "sourceVersion": "74.2"},
            "codeArchives": ["lib/libicui18n.a", "lib/libicuuc.a"],
            "data": {
                "trimmed": {"archive": "lib/libicudata.a", "filter": {"path": base_filter, "digest": write(base_filter, include_bytes!("../../../scripts/icu74-filter-root-en.json"))}},
                "en": {"archive": "lib/libicudata-en.a", "filter": {"path": en_filter, "digest": write(en_filter, include_bytes!("../../../scripts/icu74-filter-en-intl.json"))}},
                "full": {"archive": "lib/libicudata-full.a"}
            }
        });
    }
    write(
        "hermes-input-receipt.json",
        &serde_json::to_vec(&receipt).unwrap(),
    );
}
