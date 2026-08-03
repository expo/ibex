use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ibex_release_stub_contract)");
    println!("cargo:rerun-if-env-changed=IBEX_STUB_CONTRACT_PATH");
    println!("cargo:rerun-if-env-changed=IBEX_SFE_LINUX_RELEASE_STUB");
    println!("cargo:rerun-if-env-changed=HERMES_LINK_STATIC");
    compile_environment_preinit();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let linux_release_stub = env_truthy("IBEX_SFE_LINUX_RELEASE_STUB");
    if linux_release_stub {
        assert_eq!(
            target_os, "linux",
            "IBEX_SFE_LINUX_RELEASE_STUB is valid only for Linux targets"
        );
        assert!(
            env_truthy("HERMES_LINK_STATIC"),
            "IBEX_SFE_LINUX_RELEASE_STUB requires HERMES_LINK_STATIC=1"
        );
    }
    if let Some(contract_path) = std::env::var_os("IBEX_STUB_CONTRACT_PATH") {
        assert!(
            target_os != "linux" || linux_release_stub,
            "a Linux release contract requires IBEX_SFE_LINUX_RELEASE_STUB=1"
        );
        install_release_contract(PathBuf::from(contract_path));
    }
    println!("cargo:rerun-if-env-changed=HERMES_LIB_DIR");
    if target_os == "macos" {
        // Reserve deterministic load-command space for __IBEX + __payload and
        // for LC_CODE_SIGNATURE added after envelope injection.
        println!("cargo:rustc-link-arg=-Wl,-headerpad,0x1000");
        // Apple ld synthesizes a different LC_UUID on independent builders
        // even when every other unsigned stub byte matches. The SFE identity
        // is its authenticated stub-core digest, so omit that unbound nonce.
        // @ref LLP 0047#4-milestone-1--publish-a-real-release-catalog
        println!("cargo:rustc-link-arg=-Wl,-no_uuid");
    }
    if target_os != "macos" && target_os != "linux" {
        return;
    }
    if std::env::var("HERMES_LINK_STATIC")
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
    {
        return;
    }
    let repo = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../..")
        .canonicalize()
        .expect("compiled-stub repository root is absent");
    let library_dir = std::env::var_os("HERMES_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if target_os == "macos" {
                repo.join("ios/Frameworks")
            } else {
                repo.join("linux/lib")
            }
        });
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", library_dir.display());
}

fn compile_environment_preinit() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let profile_path = manifest
        .join("../../vendored-generated/compiled-environment-profile.canonical.json")
        .canonicalize()
        .expect("compiled environment profile is absent");
    println!("cargo:rerun-if-changed={}", profile_path.display());
    println!("cargo:rerun-if-changed=src/environment_preinit.c");

    let bytes = std::fs::read(&profile_path).expect("cannot read compiled environment profile");
    let text = std::str::from_utf8(&bytes).expect("compiled environment profile is not UTF-8");
    let value = capsec_semantics::strict_json::parse_strict(text)
        .expect("compiled environment profile is not strict JSON");
    assert_eq!(
        capsec_semantics::canonical::to_jcs_bytes(&value)
            .expect("compiled environment profile cannot canonicalize"),
        bytes,
        "compiled environment profile is not canonical JCS"
    );
    let names = value["allowlistDecision"]["names"]
        .as_array()
        .expect("compiled environment allowlist is not an array")
        .iter()
        .map(|name| {
            let name = name
                .as_str()
                .expect("compiled environment allowlist entry is not a string");
            assert!(
                name.bytes().enumerate().all(|(index, byte)| {
                    matches!(byte, b'A'..=b'Z' | b'_') || (index > 0 && matches!(byte, b'0'..=b'9'))
                }) && !name.is_empty(),
                "compiled environment allowlist name is not canonical: {name:?}"
            );
            name
        })
        .collect::<Vec<_>>();
    assert!(
        names.windows(2).all(|pair| pair[0] < pair[1]),
        "compiled environment allowlist must be sorted and unique"
    );

    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is absent"));
    let header = output.join("compiled_environment_allowlist.h");
    write_allowlist_header(&header, &names);
    cc::Build::new()
        .file("src/environment_preinit.c")
        .include(&output)
        .warnings_into_errors(true)
        .compile("ibex_compiled_environment_preinit");
}

fn write_allowlist_header(path: &Path, names: &[&str]) {
    let capacity = names.len().max(1);
    let entries = if names.is_empty() {
        "    NULL".to_owned()
    } else {
        names
            .iter()
            .map(|name| format!("    \"{name}\""))
            .collect::<Vec<_>>()
            .join(",\n")
    };
    let header = format!(
        "#define IBEX_COMPILED_ENVIRONMENT_ALLOWLIST_COUNT {}\n\
         static const char *const IBEX_COMPILED_ENVIRONMENT_ALLOWLIST[{capacity}] = {{\n{entries}\n}};\n",
        names.len()
    );
    std::fs::write(path, header).expect("cannot write compiled environment allowlist header");
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn install_release_contract(path: PathBuf) {
    println!("cargo:rerun-if-changed={}", path.display());
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read release stub contract {}: {error}",
            path.display()
        )
    });
    let text = std::str::from_utf8(&bytes)
        .unwrap_or_else(|error| panic!("release stub contract is not UTF-8: {error}"));
    let value = capsec_semantics::strict_json::parse_strict(text)
        .unwrap_or_else(|error| panic!("release stub contract is not strict JSON: {error}"));
    let contract: ibex_sfe_format::StubContractV3 = serde_json::from_value(value)
        .unwrap_or_else(|error| panic!("release stub contract shape is invalid: {error}"));
    let canonical = contract
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("release stub contract is invalid: {error}"));
    assert_eq!(
        canonical, bytes,
        "release stub contract must be exact canonical JCS"
    );
    assert!(
        contract.release_eligible,
        "release stub contract must be release eligible"
    );
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is absent"))
        .join("stub-contract.canonical.json");
    std::fs::write(&output, canonical)
        .unwrap_or_else(|error| panic!("cannot stage release stub contract: {error}"));
    println!("cargo:rustc-cfg=ibex_release_stub_contract");
}
