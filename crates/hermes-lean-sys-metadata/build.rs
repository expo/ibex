//! Forward unselected Hermes build inputs without forwarding linked identity.

fn main() {
    for key in [
        "INCLUDE_DIR",
        "HERMESC_PATH",
        "LIB_ROOT",
        "ARCHIVE",
        "ENGINE_DIGEST",
        "LEAN_ARCHIVE",
        "LEAN_ENGINE_DIGEST",
        "BYTECODE_VERSION",
        "LEAN_BYTECODE_VERSION",
        "ENGINE_DIR",
        "ICU_DATA_ARCHIVE",
        "ICU_DATA_DIGEST",
        "ICU_EN_DATA_ARCHIVE",
        "ICU_EN_DATA_DIGEST",
        "ICU_FULL_DATA_ARCHIVE",
        "ICU_FULL_DATA_DIGEST",
    ] {
        let source = format!("DEP_HERMES_LEAN_{key}");
        println!("cargo:rerun-if-env-changed={source}");
        if let Ok(value) = std::env::var(&source) {
            println!("cargo::metadata={}={value}", key.to_ascii_lowercase());
        }
    }
}
