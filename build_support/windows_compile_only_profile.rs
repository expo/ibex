//! Pure policy for Ibex's narrow Windows Hermes metadata-only profile.
//!
//! The profile exists solely so a non-Windows host can type-check/lint the
//! Windows embedder against an authenticated legacy header/import-lib fixture.
//! It is never a runtime profile and its plan deliberately makes codegen/link
//! fail. Keeping the selector pure lets tests exercise every refusal without
//! running Cargo recursively from `build.rs`.

pub const MODE_ENV: &str = "IBEX_WINDOWS_COMPILE_ONLY_PROFILE";
pub const SUPPORTED_TARGET: &str = "x86_64-pc-windows-msvc";
pub const POISON_LIBRARY: &str = "IBEX_WINDOWS_COMPILE_ONLY_PROFILE_MUST_NOT_LINK";

pub const FORBIDDEN_SELECTOR_ENVS: &[&str] = &[
    "EXACT_ALLOW_FALLBACK",
    "HERMESC",
    "HERMES_BINARY",
    "HERMES_CLI",
    "HERMES_COMPILER",
    "HERMES_ENABLE_DEBUGGER",
    "HERMES_LINK_STATIC",
    "HERMES_LIB_NAME",
    "HERMES_PROFILE_PROVENANCE_RECEIPT",
    "HERMES_STATIC_LIB_NAME",
    "JSI_INCLUDE_DIR",
    "JSI_LIB_DIR",
    "IBEX_PORTABLE_HERMES_ARTIFACT_ID",
    "IBEX_PORTABLE_HERMES_STORE_ROOT",
    "IBEX_PORTABLE_HERMES_ARCHIVE_DIGEST",
    "IBEX_PORTABLE_HERMES_SOURCE_REVISION",
    "IBEX_PORTABLE_HERMES_CURRENT_REVISION",
    "IBEX_PORTABLE_HERMES_PREFLIGHT_RECEIPT",
    "IBEX_PORTABLE_HERMES_PREFLIGHT_NONCE",
    "IBEX_PORTABLE_HERMES_CHECKOUT_ROOT",
    "IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP",
    "IBEX_PORTABLE_HERMES_CARGO_TARGET_MAP_DIGEST",
    "IBEX_PORTABLE_HERMES_PROMOTION_ADMISSION",
    "IBEX_PORTABLE_HERMES_PROMOTION_ADMISSION_DIGEST",
];

pub const REQUIRED_DIRECTORY_ENVS: &[&str] =
    &["HERMES_INCLUDE_DIR", "HERMES_LIB_DIR", "HERMES_BIN_DIR"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileOnlyPlan {
    pub stage_runtime_dlls: bool,
    pub add_runtime_bin_search: bool,
    pub embed_null_provenance: bool,
    pub poison_codegen_link: bool,
}

#[derive(Debug)]
pub struct SelectorRequest<'a> {
    pub mode_value: Option<&'a str>,
    pub target_os: &'a str,
    pub target_triple: &'a str,
    pub host_triple: Option<&'a str>,
    pub legacy_block_scoping: Option<&'a str>,
    pub require_provenance: Option<&'a str>,
    pub present_forbidden_selectors: &'a [&'a str],
    pub missing_required_directories: &'a [&'a str],
}

pub fn select(request: SelectorRequest<'_>) -> Result<Option<CompileOnlyPlan>, String> {
    let Some(mode_value) = request.mode_value else {
        return Ok(None);
    };
    if mode_value != "1" {
        return Err(format!(
            "{MODE_ENV} has unsupported value {mode_value:?}; expected exactly \"1\""
        ));
    }
    if request.target_os != "windows" || request.target_triple != SUPPORTED_TARGET {
        return Err(format!(
            "compile-only Windows Hermes profile supports only {SUPPORTED_TARGET}, not {}",
            request.target_triple
        ));
    }
    let host_triple = request
        .host_triple
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "HOST is required in compile-only Hermes mode".to_owned())?;
    if host_triple == request.target_triple || host_triple.contains("-windows-") {
        return Err(format!(
            "compile-only Windows Hermes profile requires cross-compilation from a non-Windows host; HOST was {host_triple} and TARGET was {}",
            request.target_triple,
        ));
    }
    if request.legacy_block_scoping != Some("1") {
        return Err(
            "compile-only Windows Hermes profile requires IBEX_LEGACY_HERMES_BLOCK_SCOPING=1"
                .to_owned(),
        );
    }
    if request.require_provenance != Some("0") {
        return Err(
            "compile-only Windows Hermes profile requires IBEX_REQUIRE_HERMES_PROFILE_PROVENANCE=0"
                .to_owned(),
        );
    }
    if let Some(selector) = request.present_forbidden_selectors.first() {
        return Err(format!(
            "compile-only Windows Hermes profile forbids runtime selector {selector}"
        ));
    }
    if let Some(directory) = request.missing_required_directories.first() {
        return Err(format!(
            "compile-only Windows Hermes profile requires explicit {directory}"
        ));
    }

    Ok(Some(CompileOnlyPlan {
        stage_runtime_dlls: false,
        add_runtime_bin_search: false,
        embed_null_provenance: true,
        poison_codegen_link: true,
    }))
}

pub fn validate_artifacts(
    binary_directory_entries: &[String],
    import_library_is_regular_file: bool,
    import_library_display: &str,
) -> Result<(), String> {
    if !binary_directory_entries.is_empty() {
        return Err(format!(
            "compile-only Windows Hermes profile binary directory must be empty; found {}",
            binary_directory_entries.join(", ")
        ));
    }
    if !import_library_is_regular_file {
        return Err(format!(
            "compile-only Windows Hermes profile requires a regular import library at {import_library_display}"
        ));
    }
    Ok(())
}
