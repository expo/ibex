//! The insecure ambient `process.env` projection is opt-in per process: it
//! activates only when the launcher (or an embedder) explicitly calls
//! `install_insecure_ambient_environment`. Creating a runtime never installs
//! it, so embedded runtimes do not silently acquire ambient host environment
//! access even in an `insecure` build — an embedder that wants the projection
//! must call the installer itself; a secure embedder supplies values through
//! authorized principal overlays instead.
//! (issues/20260724-insecure-process-env.md, "Security boundary".)
//!
//! This binary must never call the installer; it asserts the uninstalled
//! state. The store's positive semantics live in the `insecure_process_env`
//! unit tests (`src/host/process.rs`), which run in a different process.

#[test]
fn ambient_projection_is_inert_without_an_explicit_install() {
    std::env::set_var("IBEX_TEST_ENV_SENTINEL", "present-in-host");
    assert!(!ibex_runtime::host::process::insecure_ambient_environment_active());
    assert_eq!(
        ibex_runtime::host::process::insecure_ambient_env_get("IBEX_TEST_ENV_SENTINEL"),
        None,
        "ambient reads must stay unset before install"
    );
    assert_eq!(
        ibex_runtime::host::process::insecure_ambient_env_key_count(),
        None,
        "ambient enumeration must stay inactive before install"
    );
    // Mutation is a no-op while inactive rather than an implicit install.
    ibex_runtime::host::process::insecure_ambient_env_set("IBEX_TEST_ENV_SENTINEL", Some("x"));
    assert!(!ibex_runtime::host::process::insecure_ambient_environment_active());
    assert_eq!(
        ibex_runtime::host::process::insecure_ambient_env_get("IBEX_TEST_ENV_SENTINEL"),
        None
    );
}
