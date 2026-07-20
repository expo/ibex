//! Windows crypto source contracts for the default no-OpenSSL profile.

const MODULE_LOADER: &str = include_str!("../src/engine/bootstrap/module-loader.js");
const WINDOWS_CRYPTO: &str = include_str!("../src/engine/hermes_runtime_crypto_windows.cc");

#[test]
fn windows_uses_the_canonical_manifest_crypto_surface() {
    assert!(
        !MODULE_LOADER.contains("makeWindowsCryptoModule"),
        "a bootstrap-local Windows crypto module would shadow the canonical builtin"
    );
    assert!(
        !MODULE_LOADER.contains("internalModules.crypto"),
        "crypto must reach the authenticated manifest builtin resolver on Windows"
    );
}

#[test]
fn windows_native_crypto_remains_a_primitive_backend() {
    for primitive in [
        "__exactHashSync",
        "__exactHashRaw",
        "__exactHmacSync",
        "__exactHkdf",
    ] {
        assert!(
            WINDOWS_CRYPTO.contains(primitive),
            "Windows must retain its BCrypt-backed {primitive} primitive"
        );
    }
    assert!(
        WINDOWS_CRYPTO.contains("Windows is a no-OpenSSL crypto profile backed by CNG/BCrypt"),
        "the reduced Windows backend must stay explicitly documented"
    );
    assert!(
        WINDOWS_CRYPTO.contains("RFC 5869 extract") && WINDOWS_CRYPTO.contains("RFC 5869 expand"),
        "Windows HKDF must remain a real RFC 5869 construction over BCrypt HMAC"
    );
}
