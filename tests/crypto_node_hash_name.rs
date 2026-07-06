//! Node-crypto hash-name normalizer: a hyphenated WebCrypto hash name must
//! select the requested digest (ENG-23024).
//!
//! The WebCrypto TS layer passes the key's canonical hash name — e.g. "SHA-384"
//! (uppercase, hyphenated) — into the on-device `__exactSignSync` /
//! `__exactVerifySync` bridges, which normalize it before signing. The
//! normalizer used to test hyphen-less tokens against the dashed input, so
//! "sha-384" matched nothing and control fell through to a `return "sha256"`
//! default: SHA-1/SHA-384/SHA-512 were all computed over SHA-256, so signatures
//! never verified against Node/OpenSSL. This drives the exact normalizer
//! (`normalizeHashForNodeCrypto` on Apple, `digestAlgorithmFromNodeCrypto` on
//! Linux/OpenSSL) through the `ex_crypto_test_node_hash_name` C ABI hook in
//! `src/engine/hermes_runtime_crypto.cc`.

use std::os::raw::{c_char, c_int};

/// Reference a public item so the `ibex_runtime` rlib — which bundles the C++
/// static archive that defines the hook — is linked into this test binary.
fn ensure_runtime_linked() {
    let _ = std::hint::black_box(ibex_runtime::runtime_cache_dir as *const () as usize);
}

extern "C" {
    fn ex_crypto_test_node_hash_name(
        algorithm: *const c_char,
        out: *mut c_char,
        out_cap: usize,
    ) -> c_int;
}

/// Returns the normalized digest name, or `None` when no node-crypto normalizer
/// is compiled for this platform/profile (the hook returns -1).
fn normalize(algorithm: &str) -> Option<String> {
    ensure_runtime_linked();
    let c = std::ffi::CString::new(algorithm).unwrap();
    let mut buf = vec![0u8; 32];
    let n = unsafe {
        ex_crypto_test_node_hash_name(c.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len())
    };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(String::from_utf8(buf).unwrap())
}

#[test]
fn node_crypto_normalizer_honors_dashed_webcrypto_hash_names() {
    // Skip on platforms/profiles where no node-crypto normalizer is compiled.
    let Some(_) = normalize("SHA-256") else {
        return;
    };

    for (input, expected) in [
        // Hyphenated WebCrypto names (the regression class).
        ("SHA-1", "sha1"),
        ("SHA-256", "sha256"),
        ("SHA-384", "sha384"),
        ("SHA-512", "sha512"),
        // Hyphen-less and prefixed forms must keep working.
        ("sha384", "sha384"),
        ("sha512", "sha512"),
        ("RSA-SHA384", "sha384"),
        ("ecdsa-with-sha512", "sha512"),
    ] {
        assert_eq!(
            normalize(input).as_deref(),
            Some(expected),
            "hash name {input} must normalize to {expected}"
        );
    }

    // The specific defect: a dashed name must NOT silently collapse to sha256.
    assert_ne!(normalize("SHA-1").as_deref(), Some("sha256"));
    assert_ne!(normalize("SHA-384").as_deref(), Some("sha256"));
    assert_ne!(normalize("SHA-512").as_deref(), Some("sha256"));
}
