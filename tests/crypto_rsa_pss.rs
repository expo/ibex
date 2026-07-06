//! Native RSA sign/verify bridge: raw bytes + RSA-PSS with an explicit salt
//! length (ENG-23002).
//!
//! These tests drive the shared OpenSSL RSA sign/verify core that backs the
//! on-device `__exactSignSync` / `__exactVerifySync` bridges — the exact code
//! path that ships on Android/Linux — through the `ex_crypto_test_rsa_*` C ABI
//! test hooks in `src/engine/hermes_runtime_crypto.cc`. The JSI bridges
//! themselves need a full Hermes runtime to invoke, so exercising the core
//! directly is the real, buildable verification of the two defects this issue
//! fixes:
//!   * finding 3 — the message must be signed as RAW bytes, not a UTF-8
//!     re-encoding that expands every byte >= 0x80; and
//!   * finding 4 — RSA-PSS must actually use PSS padding and honour the salt
//!     length, instead of silently producing a PKCS#1 v1.5 signature.
//!
//! Only compiled with the `openssl-crypto` feature: without it the runtime has
//! no OpenSSL RSA core and the hooks are not defined.
#![cfg(feature = "openssl-crypto")]

use std::os::raw::{c_char, c_int};

/// Reference a public item so the `ibex_runtime` rlib — which bundles the C++
/// static archive that defines the `ex_crypto_test_*` hooks — is linked into
/// this test binary. A test that used only the `extern "C"` symbols below would
/// otherwise let rustc drop the (apparently unused) rlib, and the hooks would be
/// reported as undefined at link time.
fn ensure_runtime_linked() {
    let _ = std::hint::black_box(ibex_runtime::runtime_cache_dir as usize);
}

extern "C" {
    fn ex_crypto_test_rsa_sign(
        data: *const u8,
        data_len: usize,
        pem_key: *const c_char,
        pem_len: usize,
        hash_name: *const c_char,
        use_pss: c_int,
        salt_len: c_int,
        out: *mut u8,
        out_cap: usize,
    ) -> c_int;

    fn ex_crypto_test_rsa_verify(
        data: *const u8,
        data_len: usize,
        sig: *const u8,
        sig_len: usize,
        pem_pub: *const c_char,
        pem_pub_len: usize,
        hash_name: *const c_char,
        use_pss: c_int,
        salt_len: c_int,
    ) -> c_int;
}

// Fixed 2048-bit RSA test key pair + a message containing bytes >= 0x80, plus
// the golden deterministic PKCS#1 v1.5 SHA-256 signature over those RAW bytes,
// all produced offline with the `openssl` CLI (see tests/fixtures/crypto).
const PRIV_PEM: &str = include_str!("fixtures/crypto/rsa2048_priv.pem");
const PUB_PEM: &str = include_str!("fixtures/crypto/rsa2048_pub.pem");
const MSG: &[u8] = include_bytes!("fixtures/crypto/msg_highbytes.bin");
const GOLDEN_PKCS1_SHA256: &[u8] = include_bytes!("fixtures/crypto/sig_pkcs1_sha256.bin");

// Null-terminated normalized digest name for the C ABI.
const SHA256: &[u8] = b"sha256\0";

fn sign(data: &[u8], priv_pem: &str, hash: &[u8], use_pss: bool, salt_len: i32) -> Vec<u8> {
    ensure_runtime_linked();
    let mut out = vec![0u8; 1024];
    let n = unsafe {
        ex_crypto_test_rsa_sign(
            data.as_ptr(),
            data.len(),
            priv_pem.as_ptr() as *const c_char,
            priv_pem.len(),
            hash.as_ptr() as *const c_char,
            if use_pss { 1 } else { 0 },
            salt_len,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert!(n > 0, "sign returned {n}");
    out.truncate(n as usize);
    out
}

/// Returns 1 (verified), 0 (not verified), or -1 (error).
fn verify(data: &[u8], sig: &[u8], pub_pem: &str, hash: &[u8], use_pss: bool, salt_len: i32) -> i32 {
    ensure_runtime_linked();
    unsafe {
        ex_crypto_test_rsa_verify(
            data.as_ptr(),
            data.len(),
            sig.as_ptr(),
            sig.len(),
            pub_pem.as_ptr() as *const c_char,
            pub_pem.len(),
            hash.as_ptr() as *const c_char,
            if use_pss { 1 } else { 0 },
            salt_len,
        )
    }
}

/// finding 3: the bridge signs the RAW message bytes. The message contains
/// bytes >= 0x80; a deterministic PKCS#1 v1.5 signature must equal the golden
/// signature the `openssl` CLI produced over those raw bytes. Had the bridge
/// UTF-8-expanded the high bytes, the signature would differ — so this is an
/// external-oracle check, not a self-consistent round-trip.
#[test]
fn pkcs1_signs_raw_message_bytes_matching_external_oracle() {
    assert!(
        MSG.iter().any(|&b| b >= 0x80),
        "fixture must contain bytes >= 0x80 to be a meaningful test"
    );
    let sig = sign(MSG, PRIV_PEM, SHA256, false, -1);
    assert_eq!(
        sig, GOLDEN_PKCS1_SHA256,
        "PKCS#1 v1.5 signature must match the raw-byte oracle (byte-accurate sign)"
    );
    assert_eq!(
        verify(MSG, &sig, PUB_PEM, SHA256, false, -1),
        1,
        "PKCS#1 v1.5 verify of the raw-byte signature must succeed"
    );
}

/// finding 4: RSA-PSS must be genuine PSS. A PSS signature verifies as PSS and
/// is rejected as PKCS#1 v1.5; the PKCS#1 golden signature is rejected as PSS.
/// A self-consistent v1.5-only implementation could not satisfy both.
#[test]
fn rsa_pss_is_real_pss_not_pkcs1_v15() {
    let pss = sign(MSG, PRIV_PEM, SHA256, true, 32);
    assert_eq!(
        verify(MSG, &pss, PUB_PEM, SHA256, true, 32),
        1,
        "PSS signature must verify as PSS"
    );
    assert_eq!(
        verify(MSG, &pss, PUB_PEM, SHA256, false, -1),
        0,
        "PSS signature must NOT verify as PKCS#1 v1.5"
    );
    assert_eq!(
        verify(MSG, GOLDEN_PKCS1_SHA256, PUB_PEM, SHA256, true, 32),
        0,
        "PKCS#1 v1.5 signature must NOT verify as PSS"
    );
}

/// finding 4 (salt length): the salt length is threaded through both sides. A
/// signature made with salt length 32 must be rejected by a verify that demands
/// a different explicit salt length.
#[test]
fn rsa_pss_salt_length_is_honored() {
    let pss32 = sign(MSG, PRIV_PEM, SHA256, true, 32);
    assert_eq!(
        verify(MSG, &pss32, PUB_PEM, SHA256, true, 32),
        1,
        "matching salt length (32) must verify"
    );
    assert_eq!(
        verify(MSG, &pss32, PUB_PEM, SHA256, true, 48),
        0,
        "mismatched salt length (48 vs 32) must fail — proves saltLength is honoured"
    );
}

/// A negative salt length means "use the digest length" (RSA_PSS_SALTLEN_DIGEST),
/// which for SHA-256 equals an explicit 32, so the two are interchangeable.
#[test]
fn rsa_pss_default_salt_length_equals_digest_length() {
    let pss_default = sign(MSG, PRIV_PEM, SHA256, true, -1);
    assert_eq!(
        verify(MSG, &pss_default, PUB_PEM, SHA256, true, -1),
        1,
        "default salt length must round-trip"
    );
    assert_eq!(
        verify(MSG, &pss_default, PUB_PEM, SHA256, true, 32),
        1,
        "default salt length must equal an explicit digest-length salt (32 for SHA-256)"
    );
}
