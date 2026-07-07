//! Stateless `crypto.diffieHellman({ privateKey, publicKey })` end-to-end
//! tests driving the real `ibex` binary (ENG-23144).
//!
//! Before this fix the function validated its KeyObject arguments and then
//! returned `randomBytes(32)` — two peers derived "shared secrets" that never
//! matched, silently. These tests pin the fixed behavior to an external
//! oracle: `tests/fixtures/crypto/stateless_dh_oracle.json` holds fixed PEM
//! key pairs plus the shared secrets real Node (v25) derives for them, and
//! ibex must produce byte-identical secrets in BOTH directions (A priv + B
//! pub == B priv + A pub == Node's answer).
//!
//! Profile behavior: classic-DH agreement is pure BigInt math and must work
//! on every build. EC/X25519/X448 route through the OpenSSL derive bridges
//! (`__exactEcdhDeriveBits` / `__exactX25519DeriveBits`), which only exist
//! with the `openssl-crypto` feature (macOS default is the SecKey profile).
//! Without the bridge the call must throw the honest "not available in this
//! build" error — never fabricate bytes — so those cases skip on reduced
//! profiles after asserting the error is loud.
//!
//! Run with: `scripts/run-tests.sh stateless_dh` (reduced profile) and
//! `scripts/run-tests.sh --features openssl-crypto stateless_dh`.

use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

fn oracle_path() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/crypto/stateless_dh_oracle.json")
        .to_string_lossy()
        .into_owned()
}

/// Run a JS expression under `ibex -p` and return the last stdout line.
async fn eval(js: &str) -> String {
    let mut cmd = Command::new(IBEX);
    cmd.arg("-p").arg(js);
    let output = timeout(Duration::from_secs(60), cmd.output())
        .await
        .expect("ibex -p timed out")
        .expect("failed to spawn or read ibex process output");
    assert!(
        output.status.success(),
        "ibex -p should exit successfully: status={:?}, stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .lines()
        .last()
        .unwrap_or("")
        .to_string()
}

/// JS prologue: load crypto and the Node-oracle fixture.
fn prologue() -> String {
    format!(
        "var c = require('crypto'); var fs = require('fs'); \
         var f = JSON.parse(fs.readFileSync({p:?}, 'utf8'));",
        p = oracle_path()
    )
}

/// The honest no-bridge error on reduced profiles (SecKey-only macOS,
/// Windows). Tests skip — never fail — when they see it, mirroring the
/// crypto_node_builtin.rs convention.
fn is_unavailable(result: &str) -> bool {
    result.contains("not available in this build")
}

/// Classic-DH agreement is pure BigInt math: on EVERY profile ibex must
/// reproduce Node's exact shared secret in both directions, for both the
/// RFC 3526 modp14 group and a custom 512-bit group.
#[tokio::test]
async fn stateless_dh_classic_matches_node_oracle_both_directions() {
    for group in ["dh_modp14", "dh_512"] {
        let js = format!(
            "(function(){{ {prologue} \
             var e = f[{group:?}]; \
             var ab = c.diffieHellman({{ privateKey: c.createPrivateKey(e.aPriv), publicKey: c.createPublicKey(e.bPub) }}).toString('hex'); \
             var ba = c.diffieHellman({{ privateKey: c.createPrivateKey(e.bPriv), publicKey: c.createPublicKey(e.aPub) }}).toString('hex'); \
             if (ab !== e.secretHex) return 'ab mismatch: ' + ab; \
             if (ba !== e.secretHex) return 'ba mismatch: ' + ba; \
             return 'ok'; }})()",
            prologue = prologue(),
            group = group,
        );
        let result = eval(&js).await;
        assert_eq!(result, "ok", "{group} must match the Node oracle");
    }
}

/// Node pads the classic-DH shared secret to the prime length (OpenSSL
/// dh_pad): a secret whose first byte is 0x00 keeps it. The fixture entry was
/// searched out of real Node keygen until the leading byte was zero.
#[tokio::test]
async fn stateless_dh_classic_preserves_leading_zero_padding() {
    let js = format!(
        "(function(){{ {prologue} \
         var e = f.dh_512_leadingzero; \
         var s = c.diffieHellman({{ privateKey: c.createPrivateKey(e.aPriv), publicKey: c.createPublicKey(e.bPub) }}).toString('hex'); \
         return s === e.secretHex ? 'ok' : 'mismatch: ' + s; }})()",
        prologue = prologue(),
    );
    assert_eq!(eval(&js).await, "ok");
}

/// EC (P-256/P-384) and X25519/X448 agreement must be byte-identical to Node
/// in both directions on OpenSSL profiles; on reduced profiles the call must
/// throw the honest unavailable error (asserted via the skip detection).
#[tokio::test]
async fn stateless_dh_ec_and_xdh_match_node_oracle_both_directions() {
    for algo in ["x25519", "x448", "p256", "p384"] {
        let js = format!(
            "(function(){{ {prologue} \
             var e = f[{algo:?}]; \
             try {{ \
               var ab = c.diffieHellman({{ privateKey: c.createPrivateKey(e.aPriv), publicKey: c.createPublicKey(e.bPub) }}).toString('hex'); \
               var ba = c.diffieHellman({{ privateKey: c.createPrivateKey(e.bPriv), publicKey: c.createPublicKey(e.aPub) }}).toString('hex'); \
               if (ab !== e.secretHex) return 'ab mismatch: ' + ab; \
               if (ba !== e.secretHex) return 'ba mismatch: ' + ba; \
               return 'ok'; \
             }} catch (err) {{ return 'threw ' + (err.code || '') + ': ' + err.message; }} }})()",
            prologue = prologue(),
            algo = algo,
        );
        let result = eval(&js).await;
        if is_unavailable(&result) {
            eprintln!("skipping {algo}: derive bridge unavailable ({result})");
            continue;
        }
        assert_eq!(result, "ok", "{algo} must match the Node oracle");
    }
}

/// Node accepts a private KeyObject in the publicKey slot (it uses the public
/// half). Classic DH recovers y = g^x mod p in JS; EC/X25519 rely on the
/// bridge's private-material peer fallback.
#[tokio::test]
async fn stateless_dh_private_keyobject_in_public_slot_derives_same_secret() {
    for algo in ["dh_modp14", "x25519", "p256"] {
        let js = format!(
            "(function(){{ {prologue} \
             var e = f[{algo:?}]; \
             try {{ \
               var s = c.diffieHellman({{ privateKey: c.createPrivateKey(e.aPriv), publicKey: c.createPrivateKey(e.bPriv) }}).toString('hex'); \
               return s === e.secretHex ? 'ok' : 'mismatch: ' + s; \
             }} catch (err) {{ return 'threw ' + (err.code || '') + ': ' + err.message; }} }})()",
            prologue = prologue(),
            algo = algo,
        );
        let result = eval(&js).await;
        if algo != "dh_modp14" && is_unavailable(&result) {
            eprintln!("skipping {algo}: derive bridge unavailable ({result})");
            continue;
        }
        assert_eq!(result, "ok", "{algo} private-as-public must match oracle");
    }
}

/// Validation order and error codes mirror Node v25 (captured from a live
/// node run): bad options/properties, wrong KeyObject roles, mismatched key
/// types, and mismatched DH domain parameters.
#[tokio::test]
async fn stateless_dh_validation_errors_match_node_semantics() {
    let js = format!(
        "(function(){{ {prologue} \
         function code(fn) {{ try {{ fn(); return 'NO-THROW'; }} catch (e) {{ return e.code; }} }} \
         var priv = c.createPrivateKey(f.x25519.aPriv); \
         var pub = c.createPublicKey(f.x25519.bPub); \
         var out = []; \
         out.push(code(function() {{ c.diffieHellman(); }})); \
         out.push(code(function() {{ c.diffieHellman({{ privateKey: 'pem', publicKey: pub }}); }})); \
         out.push(code(function() {{ c.diffieHellman({{ privateKey: priv, publicKey: 42 }}); }})); \
         out.push(code(function() {{ c.diffieHellman({{ privateKey: c.createPublicKey(f.x25519.aPub), publicKey: pub }}); }})); \
         out.push(code(function() {{ c.diffieHellman({{ privateKey: priv, publicKey: c.createSecretKey(Buffer.alloc(16)) }}); }})); \
         out.push(code(function() {{ c.diffieHellman({{ privateKey: priv, publicKey: c.createPublicKey(f.p256.bPub) }}); }})); \
         out.push(code(function() {{ c.diffieHellman({{ privateKey: c.createPrivateKey(f.dh_512.aPriv), publicKey: c.createPublicKey(f.dh_512_othergroup_pub) }}); }})); \
         return out.join(','); }})()",
        prologue = prologue(),
    );
    let result = eval(&js).await;
    assert_eq!(
        result,
        "ERR_INVALID_ARG_TYPE,ERR_INVALID_ARG_VALUE,ERR_INVALID_ARG_VALUE,\
         ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE,ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE,\
         ERR_CRYPTO_INCOMPATIBLE_KEY,ERR_OSSL_MISMATCHING_DOMAIN_PARAMETERS",
        "error codes must match Node v25"
    );
}

/// The regression this ticket fixes: the old stub returned fresh
/// `randomBytes(32)`. On any profile the call must now either derive the
/// exact Node-oracle secret or throw loudly — it must never return bytes
/// that differ from the oracle.
#[tokio::test]
async fn stateless_dh_never_fabricates_a_secret() {
    let js = format!(
        "(function(){{ {prologue} \
         var e = f.x25519; \
         try {{ \
           var s = c.diffieHellman({{ privateKey: c.createPrivateKey(e.aPriv), publicKey: c.createPublicKey(e.bPub) }}).toString('hex'); \
           return s === e.secretHex ? 'derived-correctly' : 'FABRICATED: ' + s; \
         }} catch (err) {{ return 'threw ' + (err.code || '') + ': ' + err.message; }} }})()",
        prologue = prologue(),
    );
    let result = eval(&js).await;
    assert!(
        result == "derived-correctly" || is_unavailable(&result),
        "diffieHellman must derive the oracle secret or throw the honest \
         unavailable error, got: {result}"
    );
}
