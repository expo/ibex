//! Node crypto builtin end-to-end tests driving the real `ibex` binary
//! (ENG-23129): RSA-PSS padding/saltLength wiring on `crypto.sign`/`verify`,
//! the Sign/Verify.update() utf8 default, no-HMAC-masquerade for PEM keys,
//! Miller-Rabin-backed checkPrime, real MODP DiffieHellmanGroup math, and
//! randomInt bounds.
//!
//! Where the operation is deterministic the tests compare against golden
//! fixtures produced by Node's OpenSSL (external oracle, see
//! tests/fixtures/crypto): the PKCS#1 v1.5 signature over the UTF-8 bytes of a
//! non-ASCII message, a Node-produced RSA-PSS signature ibex must accept, and
//! the RFC 3526 modp14 prime.
//!
//! These run against the platform-native asymmetric bridge (SecKey on macOS,
//! OpenSSL with the `openssl-crypto` feature elsewhere); on profiles without
//! an asymmetric bridge the PEM-key operations must throw — never fall back
//! to an HMAC masquerading as a signature — so the tests skip when they see
//! the explicit "not available" error.
//!
//! Run with: `scripts/run-tests.sh --scope test crypto_node_builtin`.

use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

/// RFC 3526 group 14 (2048-bit MODP) prime, as dumped from Node's
/// `crypto.getDiffieHellman('modp14').getPrime('hex')`.
const MODP14_PRIME_HEX: &str = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff";

/// 256-bit prime and same-size composite (product of two 128-bit primes),
/// generated and cross-checked with Node's `crypto.checkPrimeSync` (external
/// oracle). The composite is odd, so the old low-bit-only check called it
/// prime.
const PRIME_256: &str =
    "110512616341342977629267843674713120584692940507297396484504516270300939192439";
const COMPOSITE_256: &str =
    "105586210627555387481899933998818600853359070130275686633542536689348519308411";

fn fixture_path(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/crypto")
        .join(name)
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

/// JS prologue loading the fixture RSA key pair. The private key is the
/// PKCS#1 ("BEGIN RSA PRIVATE KEY") rendering of the same key material as
/// rsa2048_priv.pem: macOS SecItemImport cannot read unencrypted PKCS#8
/// private keys, which — before ENG-23129 — silently degraded every sign()
/// with such a key into the HMAC fallback (now it throws honestly).
fn key_prologue() -> String {
    format!(
        "var c = require('crypto'); var fs = require('fs'); \
         var priv = fs.readFileSync({priv:?}, 'utf8'); \
         var pub = fs.readFileSync({pub:?}, 'utf8'); \
         var msg = new Uint8Array(fs.readFileSync({msg:?}));",
        priv = fixture_path("rsa2048_priv_pkcs1.pem"),
        pub = fixture_path("rsa2048_pub.pem"),
        msg = fixture_path("msg_highbytes.bin"),
    )
}

/// Detect the honest "no asymmetric bridge on this profile" error so tests
/// can skip rather than fail on reduced profiles.
fn is_unavailable(result: &str) -> bool {
    result.contains("not available") || result.contains("openssl-crypto")
}

/// ENG-23129 finding 1: `padding: RSA_PKCS1_PSS_PADDING` must produce a
/// genuine PSS signature, cross-rejected against PKCS#1 v1.5. A
/// padding-ignoring implementation cannot satisfy the full matrix.
#[tokio::test]
async fn sign_with_pss_padding_produces_genuine_pss() {
    let js = format!(
        "(function(){{ {prologue} \
           var pssOpts = function(k) {{ return {{ key: k, padding: c.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }}; }}; \
           try {{ \
             var pss = c.sign('sha256', msg, pssOpts(priv)); \
             var pkcs1 = c.sign('sha256', msg, priv); \
             return JSON.stringify({{ \
               pssAsPss: c.verify('sha256', msg, pssOpts(pub), pss), \
               pssAsPkcs1: c.verify('sha256', msg, pub, pss), \
               pkcs1AsPss: c.verify('sha256', msg, pssOpts(pub), pkcs1), \
               pkcs1AsPkcs1: c.verify('sha256', msg, pub, pkcs1) \
             }}); \
           }} catch (e) {{ return 'ERR:' + e.message; }} \
         }})()",
        prologue = key_prologue()
    );
    let result = eval(&js).await;
    if result.starts_with("ERR:") && is_unavailable(&result) {
        eprintln!("skipping: asymmetric crypto bridge unavailable ({result})");
        return;
    }
    assert_eq!(
        result, r#"{"pssAsPss":true,"pssAsPkcs1":false,"pkcs1AsPss":false,"pkcs1AsPkcs1":true}"#,
        "PSS/PKCS#1 cross-verification matrix must discriminate the padding"
    );
}

/// ENG-23129 finding 1 (external oracle direction): a PSS signature produced
/// by Node's OpenSSL must verify with PSS options and be rejected as
/// PKCS#1 v1.5.
#[tokio::test]
async fn verify_accepts_node_produced_pss_signature() {
    let js = format!(
        "(function(){{ {prologue} \
           var sig = new Uint8Array(fs.readFileSync({sig:?})); \
           var pssOpts = {{ key: pub, padding: c.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }}; \
           try {{ \
             return JSON.stringify({{ \
               asPss: c.verify('sha256', msg, pssOpts, sig), \
               asPkcs1: c.verify('sha256', msg, pub, sig) \
             }}); \
           }} catch (e) {{ return 'ERR:' + e.message; }} \
         }})()",
        prologue = key_prologue(),
        sig = fixture_path("sig_pss_sha256_salt32.bin"),
    );
    let result = eval(&js).await;
    if result.starts_with("ERR:") && is_unavailable(&result) {
        eprintln!("skipping: asymmetric crypto bridge unavailable ({result})");
        return;
    }
    assert_eq!(
        result, r#"{"asPss":true,"asPkcs1":false}"#,
        "Node-produced PSS signature must verify as PSS and be rejected as PKCS#1 v1.5"
    );
}

/// ENG-23129 finding 4: `createSign().update(string)` must default to utf8.
/// The deterministic PKCS#1 v1.5 signature over a non-ASCII message
/// (including a code point > U+00FF) must equal the golden signature Node's
/// OpenSSL produced over the message's UTF-8 bytes.
#[tokio::test]
async fn sign_update_defaults_to_utf8_matching_node_oracle() {
    let golden = std::fs::read(fixture_path("sig_pkcs1_sha256_utf8msg.bin"))
        .expect("golden utf8 signature fixture");
    let golden_hex = golden
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let js = format!(
        "(function(){{ {prologue} \
           try {{ \
             return c.createSign('RSA-SHA256')\
               .update('h\\u00e9llo \\u2014 \\u00fcn\\u00efc\\u00f6d\\u00e9 \\u2603')\
               .sign(priv, 'hex'); \
           }} catch (e) {{ return 'ERR:' + e.message; }} \
         }})()",
        prologue = key_prologue()
    );
    let result = eval(&js).await;
    if result.starts_with("ERR:") && is_unavailable(&result) {
        eprintln!("skipping: asymmetric crypto bridge unavailable ({result})");
        return;
    }
    assert_eq!(
        result, golden_hex,
        "update() must hash the UTF-8 bytes of the message (Node oracle)"
    );
}

/// ENG-23129 finding 3: a PEM key that the native signer rejects must throw —
/// the old path swallowed the error and returned a 32-byte HMAC keyed on the
/// PEM text, masquerading as a signature. Same for verify(): key errors must
/// surface, not read as "signature invalid".
#[tokio::test]
async fn sign_and_verify_with_bad_pem_key_throw_instead_of_hmac() {
    let js = "(function(){ var c = require('crypto'); \
        var bad = '-----BEGIN PRIVATE KEY-----\\nAAAA\\n-----END PRIVATE KEY-----\\n'; \
        var badPub = '-----BEGIN PUBLIC KEY-----\\nAAAA\\n-----END PUBLIC KEY-----\\n'; \
        var signOutcome; \
        try { \
          var s = c.sign('sha256', new Uint8Array([1,2,3]), bad); \
          signOutcome = 'signed:' + s.length; \
        } catch (e) { signOutcome = 'threw'; } \
        var verifyOutcome; \
        try { \
          c.verify('sha256', new Uint8Array([1,2,3]), badPub, new Uint8Array(256)); \
          verifyOutcome = 'returned'; \
        } catch (e) { verifyOutcome = 'threw'; } \
        return JSON.stringify({ sign: signOutcome, verify: verifyOutcome }); })()";
    let result = eval(js).await;
    assert_eq!(
        result, r#"{"sign":"threw","verify":"threw"}"#,
        "invalid PEM keys must raise, not silently produce/deny an HMAC pseudo-signature"
    );
}

/// ENG-23129 finding 2: an unsupported hash must throw instead of silently
/// signing SHA-256; sha224 must either be honestly unsupported (SecKey) or
/// produce a real SHA-224 signature (OpenSSL) — never a SHA-256 one.
#[tokio::test]
async fn unknown_or_unsupported_hash_never_silently_signs_sha256() {
    let js = format!(
        "(function(){{ {prologue} \
           var unknown; \
           try {{ c.sign('whirlpool', msg, priv); unknown = 'signed'; }} \
           catch (e) {{ unknown = 'threw'; }} \
           var sha224; \
           try {{ \
             var s = c.sign('sha224', msg, priv); \
             sha224 = JSON.stringify({{ as224: c.verify('sha224', msg, pub, s), as256: c.verify('sha256', msg, pub, s) }}); \
           }} catch (e) {{ sha224 = 'threw'; }} \
           return JSON.stringify({{ unknown: unknown, sha224: sha224 }}); \
         }})()",
        prologue = key_prologue()
    );
    let result = eval(&js).await;
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("JSON result");
    assert_eq!(
        parsed["unknown"], "threw",
        "an unknown hash name must throw, not sign SHA-256: {result}"
    );
    let sha224 = parsed["sha224"].as_str().expect("sha224 outcome");
    assert!(
        sha224 == "threw" || sha224 == r#"{"as224":true,"as256":false}"#,
        "sha224 must throw (reduced profile) or genuinely sign SHA-224: {result}"
    );
}

/// ENG-23129 finding 5: checkPrime must reject large odd composites (the old
/// code only tested the low bit past 4 bytes). Oracle values cross-checked
/// with Node's checkPrimeSync.
#[tokio::test]
async fn check_prime_rejects_large_odd_composites() {
    let js = format!(
        "(function(){{ var c = require('crypto'); \
           var prime = BigInt({PRIME_256:?}); \
           var composite = BigInt({COMPOSITE_256:?}); \
           var h = composite.toString(16); if (h.length % 2) h = '0' + h; \
           var bytes = new Uint8Array(h.length / 2); \
           for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.substr(i * 2, 2), 16); \
           return JSON.stringify({{ \
             prime: c.checkPrimeSync(prime), \
             composite: c.checkPrimeSync(composite), \
             compositeBytes: c.checkPrimeSync(bytes), \
             smallPrime: c.checkPrimeSync(65537n), \
             smallOddComposite: c.checkPrimeSync(65539n * 65543n) \
           }}); }})()"
    );
    let result = eval(&js).await;
    assert_eq!(
        result,
        r#"{"prime":true,"composite":false,"compositeBytes":false,"smallPrime":true,"smallOddComposite":false}"#,
        "checkPrime must run a real primality test on large candidates"
    );
}

/// ENG-23129 finding 6: two DiffieHellmanGroup peers on a well-known MODP
/// group must derive the SAME shared secret (they were independent
/// randomBytes() before), and the group prime must be the RFC 3526 value
/// (Node oracle) — not random bytes.
#[tokio::test]
async fn diffie_hellman_group_agreement_and_rfc3526_prime() {
    let js = "(function(){ var c = require('crypto'); \
        var a = c.getDiffieHellman('modp1'); \
        var b = c.getDiffieHellman('modp1'); \
        a.generateKeys(); b.generateKeys(); \
        var s1 = a.computeSecret(b.getPublicKey()).toString('hex'); \
        var s2 = b.computeSecret(a.getPublicKey()).toString('hex'); \
        var unknown; \
        try { c.getDiffieHellman('modp3'); unknown = 'no-throw'; } \
        catch (e) { unknown = e.code || 'threw'; } \
        return JSON.stringify({ \
          agree: s1.length > 0 && s1 === s2, \
          p14: c.getDiffieHellman('modp14').getPrime('hex'), \
          gen: c.getDiffieHellman('modp14').getGenerator('hex'), \
          unknown: unknown \
        }); })()";
    let result = eval(js).await;
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("JSON result");
    assert_eq!(
        parsed["agree"], true,
        "both peers must derive the same shared secret: {result}"
    );
    assert_eq!(
        parsed["p14"].as_str().unwrap_or(""),
        MODP14_PRIME_HEX,
        "modp14 prime must be the RFC 3526 value"
    );
    assert_eq!(parsed["gen"], "02", "modp generator must be 2");
    assert_eq!(
        parsed["unknown"], "ERR_CRYPTO_UNKNOWN_DH_GROUP",
        "unknown group names must be rejected: {result}"
    );
}

/// ENG-23301: the ECDH class must never fabricate key material. On profiles
/// with the native EC bridge two peers must agree on the shared secret; on
/// reduced profiles generateKeys/computeSecret must throw an honest
/// ERR_CRYPTO_OPERATION_FAILED (they returned fresh randomBytes before).
#[tokio::test]
async fn ecdh_class_agrees_or_throws_honestly() {
    let js = "(function(){ var c = require('crypto'); \
        try { \
          var a = c.createECDH('prime256v1'); \
          var b = c.createECDH('prime256v1'); \
          a.generateKeys(); b.generateKeys(); \
          var s1 = a.computeSecret(b.getPublicKey()).toString('hex'); \
          var s2 = b.computeSecret(a.getPublicKey()).toString('hex'); \
          return JSON.stringify({ agree: s1.length > 0 && s1 === s2 }); \
        } catch (e) { return 'ERR:' + (e.code || '') + ':' + e.message; } })()";
    let result = eval(js).await;
    if let Some(rest) = result.strip_prefix("ERR:") {
        assert!(
            rest.starts_with("ERR_CRYPTO_OPERATION_FAILED:") && rest.contains("not available"),
            "reduced-profile ECDH must fail with an honest ERR_CRYPTO_OPERATION_FAILED, got: {result}"
        );
        eprintln!("skipping agreement check: no native ECDH bridge ({result})");
        return;
    }
    assert_eq!(
        result, r#"{"agree":true}"#,
        "two ECDH peers must derive the same shared secret (random-bytes fallback would disagree): {result}"
    );
}

/// ENG-23301: classic-DH peer public values outside [2, p-2] must be rejected
/// with ERR_CRYPTO_INVALID_KEYLEN (Node oracle: "Supplied key is too
/// small"/"too large"); in-range values keep working.
#[tokio::test]
async fn dh_compute_secret_rejects_out_of_range_public_keys() {
    let js = "(function(){ var c = require('crypto'); \
        var a = c.getDiffieHellman('modp1'); a.generateKeys(); \
        var b = c.getDiffieHellman('modp1'); b.generateKeys(); \
        var p = a.getPrime(); \
        var pMinus1 = Buffer.from(p); pMinus1[pMinus1.length - 1] -= 1; \
        function code(k) { try { a.computeSecret(k); return 'no-throw'; } catch (e) { return e.code + '|' + e.message; } } \
        return JSON.stringify({ \
          zero: code(Buffer.from([0])), \
          one: code(Buffer.from([1])), \
          p: code(p), \
          pMinus1: code(pMinus1), \
          tooBig: code(Buffer.concat([Buffer.from([5]), p])), \
          valid: a.computeSecret(b.getPublicKey()).length > 0 \
        }); })()";
    let result = eval(js).await;
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("JSON result");
    let small = "ERR_CRYPTO_INVALID_KEYLEN|Supplied key is too small";
    let large = "ERR_CRYPTO_INVALID_KEYLEN|Supplied key is too large";
    assert_eq!(parsed["zero"], small, "y=0 must be rejected: {result}");
    assert_eq!(parsed["one"], small, "y=1 must be rejected: {result}");
    assert_eq!(parsed["p"], large, "y=p must be rejected: {result}");
    assert_eq!(parsed["pMinus1"], large, "y=p-1 must be rejected: {result}");
    assert_eq!(parsed["tooBig"], large, "y>p must be rejected: {result}");
    assert_eq!(
        parsed["valid"], true,
        "in-range peer keys must keep working: {result}"
    );
}

/// ENG-23465 finding 1: bare string inputs to pbkdf2/scrypt/hkdf/
/// createSecretKey/cipher.update default to utf8 like Node — not one byte per
/// UTF-16 code unit. Goldens produced by Node v25 (external oracle).
#[tokio::test]
async fn kdf_and_cipher_string_inputs_default_to_utf8() {
    let js = "(function(){ var c = require('crypto'); \
        var out = {}; \
        out.pbkdf2 = c.pbkdf2Sync('p\\u00e4ssword','salt',1,16,'sha256').toString('hex'); \
        out.scrypt = c.scryptSync('p\\u00e4ss','salt',16).toString('hex'); \
        out.hkdf = Buffer.from(c.hkdfSync('sha256','p\\u00e4ss','salt','inf\\u00f6',16)).toString('hex'); \
        out.secretKeyHmac = c.createHmac('sha256', c.createSecretKey('k\\u00e9y','utf8')).update('x').digest('hex'); \
        var ci = c.createCipheriv('aes-128-cbc', Buffer.alloc(16,1), Buffer.alloc(16,2)); \
        out.cipher = ci.update('caf\\u00e9','utf8','hex') + ci.final('hex'); \
        return JSON.stringify(out); })()";
    let result = eval(js).await;
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("JSON result");
    assert_eq!(
        parsed["pbkdf2"], "f6305ae2b0e9cd43a1c04f7af100cbed",
        "pbkdf2 utf8 golden: {result}"
    );
    assert_eq!(
        parsed["scrypt"], "afa3397a7eda04ece515b3c965505918",
        "scrypt utf8 golden: {result}"
    );
    assert_eq!(
        parsed["hkdf"], "1df47305515732fb2567394402e29dbb",
        "hkdf utf8 golden: {result}"
    );
    assert_eq!(
        parsed["secretKeyHmac"], "fc397a5e543c0c71e75934f428fc7478ae5fe0495bb2a53313b88f3410cdfa09",
        "createSecretKey utf8 golden: {result}"
    );
    assert_eq!(
        parsed["cipher"], "fc8f3a5026024f880c5713abebd34526",
        "cipher.update utf8 golden: {result}"
    );
}

/// ENG-23465 findings 7+8: second digest() throws ERR_CRYPTO_HASH_FINALIZED
/// (never a cached value), update(number) throws ERR_INVALID_ARG_TYPE, and
/// the Transform lifecycle completes — 'finish' fires so stream.pipeline on a
/// hash resolves instead of wedging.
#[tokio::test]
async fn hash_finalization_and_stream_lifecycle() {
    let js = "(function(){ var c = require('crypto'); \
        var out = {}; \
        var h = c.createHash('sha256'); h.digest(); \
        try { h.digest(); out.twice = 'no-throw'; } catch (e) { out.twice = e.code; } \
        try { c.createHash('sha256').update(123); out.num = 'no-throw'; } catch (e) { out.num = e.code; } \
        try { c.createHmac('sha256','k').update(null); out.hmacNull = 'no-throw'; } catch (e) { out.hmacNull = e.code; } \
        return JSON.stringify(out); })()";
    let result = eval(js).await;
    assert_eq!(
        result,
        r#"{"twice":"ERR_CRYPTO_HASH_FINALIZED","num":"ERR_INVALID_ARG_TYPE","hmacNull":"ERR_INVALID_ARG_TYPE"}"#,
        "hash finalization contract: {result}"
    );

    // pipeline must complete (it hung before the Transform.end delegation).
    let script = "var c = require('crypto'); var stream = require('stream'); \
        var h = c.createHash('sha256'); \
        var timer = setTimeout(function(){ console.log('HUNG'); process.exit(1); }, 5000); \
        stream.pipeline(stream.Readable.from(['x']), h, function(err) { \
          clearTimeout(timer); \
          console.log(err ? 'ERR' : 'pipeline:' + h.read().toString('hex').slice(0, 12)); \
        });";
    let mut cmd = Command::new(IBEX);
    cmd.arg("-e").arg(script);
    let output = timeout(Duration::from_secs(60), cmd.output())
        .await
        .expect("ibex -e timed out")
        .expect("failed to run ibex");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("pipeline:2d711642b726"),
        "pipeline over createHash must resolve with the digest (Node oracle 2d711642b726...): status={:?} stdout={stdout}",
        output.status.code()
    );
}

/// ENG-23465 findings 2, 4, 5, 9, 10: ECDH honors the requested curve (P-384
/// public key is 97 bytes, not P-256's 65), generatePrimeSync returns real
/// probable primes (bigint and exact bit length), createDiffieHellman decodes
/// a hex prime, generateKeyPairSync 'der' returns a Buffer, and cipher
/// construction validates key/IV lengths with Node's error codes.
#[tokio::test]
async fn ecdh_curves_primes_dh_encoding_and_cipher_validation() {
    let js = "(function(){ var c = require('crypto'); \
        var out = {}; \
        try { out.ecdh384 = c.createECDH('secp384r1').generateKeys().length; } \
        catch (e) { out.ecdh384 = 'ERR:' + e.code; } \
        var p = c.generatePrimeSync(64, { bigint: true }); \
        out.primeIsPrime = c.checkPrimeSync(p); \
        out.primeBits = p.toString(2).length; \
        var ab = c.generatePrimeSync(12); \
        out.primeAb = (ab instanceof ArrayBuffer) && ab.byteLength === 2; \
        out.dhHexPrime = c.createDiffieHellman('bb', 'hex').getPrime().toString('hex'); \
        try { \
          var kp = c.generateKeyPairSync('ec', { namedCurve: 'P-256', publicKeyEncoding: { type: 'spki', format: 'der' } }); \
          out.der = Buffer.isBuffer(kp.publicKey) ? 'buffer' : typeof kp.publicKey; \
        } catch (e) { out.der = 'ERR:' + (e.code || e.message); } \
        try { c.createDecipheriv('aes-128-cbc', Buffer.alloc(24), Buffer.alloc(16)); out.badKey = 'no-throw'; } \
        catch (e) { out.badKey = e.code; } \
        try { c.createCipheriv('aes-128-ctr', Buffer.alloc(16), Buffer.alloc(3)); out.badIv = 'no-throw'; } \
        catch (e) { out.badIv = e.code; } \
        return JSON.stringify(out); })()";
    let result = eval(js).await;
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("JSON result");
    // On reduced profiles EC keygen may throw honestly; both are acceptable,
    // silently generating a P-256 key (length 65) is not.
    let ecdh = &parsed["ecdh384"];
    assert!(
        ecdh == 97
            || ecdh
                .as_str()
                .map(|s| s.starts_with("ERR:"))
                .unwrap_or(false),
        "secp384r1 keys must be P-384-sized or throw honestly, never P-256: {result}"
    );
    assert_eq!(
        parsed["primeIsPrime"], true,
        "generatePrimeSync must return a real prime: {result}"
    );
    assert_eq!(
        parsed["primeBits"], 64,
        "generatePrimeSync must honor the exact bit length: {result}"
    );
    assert_eq!(
        parsed["primeAb"], true,
        "non-bigint generatePrimeSync returns an ArrayBuffer: {result}"
    );
    assert_eq!(
        parsed["dhHexPrime"], "bb",
        "createDiffieHellman must decode the prime encoding: {result}"
    );
    assert_eq!(
        parsed["der"], "buffer",
        "der-format key encoding must return a Buffer: {result}"
    );
    assert_eq!(
        parsed["badKey"], "ERR_CRYPTO_INVALID_KEYLEN",
        "Decipher must validate key length: {result}"
    );
    assert_eq!(
        parsed["badIv"], "ERR_CRYPTO_INVALID_IV",
        "CTR must validate IV length: {result}"
    );
}

/// ENG-23465 finding 3: verify.verify(key, signature, signatureEncoding)
/// decodes hex/base64 signature strings (they always verified false before).
#[tokio::test]
async fn verify_honors_signature_encoding() {
    let js = format!(
        "(function(){{ {prologue} \
           try {{ \
             var s = c.createSign('sha256'); s.update(msg); \
             var sig = s.sign(priv); \
             var mk = function() {{ var v = c.createVerify('sha256'); v.update(msg); return v; }}; \
             return JSON.stringify({{ \
               buf: mk().verify(pub, sig), \
               hex: mk().verify(pub, sig.toString('hex'), 'hex'), \
               b64: mk().verify(pub, sig.toString('base64'), 'base64') \
             }}); \
           }} catch (e) {{ return 'ERR:' + e.message; }} \
         }})()",
        prologue = key_prologue()
    );
    let result = eval(&js).await;
    if result.starts_with("ERR:") && is_unavailable(&result) {
        eprintln!("skipping: asymmetric crypto bridge unavailable ({result})");
        return;
    }
    assert_eq!(
        result, r#"{"buf":true,"hex":true,"b64":true}"#,
        "string signatures with signatureEncoding must verify: {result}"
    );
}

/// ENG-23456 finding 1: require('crypto') must not rewrite process.versions.
/// The LLP 0012 identity authority ships only truthful ambient keys
/// (ibex/node/hermes); the old crypto.js load-time block re-installed the
/// v8/uv/openssl/modules masquerade and clobbered versions.ibex.
#[tokio::test]
async fn requiring_crypto_does_not_masquerade_process_versions() {
    let js = "(function(){ var before = JSON.stringify(process.versions); \
        require('crypto'); \
        return JSON.stringify({ \
          same: before === JSON.stringify(process.versions), \
          ibex: typeof process.versions.ibex, \
          v8: typeof process.versions.v8, \
          uv: typeof process.versions.uv, \
          openssl: typeof process.versions.openssl, \
          modules: typeof process.versions.modules, \
          exact: typeof process.versions.exact \
        }); })()";
    let result = eval(js).await;
    assert_eq!(
        result,
        r#"{"same":true,"ibex":"string","v8":"undefined","uv":"undefined","openssl":"undefined","modules":"undefined","exact":"undefined"}"#,
        "require('crypto') must leave the truthful identity untouched: {result}"
    );
}

/// ENG-23129 finding 7 (bounds only — the bias fix is rejection sampling,
/// reviewed at the source): every draw stays in [min, max) and small ranges
/// are fully covered.
#[tokio::test]
async fn random_int_stays_in_bounds_and_covers_small_range() {
    let js = "(function(){ var c = require('crypto'); \
        var seen = {}; var inBounds = true; \
        for (var i = 0; i < 2000; i++) { \
          var v = c.randomInt(3); \
          if (v < 0 || v > 2 || v !== Math.floor(v)) inBounds = false; \
          seen[v] = true; \
        } \
        var negOk = true; \
        for (var j = 0; j < 200; j++) { \
          var w = c.randomInt(-5, -2); \
          if (w < -5 || w > -3) negOk = false; \
        } \
        return JSON.stringify({ inBounds: inBounds, covered: !!(seen[0] && seen[1] && seen[2]), negOk: negOk }); })()";
    let result = eval(js).await;
    assert_eq!(
        result, r#"{"inBounds":true,"covered":true,"negOk":true}"#,
        "randomInt must stay in [min, max) and cover the range"
    );
}

/// ENG-23467 finding 1: `subtle.decrypt({name:'AES-CBC', iv})` with a short
/// IV must reject with the IV-length error instead of forwarding the buffer
/// to the platform cipher. On macOS the Apple CommonCrypto decrypt branch
/// read a full 16-byte AES block from the IV pointer (out-of-bounds read for
/// an 8-byte IV) while Linux/OpenSSL threw cleanly; the check now lives in
/// common native code, matching the encrypt path. A correct-IV round-trip
/// guards against over-rejection.
#[tokio::test]
async fn subtle_aes_cbc_decrypt_rejects_short_iv() {
    let js = "(async function(){ \
        if (!globalThis.crypto || !crypto.subtle || !crypto.subtle.importKey) return 'unavailable'; \
        var key = await crypto.subtle.importKey('raw', new Uint8Array(16), { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']); \
        var plain = new Uint8Array([1,2,3,4,5]); \
        var ct = await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, key, plain); \
        var shortIv; \
        try { \
          await crypto.subtle.decrypt({ name: 'AES-CBC', iv: new Uint8Array(8) }, key, ct); \
          shortIv = 'no-throw'; \
        } catch (e) { shortIv = String(e.message || e); } \
        var roundtrip = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, key, ct)); \
        return JSON.stringify({ shortIv: shortIv, roundtrip: Array.from(roundtrip) }); })()";
    let result = eval(js).await;
    if result == "unavailable" {
        eprintln!("skipping: WebCrypto subtle not available on this profile");
        return;
    }
    let parsed: serde_json::Value = serde_json::from_str(&result).expect("valid JSON result");
    let short_iv = parsed["shortIv"].as_str().unwrap_or("");
    assert!(
        short_iv.contains("16 bytes"),
        "short IV must be rejected with the IV-length error, got: {result}"
    );
    assert_eq!(
        parsed["roundtrip"],
        serde_json::json!([1, 2, 3, 4, 5]),
        "correct 16-byte IV must still round-trip: {result}"
    );
}
