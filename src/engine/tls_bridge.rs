//! Native TLS bridge engine for the `tls` builtin (ENG-23492).
//!
//! One sans-IO rustls `ClientConnection` per bridged `tls.connect` socket,
//! exposed to the C++ JSI shims (`src/engine/hermes_runtime_tls.cc`) through
//! the `ibex_tls_*` extern "C" surface. The JS side owns ALL I/O: it shovels
//! ciphertext between the existing `net.Socket` and this engine, and plaintext
//! between the engine and the `TLSSocket` wrapper. The engine therefore spawns
//! no threads and installs no static destructors — the exit()-deadlock class
//! that byte-value static pools cause (ENG-23471/ENG-23498) cannot occur here.
//! @ref LLP 0004#the-tls-builtin — sans-IO bridge design, rejected alternatives
//!
//! Trust evaluation deliberately lives HERE, not in tls.js: the JS
//! `_validatePeerAuthorization` is a fingerprint-list comparator that cannot
//! verify signatures. A recording verifier wraps rustls's WebPKI verifier so
//! the handshake always completes and the real verdict is reported to JS,
//! which maps it onto Node's OpenSSL-style codes (`rejectUnauthorized:false`
//! semantics, oracle-pinned against Node v25.9.0). Hostname/identity checking
//! stays in JS (`checkServerIdentity` is user-overridable in Node).
//! @ref LLP 0004#the-tls-builtin — trust-evaluation split native/JS

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError,
    RootCertStore, SignatureScheme,
};
use rustls_pki_types::pem::PemObject;

/// Outcome of the (recorded, non-aborting) server certificate verification.
#[derive(Clone, Debug, Default)]
struct VerifyOutcome {
    /// The verifier ran (a certificate was presented).
    checked: bool,
    /// Chain is trusted (signatures + validity window + issuer chain to a
    /// root). `NotValidForName` counts as chain-ok: webpki verifies the path
    /// before the name, and Node checks hostnames separately in JS.
    chain_ok: bool,
    /// Coarse native classification; the JS side refines `UNKNOWN_ISSUER`
    /// into Node's DEPTH_ZERO_SELF_SIGNED_CERT / SELF_SIGNED_CERT_IN_CHAIN /
    /// UNABLE_TO_VERIFY_LEAF_SIGNATURE using the presented chain shape.
    code: Option<String>,
    reason: Option<String>,
}

struct Engine {
    conn: ClientConnection,
    verify: Arc<Mutex<VerifyOutcome>>,
    /// Fatal TLS error from `process_new_packets` (alert sent/received,
    /// garbage record, ...). Once set the connection is unusable; JS drains
    /// any pending alert bytes via `read_tls` and destroys the socket.
    error: Option<String>,
    /// Node-shaped error code accompanying `error` (oracle: a plaintext peer
    /// yields ERR_SSL_WRONG_VERSION_NUMBER in Node v25.9.0).
    error_code: Option<String>,
}

struct OwnedEngine {
    /// Unforgeable identity of the Hermes runtime that created this engine.
    /// Engine ids cross the JS/native boundary as numbers, so principal ids
    /// alone are not an ownership boundary: two runtimes can assign the same
    /// principal number. The runtime nonce is checked before every lookup.
    runtime_nonce: u64,
    /// Principal that minted the numeric handle. Permissive policy does not
    /// make native handles ambient across package compartments.
    owner: u64,
    // Engine operations can perform certificate parsing and rustls record
    // processing. Keep that work off the process-global registry mutex so an
    // unrelated runtime's TLS connection cannot serialize behind it.
    engine: Arc<Mutex<Engine>>,
}

fn engines() -> &'static Mutex<HashMap<u64, OwnedEngine>> {
    // Rust statics are never destroyed, so this is an immortal singleton by
    // construction (no C++-style static-destructor teardown to deadlock on).
    static ENGINES: OnceLock<Mutex<HashMap<u64, OwnedEngine>>> = OnceLock::new();
    ENGINES.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const MAX_JS_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

unsafe extern "C" {
    fn ex_hermes_current_runtime_nonce() -> u64;
    fn ex_hermes_current_principal_id() -> u64;
}

fn current_runtime_nonce() -> u64 {
    // SAFETY: this function reads the runtime-thread's current security
    // context and has no pointer arguments or lifetime requirements.
    unsafe { ex_hermes_current_runtime_nonce() }
}

fn current_principal_id() -> u64 {
    // SAFETY: like the nonce accessor, this reads runtime-thread-local
    // security context and has no pointer/lifetime preconditions.
    unsafe { ex_hermes_current_principal_id() }
}

fn allocate_engine_id(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            if next == 0 || next > MAX_JS_SAFE_INTEGER {
                None
            } else {
                next.checked_add(1)
            }
        })
        .ok()
}

thread_local! {
    // Construction errors are consumed synchronously by the C++ bridge on
    // the same runtime thread. A process-global slot let one runtime steal or
    // overwrite another runtime's error during concurrent construction.
    static LAST_ERROR: RefCell<Option<(u64, u64, String)>> = const { RefCell::new(None) };
}

fn set_last_error(message: String) {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some((current_runtime_nonce(), current_principal_id(), message))
    });
}

/// A `ServerCertVerifier` that runs the real WebPKI verification, records the
/// verdict, and then reports success so the handshake always completes. This
/// is what lets `rejectUnauthorized:false` observe `authorized:false` plus the
/// real error code over a *completed* connection, matching Node.
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    outcome: Arc<Mutex<VerifyOutcome>>,
}

fn default_crypto_provider() -> &'static Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
}

fn default_root_store() -> &'static Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Arc::new(roots)
    })
}

fn default_server_verifier() -> &'static Arc<WebPkiServerVerifier> {
    static VERIFIER: OnceLock<Arc<WebPkiServerVerifier>> = OnceLock::new();
    VERIFIER.get_or_init(|| {
        WebPkiServerVerifier::builder_with_provider(
            default_root_store().clone(),
            default_crypto_provider().clone(),
        )
        .build()
        .expect("the compiled webpki root store must build a verifier")
    })
}

fn classify_verify_error(err: &TlsError) -> (bool, String, String) {
    // (chain_ok, code, reason)
    match err {
        TlsError::InvalidCertificate(cert_err) => match cert_err {
            CertificateError::Expired => (
                false,
                "CERT_HAS_EXPIRED".into(),
                "certificate has expired".into(),
            ),
            CertificateError::ExpiredContext { .. } => (
                false,
                "CERT_HAS_EXPIRED".into(),
                "certificate has expired".into(),
            ),
            CertificateError::NotValidYet => (
                false,
                "CERT_NOT_YET_VALID".into(),
                "certificate is not yet valid".into(),
            ),
            CertificateError::NotValidYetContext { .. } => (
                false,
                "CERT_NOT_YET_VALID".into(),
                "certificate is not yet valid".into(),
            ),
            CertificateError::UnknownIssuer => (
                false,
                "UNKNOWN_ISSUER".into(),
                "unable to verify certificate issuer".into(),
            ),
            CertificateError::Revoked => {
                (false, "CERT_REVOKED".into(), "certificate revoked".into())
            }
            CertificateError::BadSignature => (
                false,
                "CERT_SIGNATURE_FAILURE".into(),
                "certificate signature failure".into(),
            ),
            CertificateError::InvalidPurpose => (
                false,
                "INVALID_PURPOSE".into(),
                "unsupported certificate purpose".into(),
            ),
            // webpki validates the path before the server name, so a name
            // mismatch means the chain itself was trusted. Node performs the
            // hostname check in JS (checkServerIdentity); report chain-ok and
            // let tls.js produce ERR_TLS_CERT_ALTNAME_INVALID Node-shaped.
            CertificateError::NotValidForName => (
                true,
                "HOSTNAME_MISMATCH".into(),
                "certificate is not valid for the server name".into(),
            ),
            CertificateError::NotValidForNameContext { .. } => (
                true,
                "HOSTNAME_MISMATCH".into(),
                "certificate is not valid for the server name".into(),
            ),
            other => (
                false,
                "UNABLE_TO_VERIFY_CERT".into(),
                format!("certificate verification failed: {other:?}"),
            ),
        },
        other => (
            false,
            "UNABLE_TO_VERIFY_CERT".into(),
            format!("certificate verification failed: {other}"),
        ),
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let mut outcome = self.outcome.lock().unwrap();
        outcome.checked = true;
        match result {
            Ok(_) => {
                outcome.chain_ok = true;
                outcome.code = None;
                outcome.reason = None;
            }
            Err(err) => {
                let (chain_ok, code, reason) = classify_verify_error(&err);
                outcome.chain_ok = chain_ok;
                outcome.code = Some(code);
                outcome.reason = Some(reason);
            }
        }
        // Never abort the handshake here: JS enforces rejectUnauthorized with
        // the recorded verdict (Node completes verification observably even
        // when it will refuse the connection).
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(serde::Deserialize)]
struct BridgeConfig {
    /// SNI name; only sent when the caller supplied `servername` (measured
    /// Node v25.9.0: bare `tls.connect({host})` sends NO SNI — example.com
    /// rejects such handshakes with alert 40, and badssl serves its fallback
    /// cert; ibex https.js sets servername explicitly).
    servername: Option<String>,
    /// Destination host; used as the verification name when no servername is
    /// given (Node verifies against `servername || host` in JS; the native
    /// record for the name check is advisory only).
    host: Option<String>,
    #[serde(default)]
    alpn: Vec<String>,
    /// Concatenated PEM certificates replacing the bundled webpki roots
    /// (Node `ca` option semantics: replaces, not extends).
    ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
    passphrase: Option<String>,
    #[serde(default, rename = "hasPfx")]
    has_pfx: bool,
    #[serde(default, rename = "hasSession")]
    has_session: bool,
    #[serde(default, rename = "cipherSuites")]
    cipher_suites: Vec<String>,
    #[serde(rename = "minVersion")]
    min_version: Option<String>,
    #[serde(rename = "maxVersion")]
    max_version: Option<String>,
}

fn build_engine(config_json: &str) -> Result<Engine, String> {
    let config: BridgeConfig =
        serde_json::from_str(config_json).map_err(|e| format!("invalid tls bridge config: {e}"))?;

    if config.has_pfx {
        return Err("pfx client identities are not supported by the rustls bridge; provide cert and key PEM options".into());
    }
    if config.has_session {
        return Err("TLS session resumption input is not supported by the rustls bridge".into());
    }
    if config.passphrase.is_some() {
        return Err("encrypted client private keys are not supported by the rustls bridge".into());
    }

    let provider = if config.cipher_suites.is_empty() {
        default_crypto_provider().clone()
    } else {
        let mut provider_value = default_crypto_provider().as_ref().clone();
        provider_value.cipher_suites.retain(|suite| {
            let (openssl, standard) = cipher_names(suite.suite());
            config.cipher_suites.iter().any(|requested| {
                openssl
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(requested))
                    || standard
                        .as_deref()
                        .is_some_and(|name| name.eq_ignore_ascii_case(requested))
            })
        });
        if provider_value.cipher_suites.is_empty() {
            return Err(format!(
                "none of the requested cipher suites are supported by the rustls bridge: {:?}",
                config.cipher_suites
            ));
        }
        Arc::new(provider_value)
    };

    let custom_roots = if let Some(ca_pem) = config.ca.as_deref() {
        let mut roots = RootCertStore::empty();
        let mut added = 0usize;
        for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
            let cert = cert.map_err(|e| format!("invalid certificate in ca option: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("invalid certificate in ca option: {e}"))?;
            added += 1;
        }
        if added == 0 {
            return Err("ca option contained no certificates".into());
        }
        Some(Arc::new(roots))
    } else {
        None
    };

    let outcome = Arc::new(Mutex::new(VerifyOutcome::default()));
    let webpki_verifier = if let Some(roots) = custom_roots {
        WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
            .build()
            .map_err(|e| format!("failed to build certificate verifier: {e}"))?
    } else if config.cipher_suites.is_empty() {
        default_server_verifier().clone()
    } else {
        WebPkiServerVerifier::builder_with_provider(default_root_store().clone(), provider.clone())
            .build()
            .map_err(|e| format!("failed to build certificate verifier: {e}"))?
    };
    let verifier = Arc::new(RecordingVerifier {
        inner: webpki_verifier,
        outcome: outcome.clone(),
    });

    // Protocol versions: rustls supports TLS 1.2/1.3. Node's defaults are
    // minVersion TLSv1.2 / maxVersion TLSv1.3; lower requested minimums clamp
    // to TLS 1.2 (the connection still negotiates >= 1.2, which satisfies a
    // lower minimum).
    if matches!(config.max_version.as_deref(), Some("TLSv1" | "TLSv1.1")) {
        return Err(format!(
            "unsupported maxVersion {:?}: rustls supports TLSv1.2 and TLSv1.3",
            config.max_version
        ));
    }
    if matches!(config.min_version.as_deref(), Some(v) if !matches!(v, "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3"))
        || matches!(config.max_version.as_deref(), Some(v) if !matches!(v, "TLSv1.2" | "TLSv1.3"))
    {
        return Err(format!(
            "unsupported TLS version range: min={:?} max={:?}",
            config.min_version, config.max_version
        ));
    }
    let min_is_13 = config.min_version.as_deref() == Some("TLSv1.3");
    let max_below_13 = config.max_version.as_deref() == Some("TLSv1.2");
    let mut versions: Vec<&'static rustls::SupportedProtocolVersion> = Vec::new();
    if !min_is_13 {
        versions.push(&rustls::version::TLS12);
    }
    if !max_below_13 {
        versions.push(&rustls::version::TLS13);
    }
    if versions.is_empty() {
        return Err(format!(
            "unsupported TLS version range: min={:?} max={:?}",
            config.min_version, config.max_version
        ));
    }

    let client_builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| format!("failed to configure TLS versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut client_config = match (config.cert.as_deref(), config.key.as_deref()) {
        (None, None) => client_builder.with_no_client_auth(),
        (Some(cert_pem), Some(key_pem)) => {
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                    .collect::<Result<_, _>>()
                    .map_err(|e| format!("invalid client certificate: {e}"))?;
            if certs.is_empty() {
                return Err("cert option contained no certificates".into());
            }
            let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
                .map_err(|e| format!("invalid client private key: {e}"))?;
            client_builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("client certificate/key mismatch: {e}"))?
        }
        _ => return Err("both cert and key are required for mutual TLS".into()),
    };

    client_config.alpn_protocols = config
        .alpn
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect();
    // Match measured Node v25.9.0: SNI is only sent when servername was
    // explicitly provided.
    client_config.enable_sni = config.servername.is_some();

    let name_source = config
        .servername
        .clone()
        .or_else(|| config.host.clone())
        .unwrap_or_else(|| "localhost".to_string());
    let server_name = ServerName::try_from(name_source.clone())
        .map_err(|e| format!("invalid servername {name_source:?}: {e}"))?;

    let conn = ClientConnection::new(Arc::new(client_config), server_name)
        .map_err(|e| format!("failed to create TLS client connection: {e}"))?;

    Ok(Engine {
        conn,
        verify: outcome,
        error: None,
        error_code: None,
    })
}

fn record_process_error(engine: &mut Engine, err: &TlsError) {
    if engine.error.is_some() {
        return;
    }
    // Oracle (Node v25.9.0): a peer speaking plaintext instead of TLS yields
    // ERR_SSL_WRONG_VERSION_NUMBER; use it for malformed-record errors and a
    // generic handshake code otherwise (only certificate codes are pinned).
    let code = match err {
        TlsError::InvalidMessage(_) => "ERR_SSL_WRONG_VERSION_NUMBER",
        TlsError::AlertReceived(_) => "ERR_SSL_TLSV1_ALERT",
        _ => "ERR_TLS_HANDSHAKE_FAILURE",
    };
    engine.error_code = Some(code.to_string());
    engine.error = Some(format!("{err}"));
}

fn with_engine<R>(id: u64, f: impl FnOnce(&mut Engine) -> R) -> Option<R> {
    let runtime_nonce = current_runtime_nonce();
    let principal = current_principal_id();
    if runtime_nonce == 0 {
        return None;
    }
    let engine = {
        let map = engines().lock().unwrap();
        let owned = map.get(&id)?;
        if owned.runtime_nonce != runtime_nonce || owned.owner != principal {
            return None;
        }
        Arc::clone(&owned.engine)
    };
    let mut engine = engine.lock().unwrap();
    Some(f(&mut engine))
}

fn to_owned_cstring(value: String) -> *mut c_char {
    match std::ffi::CString::new(value) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Create a new TLS client engine from a JSON config. Returns an engine id
/// (> 0) or 0 on failure (message retrievable via `ibex_tls_last_error`).
///
/// # Safety
/// `config_json` must be a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_client_new(config_json: *const c_char) -> u64 {
    let runtime_nonce = current_runtime_nonce();
    let owner = current_principal_id();
    if runtime_nonce == 0 {
        set_last_error("TLS engine creation requires an active runtime".into());
        return 0;
    }
    if config_json.is_null() {
        set_last_error("config required".into());
        return 0;
    }
    let config = match unsafe { std::ffi::CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("config must be UTF-8".into());
            return 0;
        }
    };
    match build_engine(config) {
        Ok(engine) => {
            let Some(id) = allocate_engine_id(&NEXT_ID) else {
                set_last_error("TLS engine id space exhausted".into());
                return 0;
            };
            let replaced = engines().lock().unwrap().insert(
                id,
                OwnedEngine {
                    runtime_nonce,
                    owner,
                    engine: Arc::new(Mutex::new(engine)),
                },
            );
            debug_assert!(
                replaced.is_none(),
                "monotonic TLS id collided with live engine"
            );
            id
        }
        Err(message) => {
            set_last_error(message);
            0
        }
    }
}

/// Take the last `ibex_tls_client_new` error. Caller frees the returned
/// string with `ibex_tls_string_free`; returns null when no error is stored.
#[no_mangle]
pub extern "C" fn ibex_tls_last_error() -> *mut c_char {
    let runtime_nonce = current_runtime_nonce();
    let principal = current_principal_id();
    match LAST_ERROR.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|(nonce, owner, _)| *nonce == runtime_nonce && *owner == principal)
        {
            slot.take().map(|(_, _, message)| message)
        } else {
            None
        }
    }) {
        Some(message) => to_owned_cstring(message),
        None => std::ptr::null_mut(),
    }
}

/// Feed ciphertext received from the socket into the engine. Returns bytes
/// consumed (>= 0) or -1 on a fatal TLS error (JS should drain `read_tls`
/// once more to flush any alert, then destroy).
///
/// # Safety
/// `data` must point to `len` readable bytes (or be null with `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_write_tls(id: u64, data: *const u8, len: usize) -> i64 {
    let slice: &[u8] = if data.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    with_engine(id, |engine| {
        if engine.error.is_some() {
            return -1;
        }
        let mut cursor = Cursor::new(slice);
        loop {
            let position = cursor.position() as usize;
            if position >= slice.len() {
                break;
            }
            match engine.conn.read_tls(&mut cursor) {
                Ok(0) => break,
                Ok(_) => {}
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::Other
                        && err.to_string().contains("plaintext buffer full")
                    {
                        // Normal rustls receive backpressure. Return the exact
                        // consumed prefix; JS drains plaintext and re-offers
                        // the untouched ciphertext remainder.
                        break;
                    }
                    engine.error_code = Some("ERR_TLS_HANDSHAKE_FAILURE".into());
                    engine.error = Some(format!("{err}"));
                    return -1;
                }
            }
            if let Err(err) = engine.conn.process_new_packets() {
                record_process_error(engine, &err);
                return -1;
            }
        }
        cursor.position() as i64
    })
    .unwrap_or(-1)
}

/// Drain ciphertext the engine wants to send to the socket into `buf`.
/// Returns bytes written (0 when nothing pending) or -1 for an unknown id.
///
/// # Safety
/// `buf` must point to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_read_tls(id: u64, buf: *mut u8, cap: usize) -> i64 {
    if buf.is_null() || cap == 0 {
        return 0;
    }
    let out: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
    with_engine(id, |engine| {
        if !engine.conn.wants_write() {
            return 0;
        }
        let mut cursor = Cursor::new(out);
        match engine.conn.write_tls(&mut cursor) {
            Ok(_) => cursor.position() as i64,
            Err(_) => 0,
        }
    })
    .unwrap_or(-1)
}

/// Queue plaintext for encryption. Returns bytes accepted (rustls buffers
/// pre-handshake writes and enforces an internal buffer limit, so this can be
/// a short count; JS re-offers the remainder after pumping ciphertext out) or
/// -1 on error / unknown id.
///
/// # Safety
/// `data` must point to `len` readable bytes (or be null with `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_write_plain(id: u64, data: *const u8, len: usize) -> i64 {
    let slice: &[u8] = if data.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }
    };
    with_engine(id, |engine| {
        if engine.error.is_some() {
            return -1;
        }
        match engine.conn.writer().write(slice) {
            Ok(n) => n as i64,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(err) => {
                engine.error_code = Some("ERR_TLS_WRITE_FAILED".into());
                engine.error = Some(err.to_string());
                -1
            }
        }
    })
    .unwrap_or(-1)
}

/// Read decrypted plaintext. Returns bytes read (> 0), 0 when no data is
/// available yet, -1 on authenticated end-of-stream (close_notify), or -2 on
/// a fatal TLS error, truncated transport, or unknown id.
///
/// # Safety
/// `buf` must point to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_read_plain(id: u64, buf: *mut u8, cap: usize) -> i64 {
    if buf.is_null() || cap == 0 {
        return 0;
    }
    let out: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
    with_engine(id, |engine| match engine.conn.reader().read(out) {
        Ok(0) => -1,
        Ok(n) => n as i64,
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
            if engine.error.is_some() {
                -2
            } else {
                0
            }
        }
        // An unauthenticated transport EOF is truncation, not a clean TLS end.
        // Treating it as close_notify lets an on-path peer cut a response at a
        // record boundary and have consumers accept the prefix as complete.
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
            engine.error_code = Some("ECONNRESET".into());
            engine.error = Some("TLS connection closed without close_notify".into());
            -2
        }
        Err(_) => -2,
    })
    .unwrap_or(-2)
}

/// Signal that the underlying transport reached EOF (raw socket 'end').
#[no_mangle]
pub extern "C" fn ibex_tls_transport_eof(id: u64) {
    with_engine(id, |engine| {
        let mut empty: &[u8] = &[];
        // read_tls from an empty reader registers EOF with rustls.
        let _ = engine.conn.read_tls(&mut empty);
        if let Err(err) = engine.conn.process_new_packets() {
            record_process_error(engine, &err);
        }
    });
}

/// Queue a close_notify alert (JS then drains `read_tls` and forwards it).
#[no_mangle]
pub extern "C" fn ibex_tls_shutdown(id: u64) {
    with_engine(id, |engine| engine.conn.send_close_notify());
}

/// Engine status as JSON:
/// `{handshaking, wantsWrite, protocol, alpn, cipher, cipherStandard,
///   error, errorCode, verify: {checked, chainOk, code, reason}}`.
/// Caller frees with `ibex_tls_string_free`; null for an unknown id.
#[no_mangle]
pub extern "C" fn ibex_tls_status_json(id: u64) -> *mut c_char {
    let json = with_engine(id, |engine| {
        let protocol = engine.conn.protocol_version().map(|v| match v {
            rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3".to_string(),
            rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2".to_string(),
            other => format!("{other:?}"),
        });
        let alpn = engine
            .conn
            .alpn_protocol()
            .map(|proto| String::from_utf8_lossy(proto).to_string());
        let (cipher, cipher_standard) = engine
            .conn
            .negotiated_cipher_suite()
            .map(|suite| cipher_names(suite.suite()))
            .unwrap_or((None, None));
        let verify = engine.verify.lock().unwrap().clone();
        serde_json::json!({
            "handshaking": engine.conn.is_handshaking(),
            "wantsWrite": engine.conn.wants_write(),
            "protocol": protocol,
            "alpn": alpn,
            "cipher": cipher,
            "cipherStandard": cipher_standard,
            "error": engine.error,
            "errorCode": engine.error_code,
            "verify": {
                "checked": verify.checked,
                "chainOk": verify.chain_ok,
                "code": verify.code,
                "reason": verify.reason,
            },
        })
        .to_string()
    });
    match json {
        Some(json) => to_owned_cstring(json),
        None => std::ptr::null_mut(),
    }
}

/// The peer certificate chain exactly as presented on the wire, as a JSON
/// array of base64 DER strings (leaf first). Caller frees with
/// `ibex_tls_string_free`; null for an unknown id.
#[no_mangle]
pub extern "C" fn ibex_tls_peer_certs_json(id: u64) -> *mut c_char {
    use base64::Engine as _;
    let json = with_engine(id, |engine| {
        let certs: Vec<String> = engine
            .conn
            .peer_certificates()
            .unwrap_or(&[])
            .iter()
            .map(|cert| base64::engine::general_purpose::STANDARD.encode(cert.as_ref()))
            .collect();
        serde_json::to_string(&certs).unwrap_or_else(|_| "[]".to_string())
    });
    match json {
        Some(json) => to_owned_cstring(json),
        None => std::ptr::null_mut(),
    }
}

/// Release an engine.
#[no_mangle]
pub extern "C" fn ibex_tls_free(id: u64) {
    let runtime_nonce = current_runtime_nonce();
    let principal = current_principal_id();
    let mut map = engines().lock().unwrap();
    if map
        .get(&id)
        .is_some_and(|owned| owned.runtime_nonce == runtime_nonce && owned.owner == principal)
    {
        map.remove(&id);
    }
}

/// Release every TLS engine owned by a runtime during runtime destruction.
/// The explicit nonce is required because teardown clears the thread-local
/// current-runtime context after invoking native cleanup hooks.
#[no_mangle]
pub extern "C" fn ibex_tls_cleanup_runtime(runtime_nonce: u64) {
    if runtime_nonce == 0 {
        return;
    }
    engines()
        .lock()
        .unwrap()
        .retain(|_, owned| owned.runtime_nonce != runtime_nonce);
}

/// Free a string returned by the `*_json` / last-error functions.
///
/// # Safety
/// `s` must be a pointer previously returned by this module (or null).
#[no_mangle]
pub unsafe extern "C" fn ibex_tls_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(s) });
    }
}

/// Map a negotiated suite to Node's `getCipher()` names:
/// (`name` — OpenSSL style, `standardName` — IANA style). Oracle: Node
/// v25.9.0 reports e.g. `{name:'TLS_AES_256_GCM_SHA384', standardName:
/// 'TLS_AES_256_GCM_SHA384'}` for TLS 1.3 and `{name:
/// 'ECDHE-RSA-AES128-GCM-SHA256', standardName:
/// 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'}` for TLS 1.2.
fn cipher_names(suite: rustls::CipherSuite) -> (Option<String>, Option<String>) {
    use rustls::CipherSuite::*;
    let (name, standard) = match suite {
        TLS13_AES_256_GCM_SHA384 => ("TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384"),
        TLS13_AES_128_GCM_SHA256 => ("TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"),
        TLS13_CHACHA20_POLY1305_SHA256 => (
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
        ),
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => (
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        ),
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => (
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ),
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => (
            "ECDHE-RSA-AES128-GCM-SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        ),
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => (
            "ECDHE-RSA-AES256-GCM-SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ),
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => (
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => (
            "ECDHE-RSA-CHACHA20-POLY1305",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        ),
        other => {
            let debug = format!("{other:?}");
            return (Some(debug.clone()), Some(debug));
        }
    };
    (Some(name.to_string()), Some(standard.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{allocate_engine_id, MAX_JS_SAFE_INTEGER};
    use std::sync::atomic::AtomicU64;

    #[test]
    fn tls_engine_ids_stop_before_javascript_number_aliasing() {
        let counter = AtomicU64::new(MAX_JS_SAFE_INTEGER - 1);
        assert_eq!(allocate_engine_id(&counter), Some(MAX_JS_SAFE_INTEGER - 1));
        assert_eq!(allocate_engine_id(&counter), Some(MAX_JS_SAFE_INTEGER));
        assert_eq!(allocate_engine_id(&counter), None);
        assert_eq!(allocate_engine_id(&counter), None);
    }

    #[test]
    fn tls_engine_id_zero_is_never_allocated() {
        let counter = AtomicU64::new(0);
        assert_eq!(allocate_engine_id(&counter), None);
    }
}
