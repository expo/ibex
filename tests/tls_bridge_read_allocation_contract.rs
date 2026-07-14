//! Cross-language contract for exact-size native TLS read leases. Behavioral
//! TLS tests exercise the pump; these assertions keep non-Hermes builds from
//! regressing to speculative 64 KiB allocations, repeated owner/registry
//! lookups, silent probe failures, or allocation-time read races.

const TLS_RUST: &str = include_str!("../src/engine/tls_bridge.rs");
const TLS_JSI: &str = include_str!("../src/engine/hermes_runtime_tls.cc");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split(start)
        .nth(1)
        .unwrap_or_else(|| panic!("missing section start: {start}"))
        .split(end)
        .next()
        .unwrap()
}

#[test]
fn jsi_reads_use_one_native_reservation_and_allocate_before_consuming() {
    let ciphertext = section(TLS_JSI, "auto tlsReadTlsFn =", "auto tlsWritePlainFn =");
    assert!(ciphertext.contains("requireTlsEngineHandle("));
    assert!(!ciphertext.contains("requireTlsEngineId("));
    assert_eq!(ciphertext.matches("ibex_tls_tls_read_begin(").count(), 1);
    assert!(!ciphertext.contains("ibex_tls_check_owner("));
    assert!(!ciphertext.contains("ibex_tls_tls_bytes_pending("));
    assert!(!ciphertext.contains("ibex_tls_read_tls("));

    let begin = ciphertext.find("ibex_tls_tls_read_begin(").unwrap();
    let allocation = ciphertext
        .find("makeTlsReadBuffer(runtime, readBytes, tlsArrayBufferIntrinsic)")
        .expect("right-sized ciphertext allocation");
    let finish = ciphertext
        .find("lease.finish(buffer.data(runtime), readBytes)")
        .expect("direct ciphertext lease fill");
    assert!(begin < allocation && allocation < finish);
    assert!(!ciphertext.contains("makeTlsReadBuffer(runtime, maxBytes)"));
    assert!(!ciphertext.contains("makeTlsReadView"));
    assert!(!ciphertext.contains("runtime.global()"));
    assert!(ciphertext.contains("facebook::jsi::Value(std::move(buffer))"));

    let plaintext = section(TLS_JSI, "auto tlsReadPlainFn =", "auto tlsEofFn =");
    assert!(plaintext.contains("requireTlsEngineHandle("));
    assert!(!plaintext.contains("requireTlsEngineId("));
    assert_eq!(
        plaintext.matches("ibex_tls_plaintext_read_begin(").count(),
        1
    );
    assert!(!plaintext.contains("ibex_tls_check_owner("));
    assert!(!plaintext.contains("ibex_tls_plaintext_bytes_pending("));
    assert!(!plaintext.contains("ibex_tls_read_plain("));

    let begin = plaintext.find("ibex_tls_plaintext_read_begin(").unwrap();
    let allocation = plaintext
        .find("makeTlsReadBuffer(runtime, readBytes, tlsArrayBufferIntrinsic)")
        .expect("right-sized plaintext allocation");
    let finish = plaintext
        .find("lease.finish(buffer.data(runtime), readBytes)")
        .expect("direct plaintext lease fill");
    assert!(begin < allocation && allocation < finish);
    assert!(!plaintext.contains("makeTlsReadBuffer(runtime, maxBytes)"));
    assert!(!plaintext.contains("makeTlsReadView"));
    assert!(!plaintext.contains("runtime.global()"));
    assert!(plaintext.contains("facebook::jsi::Value(std::move(buffer))"));
}

#[test]
fn leased_read_buffers_do_not_use_mutable_global_constructors() {
    let allocation = section(
        TLS_JSI,
        "facebook::jsi::ArrayBuffer makeTlsReadBuffer",
        "// Rust returns an owned C string",
    );
    assert!(allocation.contains("EXACT_HAVE_JSI_MUTABLE_BUFFER"));
    assert!(allocation.contains("std::make_shared<VectorBuffer>"));
    assert!(allocation.contains("facebook::jsi::ArrayBuffer(runtime, backing)"));
    assert!(!allocation.contains("runtime.global()"));
    assert!(!allocation.contains("Uint8Array"));

    // The compatibility path is pinned to the original intrinsic captured at
    // runtime setup, rather than looking up a replaceable global while a Rust
    // engine is reserved.
    assert!(allocation.contains("arrayBufferIntrinsic"));
    assert!(allocation.contains("->callAsConstructor"));
    let installation = section(
        TLS_JSI,
        "void installTlsHostFunctions",
        "auto tlsOwnerTokenFn =",
    );
    assert!(installation.contains("tlsArrayBufferIntrinsic"));
    assert!(installation.contains("getPropertyAsFunction(rt, \"ArrayBuffer\")"));
}

#[test]
fn probe_and_ownership_failures_are_explicit_not_empty_polls() {
    let errors = section(
        TLS_JSI,
        "[[noreturn]] void throwTlsReadError",
        "class TlsReadLease",
    );
    assert!(errors.contains("status == kTlsReadProbeError"));
    assert!(errors.contains("pending-length probe failed"));
    assert!(errors.contains("status == kTlsReadUnknownEngine"));
    assert!(errors.contains("status == kTlsReadWrongOwner"));

    let ciphertext = section(TLS_JSI, "auto tlsReadTlsFn =", "auto tlsWritePlainFn =");
    assert!(ciphertext.contains("if (pending == kTlsReadEmpty)"));
    assert!(ciphertext.contains("if (pending < 0)"));
    assert!(!ciphertext.contains("if (pending <= 0)"));

    let begin = section(
        TLS_RUST,
        "unsafe fn begin_read(",
        "pub unsafe extern \"C\" fn ibex_tls_tls_read_begin",
    );
    assert!(begin.contains("!(1..=MAX_TLS_READ_BYTES).contains(&max_bytes)"));
    assert_eq!(begin.matches("lookup_owned_engine(id)").count(), 1);
    assert!(begin.contains("EngineLookupError::Missing"));
    assert!(begin.contains("EngineLookupError::WrongOwner"));

    let pending = section(TLS_RUST, "fn pending_read_length", "fn reserve_read_lease");
    assert!(pending.contains("Err(()) => TLS_READ_PROBE_ERROR"));
}

#[test]
fn native_lease_is_exclusive_cancel_safe_and_lookup_free_on_finish() {
    let reservation = section(TLS_RUST, "fn reserve_read_lease", "unsafe fn begin_read");
    assert!(reservation.contains("let Some(engine) = slot.take()"));
    assert!(reservation.contains("pending.min(max_bytes)"));

    let lease_drop = section(TLS_RUST, "impl Drop for ReadLease", "struct OwnerToken");
    assert!(lease_drop.contains("self.engine.take()"));
    assert!(lease_drop.contains("*slot = Some(engine)"));

    let finish = section(
        TLS_RUST,
        "pub unsafe extern \"C\" fn ibex_tls_read_finish",
        "pub unsafe extern \"C\" fn ibex_tls_read_cancel",
    );
    assert!(finish.contains("lease.runtime_nonce != current_runtime_nonce()"));
    assert!(finish.contains("lease.owner != current_principal_id()"));
    assert!(!finish.contains("lookup_owned_engine"));
    assert!(!finish.contains("with_engine"));
    assert!(!finish.contains("engines()"));

    let guard = section(
        TLS_JSI,
        "class TlsReadLease",
        "uint64_t requireTlsOwnerToken",
    );
    assert!(guard.contains("ibex_tls_read_cancel(lease_)"));
    assert!(guard.contains("ibex_tls_read_finish(lease, data, size)"));

    let production = TLS_RUST.split("#[cfg(test)]").next().unwrap();
    assert!(production.contains("poisoned.into_inner()"));
    assert!(
        !production.contains(".lock().unwrap()"),
        "mutex poison must not unwind across a TLS FFI entry point"
    );
    assert!(!reservation.contains(".expect("));
}

#[test]
fn ciphertext_pending_probe_remains_exact_and_non_consuming() {
    let ciphertext = section(TLS_RUST, "fn tls_bytes_pending", "fn plain_read_result");
    assert!(ciphertext.contains("PendingWriteCounter::default()"));
    assert!(ciphertext.contains("conn.write_tls(&mut counter)"));

    let counter = section(
        TLS_RUST,
        "impl Write for PendingWriteCounter",
        "struct OwnedEngine",
    );
    assert!(counter.matches("Ok(0)").count() >= 2);
}
