//! Cross-host source contract for native zlib stream ownership. The JS test
//! exercises the public-property attack directly; these assertions keep the
//! native runtime/principal boundary from drifting on platforms where the
//! Hermes bridge is not built by ordinary unit tests.

const ZLIB_NATIVE: &str = include_str!("../src/engine/hermes_runtime_zlib_streams.h");
const ZLIB_JS: &str = include_str!("../src/builtins/zlib.js");
const STREAM_JS: &str = include_str!("../src/builtins/stream.js");
const CRYPTO_NATIVE: &str = include_str!("../src/engine/hermes_runtime_crypto.cc");
const CRYPTO_WINDOWS: &str = include_str!("../src/engine/hermes_runtime_crypto_windows.cc");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source
        .find(start)
        .unwrap_or_else(|| panic!("missing section start {start:?}"));
    let tail = &source[start..];
    let end = tail
        .find(end)
        .unwrap_or_else(|| panic!("missing section end {end:?}"));
    &tail[..end]
}

#[test]
fn native_stream_operations_require_runtime_and_principal_ownership() {
    assert!(ZLIB_NATIVE.contains("uint64_t runtime_nonce = 0;"));
    assert!(ZLIB_NATIVE.contains("uint64_t owner = 0;"));
    assert!(ZLIB_NATIVE.contains("state->runtime_nonce = handle->runtime_nonce;"));
    assert!(ZLIB_NATIVE.contains("state->owner = currentPrincipalId();"));

    let lookup = section(
        ZLIB_NATIVE,
        "inline std::shared_ptr<ZlibStreamState> requireOwnedZlibStream(",
        "inline void installZlibStreamHostFunctions(",
    );
    assert!(lookup.contains("runtime_nonce != exactCurrentRuntimeNonce()"));
    assert!(lookup.contains("owner != currentPrincipalId()"));
    assert_eq!(
        ZLIB_NATIVE
            .matches("requireOwnedZlibStream(runtime, id)")
            .count(),
        3,
        "write, params, and the JS-entry preflight must use the unconditional owner lookup"
    );
    assert!(ZLIB_NATIVE.contains("__exactZlibCheckOwner"));

    let close = section(
        ZLIB_NATIVE,
        "auto closeFn = facebook::jsi::Function::createFromHostFunction(",
        "rt.global().setProperty(rt, \"__exactZlibClose\"",
    );
    assert!(close.contains("runtime_nonce != exactCurrentRuntimeNonce()"));
    assert!(close.contains("owner != currentPrincipalId()"));
    assert!(close.contains("zlibStreams().erase(it);"));
    assert!(
        !close.contains("isAllowAll()"),
        "permissive posture must not bypass native stream ownership"
    );
}

#[test]
fn javascript_does_not_expose_the_native_registry_id_as_writable_authority() {
    assert!(ZLIB_JS.contains(
        "var _nativeZlibStreamIds = typeof WeakMap === 'function' ? new WeakMap() : null;"
    ));
    assert!(!ZLIB_JS.contains("this._nativeId ="));
    assert!(!ZLIB_JS.contains("this._nativeId,"));
    assert!(ZLIB_JS.contains("_nativeZlibStreamIds.set(this, id);"));
    assert!(ZLIB_JS.contains("_nativeZlibStreamIds.delete(this);"));
    assert!(ZLIB_JS.contains("assertNativeZlibStreamOwner(this);"));
}

#[test]
fn decompression_is_bounded_before_native_output_growth() {
    assert!(ZLIB_NATIVE.contains("kNativeZlibOutputLimit = 64 * 1024 * 1024"));
    assert!(ZLIB_NATIVE.contains("const size_t output_limit = readZlibOutputLimit("));
    let inflater = section(
        ZLIB_NATIVE,
        "inline std::vector<uint8_t> inflateStreamWrite(",
        "inline std::vector<uint8_t> deflateStreamParams(",
    );
    let bound = inflater
        .find("zlibOutputFits(output.size(), have, output_limit)")
        .expect("incremental inflater must check its output budget");
    let append = inflater
        .find("output.insert(output.end(), out_buf, out_buf + have);")
        .expect("incremental inflater must append its output");
    assert!(
        bound < append,
        "the native budget must be enforced before vector growth"
    );

    for native in [CRYPTO_NATIVE, CRYPTO_WINDOWS] {
        let sync_inflater = section(
            native,
            "auto inflateSyncFn = facebook::jsi::Function::createFromHostFunction(",
            "rt.global().setProperty(rt, \"__exactInflateSync\"",
        );
        assert!(sync_inflater.contains(
            "facebook::jsi::PropNameID::forAscii(rt, \"__exactInflateSync\"),\n      6,"
        ));
        assert!(native.contains("count > 5 ? &args[5] : nullptr"));
        let bound = sync_inflater
            .find("zlibOutputFits(")
            .expect("one-shot inflater must check its output budget");
        let append = sync_inflater
            .find("output.insert(output.end(), outBuf, outBuf + have);")
            .expect("one-shot inflater must append its output");
        assert!(
            bound < append,
            "one-shot native budget must be enforced before vector growth"
        );
        assert!(sync_inflater.contains("throwZlibOutputLimit(runtime, outputLimit)"));
    }

    let brotli = section(
        CRYPTO_NATIVE,
        "auto brotliDecompressSyncFn = facebook::jsi::Function::createFromHostFunction(",
        "rt.global().setProperty(rt, \"__exactBrotliDecompressSync\"",
    );
    assert!(brotli.contains(
        "facebook::jsi::PropNameID::forAscii(rt, \"__exactBrotliDecompressSync\"),\n      4,"
    ));
    assert!(brotli.contains("count > 3 ? &args[3] : nullptr"));
    let brotli_bound = brotli
        .find("zlibOutputFits(")
        .expect("Brotli must check its output budget");
    let brotli_append = brotli
        .find("output.insert(output.end(), outBuf, outBuf + have);")
        .expect("Brotli must append its output");
    assert!(
        brotli_bound < brotli_append,
        "Brotli budget must be enforced before vector growth"
    );
    assert!(brotli.contains("throwZlibOutputLimit(runtime, outputLimit)"));
    assert!(ZLIB_JS.contains(
        "__exactBrotliDecompressSync(\n      bytes,\n      false,\n      0,\n      nativeZlibOutputBudget(maxOutputLength, 0))"
    ));
    assert!(ZLIB_JS.contains("nativeZlibOutputBudget(this._maxOutputLength"));
    assert!(ZLIB_JS.contains("ERR_BUFFER_TOO_LARGE"));
    assert!(ZLIB_NATIVE.contains("return current <= limit && additional <= limit - current;"));
    assert!(
        !ZLIB_JS.contains("for (var outputIndex = 0; outputIndex < allOutputs.length"),
        "multi-member accounting must remain linear"
    );
}

#[test]
fn gzip_rejects_nonzero_trailing_data_but_accepts_zero_padding() {
    let inflater = section(
        ZLIB_NATIVE,
        "inline std::vector<uint8_t> inflateStreamWrite(",
        "inline std::vector<uint8_t> deflateStreamParams(",
    );
    assert!(inflater.contains("isZeroPadding(next_in, remaining)"));
    assert!(inflater.contains("inflate failed: trailing data"));
    assert!(inflater.contains("gzip_padding_started"));

    for native in [CRYPTO_NATIVE, CRYPTO_WINDOWS] {
        assert!(native.contains("isZeroPadding(nextIn, remaining)"));
        assert!(native.contains("inflate failed: trailing data"));
    }
}

#[test]
fn inherited_stream_prototypes_cannot_bypass_the_zlib_owner_guard() {
    assert!(ZLIB_JS.contains("Transform.call(this, opts, assertNativeZlibStreamOwner);"));
    assert!(STREAM_JS.contains("var _retainedOwnerGuards = new WeakMap();"));
    assert!(STREAM_JS.contains("_registerRetainedOwnerGuard(this, retainedOwnerGuard);"));

    for entry in [
        "Stream.prototype.destroy = function(error, callback) {",
        "Writable.prototype.write = function(chunk, encoding, callback) {",
        "Writable.prototype.end = function(chunk, encoding, callback) {",
        "Writable.prototype._flushWriteQueue = function() {",
        "Transform.prototype._write = function(chunk, encoding, callback) {",
    ] {
        let body = section(STREAM_JS, entry, "\n};");
        assert!(
            body.contains("_assertRetainedOwner(this);"),
            "{entry} must authenticate before touching retained stream state"
        );
    }
}
