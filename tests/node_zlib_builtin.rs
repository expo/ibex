//! End-to-end tests for the Node-compat zlib builtin, driving the real
//! `ibex` binary (ENG-23456 finding 2): the deflate/inflate host functions
//! are registered per-platform, and on builds without them (Windows today)
//! the JS call sites used to raise a bare `ReferenceError:
//! __exactDeflateSync is not defined` from inside gzipSync. They must fail
//! with the same clear "not available" error shape the brotli/zstd paths
//! already use — and keep working where the bridge exists.
//!
//! Run with: `scripts/run-tests.sh --scope test node_zlib`

use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

const IBEX: &str = env!("CARGO_BIN_EXE_ibex");

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

/// Round-trips through every deflate/inflate family entry point on a build
/// where the native bridge exists.
#[tokio::test]
async fn node_zlib_deflate_family_roundtrips() {
    let js = "(function(){ var z = require('zlib'); \
        var msg = Buffer.from('ENG-23456 zlib roundtrip \\u00e9\\u00e9'); \
        return JSON.stringify({ \
          gzip: z.gunzipSync(z.gzipSync(msg)).equals(msg), \
          deflate: z.inflateSync(z.deflateSync(msg)).equals(msg), \
          raw: z.inflateRawSync(z.deflateRawSync(msg)).equals(msg), \
          unzip: z.unzipSync(z.gzipSync(msg)).equals(msg) \
        }); })()";
    let result = eval(js).await;
    assert_eq!(
        result, r#"{"gzip":true,"deflate":true,"raw":true,"unzip":true}"#,
        "zlib roundtrips must work where the bridge is registered: {result}"
    );
}

/// Simulates the bridge-less profile (Windows) by clobbering the host
/// functions: every deflate/inflate entry point must throw the clean
/// "not available" error, never a ReferenceError.
#[tokio::test]
async fn node_zlib_missing_bridge_fails_cleanly_not_referenceerror() {
    let js = "(function(){ var z = require('zlib'); \
        globalThis.__exactDeflateSync = undefined; \
        globalThis.__exactInflateSync = undefined; \
        function probe(fn) { \
          try { fn(); return 'no-throw'; } \
          catch (e) { \
            if (e instanceof ReferenceError) return 'ReferenceError'; \
            return e.message.indexOf('not available') !== -1 ? 'clean' : 'other:' + e.message.slice(0, 40); \
          } \
        } \
        var data = Buffer.from('x'); \
        return JSON.stringify({ \
          gzipSync: probe(function(){ z.gzipSync(data); }), \
          deflateSync: probe(function(){ z.deflateSync(data); }), \
          deflateRawSync: probe(function(){ z.deflateRawSync(data); }), \
          gunzipSync: probe(function(){ z.gunzipSync(data); }), \
          inflateSync: probe(function(){ z.inflateSync(data); }), \
          inflateRawSync: probe(function(){ z.inflateRawSync(data); }), \
          unzipSync: probe(function(){ z.unzipSync(data); }) \
        }); })()";
    let result = eval(js).await;
    assert_eq!(
        result,
        r#"{"gzipSync":"clean","deflateSync":"clean","deflateRawSync":"clean","gunzipSync":"clean","inflateSync":"clean","inflateRawSync":"clean","unzipSync":"clean"}"#,
        "bridge-less zlib must throw the clean 'not available' error: {result}"
    );
}
