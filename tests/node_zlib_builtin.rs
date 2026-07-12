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
    let dir = tempfile::tempdir().expect("create eval tempdir");
    let entry = dir.path().join("eval.js");
    std::fs::write(
        &entry,
        format!(
            "(function () {{\n  var watchdog = setTimeout(function () {{\n    console.error('diagnostic eval timed out');\n    process.exitCode = 1;\n  }}, 55000);\n  var result = (\n{js}\n  );\n  function resolve(value) {{\n    clearTimeout(watchdog);\n    console.log(value);\n  }}\n  function reject(error) {{\n    clearTimeout(watchdog);\n    console.error(error && error.stack || error);\n    process.exitCode = 1;\n  }}\n  if (result && typeof result.then === 'function') result.then(resolve, reject);\n  else resolve(result);\n}})();\n"
        ),
    )
    .expect("write eval fixture");
    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec").arg("audit").arg(&entry);
    let output = timeout(Duration::from_secs(60), cmd.output())
        .await
        .expect("ibex capsec audit timed out")
        .expect("failed to spawn or read ibex process output");
    assert!(
        output.status.success(),
        "ibex capsec audit should exit successfully: status={:?}, stderr={}",
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

#[tokio::test]
async fn node_zlib_streams_roundtrip_incrementally_across_flush_and_split_input() {
    let js = r#"(async function(){
        var z = require('zlib');
        var input = Buffer.alloc(256 * 1024);
        for (var i = 0; i < input.length; i++) input[i] = 65 + (i % 26);

        function gzipStream() {
          return new Promise(function(resolve, reject) {
            var gz = z.createGzip();
            var chunks = [];
            var bytesBeforeEnd = 0;
            gz.on('data', function(chunk) { chunks.push(Buffer.from(chunk)); });
            gz.on('error', reject);
            gz.on('end', function() {
              resolve({
                compressed: Buffer.concat(chunks),
                bytesBeforeEnd: bytesBeforeEnd,
                chunkCount: chunks.length
              });
            });
            gz.write(input.subarray(0, 64 * 1024));
            gz.flush(z.constants.Z_SYNC_FLUSH, function(err) {
              if (err) { reject(err); return; }
              bytesBeforeEnd = Buffer.concat(chunks).length;
              gz.write(input.subarray(64 * 1024, 128 * 1024));
              gz.end(input.subarray(128 * 1024));
            });
          });
        }

        function gunzipStream(compressed) {
          return new Promise(function(resolve, reject) {
            var gunzip = z.createGunzip();
            var out = [];
            gunzip.on('data', function(chunk) { out.push(Buffer.from(chunk)); });
            gunzip.on('error', reject);
            gunzip.on('end', function() { resolve(Buffer.concat(out)); });
            gunzip.write(compressed.subarray(0, 17));
            gunzip.write(compressed.subarray(17, 4099));
            gunzip.end(compressed.subarray(4099));
          });
        }

        var gz = await gzipStream();
        var decoded = await gunzipStream(gz.compressed);
        return JSON.stringify({
          roundtrip: decoded.equals(input),
          emittedBeforeEnd: gz.bytesBeforeEnd > 0,
          multipleGzipChunks: gz.chunkCount >= 2
        });
      })()"#;
    let result = eval(js).await;
    assert_eq!(
        result, r#"{"roundtrip":true,"emittedBeforeEnd":true,"multipleGzipChunks":true}"#,
        "zlib streams must round-trip split inputs and emit data before final end: {result}"
    );
}

#[tokio::test]
async fn node_gunzip_concatenated_members_survive_every_chunk_split() {
    let js = r#"(async function(){
        var z = require('zlib');
        var first = z.gzipSync(Buffer.from('first member: alpha'));
        var second = z.gzipSync(Buffer.from('second member: omega'));
        var compressed = Buffer.concat([first, second]);
        var expected = 'first member: alphasecond member: omega';

        function decodeAt(split) {
          return new Promise(function(resolve) {
            var gunzip = z.createGunzip();
            var out = [];
            gunzip.on('data', function(chunk) { out.push(Buffer.from(chunk)); });
            gunzip.on('error', function(err) { resolve('error:' + err.message); });
            gunzip.on('end', function() { resolve(Buffer.concat(out).toString()); });
            // Three writes exercise both an arbitrary payload split and a
            // one-byte split immediately after it. In particular, the split
            // at first.length leaves one byte of the next gzip magic in the
            // second write.
            gunzip.write(compressed.subarray(0, split));
            gunzip.write(compressed.subarray(split, split + 1));
            gunzip.end(compressed.subarray(split + 1));
          });
        }

        var failures = [];
        for (var split = 1; split < compressed.length; split++) {
          var decoded = await decodeAt(split);
          if (decoded !== expected) failures.push([split, decoded]);
        }

        var truncated = await new Promise(function(resolve) {
          var gunzip = z.createGunzip();
          var joined = Buffer.concat([first, second.subarray(0, second.length - 4)]);
          gunzip.on('error', function(err) { resolve(err.code || err.message); });
          gunzip.on('end', function() { resolve('unexpected-end'); });
          gunzip.write(joined.subarray(0, first.length + 1));
          gunzip.end(joined.subarray(first.length + 1));
        });

        return JSON.stringify({ failures: failures, truncated: truncated });
      })()"#;
    let result = eval(js).await;
    assert_eq!(
        result, r#"{"failures":[],"truncated":"Z_DATA_ERROR"}"#,
        "concatenated gzip must tolerate every chunk split and reject a truncated later member: {result}"
    );
}

#[tokio::test]
async fn node_gunzip_large_multichunk_input_emits_before_final_and_preserves_order() {
    let js = r#"(async function(){
        var z = require('zlib');
        var input = Buffer.alloc(4 * 1024 * 1024);
        var state = 0x12345678;
        for (var i = 0; i < input.length; i++) {
          state ^= state << 13;
          state ^= state >>> 17;
          state ^= state << 5;
          input[i] = state & 255;
        }
        var compressed = z.gzipSync(input);
        var chunkSize = 64 * 1024;

        var result = await new Promise(function(resolve, reject) {
          var gunzip = z.createGunzip();
          var out = [];
          var bytesBeforeEnd = 0;
          gunzip.on('data', function(chunk) { out.push(Buffer.from(chunk)); });
          gunzip.on('error', reject);
          gunzip.on('end', function() {
            resolve({
              decoded: Buffer.concat(out),
              bytesBeforeEnd: bytesBeforeEnd
            });
          });
          var offset = 0;
          while (offset + chunkSize < compressed.length) {
            gunzip.write(compressed.subarray(offset, offset + chunkSize));
            offset += chunkSize;
          }
          for (var j = 0; j < out.length; j++) bytesBeforeEnd += out[j].length;
          gunzip.end(compressed.subarray(offset));
        });

        return JSON.stringify({
          compressedChunks: Math.ceil(compressed.length / chunkSize),
          emittedBeforeEnd: result.bytesBeforeEnd > 0,
          roundtrip: result.decoded.equals(input)
        });
      })()"#;
    let result = eval(js).await;
    let parsed: serde_json::Value = serde_json::from_str(&result)
        .unwrap_or_else(|err| panic!("invalid result {result:?}: {err}"));
    assert_eq!(
        parsed["emittedBeforeEnd"], true,
        "decoder must emit before end: {result}"
    );
    assert_eq!(
        parsed["roundtrip"], true,
        "decoder output ordering changed: {result}"
    );
    assert!(
        parsed["compressedChunks"].as_u64().unwrap_or(0) >= 32,
        "test input must exercise many native writes: {result}"
    );
}
