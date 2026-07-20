//! End-to-end tests for the Node-compat zlib builtin, driving the real
//! `ibex` binary (ENG-23456 finding 2): the deflate/inflate host functions
//! are registered per-platform, and on builds without them the JS call sites
//! used to raise a bare `ReferenceError:
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
            "(function () {{\n  var watchdog = setTimeout(function () {{\n    console.error('diagnostic eval timed out');\n    process.exit(1);\n  }}, 110000);\n  var result = (\n{js}\n  );\n  if (watchdog && typeof watchdog.ref === 'function') watchdog.ref();\n  function resolve(value) {{\n    clearTimeout(watchdog);\n    console.log(value);\n    process.exit(0);\n  }}\n  function reject(error) {{\n    clearTimeout(watchdog);\n    console.error(error && error.stack || error);\n    process.exit(1);\n  }}\n  if (result && typeof result.then === 'function') result.then(resolve, reject);\n  else resolve(result);\n}})();\n"
        ),
    )
    .expect("write eval fixture");
    let mut cmd = Command::new(IBEX);
    cmd.arg("capsec").arg("audit").arg(&entry);
    let output = timeout(Duration::from_secs(120), cmd.output())
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

#[tokio::test]
async fn node_zlib_preset_dictionaries_roundtrip_direct_one_shot_and_streaming() {
    let js = r#"(async function(){
        var z = require('zlib');
        var dictionary = Buffer.from('shared-dictionary:alpha-beta-gamma-delta:0123456789');
        var records = [];
        for (var i = 0; i < 64; i++) {
          records.push(dictionary.toString() + ':record-' + (i % 7) + '\n');
        }
        var input = Buffer.from(records.join(''));
        var keepAlive = setInterval(function() {}, 1000);
        if (keepAlive && typeof keepAlive.ref === 'function') keepAlive.ref();

        function streamRoundtrip(rawMode) {
          return new Promise(function(resolve, reject) {
            var encoder = rawMode
              ? z.createDeflateRaw({ dictionary: dictionary })
              : z.createDeflate({ dictionary: dictionary });
            var compressedChunks = [];
            encoder.on('data', function(chunk) { compressedChunks.push(Buffer.from(chunk)); });
            encoder.on('error', reject);
            encoder.on('end', function() {
              var compressed = Buffer.concat(compressedChunks);
              var decoder = rawMode
                ? z.createInflateRaw({ dictionary: dictionary })
                : z.createInflate({ dictionary: dictionary });
              var output = [];
              decoder.on('data', function(chunk) { output.push(Buffer.from(chunk)); });
              decoder.on('error', reject);
              decoder.on('end', function() { resolve(Buffer.concat(output).equals(input)); });
              var split = Math.max(1, Math.floor(compressed.length / 2));
              decoder.write(compressed.subarray(0, split));
              decoder.end(compressed.subarray(split));
            });
            encoder.write(input.subarray(0, 97));
            encoder.end(input.subarray(97));
          });
        }

        try {
          var directWrappedCompressed = __exactDeflateSync(input, 6, 0, dictionary);
          var directRawCompressed = __exactDeflateSync(input, 6, 2, dictionary);
          var directWrapped = Buffer.from(
            __exactInflateSync(directWrappedCompressed, 0, false, 0, dictionary)
          ).equals(input);
          var directRaw = Buffer.from(
            __exactInflateSync(directRawCompressed, 2, false, 0, dictionary)
          ).equals(input);

          var wrapped = z.deflateSync(input, { dictionary: dictionary });
          var raw = z.deflateRawSync(input, { dictionary: dictionary });
          return JSON.stringify({
            directWrapped: directWrapped,
            directRaw: directRaw,
            oneShotWrapped: z.inflateSync(wrapped, { dictionary: dictionary }).equals(input),
            oneShotRaw: z.inflateRawSync(raw, { dictionary: dictionary }).equals(input),
            streamWrapped: await streamRoundtrip(false),
            streamRaw: await streamRoundtrip(true)
          });
        } finally {
          clearInterval(keepAlive);
        }
      })()"#;
    let result = eval(js).await;
    assert_eq!(
        result,
        r#"{"directWrapped":true,"directRaw":true,"oneShotWrapped":true,"oneShotRaw":true,"streamWrapped":true,"streamRaw":true}"#,
        "preset dictionaries must reach wrapped/raw one-shot and stream codecs: {result}"
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
async fn node_zlib_flush_options_and_queued_controls_preserve_order() {
    let js = r#"(async function(){
        var z = require('zlib');
        var keepAlive = setInterval(function() {}, 1000);
        if (keepAlive && typeof keepAlive.ref === 'function') keepAlive.ref();

        function byteLength(chunks) {
          var total = 0;
          for (var i = 0; i < chunks.length; i++) total += chunks[i].length;
          return total;
        }

        function optionsFlushCase() {
          return new Promise(function(resolve, reject) {
            var stream = z.createDeflate({ flush: z.constants.Z_SYNC_FLUSH });
            var chunks = [];
            var firstBytes = 0;
            var secondBytes = 0;
            stream.on('data', function(chunk) { chunks.push(Buffer.from(chunk)); });
            stream.on('error', reject);
            stream.on('end', function() {
              var compressed = Buffer.concat(chunks);
              resolve({
                roundtrip: z.inflateSync(compressed).toString() === 'alphabetaomega',
                firstWriteEmitted: firstBytes > 0,
                secondWriteEmitted: secondBytes > firstBytes
              });
            });
            stream.write('alpha', function(err) {
              if (err) { reject(err); return; }
              firstBytes = byteLength(chunks);
              stream.write('beta', function(secondErr) {
                if (secondErr) { reject(secondErr); return; }
                secondBytes = byteLength(chunks);
                stream.end('omega');
              });
            });
          });
        }

        function orderedControlsCase() {
          return new Promise(function(resolve, reject) {
            var stream = z.createDeflate({ level: 0 });
            var chunks = [];
            var callbacks = [];
            stream.on('data', function(chunk) { chunks.push(Buffer.from(chunk)); });
            stream.on('error', reject);
            stream.on('end', function() {
              resolve({
                roundtrip: z.inflateSync(Buffer.concat(chunks)).toString() === 'pendingtail',
                callbacks: callbacks
              });
            });
            stream.cork();
            stream.write('pending', function(err) {
              if (err) { reject(err); return; }
              callbacks.push('write');
            });
            stream.flush(z.constants.Z_SYNC_FLUSH, function(err) {
              if (err) { reject(err); return; }
              callbacks.push('flush');
            });
            stream.params(9, z.constants.Z_DEFAULT_STRATEGY, function(err) {
              if (err) { reject(err); return; }
              callbacks.push('params');
              stream.end('tail');
            });
            stream.uncork();
          });
        }

        function flushAfterEndCase() {
          return new Promise(function(resolve, reject) {
            var stream = z.createDeflate();
            var chunks = [];
            stream.on('data', function(chunk) { chunks.push(Buffer.from(chunk)); });
            stream.on('error', reject);
            stream.on('end', function() {
              var compressed = Buffer.concat(chunks);
              var returned = stream.flush(function(err) {
                resolve({
                  roundtrip: z.inflateSync(compressed).toString() === 'payload',
                  sameStream: returned === stream,
                  callbackError: err ? (err.code || err.message) : null
                });
              });
            });
            stream.end('payload');
          });
        }

        try {
          return JSON.stringify({
            optionsFlush: await optionsFlushCase(),
            ordered: await orderedControlsCase(),
            afterEnd: await flushAfterEndCase()
          });
        } finally {
          clearInterval(keepAlive);
        }
      })()"#;
    let result = eval(js).await;
    assert_eq!(
        result,
        r#"{"optionsFlush":{"roundtrip":true,"firstWriteEmitted":true,"secondWriteEmitted":true},"ordered":{"roundtrip":true,"callbacks":["write","flush","params"]},"afterEnd":{"roundtrip":true,"sameStream":true,"callbackError":null}}"#,
        "flush options and queued controls must preserve Node-compatible ordering: {result}"
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
        // A fixture-owned referenced timer created after module initialization
        // keeps the audit file runner pumping across the stream's final event
        // turn; a pending Promise alone does not keep that runner alive.
        var keepAlive = setInterval(function() {}, 1000);
        if (keepAlive && typeof keepAlive.ref === 'function') keepAlive.ref();

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
        try {
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
        } finally {
          clearInterval(keepAlive);
        }
      })()"#;
    let result = eval(js).await;
    assert_eq!(
        result, r#"{"failures":[],"truncated":"Z_DATA_ERROR"}"#,
        "concatenated gzip must tolerate every chunk split and reject a truncated later member: {result}"
    );
}

#[tokio::test]
async fn node_gunzip_accepts_zero_padding_and_rejects_nonzero_trailing_data() {
    let js = r#"(async function(){
        var z = require('zlib');
        var member = z.gzipSync(Buffer.from('payload'));
        var zeros = Buffer.from([0, 0, 0]);
        var evil = Buffer.from('evil');
        var keepAlive = setInterval(function() {}, 1000);
        if (keepAlive && typeof keepAlive.ref === 'function') keepAlive.ref();

        function sync(tail) {
          try { return z.gunzipSync(Buffer.concat([member, tail])).toString(); }
          catch (err) { return err.code || err.message; }
        }

        function syncLenient(tail) {
          try {
            return z.gunzipSync(Buffer.concat([member, tail]), {
              finishFlush: z.constants.Z_SYNC_FLUSH
            }).toString();
          } catch (err) { return err.code || err.message; }
        }

        function streamed(tail, split) {
          return new Promise(function(resolve) {
            var gunzip = z.createGunzip();
            var out = [];
            gunzip.on('data', function(chunk) { out.push(Buffer.from(chunk)); });
            gunzip.on('error', function(err) { resolve(err.code || err.message); });
            gunzip.on('end', function() { resolve(Buffer.concat(out).toString()); });
            if (split) {
              gunzip.write(member);
              gunzip.end(tail);
            } else {
              gunzip.end(Buffer.concat([member, tail]));
            }
          });
        }

        function paddingThenGarbage() {
          return new Promise(function(resolve) {
            var gunzip = z.createGunzip();
            gunzip.on('error', function(err) { resolve(err.code || err.message); });
            gunzip.on('end', function() { resolve('unexpected-end'); });
            gunzip.write(member);
            gunzip.write(Buffer.from([0]));
            gunzip.end(evil);
          });
        }

        try {
          return JSON.stringify({
            syncZeros: sync(zeros),
            syncEvil: sync(evil),
            syncLenientEvil: syncLenient(evil),
            streamZerosTogether: await streamed(zeros, false),
            streamZerosSplit: await streamed(zeros, true),
            streamEvilTogether: await streamed(evil, false),
            streamEvilSplit: await streamed(evil, true),
            paddingThenGarbage: await paddingThenGarbage()
          });
        } finally {
          clearInterval(keepAlive);
        }
      })()"#;
    let result = eval(js).await;
    assert_eq!(
        result,
        r#"{"syncZeros":"payload","syncEvil":"Z_DATA_ERROR","syncLenientEvil":"Z_DATA_ERROR","streamZerosTogether":"payload","streamZerosSplit":"payload","streamEvilTogether":"Z_DATA_ERROR","streamEvilSplit":"Z_DATA_ERROR","paddingThenGarbage":"Z_DATA_ERROR"}"#,
        "gzip trailing bytes must be either valid zero padding or a new member: {result}"
    );
}

#[tokio::test]
async fn node_zlib_enforces_output_budget_inside_native_inflate() {
    let js = r#"(async function(){
        var z = require('zlib');
        var compressed = z.deflateSync(Buffer.alloc(1024 * 1024, 65));
        var direct;
        try {
          __exactInflateSync(compressed, 0, false, 0, undefined, 1024);
          direct = 'unexpected-success';
        } catch (err) {
          direct = String(err.message);
        }
        var directZero;
        try {
          __exactInflateSync(compressed, 0, false, 0, undefined, 0);
          directZero = 'unexpected-success';
        } catch (err) {
          directZero = String(err.message);
        }
        var sync;
        try {
          z.inflateSync(compressed, { maxOutputLength: 1024 });
          sync = 'unexpected-success';
        } catch (err) {
          sync = err.code || err.message;
        }
        var syncZero;
        try {
          z.inflateSync(compressed, { maxOutputLength: 0 });
          syncZero = 'unexpected-success';
        } catch (err) {
          syncZero = err.code || err.message;
        }
        var keepAlive = setInterval(function() {}, 1000);
        if (keepAlive && typeof keepAlive.ref === 'function') keepAlive.ref();
        try {
          var stream = await new Promise(function(resolve) {
            var inflate = z.createInflate({ maxOutputLength: 1024 });
            inflate.on('error', function(err) { resolve(err.code || err.message); });
            inflate.on('end', function() { resolve('unexpected-end'); });
            inflate.end(compressed);
          });
          return JSON.stringify({
            direct: direct.indexOf('zlib output exceeds maxOutputLength') !== -1,
            directZero: directZero.indexOf('zlib output exceeds maxOutputLength') !== -1,
            sync: sync,
            syncZero: syncZero,
            stream: stream
          });
        } finally {
          clearInterval(keepAlive);
        }
      })()"#;
    let result = eval(js).await;
    assert_eq!(
        result,
        r#"{"direct":true,"directZero":true,"sync":"ERR_BUFFER_TOO_LARGE","syncZero":"ERR_BUFFER_TOO_LARGE","stream":"ERR_BUFFER_TOO_LARGE"}"#,
        "one-shot and incremental inflate must enforce the native allocation budget: {result}"
    );
}

// Windows' replacement crypto translation unit installs deflate/inflate and
// streaming zlib, but it does not install the vendored Brotli host functions.
#[cfg(not(windows))]
#[tokio::test]
async fn node_brotli_enforces_output_budget_before_native_growth() {
    let js = r#"(async function(){
        var z = require('zlib');
        var compressed = z.brotliCompressSync(Buffer.alloc(1024 * 1024, 65));
        var direct;
        try {
          __exactBrotliDecompressSync(compressed, false, 0, 1024);
          direct = 'unexpected-success';
        } catch (err) {
          direct = String(err.message);
        }
        var directZero;
        try {
          __exactBrotliDecompressSync(compressed, false, 0, 0);
          directZero = 'unexpected-success';
        } catch (err) {
          directZero = String(err.message);
        }
        var sync;
        try {
          z.brotliDecompressSync(compressed, { maxOutputLength: 1024 });
          sync = 'unexpected-success';
        } catch (err) {
          sync = err.code || err.message;
        }
        var syncZero;
        try {
          z.brotliDecompressSync(compressed, { maxOutputLength: 0 });
          syncZero = 'unexpected-success';
        } catch (err) {
          syncZero = err.code || err.message;
        }
        var stream = await new Promise(function(resolve) {
          var decoder = z.createBrotliDecompress({ maxOutputLength: 1024 });
          decoder.on('error', function(err) { resolve(err.code || err.message); });
          decoder.on('end', function() { resolve('unexpected-end'); });
          decoder.end(compressed);
        });
        var streamZero = await new Promise(function(resolve) {
          var decoder = z.createBrotliDecompress({ maxOutputLength: 0 });
          decoder.on('error', function(err) { resolve(err.code || err.message); });
          decoder.on('end', function() { resolve('unexpected-end'); });
          decoder.end(compressed);
        });
        return JSON.stringify({
          direct: direct.indexOf('zlib output exceeds maxOutputLength') !== -1,
          directZero: directZero.indexOf('zlib output exceeds maxOutputLength') !== -1,
          sync: sync,
          syncZero: syncZero,
          stream: stream,
          streamZero: streamZero
        });
      })()"#;
    let result = eval(js).await;
    assert_eq!(
        result,
        r#"{"direct":true,"directZero":true,"sync":"ERR_BUFFER_TOO_LARGE","syncZero":"ERR_BUFFER_TOO_LARGE","stream":"ERR_BUFFER_TOO_LARGE","streamZero":"ERR_BUFFER_TOO_LARGE"}"#,
        "Brotli must enforce maxOutputLength before native allocation growth: {result}"
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
