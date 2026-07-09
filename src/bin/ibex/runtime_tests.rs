//! Hidden in-binary smoke tests for `ibex self-test`.

use crate::cli::Cli;
use crate::runtime::Runtime;
use anyhow::{bail, Context, Result};

pub async fn run_all(cli: &Cli) -> Result<()> {
    let runtime = Runtime::from_cli(cli).context("create runtime")?;
    runtime.load_runtime().await.context("load runtime")?;

    expect_eval(&runtime, "1 + 1", "2", "eval arithmetic").await?;

    // Windows skip reason (audited for ENG-23705): these rows need the
    // embedded node-compat runtime, which is disabled on Windows
    // (`use_embedded_runtime = ... && !cfg!(windows)` in engine/hermes.rs) —
    // unrelated to the ENG-23639 console-flush fix that un-gated the
    // timer-driven TLS oracle tests.
    if !cfg!(windows) {
        expect_eval(
            &runtime,
            "typeof require === 'function'",
            "true",
            "CommonJS loader installed",
        )
        .await?;
        expect_eval(
            &runtime,
            "process.release && process.release.name",
            "node",
            "Node-compatible process identity",
        )
        .await?;
        expect_eval(
            &runtime,
            "typeof process.env === 'object' && process.env !== null",
            "true",
            "process.env initialized",
        )
        .await?;
        expect_eval(
            &runtime,
            "Buffer.from('ibex').toString('utf8')",
            "ibex",
            "Buffer builtin",
        )
        .await?;
        expect_eval(
            &runtime,
            "require('node:path').basename('/tmp/ibex.txt')",
            "ibex.txt",
            "node:path builtin",
        )
        .await?;
        expect_eval(
            &runtime,
            "typeof require('node:events').EventEmitter",
            "function",
            "node:events builtin",
        )
        .await?;

        // LLP 0297 W3: the async host-call channel. Kick each promise off in
        // one eval (whose event-loop drive delivers the resolution) and read
        // the settled outcome in the next.
        expect_eval(
            &runtime,
            "typeof __hostCallAsync === 'function' ? 'true' : 'false'",
            "true",
            "__hostCallAsync installed",
        )
        .await?;
        expect_eval(
            &runtime,
            "globalThis.__hcAsyncResolve = 'pending'; \
             __hostCallAsync('agent.captureScreenshot', '{}').then(\
                 function(r) { globalThis.__hcAsyncResolve = 'ok:' + (r && typeof r.error === 'string'); },\
                 function() { globalThis.__hcAsyncResolve = 'rejected'; }); 'kicked'",
            "kicked",
            "async host-call resolve kickoff",
        )
        .await?;
        expect_eval(
            &runtime,
            "globalThis.__hcAsyncResolve",
            "ok:true",
            "async host-call resolve path",
        )
        .await?;
        expect_eval(
            &runtime,
            "globalThis.__hcAsyncReject = 'pending'; \
             __hostCallAsync('selftest.unknown-op', '{}').then(\
                 function() { globalThis.__hcAsyncReject = 'resolved'; },\
                 function(e) { globalThis.__hcAsyncReject = (e && typeof e.message === 'string' && e.message.indexOf('Unknown host call') !== -1) ? 'rejected-with-message' : 'rejected-odd'; }); 'kicked'",
            "kicked",
            "async host-call reject kickoff",
        )
        .await?;
        expect_eval(
            &runtime,
            "globalThis.__hcAsyncReject",
            "rejected-with-message",
            "async host-call reject path",
        )
        .await?;

        // ENG-22885: raw callers pass objects (not pre-stringified JSON) and
        // omit args entirely; the bridge must coerce instead of throwing
        // synchronously before the promise exists.
        expect_eval(
            &runtime,
            "globalThis.__hcAsyncObjArgs = 'pending'; \
             __hostCallAsync('selftest.echoArgs', { a: 1, b: 'two' }).then(\
                 function(r) { globalThis.__hcAsyncObjArgs = r && r.received; },\
                 function(e) { globalThis.__hcAsyncObjArgs = 'rejected:' + (e && e.message); }); 'kicked'",
            "kicked",
            "async host-call object-args kickoff",
        )
        .await?;
        expect_eval(
            &runtime,
            "globalThis.__hcAsyncObjArgs",
            "{\"a\":1,\"b\":\"two\"}",
            "async host-call object args are JSON.stringify'd",
        )
        .await?;
        expect_eval(
            &runtime,
            "globalThis.__hcAsyncNoArgs = 'pending'; \
             __hostCallAsync('selftest.echoArgs').then(\
                 function(r) { globalThis.__hcAsyncNoArgs = r && r.received; },\
                 function(e) { globalThis.__hcAsyncNoArgs = 'rejected:' + (e && e.message); }); 'kicked'",
            "kicked",
            "async host-call omitted-args kickoff",
        )
        .await?;
        expect_eval(
            &runtime,
            "globalThis.__hcAsyncNoArgs",
            "{}",
            "async host-call omitted args default to {}",
        )
        .await?;
        expect_eval(
            &runtime,
            "(function(){ try { var r = __hostCall('selftest.echoArgs', { sync: true }); return r && r.received; } catch (e) { return 'threw:' + (e && e.message); } })()",
            "{\"sync\":true}",
            "sync host-call object args are JSON.stringify'd",
        )
        .await?;

        // ENG-22995: async native DNS bridge. dns.lookup/resolve/reverse now
        // dispatch the blocking resolver call to a worker pool and resolve on
        // the event loop, so a slow lookup never freezes timers/other I/O.
        // DNS host functions install lazily on first require('dns'), so trigger
        // the load before probing for the async bridge.
        expect_eval(
            &runtime,
            "(function(){ require('dns'); return (typeof __exactDnsLookupAsync === 'function' && typeof __exactDnsResolveAsync === 'function' && typeof __exactDnsReverseAsync === 'function') ? 'true' : 'false'; })()",
            "true",
            "async DNS host functions installed",
        )
        .await?;
        // Kick a localhost lookup plus a concurrent timer, then read the
        // settled state in the next eval (whose event-loop drive delivers the
        // off-thread resolution). The synchronous marker must precede the
        // callback, proving dispatch does not block the caller.
        expect_eval(
            &runtime,
            "globalThis.__dnsProbe = { order: [], result: 'pending' }; \
             var __dns = require('dns'); \
             __dns.lookup('localhost', { family: 4 }, function(err, addr) { \
                 globalThis.__dnsProbe.order.push('dns'); \
                 globalThis.__dnsProbe.result = err ? ('err:' + err.code) : addr; }); \
             setTimeout(function() { globalThis.__dnsProbe.order.push('timer'); }, 0); \
             globalThis.__dnsProbe.order.push('sync'); 'kicked'",
            "kicked",
            "async dns.lookup kickoff",
        )
        .await?;
        expect_eval(
            &runtime,
            "globalThis.__dnsProbe.result",
            "127.0.0.1",
            "async dns.lookup resolves localhost off-thread",
        )
        .await?;
        expect_eval(
            &runtime,
            "(globalThis.__dnsProbe.order[0] === 'sync' \
              && globalThis.__dnsProbe.order.indexOf('timer') !== -1 \
              && globalThis.__dnsProbe.order.indexOf('dns') !== -1) ? 'ok' : globalThis.__dnsProbe.order.join(',')",
            "ok",
            "dns.lookup callback is async; timer fires without being blocked",
        )
        .await?;
        // dns/promises rides the same async path.
        expect_eval(
            &runtime,
            "globalThis.__dnsPromise = 'pending'; \
             require('dns').promises.lookup('localhost', { family: 4 }).then(\
                 function(r) { globalThis.__dnsPromise = r && r.address; },\
                 function(e) { globalThis.__dnsPromise = 'rejected:' + (e && e.code); }); 'kicked'",
            "kicked",
            "async dns.promises.lookup kickoff",
        )
        .await?;
        expect_eval(
            &runtime,
            "globalThis.__dnsPromise",
            "127.0.0.1",
            "dns.promises.lookup resolves via the async path",
        )
        .await?;
    }

    eprintln!("ibex self-test OK");
    Ok(())
}

async fn expect_eval(runtime: &Runtime, code: &str, expected: &str, label: &str) -> Result<()> {
    let actual = runtime
        .eval(code)
        .await
        .with_context(|| format!("{label}: eval failed"))?
        .unwrap_or_default();

    if actual != expected {
        bail!("{label}: expected {expected:?}, got {actual:?}");
    }

    Ok(())
}
