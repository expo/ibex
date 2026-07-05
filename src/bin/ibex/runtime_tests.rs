//! Hidden in-binary smoke tests for `ibex self-test`.

use crate::cli::Cli;
use crate::runtime::Runtime;
use anyhow::{bail, Context, Result};

pub async fn run_all(cli: &Cli) -> Result<()> {
    let runtime = Runtime::from_cli(cli).context("create runtime")?;
    runtime.load_runtime().await.context("load runtime")?;

    expect_eval(&runtime, "1 + 1", "2", "eval arithmetic").await?;

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
