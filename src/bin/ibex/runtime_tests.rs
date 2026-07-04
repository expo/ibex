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
