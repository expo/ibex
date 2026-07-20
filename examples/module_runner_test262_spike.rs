use std::path::PathBuf;

use anyhow::{Context, Result};
use ibex_runtime::module_loader::producer_spike::generate_test262_artifact_bundle;

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let subset = PathBuf::from(
        args.next()
            .context("usage: module_runner_test262_spike SUBSET OUTPUT")?,
    );
    let output = PathBuf::from(
        args.next()
            .context("usage: module_runner_test262_spike SUBSET OUTPUT")?,
    );
    if args.next().is_some() {
        anyhow::bail!("usage: module_runner_test262_spike SUBSET OUTPUT");
    }
    let bundle = generate_test262_artifact_bundle(&subset)?;
    let rendered = serde_json::to_string_pretty(&bundle)? + "\n";
    std::fs::write(&output, rendered)
        .with_context(|| format!("write test262 artifacts {}", output.display()))?;
    Ok(())
}
