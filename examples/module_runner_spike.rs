use std::path::PathBuf;

use anyhow::{Context, Result};
use ibex_runtime::module_loader::producer_spike::generate_spike_bundle;

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let manifest = PathBuf::from(
        args.next()
            .context("usage: module_runner_spike MANIFEST OUTPUT")?,
    );
    let output = PathBuf::from(
        args.next()
            .context("usage: module_runner_spike MANIFEST OUTPUT")?,
    );
    if args.next().is_some() {
        anyhow::bail!("usage: module_runner_spike MANIFEST OUTPUT");
    }
    let bundle = generate_spike_bundle(&manifest)?;
    let rendered = serde_json::to_string_pretty(&bundle)? + "\n";
    std::fs::write(&output, rendered)
        .with_context(|| format!("write canonical artifacts {}", output.display()))?;
    Ok(())
}
