//! Internal assembler/verifier for the release policy-authoring support tree.
//! @ref LLP 0047#8-milestone-5--distribution-and-usability

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use ibex_sfe_catalog::policy_toolchain::{
    admit_policy_toolchain_directory, PolicyToolchainManifestV1, POLICY_TOOLCHAIN_MANIFEST,
};

struct Arguments {
    root: PathBuf,
    target: String,
    runner: PathBuf,
    script: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ibex-sfe-policy-toolchain: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = parse_arguments(std::env::args_os().skip(1))?;
    let manifest = PolicyToolchainManifestV1::assemble(
        &arguments.root,
        &arguments.target,
        &arguments.runner,
        &arguments.script,
    )?;
    let manifest_path = arguments.root.join(POLICY_TOOLCHAIN_MANIFEST);
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .with_context(|| format!("cannot create {}", manifest_path.display()))?;
    output.write_all(&manifest.canonical_bytes()?)?;
    let admitted = admit_policy_toolchain_directory(
        &arguments.root,
        &manifest.toolchain_digest,
        &arguments.target,
    )?;
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "toolchainDigest": admitted.digest,
            "toolchainRoot": admitted.root,
            "target": admitted.target,
            "entryCount": admitted.entry_count,
        }))?
    );
    Ok(())
}

fn parse_arguments(arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<Arguments> {
    let mut arguments = arguments;
    let mut root = None;
    let mut target = None;
    let mut runner = None;
    let mut script = None;
    while let Some(argument) = arguments.next() {
        let name = argument
            .into_string()
            .map_err(|_| anyhow::anyhow!("argument names must be Unicode"))?;
        let value = arguments
            .next()
            .with_context(|| format!("{name} requires a value"))?;
        match name.as_str() {
            "--root" => root = Some(PathBuf::from(value)),
            "--target" => {
                target = Some(
                    value
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("--target must be Unicode"))?,
                )
            }
            "--runner" => runner = Some(PathBuf::from(value)),
            "--script" => script = Some(PathBuf::from(value)),
            _ => bail!("unknown argument {name:?}"),
        }
    }
    Ok(Arguments {
        root: root.context("--root is required")?,
        target: target.context("--target is required")?,
        runner: runner.context("--runner is required")?,
        script: script.context("--script is required")?,
    })
}
