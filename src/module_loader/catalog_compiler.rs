//! Catalog-authenticated hermesc execution for single-file carrier production.
//!
//! The caller can reach this module only after the catalog has admitted the
//! compiler bytes, unsigned stub, and release contract as one target tuple.
//! The invocation recipe is fixed and digest-bound; emitted HBC metadata is
//! inspected rather than accepted from the process or caller.
//! @ref LLP 0029#1-command-surface-and-producer-pipeline — release HBC uses the
//! catalog-paired compiler and binds the target stub's engine identity.

use std::io::Write as _;
use std::process::{Command, Stdio};

use anyhow::{bail, Context as _, Result};
use capsec_semantics::model::Digest;
use ibex_sfe_catalog::AdmittedCatalogTargetV1;
use ibex_sfe_format::{EngineCompatibilityV1, HermescCompatibilityV1, HermescRecipeV1};

use super::carrier::{
    HermesBytecodeMetadataV1, PreparedCarrierEncodingV2, PreparedCarrierEngineBindingV2,
    PreparedModuleCarrierV2,
};
#[cfg(any(test, feature = "module-runner"))]
use super::runner_pipeline::{EmbeddedPreparedCarrierV1, PreparedEmbeddedSourceGraphV1};

/// Compile every per-module carrier in one authenticated embedded graph with
/// the single catalog-paired compiler/engine tuple. Pair ids and the embedded
/// graph remain unchanged because HBC is a physical carrier encoding; each
/// manifest rotates its payload digest and engine binding after inspection.
/// @ref LLP 0029#1-command-surface-and-producer-pipeline
#[cfg(any(test, feature = "module-runner"))]
pub fn compile_catalog_embedded_graph_to_hbc(
    target: &AdmittedCatalogTargetV1<'_>,
    source: PreparedEmbeddedSourceGraphV1,
) -> Result<PreparedEmbeddedSourceGraphV1> {
    let carriers = source
        .carriers
        .into_iter()
        .map(|carrier| {
            let (manifest, payload) =
                compile_catalog_carrier_to_hbc(target, &carrier.manifest, &carrier.payload)?;
            Ok(EmbeddedPreparedCarrierV1 {
                pair_id: carrier.pair_id,
                manifest,
                payload,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PreparedEmbeddedSourceGraphV1 {
        graph: source.graph,
        carriers,
        candidate_tables: source.candidate_tables,
    })
}

pub fn compile_catalog_carrier_to_hbc(
    target: &AdmittedCatalogTargetV1<'_>,
    source_manifest: &PreparedModuleCarrierV2,
    factory_table_source: &[u8],
) -> Result<(PreparedModuleCarrierV2, Vec<u8>)> {
    if source_manifest.encoding != PreparedCarrierEncodingV2::JavascriptFactoryTable {
        bail!("catalog hermesc input must be a JavaScript factory-table carrier");
    }
    std::str::from_utf8(factory_table_source)
        .context("catalog hermesc input is not UTF-8 JavaScript")?;
    let recipe_digest = HermescRecipeV1::production()
        .digest()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let HermescCompatibilityV1::CatalogArtifact {
        hbc_version,
        recipe_digest: contract_recipe,
        ..
    } = &target.contract.hermesc
    else {
        bail!("admitted catalog target has no release hermesc identity");
    };
    if contract_recipe != &recipe_digest || *hbc_version != target.entry.hbc_version {
        bail!("catalog hermesc contract disagrees with the fixed production recipe");
    }
    let EngineCompatibilityV1::StaticHermes {
        hbc_version: engine_hbc_version,
        ..
    } = &target.contract.engine
    else {
        bail!("admitted catalog target has no static Hermes engine identity");
    };
    if engine_hbc_version != hbc_version {
        bail!("catalog compiler and static engine HBC versions disagree");
    }

    let hbc = run_fixed_hermesc(target.hermesc, factory_table_source)?;
    let metadata = HermesBytecodeMetadataV1::inspect(&hbc)?;
    if metadata.bytecode_version != *hbc_version {
        bail!(
            "catalog hermesc emitted HBC version {} but the target contract requires {}",
            metadata.bytecode_version,
            hbc_version
        );
    }
    let binding = PreparedCarrierEngineBindingV2::StaticCompatibility {
        compatibility_identity: Digest::new(target.entry.engine_compatibility_identity.clone())
            .map_err(anyhow::Error::msg)?,
    };
    let manifest = source_manifest.bind_hermes_bytecode(&hbc, binding)?;
    Ok((manifest, hbc))
}

fn run_fixed_hermesc(hermesc: &[u8], source: &[u8]) -> Result<Vec<u8>> {
    let directory = tempfile::Builder::new()
        .prefix("ibex-catalog-hermesc-")
        .tempdir()
        .context("cannot create private hermesc work directory")?;
    let compiler = directory.path().join(if cfg!(windows) {
        "hermesc.exe"
    } else {
        "hermesc"
    });
    let input = directory.path().join("carrier.js");
    let output = directory.path().join("carrier.hbc");

    write_new(&compiler, hermesc)?;
    write_new(&input, source)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o500))
            .context("cannot make catalog hermesc executable")?;
    }

    let result = Command::new(&compiler)
        .arg("-emit-binary")
        .arg("-out")
        .arg(&output)
        .arg(&input)
        .env_clear()
        .current_dir(directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("catalog hermesc could not be executed")?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let bounded = stderr.chars().take(4096).collect::<String>();
        bail!("catalog hermesc refused the carrier: {bounded}");
    }
    let bytes = std::fs::read(&output).context("catalog hermesc produced no HBC output")?;
    if bytes.is_empty() {
        bail!("catalog hermesc produced empty HBC output");
    }
    Ok(bytes)
}

fn write_new(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("cannot create private compiler input {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("cannot write private compiler input {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot sync private compiler input {}", path.display()))?;
    Ok(())
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::*;

    #[test]
    fn fixed_recipe_emits_inspectable_real_hbc() {
        let compiler = std::env::var_os("HERMESC")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tools/hermes/hermesc-macos-arm64")
            });
        let compiler = std::fs::read(compiler).expect("checked-in macOS hermesc");
        let hbc = run_fixed_hermesc(
            &compiler,
            b"(function(){return Object.freeze(Object.create(null));})()",
        )
        .unwrap();
        let metadata = HermesBytecodeMetadataV1::inspect(&hbc).unwrap();
        assert_eq!(metadata.file_length as usize, hbc.len());
        assert!(metadata.bytecode_version > 0);
    }
}
