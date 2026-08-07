//! Internal release-catalog assembler and content-addressed installer.
//!
//! It accepts a canonical release contract plus the exact stub/compiler bytes,
//! derives the manifest, self-admits the complete target, and publishes one
//! immutable digest-addressed catalog directory.
//! @ref LLP 0029#2-executable-layout-stub-envelope-footer

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ibex_sfe_catalog::app_bound::{CatalogManifestV2, PinnedCatalogV2};
use ibex_sfe_catalog::{
    install_pinned_catalog_directory, CatalogManifestV1, CatalogTargetArtifacts, PinnedCatalogV1,
};

const RELEASE_CATALOG_DIGEST: Option<&str> = match option_env!("IBEX_RELEASE_SFE_CATALOG_DIGEST") {
    Some(value) => Some(value),
    None => option_env!("IBEX_RELEASE_APP_SFE_CATALOG_DIGEST"),
};

struct Arguments {
    release: String,
    sequence: u64,
    contract: PathBuf,
    stub: PathBuf,
    hermesc: PathBuf,
    catalogs_dir: PathBuf,
    advertisement: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ibex-sfe-catalog: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut raw_arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if raw_arguments
        .first()
        .is_some_and(|argument| argument == "install")
    {
        raw_arguments.remove(0);
        return install(parse_install_arguments(raw_arguments.into_iter())?);
    }
    if raw_arguments
        .first()
        .is_some_and(|argument| argument == "assemble")
    {
        raw_arguments.remove(0);
    }
    let arguments = parse_arguments(raw_arguments.into_iter())?;
    let contract = read_regular(&arguments.contract, "stub contract")?;
    let stub = read_regular(&arguments.stub, "unsigned stub core")?;
    let hermesc = read_regular(&arguments.hermesc, "hermesc")?;
    let advertisement = arguments
        .advertisement
        .as_ref()
        .map(|path| read_regular(path, "restricted-worker target advertisement"))
        .transpose()?;
    let (manifest_bytes, catalog_digest) = if let Some(advertisement) = &advertisement {
        let manifest = CatalogManifestV2::from_target_artifacts(
            arguments.release,
            arguments.sequence,
            &contract,
            &stub,
            &hermesc,
            advertisement,
        )?;
        (manifest.canonical_bytes()?, manifest.digest()?)
    } else {
        let manifest = CatalogManifestV1::from_target_artifacts(
            arguments.release,
            arguments.sequence,
            &contract,
            &stub,
            &hermesc,
        )?;
        (manifest.canonical_bytes()?, manifest.digest()?)
    };
    let key = catalog_digest
        .strip_prefix("sha256-")
        .context("catalog digest has no sha256 prefix")?;
    std::fs::create_dir_all(&arguments.catalogs_dir).with_context(|| {
        format!(
            "cannot create catalog store {}",
            arguments.catalogs_dir.display()
        )
    })?;
    let final_root = arguments.catalogs_dir.join(key);
    if final_root.exists() {
        verify_catalog_root(&final_root, &catalog_digest)?;
        print_result(&catalog_digest, &final_root)?;
        return Ok(());
    }

    let staging = tempfile::Builder::new()
        .prefix(".ibex-sfe-catalog-")
        .tempdir_in(&arguments.catalogs_dir)
        .context("cannot create catalog staging directory")?;
    write_new(&staging.path().join("manifest.json"), &manifest_bytes)?;
    let value: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    let entry = &value["entries"][0];
    for (artifact, bytes) in [
        (&entry["contract"], contract.as_slice()),
        (&entry["stubUnsignedCore"], stub.as_slice()),
        (&entry["hermesc"], hermesc.as_slice()),
    ] {
        write_json_artifact(staging.path(), artifact, bytes)?;
    }
    if let Some(advertisement) = &advertisement {
        write_json_artifact(
            staging.path(),
            &entry["restrictedWorkerTarget"]["artifact"],
            advertisement,
        )?;
    }
    verify_catalog_root(staging.path(), &catalog_digest)?;
    let staging_path = staging.keep();
    std::fs::rename(&staging_path, &final_root).with_context(|| {
        format!(
            "cannot publish catalog {} to {}",
            staging_path.display(),
            final_root.display()
        )
    })?;
    print_result(&catalog_digest, &final_root)
}

struct InstallArguments {
    source: PathBuf,
    catalogs_dir: Option<PathBuf>,
}

fn install(arguments: InstallArguments) -> Result<()> {
    let expected_digest = RELEASE_CATALOG_DIGEST.context(
        "SFC001 catalog trust root refused: catalog installation requires the ibex-sfe-catalog binary shipped with a catalog-pinned Ibex release",
    )?;
    let catalogs_dir = match arguments.catalogs_dir {
        Some(path) => path,
        None => dirs::cache_dir()
            .context("cannot locate the user cache directory")?
            .join("ibex")
            .join("sfe-catalogs"),
    };
    let root = install_pinned_catalog_directory(&arguments.source, &catalogs_dir, expected_digest)?;
    print_result(expected_digest, &root)
}

fn parse_install_arguments(
    arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<InstallArguments> {
    let mut arguments = arguments;
    let mut source = None;
    let mut catalogs_dir = None;
    while let Some(argument) = arguments.next() {
        let name = argument
            .into_string()
            .map_err(|_| anyhow::anyhow!("argument names must be Unicode"))?;
        let value = arguments
            .next()
            .with_context(|| format!("{name} requires a value"))?;
        match name.as_str() {
            "--source" => source = Some(PathBuf::from(value)),
            "--catalogs-dir" => catalogs_dir = Some(PathBuf::from(value)),
            _ => bail!("unknown install argument {name:?}"),
        }
    }
    Ok(InstallArguments {
        source: source.context("install --source is required")?,
        catalogs_dir,
    })
}

fn parse_arguments(arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<Arguments> {
    let mut arguments = arguments;
    let mut release = None;
    let mut sequence = None;
    let mut contract = None;
    let mut stub = None;
    let mut hermesc = None;
    let mut catalogs_dir = None;
    let mut advertisement = None;
    while let Some(argument) = arguments.next() {
        let name = argument
            .into_string()
            .map_err(|_| anyhow::anyhow!("argument names must be Unicode"))?;
        let value = arguments
            .next()
            .with_context(|| format!("{name} requires a value"))?;
        match name.as_str() {
            "--release" => {
                release = Some(
                    value
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("--release must be Unicode"))?,
                )
            }
            "--sequence" => {
                sequence = Some(
                    value
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("--sequence must be Unicode"))?
                        .parse::<u64>()
                        .context("--sequence must be an unsigned integer")?,
                )
            }
            "--contract" => contract = Some(PathBuf::from(value)),
            "--stub" => stub = Some(PathBuf::from(value)),
            "--hermesc" => hermesc = Some(PathBuf::from(value)),
            "--catalogs-dir" => catalogs_dir = Some(PathBuf::from(value)),
            "--advertisement" => advertisement = Some(PathBuf::from(value)),
            _ => bail!("unknown argument {name:?}"),
        }
    }
    let release = release.context("--release is required")?;
    if release.is_empty() {
        bail!("--release must not be empty");
    }
    Ok(Arguments {
        release,
        sequence: sequence.context("--sequence is required")?,
        contract: contract.context("--contract is required")?,
        stub: stub.context("--stub is required")?,
        hermesc: hermesc.context("--hermesc is required")?,
        catalogs_dir: catalogs_dir.context("--catalogs-dir is required")?,
        advertisement,
    })
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{label} is not a regular file: {}", path.display());
    }
    std::fs::read(path).with_context(|| format!("cannot read {label} {}", path.display()))
}

fn write_json_artifact(root: &Path, artifact: &serde_json::Value, bytes: &[u8]) -> Result<()> {
    let digest = artifact["digest"]
        .as_str()
        .context("catalog artifact digest is absent")?;
    let key = digest
        .strip_prefix("sha256-")
        .context("catalog artifact digest is malformed")?;
    let path = root.join(format!("sha256/{key}/blob"));
    let parent = path.parent().context("catalog artifact has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("cannot create artifact directory {}", parent.display()))?;
    write_new(&path, bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    output
        .write_all(bytes)
        .with_context(|| format!("cannot write {}", path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("cannot sync {}", path.display()))
}

fn verify_catalog_root(root: &Path, expected_digest: &str) -> Result<()> {
    let manifest_bytes = read_regular(&root.join("manifest.json"), "catalog manifest")?;
    let schema = serde_json::from_slice::<serde_json::Value>(&manifest_bytes)?["schema"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    if schema == ibex_sfe_catalog::app_bound::CATALOG_SCHEMA_V2 {
        let catalog = PinnedCatalogV2::load(&manifest_bytes, expected_digest)?;
        if catalog.manifest().entries.len() != 1 {
            bail!("catalog assembler currently requires exactly one target entry");
        }
        let entry = &catalog.manifest().entries[0];
        let content_path = |digest: &str| -> Result<PathBuf> {
            let key = digest
                .strip_prefix("sha256-")
                .context("artifact digest is malformed")?;
            Ok(root.join(format!("sha256/{key}/blob")))
        };
        let contract = read_regular(
            &content_path(&entry.contract.digest)?,
            "catalog contract artifact",
        )?;
        let stub = read_regular(
            &content_path(&entry.stub_unsigned_core.digest)?,
            "catalog stub artifact",
        )?;
        let hermesc = read_regular(
            &content_path(&entry.hermesc.digest)?,
            "catalog compiler artifact",
        )?;
        let worker = entry
            .restricted_worker_target
            .as_ref()
            .context("V2 catalog worker row is absent")?;
        let advertisement = read_regular(
            &content_path(&worker.artifact.digest)?,
            "target advertisement artifact",
        )?;
        catalog.admit_target(&entry.target, &contract, &stub, &hermesc, &advertisement)?;
        return Ok(());
    }
    let catalog = PinnedCatalogV1::load(&manifest_bytes, expected_digest)?;
    if catalog.manifest().entries.len() != 1 {
        bail!("catalog assembler currently requires exactly one target entry");
    }
    let entry = &catalog.manifest().entries[0];
    let contract = read_regular(
        &root.join(entry.contract.content_address()?),
        "catalog contract artifact",
    )?;
    let stub = read_regular(
        &root.join(entry.stub_unsigned_core.content_address()?),
        "catalog stub artifact",
    )?;
    let hermesc = read_regular(
        &root.join(entry.hermesc.content_address()?),
        "catalog compiler artifact",
    )?;
    catalog.admit_target(
        &entry.target,
        CatalogTargetArtifacts {
            contract: &contract,
            stub_unsigned_core: &stub,
            hermesc: &hermesc,
        },
    )?;
    Ok(())
}

fn print_result(digest: &str, root: &Path) -> Result<()> {
    let value = serde_json::json!({
        "catalogDigest": digest,
        "catalogRoot": root,
    });
    let bytes = capsec_semantics::canonical::to_jcs_bytes(&value).map_err(anyhow::Error::msg)?;
    println!("{}", std::str::from_utf8(&bytes).expect("JCS is UTF-8"));
    Ok(())
}
