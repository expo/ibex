//! Internal release-stub contract builder.
//!
//! Target/platform and static-archive provenance remain explicit release-build
//! inputs. Compiler and VM HBC versions and compiler bytes are derived here so
//! a caller cannot relabel them while constructing the catalog contract.
//! @ref LLP 0029#2-executable-layout-stub-envelope-footer

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ibex_runtime::compiled_contract::{
    release_app_bound_stub_contract, release_stub_contract, ReleaseExternalWorkerFactsV1,
    ReleaseStubFactsV1,
};
use ibex_runtime::module_loader::artifact::source_integrity;
use ibex_sfe_format::app_bound::{
    LimitsV1, TargetAdvertisementV1, TargetEvidenceV1, RESTRICTED_WORKER_ABI_V1,
    RESTRICTED_WORKER_BROKER_V1, RESTRICTED_WORKER_GLOBAL_INVENTORY_DOMAIN_V1,
    RESTRICTED_WORKER_LANGUAGE_PROFILE_DOMAIN_V1, RESTRICTED_WORKER_LANGUAGE_PROFILE_V1,
    RESTRICTED_WORKER_POLICY_DOMAIN_V1, RESTRICTED_WORKER_POLICY_V1,
    TARGET_ADVERTISEMENT_SCHEMA_V1, TARGET_EVIDENCE_SCHEMA_V1,
};
use ibex_sfe_format::HermescRecipeV1;

struct Arguments {
    target: String,
    minimum_platform: String,
    engine_profile: String,
    static_archives: Vec<(String, PathBuf)>,
    hermesc: PathBuf,
    hermes: PathBuf,
    output: PathBuf,
    advertisement_output: Option<PathBuf>,
    worker_profile: Option<PathBuf>,
    worker_policy: Option<PathBuf>,
    worker_global_inventory: Option<PathBuf>,
    worker_suite: Option<PathBuf>,
    worker_broker_corpus: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ibex-sfe-contract: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let arguments = parse_arguments(std::env::args_os().skip(1))?;
    let hermesc = read_regular(&arguments.hermesc, "hermesc")?;
    let (static_archive_digest, static_archive_bundle) =
        archive_bundle_digest(&arguments.static_archives)?;
    let compiler_hbc = hbc_version(&arguments.hermesc, "hermesc")?;
    let runtime_hbc = hbc_version(&arguments.hermes, "Hermes VM")?;
    if compiler_hbc != runtime_hbc {
        bail!(
            "Hermes compiler/runtime HBC mismatch: hermesc {compiler_hbc}, runtime {runtime_hbc}"
        );
    }
    let facts = ReleaseStubFactsV1 {
        profile: "sfe-v1".into(),
        target_triple: arguments.target.clone(),
        minimum_platform: arguments.minimum_platform.clone(),
        engine_build_profile: arguments.engine_profile,
        static_archive_digest: static_archive_digest.as_str().into(),
        hbc_version: compiler_hbc,
        hermesc_binary_digest: source_integrity(&hermesc)?.as_str().into(),
        hermesc_recipe_digest: HermescRecipeV1::production().digest()?,
    };
    let (bytes, contract_digest, contract_target, advertisement_digest) =
        if let Some(advertisement_output) = arguments.advertisement_output.as_ref() {
            let profile = semantic_artifact(
                required_path(&arguments.worker_profile, "--worker-profile")?,
                RESTRICTED_WORKER_LANGUAGE_PROFILE_V1,
                RESTRICTED_WORKER_LANGUAGE_PROFILE_DOMAIN_V1,
            )?;
            let policy = semantic_artifact(
                required_path(&arguments.worker_policy, "--worker-policy")?,
                RESTRICTED_WORKER_POLICY_V1,
                RESTRICTED_WORKER_POLICY_DOMAIN_V1,
            )?;
            let inventory = semantic_artifact(
                required_path(
                    &arguments.worker_global_inventory,
                    "--worker-global-inventory",
                )?,
                "ibex/restricted-worker-global-inventory/1",
                RESTRICTED_WORKER_GLOBAL_INVENTORY_DOMAIN_V1,
            )?;
            let base = release_stub_contract(facts.clone())?;
            let advertisement = TargetAdvertisementV1 {
                schema: TARGET_ADVERTISEMENT_SCHEMA_V1.into(),
                target: base.target.clone(),
                engine_compatibility_digest: base.engine.identity().into(),
                native_abi: RESTRICTED_WORKER_ABI_V1.into(),
                language_profile: RESTRICTED_WORKER_LANGUAGE_PROFILE_V1.into(),
                language_profile_digest: profile,
                worker_policy: RESTRICTED_WORKER_POLICY_V1.into(),
                worker_policy_digest: policy.clone(),
                broker_protocol: RESTRICTED_WORKER_BROKER_V1.into(),
                global_inventory_digest: inventory,
                defaults_digest: LimitsV1::defaults().digest()?,
                maxima_digest: LimitsV1::maxima().digest()?,
                evidence: TargetEvidenceV1 {
                    schema: TARGET_EVIDENCE_SCHEMA_V1.into(),
                    suite_digest: source_integrity(&read_regular(
                        required_path(&arguments.worker_suite, "--worker-suite")?,
                        "restricted-worker suite",
                    )?)?
                    .as_str()
                    .into(),
                    engine_artifact_digest: source_integrity(&read_regular(
                        &arguments.hermes,
                        "Hermes VM",
                    )?)?
                    .as_str()
                    .into(),
                    policy_artifact_digest: source_integrity(&read_regular(
                        required_path(&arguments.worker_policy, "--worker-policy")?,
                        "restricted-worker policy",
                    )?)?
                    .as_str()
                    .into(),
                    broker_corpus_digest: source_integrity(&read_regular(
                        required_path(&arguments.worker_broker_corpus, "--worker-broker-corpus")?,
                        "restricted-worker broker corpus",
                    )?)?
                    .as_str()
                    .into(),
                },
            };
            let advertisement_bytes = advertisement.canonical_bytes()?;
            write_if_absent_or_equal(advertisement_output, &advertisement_bytes)?;
            let advertisement_digest = advertisement.digest()?;
            let contract = release_app_bound_stub_contract(
                facts,
                ReleaseExternalWorkerFactsV1 {
                    language_profile_digest: advertisement.language_profile_digest.clone(),
                    worker_policy_digest: policy,
                    global_inventory_digest: advertisement.global_inventory_digest.clone(),
                    target_advertisement_digest: advertisement_digest.clone(),
                },
            )?;
            (
                contract.canonical_bytes()?,
                contract.digest()?,
                contract.target.triple.clone(),
                Some(advertisement_digest),
            )
        } else {
            let contract = release_stub_contract(facts)?;
            (
                contract.canonical_bytes()?,
                contract.digest()?,
                contract.target.triple.clone(),
                None,
            )
        };
    write_if_absent_or_equal(&arguments.output, &bytes)?;
    let report = serde_json::json!({
        "contractDigest": contract_digest,
        "staticArchiveBundle": static_archive_bundle,
        "staticArchiveBundleDigest": static_archive_digest,
        "hbcVersion": compiler_hbc,
        "output": arguments.output,
        "target": contract_target,
        "targetAdvertisementDigest": advertisement_digest,
    });
    let report = capsec_semantics::canonical::to_jcs_bytes(&report).map_err(anyhow::Error::msg)?;
    println!("{}", std::str::from_utf8(&report).expect("JCS is UTF-8"));
    Ok(())
}

fn parse_arguments(arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<Arguments> {
    let mut arguments = arguments;
    let mut target = None;
    let mut minimum_platform = None;
    let mut engine_profile = None;
    let mut static_archives = Vec::new();
    let mut hermesc = None;
    let mut hermes = None;
    let mut output = None;
    let mut advertisement_output = None;
    let mut worker_profile = None;
    let mut worker_policy = None;
    let mut worker_global_inventory = None;
    let mut worker_suite = None;
    let mut worker_broker_corpus = None;
    while let Some(argument) = arguments.next() {
        let name = argument
            .into_string()
            .map_err(|_| anyhow::anyhow!("argument names must be Unicode"))?;
        if name == "--static-archive" {
            let role = arguments
                .next()
                .context("--static-archive requires a role and path")?;
            let role = unicode_value(role, "--static-archive role")?;
            if !role.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-')
            }) {
                bail!("--static-archive role must be lowercase ASCII kebab-case");
            }
            let path = arguments
                .next()
                .context("--static-archive requires a path after its role")?;
            static_archives.push((role, PathBuf::from(path)));
            continue;
        }
        let value = arguments
            .next()
            .with_context(|| format!("{name} requires a value"))?;
        match name.as_str() {
            "--target" => target = Some(unicode_value(value, "--target")?),
            "--minimum-platform" => {
                minimum_platform = Some(unicode_value(value, "--minimum-platform")?)
            }
            "--engine-profile" => engine_profile = Some(unicode_value(value, "--engine-profile")?),
            "--hermesc" => hermesc = Some(PathBuf::from(value)),
            "--hermes" => hermes = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            "--advertisement-output" => advertisement_output = Some(PathBuf::from(value)),
            "--worker-profile" => worker_profile = Some(PathBuf::from(value)),
            "--worker-policy" => worker_policy = Some(PathBuf::from(value)),
            "--worker-global-inventory" => worker_global_inventory = Some(PathBuf::from(value)),
            "--worker-suite" => worker_suite = Some(PathBuf::from(value)),
            "--worker-broker-corpus" => worker_broker_corpus = Some(PathBuf::from(value)),
            _ => bail!("unknown argument {name:?}"),
        }
    }
    Ok(Arguments {
        target: target.context("--target is required")?,
        minimum_platform: minimum_platform.context("--minimum-platform is required")?,
        engine_profile: engine_profile.context("--engine-profile is required")?,
        static_archives,
        hermesc: hermesc.context("--hermesc is required")?,
        hermes: hermes.context("--hermes is required")?,
        output: output.context("--output is required")?,
        advertisement_output,
        worker_profile,
        worker_policy,
        worker_global_inventory,
        worker_suite,
        worker_broker_corpus,
    })
}

fn required_path<'a>(value: &'a Option<PathBuf>, name: &str) -> Result<&'a Path> {
    value
        .as_deref()
        .with_context(|| format!("{name} is required with --advertisement-output"))
}

fn semantic_artifact(path: &Path, schema: &str, domain: &str) -> Result<String> {
    let bytes = read_regular(path, schema)?;
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{schema} is not UTF-8"))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .with_context(|| format!("{schema} is not strict JSON"))?;
    if value.get("schema").and_then(serde_json::Value::as_str) != Some(schema)
        || capsec_semantics::canonical::to_jcs_bytes(&value).map_err(anyhow::Error::msg)? != bytes
    {
        bail!("{schema} artifact is not exact canonical JCS with the required schema");
    }
    capsec_semantics::digest::compute_domain_digest(domain, &value, &[]).map_err(anyhow::Error::msg)
}

fn archive_bundle_digest(
    archives: &[(String, PathBuf)],
) -> Result<(capsec_semantics::model::Digest, serde_json::Value)> {
    if archives.is_empty() {
        bail!("at least one --static-archive <role> <path> is required");
    }
    let mut rows = archives
        .iter()
        .map(|(role, path)| {
            let bytes = read_regular(path, &format!("static archive {role}"))?;
            Ok(serde_json::json!({
                "role": role,
                "digest": source_integrity(&bytes)?,
                "size": bytes.len(),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    rows.sort_by(|left, right| left["role"].as_str().cmp(&right["role"].as_str()));
    if rows
        .windows(2)
        .any(|pair| pair[0]["role"] == pair[1]["role"])
    {
        bail!("static archive roles must be unique");
    }
    let value = serde_json::json!({
        "schema": "ibex/static-hermes-archive-bundle/1",
        "artifacts": rows,
    });
    let digest = capsec_semantics::digest::compute_domain_digest(
        "ibex:static-hermes-archive-bundle:1",
        &value,
        &[],
    )
    .map_err(anyhow::Error::msg)?;
    Ok((
        capsec_semantics::model::Digest::new(digest).map_err(anyhow::Error::msg)?,
        value,
    ))
}

fn unicode_value(value: std::ffi::OsString, name: &str) -> Result<String> {
    let value = value
        .into_string()
        .map_err(|_| anyhow::anyhow!("{name} must be Unicode"))?;
    if value.is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

fn read_regular(path: &Path, label: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{label} is not a regular file: {}", path.display());
    }
    std::fs::read(path).with_context(|| format!("cannot read {label} {}", path.display()))
}

fn hbc_version(path: &Path, label: &str) -> Result<u32> {
    read_regular(path, label)?;
    let result = std::process::Command::new(path)
        .arg("-version")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()
        .with_context(|| format!("cannot execute {label} {}", path.display()))?;
    if !result.status.success() {
        bail!(
            "{label} version probe failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
    }
    let combined = [result.stdout, result.stderr].concat();
    let text =
        std::str::from_utf8(&combined).with_context(|| format!("{label} version is not UTF-8"))?;
    let versions = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix("HBC bytecode version: "))
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if versions.len() != 1 || versions[0] == 0 {
        bail!("{label} must report exactly one nonzero HBC bytecode version");
    }
    Ok(versions[0])
}

fn write_if_absent_or_equal(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        let existing = read_regular(path, "existing contract")?;
        if existing == bytes {
            return Ok(());
        }
        bail!(
            "refusing to overwrite a different contract at {}",
            path.display()
        );
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("cannot create contract directory {}", parent.display()))?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("cannot create contract {}", path.display()))?;
    output
        .write_all(bytes)
        .with_context(|| format!("cannot write contract {}", path.display()))?;
    output
        .sync_all()
        .with_context(|| format!("cannot sync contract {}", path.display()))
}
