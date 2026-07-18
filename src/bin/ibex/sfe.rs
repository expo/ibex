//! Public single-file executable producer and read-only inspector.
//!
//! Release compilation is anchored in a catalog digest compiled into this
//! `ibex` binary. There is deliberately no CLI argument or runtime environment
//! override for that trust root.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "module-runner")]
use std::ffi::OsString;
#[cfg(feature = "module-runner")]
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use capsec_semantics::model::Digest;
#[cfg(feature = "module-runner")]
use capsec_semantics::policy::CanonicalMountProfile;
use capsec_semantics::policy::{CanonicalPolicy, CanonicalTargetProfile, ExpectedPolicyIdentity};
use capsec_semantics::registry::ValidatedProfile;
#[cfg(feature = "module-runner")]
use ibex_runtime::module_loader::artifact::{digest_bytes, source_integrity};
use ibex_runtime::module_loader::carrier::{
    AdmittedPreparedCarrierV2, PreparedCarrierAdmissionV2, PreparedCarrierEncodingV2,
    PreparedModuleCarrierV2,
};
use ibex_runtime::module_loader::computed_candidates::ComputedCandidateTableV1;
use ibex_runtime::module_loader::embedded_graph::{EmbeddedCarrierFactV1, EmbeddedModuleGraphV1};
#[cfg(feature = "module-runner")]
use ibex_runtime::module_loader::{
    catalog_compiler::compile_catalog_embedded_graph_to_hbc,
    runner_pipeline::{capture_embedded_source_graph_v1, CapturedEmbeddedSourceGraphV1},
};
#[cfg(feature = "module-runner")]
use ibex_sfe_catalog::AdmittedCatalogTargetV1;
use ibex_sfe_catalog::{CatalogTargetArtifacts, PinnedCatalogV1};
#[cfg(feature = "module-runner")]
use ibex_sfe_format::{
    admit_executable_v1, build_executable_v1, CompilePlanV1, SectionInputV1,
    COMPILE_PLAN_SCHEMA_V1, PACKAGE_PROVENANCE_SCHEMA_V1,
};
use ibex_sfe_format::{
    inspect_executable_v1, CompileCarrierEncodingV1, EntryDesignationV1, PackageProvenanceV1,
    SectionKindV1,
};
use serde_json::{json, Value};

use crate::cli::CompileCarrier;

const INSPECTION_SCHEMA_V1: &str = "ibex/executable-inspection/1";
const RELEASE_CATALOG_DIGEST: Option<&str> = option_env!("IBEX_RELEASE_SFE_CATALOG_DIGEST");

struct InnerAdmissionSummary {
    graph_identity: Digest,
    policy_digest: Digest,
    record_count: usize,
    carrier_count: usize,
}

pub fn compile(
    entry: &Path,
    output: &Path,
    carrier: CompileCarrier,
    root_policy: Option<&Path>,
    compile_policy: Option<&Path>,
    deny_unsupported: bool,
) -> Result<()> {
    if root_policy.is_some() && compile_policy.is_some() {
        bail!("root --policy and compile-local --policy conflict; name the canonical policy once");
    }
    if carrier == CompileCarrier::FactoryTable {
        bail!("factory-table carriers are diagnostic-only and cannot produce a release executable");
    }

    let target = host_target_triple()?;
    let catalog_digest = RELEASE_CATALOG_DIGEST.context(
        "SFC001 catalog trust root refused: this ibex release has no pinned SFE catalog; install a release that publishes compiled-executable artifacts",
    )?;
    let catalog_root = release_catalog_root(catalog_digest)?;
    let manifest_path = catalog_root.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path).with_context(|| {
        format!(
            "SFC003 catalog target unavailable: install this release's SFE catalog at {}",
            catalog_root.display()
        )
    })?;
    let catalog = PinnedCatalogV1::load(&manifest_bytes, catalog_digest)?;
    let entry_row = catalog.entry(target)?;
    let contract = read_catalog_artifact(&catalog_root, &entry_row.contract)?;
    let stub = read_catalog_artifact(&catalog_root, &entry_row.stub_unsigned_core)?;
    let hermesc = read_catalog_artifact(&catalog_root, &entry_row.hermesc)?;
    let admitted = catalog.admit_target(
        target,
        CatalogTargetArtifacts {
            contract: &contract,
            stub_unsigned_core: &stub,
            hermesc: &hermesc,
        },
    )?;

    #[cfg(feature = "module-runner")]
    {
        return compile_admitted_target(
            entry,
            output,
            root_policy.or(compile_policy),
            deny_unsupported,
            catalog.manifest().sequence,
            &admitted,
        );
    }
    #[cfg(not(feature = "module-runner"))]
    {
        let _ = (
            entry,
            output,
            root_policy,
            compile_policy,
            deny_unsupported,
            admitted,
        );
        bail!("single-file executable compilation requires the module-runner build feature")
    }
}

#[cfg(feature = "module-runner")]
fn compile_admitted_target(
    entry: &Path,
    output: &Path,
    policy_path: Option<&Path>,
    deny_unsupported: bool,
    catalog_sequence: u64,
    target: &AdmittedCatalogTargetV1<'_>,
) -> Result<()> {
    let producer_digest = digest_bytes(
        "ibex:sfe-release-producer:1",
        format!("{}\0{}", env!("CARGO_PKG_VERSION"), target.catalog_digest).as_bytes(),
    )?;
    let captured = capture_embedded_source_graph_v1(entry, producer_digest).with_context(|| {
        if deny_unsupported {
            "SFE graph capture refused under --deny-unsupported"
        } else {
            "SFE graph capture refused; unsupported computed sites remain decision-gated"
        }
    })?;
    let policy_path = match policy_path {
        Some(path) => path.to_path_buf(),
        None => default_compile_policy_path(entry, &target.entry.target)?,
    };
    let authored_policy = std::fs::read(&policy_path).with_context(|| {
        format!(
            "canonical compiled policy is absent at {}; run `ibex policy generate --entry {} --target-triple {}` and commit the result",
            policy_path.display(),
            entry.display(),
            target.entry.target,
        )
    })?;
    let policy = admit_policy(&authored_policy, &captured.prepared.graph.graph_identity)
        .with_context(|| format!("compiled policy {} was refused", policy_path.display()))?;
    validate_compile_policy(&policy, &captured, &target.entry.target)?;
    let canonical_policy =
        capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(&policy)?)?;

    let compiled = compile_catalog_embedded_graph_to_hbc(target, captured.prepared)?;
    let plan = CompilePlanV1 {
        schema: COMPILE_PLAN_SCHEMA_V1.into(),
        graph_snapshot_digest: compiled.graph.graph_identity.as_str().into(),
        policy_digest: policy.policy_digest.as_str().into(),
        stub_contract_digest: target.entry.contract_digest.clone(),
        catalog_digest: target.catalog_digest.into(),
        compiler_identity: target.entry.hermesc_identity.clone(),
        carrier_encoding: CompileCarrierEncodingV1::HermesBytecode,
        target: target.entry.target.clone(),
        environment_profile_digest: target.contract.environment_profile_digest.clone(),
    };
    let provenance = PackageProvenanceV1 {
        schema: PACKAGE_PROVENANCE_SCHEMA_V1.into(),
        compile_plan_digest: plan.digest()?,
        compile_plan: plan,
        catalog_sequence,
        catalog_entry_target: target.entry.target.clone(),
        stub_core_digest: target.entry.stub_unsigned_core.digest.clone(),
        producer_identity: format!("ibex-compile/{}", env!("CARGO_PKG_VERSION")),
    };
    let entry_designation =
        EntryDesignationV1::one(compiled.graph.entry.0.encode()?).canonical_bytes()?;
    let mut sections = vec![
        SectionInputV1::canonical(
            "provenance",
            SectionKindV1::ProvenanceManifest,
            provenance.canonical_bytes()?,
        ),
        SectionInputV1::canonical(
            "graph",
            SectionKindV1::EmbeddedModuleGraph,
            compiled.graph.canonical_bytes()?,
        ),
        SectionInputV1::canonical("policy", SectionKindV1::ResolvedPolicy, canonical_policy),
        SectionInputV1::canonical("entry", SectionKindV1::EntryDesignation, entry_designation),
    ];
    for table in compiled.candidate_tables {
        sections.push(SectionInputV1::canonical(
            table.digest()?.as_str(),
            SectionKindV1::CandidateTable,
            table.canonical_bytes()?,
        ));
    }
    for (index, carrier) in compiled.carriers.into_iter().enumerate() {
        sections.push(SectionInputV1::carrier(
            format!("carrier-manifest-{index:04}"),
            SectionKindV1::CarrierManifest,
            carrier.pair_id.clone(),
            carrier.manifest.encode_canonical()?,
        ));
        sections.push(SectionInputV1::carrier(
            format!("carrier-payload-{index:04}"),
            SectionKindV1::CarrierPayload,
            carrier.pair_id,
            carrier.payload,
        ));
    }
    let unsigned = if target.stub_unsigned_core.get(..4) == Some(&0xfeedfacfu32.to_le_bytes()) {
        let envelope = build_executable_v1(&[], &target.entry.contract_digest, sections)?;
        ibex_sfe_format::macho::inject_envelope_segment_v1(target.stub_unsigned_core, &envelope)?
    } else {
        build_executable_v1(
            target.stub_unsigned_core,
            &target.entry.contract_digest,
            sections,
        )?
    };
    admit_executable_v1(&unsigned, &target.entry.contract_digest)
        .context("assembled release envelope failed its own bulk preflight")?;
    publish_compiled_output(output, &unsigned, &provenance)
}

#[cfg(feature = "module-runner")]
fn validate_compile_policy(
    policy: &CanonicalPolicy,
    captured: &CapturedEmbeddedSourceGraphV1,
    target: &str,
) -> Result<()> {
    let CanonicalTargetProfile::Compiled {
        profile,
        target_triple,
    } = &policy.target_profile
    else {
        bail!("compiled policy carries a source target profile");
    };
    if profile.as_str() != "sfe-v1" || target_triple.as_str() != target {
        bail!("compiled policy target profile disagrees with the catalog target");
    }
    if !matches!(
        policy.mount_profile,
        CanonicalMountProfile::CompiledAppWorkV1
    ) {
        bail!("compiled policy does not use the compiled-app-work-v1 mount profile");
    }
    if policy.entry_identity.components != captured.entry_components
        || policy.entry_identity.source_integrity != captured.entry_source_integrity
    {
        bail!("compiled policy entry identity disagrees with captured source bytes");
    }
    let mut candidate_sets = captured
        .prepared
        .candidate_tables
        .iter()
        .map(|table| table.graph_projection())
        .collect::<Result<Vec<_>>>()?;
    candidate_sets.sort_by_key(|row| canonical_value(&serde_json::to_value(row).unwrap()).unwrap());
    let policy_candidates = policy
        .computed_candidates
        .materialized_sites
        .iter()
        .map(|row| {
            (
                row.requester.as_str().to_owned(),
                row.label.as_str().to_owned(),
                row.candidates
                    .iter()
                    .map(|value| value.as_str().to_owned())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeSet<_>>();
    let captured_candidates = captured
        .prepared
        .candidate_tables
        .iter()
        .map(|table| {
            let path = match &table.requester.0 {
                ibex_runtime::module_loader::identity::SourceId::File {
                    principal: capsec_semantics::model::Principal::Root { .. },
                    path,
                } => path
                    .iter()
                    .map(|component| std::str::from_utf8(component.bytes()).map(str::to_owned))
                    .collect::<std::result::Result<Vec<_>, _>>()?
                    .join("/"),
                _ => bail!("computed-candidate requester is not a root file"),
            };
            Ok((
                path,
                table.label.as_str().to_owned(),
                table
                    .candidates
                    .iter()
                    .map(|candidate| candidate.specifier.as_str().to_owned())
                    .collect::<Vec<_>>(),
            ))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if policy_candidates != captured_candidates {
        bail!("compiled policy computed candidates disagree with captured producer sites");
    }
    let snapshot = captured
        .prepared
        .graph
        .authenticated_snapshot(candidate_sets)?;
    let graph_packages = snapshot.packages.into_iter().collect::<BTreeSet<_>>();
    let policy_packages = policy
        .principals
        .iter()
        .map(|row| row.principal.clone())
        .collect::<BTreeSet<_>>();
    if graph_packages != policy_packages {
        bail!("compiled policy package principals disagree with the captured graph");
    }
    Ok(())
}

#[cfg(feature = "module-runner")]
fn default_compile_policy_path(entry: &Path, target: &str) -> Result<PathBuf> {
    let entry = std::fs::canonicalize(entry)
        .with_context(|| format!("cannot canonicalize entry {}", entry.display()))?;
    let parent = entry.parent().context("compiled entry has no parent")?;
    let mut root = parent;
    loop {
        if root.join("package.json").is_file() {
            break;
        }
        let Some(next) = root.parent() else {
            root = parent;
            break;
        };
        root = next;
    }
    let relative = entry
        .strip_prefix(root)
        .context("compiled entry escapes the discovered project root")?;
    let key = relative
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    Ok(root.join(format!(
        "ibex-policy.{key}.sfe-v1.{target}.compiled-app-work-v1.json"
    )))
}

#[cfg(feature = "module-runner")]
fn publish_compiled_output(
    output: &Path,
    unsigned: &[u8],
    provenance: &PackageProvenanceV1,
) -> Result<()> {
    let unsigned_digest = source_integrity(unsigned)?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("cannot create output directory {}", parent.display()))?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot stage executable beside {}", output.display()))?;
    staged.write_all(unsigned)?;
    staged.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(target_os = "macos")]
    if unsigned.get(..4) == Some(&0xfeedfacfu32.to_le_bytes()) {
        let result = std::process::Command::new("/usr/bin/codesign")
            .args(["--force", "--sign", "-", "--timestamp=none"])
            .arg(staged.path())
            .output()
            .context("cannot invoke ad-hoc codesign for compiled executable")?;
        if !result.status.success() {
            bail!(
                "ad-hoc codesign refused compiled executable: {}",
                String::from_utf8_lossy(&result.stderr).trim()
            );
        }
        let signed = std::fs::read(staged.path())?;
        ibex_sfe_format::macho::validate_signed_envelope_layout_v1(&signed)?;
    }
    staged
        .persist(output)
        .map_err(|error| anyhow::anyhow!("cannot publish {}: {}", output.display(), error.error))?;
    let published = std::fs::read(output)?;
    let published_digest = source_integrity(&published)?;
    let statement = json!({
        "schema": "ibex/sfe-build-statement/1",
        "compilePlanDigest": provenance.compile_plan_digest,
        "stubCoreDigest": provenance.stub_core_digest,
        "unsignedFileDigest": unsigned_digest,
        "publishedFileDigest": published_digest,
        "platformSignature": if published == unsigned { "not-applicable" } else { "ad-hoc" },
    });
    let statement_bytes = canonical_value(&statement)?;
    let mut statement_name = OsString::from(output.as_os_str());
    statement_name.push(".build.json");
    let statement_path = PathBuf::from(statement_name);
    let statement_parent = statement_path.parent().unwrap_or_else(|| Path::new("."));
    let mut staged_statement = tempfile::NamedTempFile::new_in(statement_parent)?;
    staged_statement.write_all(&statement_bytes)?;
    staged_statement.as_file().sync_all()?;
    staged_statement.persist(&statement_path).map_err(|error| {
        anyhow::anyhow!(
            "cannot publish {}: {}",
            statement_path.display(),
            error.error
        )
    })?;
    Ok(())
}

fn read_catalog_artifact(
    root: &Path,
    artifact: &ibex_sfe_catalog::CatalogArtifactV1,
) -> Result<Vec<u8>> {
    let address = artifact.content_address()?;
    let path = root.join(address);
    std::fs::read(&path)
        .with_context(|| format!("catalog artifact is absent at {}", path.display()))
}

fn release_catalog_root(digest: &str) -> Result<PathBuf> {
    let key = digest
        .strip_prefix("sha256-")
        .context("compiled SFE catalog digest is malformed")?;
    let cache = dirs::cache_dir().context("cannot locate the user cache directory")?;
    Ok(cache.join("ibex").join("sfe-catalogs").join(key))
}

fn host_target_triple() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        (os, arch) => bail!("single-file executable compilation is unavailable for {os}-{arch}"),
    }
}

pub fn inspect(path: &Path) -> Result<()> {
    let file = std::fs::read(path)
        .with_context(|| format!("cannot read executable {}", path.display()))?;
    let envelope = inspect_executable_v1(&file)
        .with_context(|| format!("executable envelope {} is inconsistent", path.display()))?;

    let provenance = canonical_section_value(&envelope, SectionKindV1::ProvenanceManifest)?;
    let graph = canonical_section_value(&envelope, SectionKindV1::EmbeddedModuleGraph)?;
    let policy = canonical_section_value(&envelope, SectionKindV1::ResolvedPolicy)?;
    let entry = canonical_section_value(&envelope, SectionKindV1::EntryDesignation)?;
    let typed_provenance = serde_json::from_value::<PackageProvenanceV1>(provenance.clone())
        .ok()
        .filter(|value| {
            value.canonical_bytes().ok().as_deref() == canonical_value(&provenance).ok().as_deref()
        });
    if provenance.get("compilePlan").is_some() && typed_provenance.is_none() {
        bail!("release package provenance is malformed or internally inconsistent");
    }
    let inner = admit_inner_contracts(&envelope, typed_provenance.as_ref())?;

    let (environment_profile_digest, provenance_kind) = typed_provenance
        .as_ref()
        .map(|value| {
            (
                Some(value.compile_plan.environment_profile_digest.clone()),
                "release-v1",
            )
        })
        .unwrap_or((None, "development-or-unknown"));
    let complete_authority = typed_provenance.is_some()
        && policy.get("rootCeiling").is_some()
        && policy.get("mountProfile").is_some()
        && policy.get("principals").is_some();
    let incomplete = if complete_authority {
        Vec::<String>::new()
    } else {
        vec![
            "the executable predates release CompilePlanV1 provenance or omits an authority projection required for reconstruction".into(),
        ]
    };
    let attestation_path = PathBuf::from(format!("{}.build.json", path.display()));
    let attestation = if attestation_path.is_file() {
        json!({
            "state": "unverified",
            "reason": "a detached statement exists, but this release has no configured publisher trust policy",
            "path": attestation_path,
        })
    } else {
        json!({
            "state": "absent",
            "reason": "no detached build or publisher statement is adjacent to the executable",
        })
    };

    let report = json!({
        "schema": INSPECTION_SCHEMA_V1,
        "file": path,
        "envelopeConsistency": {
            "state": "consistent",
            "schema": envelope.directory.schema,
            "envelopeDigest": envelope.envelope_digest,
            "stubContractDigest": envelope.directory.stub_contract_digest,
            "sectionCount": envelope.directory.sections.len(),
        },
        "platformSignature": platform_signature_state(path, &file),
        "externalAttestation": attestation,
        "runtimeAdmission": {
            "state": "inner-contracts-admitted",
            "graphIdentity": inner.graph_identity,
            "policyDigest": inner.policy_digest,
            "recordCount": inner.record_count,
            "carrierCount": inner.carrier_count,
            "note": "graph, policy, entry, carrier payloads, and release provenance are internally cross-checked; release-catalog trust and platform/external authentication are reported separately",
        },
        "provenanceKind": provenance_kind,
        "provenance": provenance,
        "authorityBundle": {
            "complete": complete_authority,
            "incompleteReasons": incomplete,
            "graphIdentity": graph.get("graphIdentity"),
            "policyDigest": policy.get("policyDigest"),
            "rootCeiling": policy.get("rootCeiling"),
            "mountProfile": policy.get("mountProfile"),
            "environmentProfileDigest": environment_profile_digest,
            "policy": policy,
            "embeddedGraph": graph,
            "entryDesignation": entry,
        },
        "sections": envelope.directory.sections,
    });
    let bytes = canonical_value(&report)?;
    println!("{}", std::str::from_utf8(&bytes).expect("JCS is UTF-8"));
    Ok(())
}

/// Re-run the path-independent portion of compiled boot admission without
/// evaluating application code. Trust in the release catalog, platform
/// signature, and detached publisher statement remains a separate report axis.
/// @ref LLP 0029#1-command-surface-and-producer-pipeline
fn admit_inner_contracts(
    envelope: &ibex_sfe_format::AdmittedEnvelopeV1<'_>,
    provenance: Option<&PackageProvenanceV1>,
) -> Result<InnerAdmissionSummary> {
    let graph_bytes = section_bytes(envelope, SectionKindV1::EmbeddedModuleGraph)?;
    let preliminary_graph = EmbeddedModuleGraphV1::decode_canonical(graph_bytes)?;
    let authorized_semantic_digests = preliminary_graph
        .records
        .iter()
        .map(|record| record.semantic_digest.clone())
        .collect::<BTreeSet<_>>();
    let mut carrier_facts = BTreeMap::new();
    let mut carrier_encodings = BTreeSet::new();
    for manifest_section in envelope
        .sections()
        .filter(|section| section.record.kind == SectionKindV1::CarrierManifest)
    {
        let pair = manifest_section
            .record
            .pair_id
            .as_deref()
            .context("carrier manifest has no pair id")?;
        let payload = envelope
            .sections()
            .find(|section| {
                section.record.kind == SectionKindV1::CarrierPayload
                    && section.record.pair_id.as_deref() == Some(pair)
            })
            .with_context(|| format!("carrier pair {pair:?} has no payload"))?;
        let manifest: PreparedModuleCarrierV2 =
            decode_canonical_section(manifest_section.bytes, "carrier manifest")?;
        if manifest.entries.len() != 1 {
            bail!("v1 executable carrier pair {pair:?} must contain one module entry");
        }
        let (engine_binding, bytecode_version, encoding) = match &manifest.encoding {
            PreparedCarrierEncodingV2::JavascriptFactoryTable => (None, None, "factory-table"),
            PreparedCarrierEncodingV2::HermesBytecode {
                engine_binding,
                bytecode_version,
            } => (
                Some(engine_binding.clone()),
                Some(*bytecode_version),
                "hermes-bytecode",
            ),
        };
        carrier_encodings.insert(encoding);
        let admission = PreparedCarrierAdmissionV2 {
            expected_principal: manifest.defining_principal.clone(),
            expected_producer_id: manifest.producer_id.clone(),
            producer_binary_digest: manifest.producer_binary_digest.clone(),
            deployment_graph_digest: preliminary_graph.graph_identity.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            expected_engine_binding: engine_binding,
            expected_bytecode_version: bytecode_version,
        };
        AdmittedPreparedCarrierV2::decode_and_admit(
            manifest_section.bytes,
            payload.bytes,
            &admission,
        )?;
        let entry = &manifest.entries[0];
        if carrier_facts
            .insert(
                pair.to_owned(),
                EmbeddedCarrierFactV1 {
                    source_id: entry.semantics.source_id.clone(),
                    semantic_digest: entry.semantic_digest.clone(),
                    entry_id: entry.entry_id.clone(),
                },
            )
            .is_some()
        {
            bail!("duplicate carrier pair {pair:?}");
        }
    }
    let candidate_sets = envelope
        .sections()
        .filter(|section| section.record.kind == SectionKindV1::CandidateTable)
        .map(|section| {
            let table = ComputedCandidateTableV1::decode_canonical(section.bytes)?;
            if table.digest()?.as_str() != section.record.id {
                bail!("candidate-table section id disagrees with its canonical bytes");
            }
            table.graph_projection()
        })
        .collect::<Result<Vec<_>>>()?;
    let graph =
        EmbeddedModuleGraphV1::decode_and_admit(graph_bytes, &carrier_facts, &candidate_sets)?;
    let policy_bytes = section_bytes(envelope, SectionKindV1::ResolvedPolicy)?;
    let policy = admit_policy(policy_bytes, &graph.graph_identity)?;
    let entry: EntryDesignationV1 = decode_canonical_section(
        section_bytes(envelope, SectionKindV1::EntryDesignation)?,
        "entry designation",
    )?;
    let graph_entry = graph.entry.0.encode()?;
    if entry.entries.len() != 1
        || entry.entries[0].name != "main"
        || entry.entries[0].source_id != graph_entry
    {
        bail!("entry designation disagrees with the admitted embedded graph");
    }

    if let Some(provenance) = provenance {
        let plan = &provenance.compile_plan;
        if plan.graph_snapshot_digest != graph.graph_identity.as_str()
            || plan.policy_digest != policy.policy_digest.as_str()
            || plan.stub_contract_digest != envelope.directory.stub_contract_digest
        {
            bail!("release CompilePlanV1 disagrees with admitted envelope sections");
        }
        let policy_target = match &policy.target_profile {
            CanonicalTargetProfile::Compiled { target_triple, .. } => target_triple.as_str(),
            CanonicalTargetProfile::Source { .. } => {
                bail!("release executable carries a source-mode policy target")
            }
        };
        if plan.target != policy_target {
            bail!("release CompilePlanV1 and policy target triples disagree");
        }
        let encoding_matches = match plan.carrier_encoding {
            CompileCarrierEncodingV1::HermesBytecode => {
                carrier_encodings.len() == 1 && carrier_encodings.contains("hermes-bytecode")
            }
            CompileCarrierEncodingV1::FactoryTable => {
                carrier_encodings.len() == 1 && carrier_encodings.contains("factory-table")
            }
        };
        if !encoding_matches {
            bail!("release CompilePlanV1 and carrier encodings disagree");
        }
    }

    Ok(InnerAdmissionSummary {
        graph_identity: graph.graph_identity,
        policy_digest: policy.policy_digest,
        record_count: graph.records.len(),
        carrier_count: carrier_facts.len(),
    })
}

fn admit_policy(bytes: &[u8], graph_identity: &Digest) -> Result<CanonicalPolicy> {
    let identity: Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/capsec/examples/canonical-policy.canonical.json"
    )))?;
    let expected = ExpectedPolicyIdentity {
        profile: "ibex/capsec/1".into(),
        semantic_core: "capsec/semantics/1".into(),
        vocab_digest: Digest::new(
            identity["vocabDigest"]
                .as_str()
                .context("current policy identity omits vocabDigest")?,
        )
        .map_err(anyhow::Error::msg)?,
        registry_digest: Digest::new(
            identity["registryDigest"]
                .as_str()
                .context("current policy identity omits registryDigest")?,
        )
        .map_err(anyhow::Error::msg)?,
    };
    let profile = ValidatedProfile::from_json(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/capability-definitions.json"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/policy-rules.json"
        )),
    )?;
    let policy = CanonicalPolicy::load(bytes, &expected, &profile.definitions)?;
    if &policy.graph_identity != graph_identity {
        bail!("embedded policy is bound to a different graph identity");
    }
    Ok(policy)
}

fn section_bytes<'a>(
    envelope: &'a ibex_sfe_format::AdmittedEnvelopeV1<'a>,
    kind: SectionKindV1,
) -> Result<&'a [u8]> {
    envelope
        .sections()
        .find(|section| section.record.kind == kind)
        .map(|section| section.bytes)
        .with_context(|| format!("required {kind:?} section is absent"))
}

fn decode_canonical_section<T: for<'de> serde::Deserialize<'de>>(
    bytes: &[u8],
    label: &str,
) -> Result<T> {
    let text = std::str::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .with_context(|| format!("{label} is not strict JSON"))?;
    if canonical_value(&value)? != bytes {
        bail!("{label} is not canonical JCS");
    }
    serde_json::from_value(value).with_context(|| format!("{label} has an invalid shape"))
}

fn canonical_section_value(
    envelope: &ibex_sfe_format::AdmittedEnvelopeV1<'_>,
    kind: SectionKindV1,
) -> Result<Value> {
    let section = envelope
        .sections()
        .find(|section| section.record.kind == kind)
        .with_context(|| format!("required {kind:?} section is absent"))?;
    let text = std::str::from_utf8(section.bytes)
        .with_context(|| format!("{kind:?} section is not UTF-8"))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .with_context(|| format!("{kind:?} section is not strict JSON"))?;
    if canonical_value(&value)? != section.bytes {
        bail!("{kind:?} section is not canonical JCS");
    }
    Ok(value)
}

fn canonical_value(value: &Value) -> Result<Vec<u8>> {
    capsec_semantics::canonical::to_jcs_bytes(value).map_err(anyhow::Error::msg)
}

fn platform_signature_state(path: &Path, file: &[u8]) -> Value {
    const MACHO_MAGIC: [u8; 4] = 0xfeedfacfu32.to_le_bytes();
    if file.get(..4) != Some(&MACHO_MAGIC) {
        return json!({
            "state": "not-applicable",
            "format": if file.get(..4) == Some(b"\x7fELF") { "elf" } else { "unknown" },
            "reason": "this executable format has no v1 platform-signature verifier",
        });
    }
    if let Err(error) = ibex_sfe_format::macho::validate_signed_envelope_layout_v1(file) {
        return json!({
            "state": "invalid",
            "format": "mach-o",
            "reason": error.to_string(),
        });
    }
    verify_macos_signature(path)
}

#[cfg(target_os = "macos")]
fn verify_macos_signature(path: &Path) -> Value {
    match std::process::Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--verbose=2"])
        .arg(path)
        .output()
    {
        Ok(output) if output.status.success() => json!({
            "state": "valid",
            "format": "mach-o",
            "mechanism": "codesign-strict-plus-ibex-layout",
        }),
        Ok(output) => json!({
            "state": "invalid",
            "format": "mach-o",
            "reason": String::from_utf8_lossy(&output.stderr).trim(),
        }),
        Err(error) => json!({
            "state": "unavailable",
            "format": "mach-o",
            "reason": format!("cannot invoke /usr/bin/codesign: {error}"),
        }),
    }
}

#[cfg(not(target_os = "macos"))]
fn verify_macos_signature(_path: &Path) -> Value {
    json!({
        "state": "unavailable",
        "format": "mach-o",
        "reason": "Mach-O cryptographic signature verification requires macOS",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "module-runner")]
    use capsec_semantics::model::{PathComponent, Principal};
    #[cfg(feature = "module-runner")]
    use ibex_runtime::module_loader::identity::SourceId;

    #[cfg(feature = "module-runner")]
    fn compiled_policy_bytes(captured: &CapturedEmbeddedSourceGraphV1, target: &str) -> Vec<u8> {
        let identity: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/examples/canonical-policy.canonical.json"
        )))
        .unwrap();
        let candidate_sites = captured
            .prepared
            .candidate_tables
            .iter()
            .map(|table| {
                let requester = match &table.requester.0 {
                    SourceId::File {
                        principal: Principal::Root { .. },
                        path,
                    } => path
                        .iter()
                        .map(|component| match component {
                            PathComponent::Utf8(value) => value.as_str(),
                            PathComponent::Base64Url(_) => panic!("test requester is not UTF-8"),
                        })
                        .collect::<Vec<_>>()
                        .join("/"),
                    _ => panic!("test candidate requester is not a root file"),
                };
                let candidates = table
                    .candidates
                    .iter()
                    .map(|candidate| candidate.specifier.as_str())
                    .collect::<Vec<_>>();
                (requester, table.label.as_str(), candidates)
            })
            .collect::<Vec<_>>();
        let declarations = candidate_sites
            .iter()
            .map(|(requester, label, candidates)| {
                json!({
                    "requester": requester,
                    "label": label,
                    "specifiers": candidates,
                    "packageClosures": [],
                })
            })
            .collect::<Vec<_>>();
        let materialized_sites = candidate_sites
            .iter()
            .map(|(requester, label, candidates)| {
                json!({"requester": requester, "label": label, "candidates": candidates})
            })
            .collect::<Vec<_>>();
        let mut document = json!({
            "policySchema": "ibex/capsec-policy/2",
            "capsVocab": "ibex/capsec/1",
            "semanticCore": "capsec/semantics/1",
            "vocabDigest": identity["vocabDigest"],
            "registryDigest": identity["registryDigest"],
            "policyDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "purpose": "production",
            "mode": "enforce",
            "graphIdentity": captured.prepared.graph.graph_identity,
            "entryIdentity": {
                "root": "project",
                "components": captured.entry_components,
                "sourceIntegrity": captured.entry_source_integrity,
            },
            "targetProfile": {
                "kind": "compiled",
                "profile": "sfe-v1",
                "targetTriple": target,
            },
            "mountProfile": "compiled-app-work-v1",
            "rootCeiling": [],
            "computedCandidates": {
                "schema": "ibex/computed-candidate-manifest/1",
                "declarations": declarations,
                "packageClosureOptIns": [],
                "materializedSites": materialized_sites,
            },
            "principals": [],
        });
        document["policyDigest"] = Value::String(
            capsec_semantics::digest::compute_checked_contract_digest(
                capsec_semantics::digest::DigestKind::Policy,
                &document,
            )
            .unwrap(),
        );
        canonical_value(&document).unwrap()
    }

    #[test]
    fn compile_refuses_without_a_release_trust_root_before_source_access() {
        if RELEASE_CATALOG_DIGEST.is_none() {
            let error = compile(
                Path::new("definitely-absent-entry.ts"),
                Path::new("out"),
                CompileCarrier::Hbc,
                None,
                None,
                false,
            )
            .unwrap_err();
            assert!(error.to_string().contains("no pinned SFE catalog"));
        }
    }

    #[test]
    fn compile_policy_spelling_is_an_explicit_conflict() {
        let error = compile(
            Path::new("entry.ts"),
            Path::new("out"),
            CompileCarrier::Hbc,
            Some(Path::new("root-policy.json")),
            Some(Path::new("local-policy.json")),
            false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflict"));
    }

    #[cfg(feature = "module-runner")]
    #[test]
    fn captured_graph_and_compiled_policy_are_exactly_cross_bound() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::write(
            temporary.path().join("entry.mjs"),
            "import { value } from './value.mjs'; export const answer = value + 1;",
        )
        .unwrap();
        std::fs::write(
            temporary.path().join("value.mjs"),
            "export const value = 41;",
        )
        .unwrap();
        let producer = digest_bytes("ibex:sfe-test-producer:1", b"producer").unwrap();
        let captured =
            capture_embedded_source_graph_v1(&temporary.path().join("entry.mjs"), producer)
                .unwrap();
        let bytes = compiled_policy_bytes(&captured, "aarch64-apple-darwin");
        let policy = admit_policy(&bytes, &captured.prepared.graph.graph_identity).unwrap();
        validate_compile_policy(&policy, &captured, "aarch64-apple-darwin").unwrap();

        let error =
            validate_compile_policy(&policy, &captured, "x86_64-unknown-linux-gnu").unwrap_err();
        assert!(error.to_string().contains("catalog target"));
    }

    #[cfg(feature = "module-runner")]
    #[test]
    fn computed_candidate_tables_are_cross_bound_into_compiled_policy_and_graph() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::write(
            temporary.path().join("package.json"),
            r#"{"ibex":{"computedCandidates":{"sites":[{"requester":"entry.mjs","label":"routes","specifiers":["./left.mjs","./right.mjs"]}]}}}"#,
        )
        .unwrap();
        std::fs::write(
            temporary.path().join("entry.mjs"),
            "const route = './left.mjs'; export const selected = import(route, { with: { 'ibex:site': 'routes' } });",
        )
        .unwrap();
        std::fs::write(
            temporary.path().join("left.mjs"),
            "export const side = 'left';",
        )
        .unwrap();
        std::fs::write(
            temporary.path().join("right.mjs"),
            "export const side = 'right';",
        )
        .unwrap();
        let producer = digest_bytes("ibex:sfe-candidate-test-producer:1", b"producer").unwrap();
        let captured =
            capture_embedded_source_graph_v1(&temporary.path().join("entry.mjs"), producer)
                .unwrap();
        assert_eq!(captured.prepared.candidate_tables.len(), 1);
        assert_eq!(
            captured
                .prepared
                .graph
                .records
                .iter()
                .map(|record| record.candidate_table_refs.len())
                .sum::<usize>(),
            1
        );
        let bytes = compiled_policy_bytes(&captured, "aarch64-apple-darwin");
        let policy = admit_policy(&bytes, &captured.prepared.graph.graph_identity).unwrap();
        validate_compile_policy(&policy, &captured, "aarch64-apple-darwin").unwrap();

        let mut widened = captured;
        widened.prepared.candidate_tables[0].candidates.pop();
        assert!(validate_compile_policy(&policy, &widened, "aarch64-apple-darwin").is_err());
    }

    #[cfg(all(
        feature = "module-runner",
        target_os = "macos",
        target_arch = "aarch64"
    ))]
    #[test]
    fn admitted_catalog_target_drives_complete_hbc_envelope_assembly() {
        use ibex_runtime::module_loader::artifact::source_integrity;
        use ibex_sfe_catalog::{CatalogArtifactRoleV1, CatalogArtifactV1, CatalogEntryV1};
        use ibex_sfe_format::{EngineCompatibilityV1, HermescCompatibilityV1, HermescRecipeV1};

        let temporary = tempfile::tempdir().unwrap();
        let entry_path = temporary.path().join("entry.mjs");
        std::fs::write(
            temporary.path().join("package.json"),
            r#"{"ibex":{"computedCandidates":{"sites":[{"requester":"entry.mjs","label":"routes","specifiers":["./left.mjs","./right.mjs"]}]}}}"#,
        )
        .unwrap();
        std::fs::write(
            &entry_path,
            "const route = './left.mjs'; const selected = await import(route, { with: { 'ibex:site': 'routes' } }); export const answer = selected.value + 1;",
        )
        .unwrap();
        std::fs::write(
            temporary.path().join("left.mjs"),
            "export const value = 41;",
        )
        .unwrap();
        std::fs::write(
            temporary.path().join("right.mjs"),
            "export const value = 40;",
        )
        .unwrap();
        let producer = digest_bytes("ibex:sfe-release-producer:1", b"fixture").unwrap();
        let captured = capture_embedded_source_graph_v1(&entry_path, producer).unwrap();
        let policy_path = temporary.path().join("policy.json");
        std::fs::write(
            &policy_path,
            compiled_policy_bytes(&captured, "aarch64-apple-darwin"),
        )
        .unwrap();

        let hermesc = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/hermes/hermesc-macos-arm64"),
        )
        .unwrap();
        let hbc_version = ibex_runtime::engine::loaded_engine_bytecode_version().unwrap();
        let stub = b"\x7fELFsynthetic-release-stub".to_vec();
        let mut contract =
            ibex_runtime::compiled_contract::diagnostic_development_stub_contract().unwrap();
        contract.release_eligible = true;
        contract.profile = "sfe-v1".into();
        contract.target.triple = "aarch64-apple-darwin".into();
        contract.target.minimum_platform = "macos-13.0-arm64".into();
        contract.engine = EngineCompatibilityV1::static_hermes(
            "full",
            source_integrity(b"static archive closure")
                .unwrap()
                .as_str(),
            hbc_version,
        )
        .unwrap();
        contract.hermesc = HermescCompatibilityV1::catalog_artifact(
            source_integrity(&hermesc).unwrap().as_str(),
            hbc_version,
            HermescRecipeV1::production().digest().unwrap(),
        )
        .unwrap();
        let contract_bytes = contract.canonical_bytes().unwrap();
        let contract_digest = contract.digest().unwrap();
        let row = CatalogEntryV1 {
            target: contract.target.triple.clone(),
            minimum_platform: contract.target.minimum_platform.clone(),
            contract_digest: contract_digest.clone(),
            engine_compatibility_identity: contract.engine.identity().into(),
            hermesc_identity: contract.hermesc.identity().unwrap().into(),
            hbc_version,
            contract: CatalogArtifactV1::from_bytes(
                CatalogArtifactRoleV1::StubContract,
                "application/json",
                &contract_bytes,
            ),
            stub_unsigned_core: CatalogArtifactV1::from_bytes(
                CatalogArtifactRoleV1::StubUnsignedCore,
                "application/octet-stream",
                &stub,
            ),
            hermesc: CatalogArtifactV1::from_bytes(
                CatalogArtifactRoleV1::Hermesc,
                "application/octet-stream",
                &hermesc,
            ),
        };
        let catalog_digest = source_integrity(b"catalog").unwrap().to_string();
        let target = AdmittedCatalogTargetV1 {
            catalog_digest: &catalog_digest,
            entry: &row,
            contract,
            stub_unsigned_core: &stub,
            hermesc: &hermesc,
        };
        let output = temporary.path().join("app");
        compile_admitted_target(&entry_path, &output, Some(&policy_path), true, 1, &target)
            .unwrap();

        let bytes = std::fs::read(&output).unwrap();
        let envelope = admit_executable_v1(&bytes, &contract_digest).unwrap();
        let provenance: PackageProvenanceV1 = decode_canonical_section(
            section_bytes(&envelope, SectionKindV1::ProvenanceManifest).unwrap(),
            "provenance",
        )
        .unwrap();
        let inner = admit_inner_contracts(&envelope, Some(&provenance)).unwrap();
        assert_eq!(inner.record_count, 3);
        assert_eq!(inner.carrier_count, 3);
        assert_eq!(
            envelope
                .sections()
                .filter(|section| section.record.kind == SectionKindV1::CandidateTable)
                .count(),
            1
        );
        assert!(output.with_file_name("app.build.json").is_file());
    }
}
