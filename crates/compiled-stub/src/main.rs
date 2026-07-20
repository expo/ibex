//! Dedicated compiled-executable stub; currently the phase-0 dynamically
//! linked development profile from LLP 0029.
//!
//! The image reads no original application source. It authenticates its own
//! envelope, resolved policy, embedded graph, and prepared carrier before an
//! explicitly diagnostic Hermes runtime evaluates the entry.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;

use anyhow::{anyhow, bail, Context, Result};
use capsec_semantics::model::{Digest, NonEmptyString};
use capsec_semantics::policy::{CanonicalPolicy, ExpectedPolicyIdentity};
use capsec_semantics::registry::ValidatedProfile;
use ibex_runtime::engine::module_runner::{
    preflight_hermes_bytecode, ComputedDynamicImportLinks, DiagnosticModuleRuntime,
    GraphEvaluationContext, NativeModuleRecordConfig, NativeSynchronousGraph,
};
use ibex_runtime::module_loader::artifact::{ArtifactAdmissionV1, ModuleArtifactV1};
use ibex_runtime::module_loader::carrier::{
    AdmittedPreparedCarrierV2, PreparedCarrierAdmissionV2, PreparedCarrierEncodingV2,
    PreparedCarrierEngineBindingV2, PreparedModuleCarrierV2, VerifiedPreparedCarrierEntryV2,
};
use ibex_runtime::module_loader::computed_candidates::ComputedCandidateTableV1;
use ibex_runtime::module_loader::embedded_graph::{EmbeddedCarrierFactV1, EmbeddedModuleGraphV1};
use ibex_runtime::module_loader::graph::{GraphEdgeKey, SynchronousGraphPlan};
use ibex_runtime::module_loader::identity::SourceId;
use ibex_sfe_format::{
    admit_executable_v1, CompileCarrierEncodingV1, EngineCompatibilityV1, PackageProvenanceV1,
    SectionKindV1, StubContractV1,
};
use serde::Deserialize;

mod environment;
mod process;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DevelopmentProvenanceV1 {
    schema: String,
    stub_contract_digest: String,
    graph_identity: Digest,
    producer_id: NonEmptyString,
    producer_binary_digest: Digest,
}

enum BootProvenanceV1 {
    Development(DevelopmentProvenanceV1),
    Release(PackageProvenanceV1),
}

impl BootProvenanceV1 {
    fn graph_identity<'a>(&'a self, graph: &'a EmbeddedModuleGraphV1) -> Result<&'a Digest> {
        match self {
            Self::Development(value) => Ok(&value.graph_identity),
            Self::Release(value) => {
                if value.compile_plan.graph_snapshot_digest != graph.graph_identity.as_str() {
                    bail!("release CompilePlanV1 names a different graph snapshot");
                }
                Ok(&graph.graph_identity)
            }
        }
    }

    fn expected_producer(&self, manifest: &PreparedModuleCarrierV2) -> (NonEmptyString, Digest) {
        match self {
            Self::Development(value) => (
                value.producer_id.clone(),
                value.producer_binary_digest.clone(),
            ),
            Self::Release(_) => (
                manifest.producer_id.clone(),
                manifest.producer_binary_digest.clone(),
            ),
        }
    }

    fn is_release(&self) -> bool {
        matches!(self, Self::Release(_))
    }
}

fn main() {
    let result = run();
    // Orderly completion, root-selected exitCode, and refusal all drain output
    // accepted by the broker before the process terminates.
    // @ref LLP 0025#8-exit-and-lifecycle
    ibex_runtime::host::abi::ex_host_console_flush(500);
    match result {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("ibex compiled development stub refused: {error:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32> {
    let environment = environment::captured_environment()
        .context("compiled environment capture/sanitization did not complete")?;
    ibex_runtime::host::process::install_compiled_environment_base(environment.broker_base()?)?;
    let process_arguments = process::CapturedProcessArguments::capture()?;
    let contract = compiled_stub_contract()?;
    let contract_digest = contract.digest()?;
    let mut pinned_image = ibex_runtime::engine::open_pinned_self_image()
        .map_err(anyhow::Error::msg)
        .context("cannot pin the mapped executable image")?;
    let before = pinned_image
        .metadata()
        .context("cannot inspect the pinned executable image")?;
    let mut file = Vec::with_capacity(before.len().try_into().unwrap_or(0));
    pinned_image
        .read_to_end(&mut file)
        .context("cannot read the pinned executable image")?;
    let after = pinned_image
        .metadata()
        .context("cannot revalidate the pinned executable image")?;
    if before.len() != after.len() || after.len() != file.len() as u64 {
        bail!("pinned executable image changed while it was read");
    }
    if file.get(..4) == Some(&0xfeedfacfu32.to_le_bytes()) {
        ibex_sfe_format::macho::validate_signed_envelope_layout_v1(&file)?;
    }
    let envelope = admit_executable_v1(&file, &contract_digest)?;
    let provenance = decode_boot_provenance(
        section_bytes(&envelope, SectionKindV1::ProvenanceManifest)?,
        &contract,
        &contract_digest,
    )?;

    let graph_bytes = section_bytes(&envelope, SectionKindV1::EmbeddedModuleGraph)?;
    let preliminary_graph = EmbeddedModuleGraphV1::decode_canonical(graph_bytes)?;
    if &preliminary_graph.graph_identity != provenance.graph_identity(&preliminary_graph)? {
        bail!("embedded provenance and graph name different snapshots");
    }
    admit_policy(
        section_bytes(&envelope, SectionKindV1::ResolvedPolicy)?,
        &preliminary_graph.graph_identity,
    )?;

    let authorized_semantic_digests = preliminary_graph
        .records
        .iter()
        .map(|record| record.semantic_digest.clone())
        .collect::<BTreeSet<_>>();
    let mut carrier_manifests = BTreeMap::new();
    let mut admitted_carriers = BTreeMap::new();
    let mut carrier_facts = BTreeMap::new();
    for manifest_section in envelope
        .sections()
        .filter(|section| section.record.kind == SectionKindV1::CarrierManifest)
    {
        let pair = manifest_section
            .record
            .pair_id
            .as_deref()
            .ok_or_else(|| anyhow!("carrier manifest has no pair id"))?;
        let payload = envelope
            .sections()
            .find(|section| {
                section.record.kind == SectionKindV1::CarrierPayload
                    && section.record.pair_id.as_deref() == Some(pair)
            })
            .ok_or_else(|| anyhow!("carrier pair {pair:?} has no payload"))?;
        let manifest: PreparedModuleCarrierV2 =
            decode_canonical_section(manifest_section.bytes, "carrier manifest")?;
        if manifest.entries.len() != 1 {
            bail!("phase-0 v1 requires one original module per carrier pair");
        }
        let (expected_producer_id, producer_binary_digest) =
            provenance.expected_producer(&manifest);
        let (expected_engine_binding, expected_bytecode_version) =
            expected_carrier_engine(&contract, &manifest, provenance.is_release())?;
        let admission = PreparedCarrierAdmissionV2 {
            expected_principal: manifest.defining_principal.clone(),
            expected_producer_id,
            producer_binary_digest,
            deployment_graph_digest: preliminary_graph.graph_identity.clone(),
            authorized_semantic_digests: authorized_semantic_digests.clone(),
            expected_engine_binding,
            expected_bytecode_version,
        };
        let admitted = AdmittedPreparedCarrierV2::decode_and_admit(
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
            bail!("duplicate admitted carrier pair {pair:?}");
        }
        carrier_manifests.insert(pair.to_owned(), manifest);
        admitted_carriers.insert(pair.to_owned(), admitted);
    }
    for carrier in admitted_carriers.values() {
        if matches!(
            carrier.manifest().encoding,
            ibex_runtime::module_loader::carrier::PreparedCarrierEncodingV2::HermesBytecode { .. }
        ) {
            preflight_hermes_bytecode(carrier.bytes())?;
        }
    }
    let candidate_tables = envelope
        .sections()
        .filter(|section| section.record.kind == SectionKindV1::CandidateTable)
        .map(|section| {
            let table = ComputedCandidateTableV1::decode_canonical(section.bytes)?;
            if table.digest()?.as_str() != section.record.id {
                bail!("computed-candidate section id disagrees with its canonical bytes");
            }
            Ok(table)
        })
        .collect::<Result<Vec<_>>>()?;
    let candidate_sets = candidate_tables
        .iter()
        .map(ComputedCandidateTableV1::graph_projection)
        .collect::<Result<Vec<_>>>()?;
    let graph =
        EmbeddedModuleGraphV1::decode_and_admit(graph_bytes, &carrier_facts, &candidate_sets)?;
    if &graph.graph_identity != provenance.graph_identity(&graph)? {
        bail!("admitted graph identity changed across bulk preflight");
    }
    let (artifacts, admissions) = prepared_artifacts(
        &graph,
        &carrier_manifests,
        &provenance,
        &authorized_semantic_digests,
    )?;
    let computed_candidates = admit_computed_candidates(&candidate_tables, &graph, &artifacts)?;
    let plan_records = graph
        .records
        .iter()
        .map(|record| {
            let artifact = artifacts
                .get(&record.source_id.0)
                .ok_or_else(|| anyhow!("prepared artifact is absent"))?;
            let verified = artifact.verify_for_admission(
                admissions
                    .get(&record.source_id.0)
                    .ok_or_else(|| anyhow!("prepared admission is absent"))?,
            )?;
            let edges = record
                .edges
                .iter()
                .map(|edge| {
                    (
                        GraphEdgeKey::new(edge.specifier.as_str(), edge.resolution_kind),
                        edge.target.0.clone(),
                    )
                })
                .collect();
            Ok((verified, edges))
        })
        .collect::<Result<Vec<_>>>()?;
    let plan = SynchronousGraphPlan::new_typed(plan_records)?;
    let prepared_entries = prepared_entries(&graph, &admitted_carriers)?;
    let configs = native_configs(&graph)?;
    let entry_designation = graph
        .records
        .iter()
        .find(|record| record.source_id == graph.entry)
        .map(|record| record.virtual_source.path.clone())
        .ok_or_else(|| anyhow!("compiled entry designation is absent from the graph"))?;
    let process = process_arguments.bind_entry(entry_designation)?;

    if provenance.is_release() {
        // A release stub may not manufacture complete target evidence or an
        // environment posture merely because its inner bytes are consistent.
        // @ref LLP 0029#7-phases-gates-and-the-author-decision-register
        bail!(
            "release compiled arming remains closed until the SFE CapSec target advertisement and environment decisions are accepted"
        );
    }
    ibex_runtime::host::abi::install_host(ibex_runtime::host::Host::strict());
    let mut owner = DiagnosticModuleRuntime::new()?;
    owner.install_compiled_process_metadata(
        &process.exec_path,
        &process.entry_designation,
        &process.invoked_name,
        &process.application_arguments,
    )?;
    let namespace = {
        let runtime = owner.borrow()?;
        let mut linked = NativeSynchronousGraph::link_prepared_with_computed_candidates(
            &runtime,
            &plan,
            &graph.entry.0,
            configs,
            &prepared_entries,
            &computed_candidates,
        )?;
        linked.evaluate()?;
        linked.namespace_json(&graph.entry.0)?
    };
    println!("{namespace}");
    owner.drive_compiled_event_loop_to_quiescence()?;
    owner.compiled_process_exit_code()
}

fn decode_boot_provenance(
    bytes: &[u8],
    contract: &StubContractV1,
    contract_digest: &str,
) -> Result<BootProvenanceV1> {
    let value: serde_json::Value = decode_canonical_section(bytes, "provenance")?;
    if value.get("compilePlan").is_some() {
        let release: PackageProvenanceV1 = serde_json::from_value(value)?;
        if release.canonical_bytes()? != bytes {
            bail!("release package provenance is not canonical");
        }
        let plan = &release.compile_plan;
        if plan.stub_contract_digest != contract_digest
            || plan.target != contract.target.triple
            || plan.environment_profile_digest != contract.environment_profile_digest
            || plan.compiler_identity != contract.hermesc.identity().unwrap_or_default()
            || plan.carrier_encoding != CompileCarrierEncodingV1::HermesBytecode
        {
            bail!("release CompilePlanV1 disagrees with the compiled stub contract");
        }
        Ok(BootProvenanceV1::Release(release))
    } else {
        let development: DevelopmentProvenanceV1 = serde_json::from_value(value)?;
        if development.schema != "ibex/package-provenance/1"
            || development.stub_contract_digest != contract_digest
        {
            bail!("embedded provenance disagrees with the compiled stub contract");
        }
        Ok(BootProvenanceV1::Development(development))
    }
}

fn expected_carrier_engine(
    contract: &StubContractV1,
    manifest: &PreparedModuleCarrierV2,
    release: bool,
) -> Result<(Option<PreparedCarrierEngineBindingV2>, Option<u32>)> {
    match &manifest.encoding {
        PreparedCarrierEncodingV2::JavascriptFactoryTable => {
            if release {
                bail!("release executable contains a diagnostic factory-table carrier");
            }
            Ok((None, None))
        }
        PreparedCarrierEncodingV2::HermesBytecode {
            engine_binding,
            bytecode_version,
        } => {
            let EngineCompatibilityV1::StaticHermes {
                compatibility_identity,
                hbc_version,
                ..
            } = &contract.engine
            else {
                bail!("Hermes-bytecode carrier is paired with a diagnostic source engine");
            };
            let PreparedCarrierEngineBindingV2::StaticCompatibility {
                compatibility_identity: carrier_identity,
            } = engine_binding
            else {
                bail!("release HBC carrier uses a loaded-file engine identity");
            };
            if carrier_identity.as_str() != compatibility_identity
                || bytecode_version != hbc_version
            {
                bail!("release HBC carrier disagrees with static engine compatibility");
            }
            Ok((Some(engine_binding.clone()), Some(*bytecode_version)))
        }
    }
}

#[cfg(ibex_release_stub_contract)]
fn compiled_stub_contract() -> Result<ibex_sfe_format::StubContractV1> {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/stub-contract.canonical.json"));
    let contract: ibex_sfe_format::StubContractV1 = serde_json::from_slice(bytes)?;
    if contract.canonical_bytes()? != bytes {
        bail!("compiled release stub contract bytes are not canonical");
    }
    Ok(contract)
}

#[cfg(not(ibex_release_stub_contract))]
fn compiled_stub_contract() -> Result<ibex_sfe_format::StubContractV1> {
    Ok(ibex_runtime::compiled_contract::diagnostic_development_stub_contract()?)
}

fn prepared_artifacts(
    graph: &EmbeddedModuleGraphV1,
    manifests: &BTreeMap<String, PreparedModuleCarrierV2>,
    provenance: &BootProvenanceV1,
    authorized: &BTreeSet<Digest>,
) -> Result<(
    BTreeMap<SourceId, ModuleArtifactV1>,
    BTreeMap<SourceId, ArtifactAdmissionV1>,
)> {
    let mut artifacts = BTreeMap::new();
    let mut admissions = BTreeMap::new();
    for record in &graph.records {
        let pair = record.carrier.pair_id.as_str();
        let manifest = manifests
            .get(pair)
            .ok_or_else(|| anyhow!("graph carrier pair {pair:?} is absent"))?;
        let artifact = manifest.prepared_artifact(record.carrier.entry_id.as_str())?;
        let (expected_producer_id, producer_binary_digest) = provenance.expected_producer(manifest);
        let admission = ArtifactAdmissionV1::DigestBoundPrepared {
            expected_source_id: record.source_id.0.clone(),
            expected_source_integrity: record.source_integrity.clone(),
            expected_producer_id,
            producer_binary_digest,
            deployment_graph_digest: graph.graph_identity.clone(),
            expected_carrier_digest: manifest.carrier_digest.clone(),
            expected_entry_id: record.carrier.entry_id.clone(),
            authorized_semantic_digests: authorized.clone(),
            transform_fingerprint_digest: artifact.semantics.transform_fingerprint.digest()?,
        };
        artifacts.insert(record.source_id.0.clone(), artifact);
        admissions.insert(record.source_id.0.clone(), admission);
    }
    Ok((artifacts, admissions))
}

fn admit_computed_candidates(
    tables: &[ComputedCandidateTableV1],
    graph: &EmbeddedModuleGraphV1,
    artifacts: &BTreeMap<SourceId, ModuleArtifactV1>,
) -> Result<ComputedDynamicImportLinks> {
    let mut links = ComputedDynamicImportLinks::new();
    for table in tables {
        if table.generation != 1 {
            bail!("compiled candidate table names a stale execution generation");
        }
        let requester_artifact = artifacts
            .get(&table.requester.0)
            .ok_or_else(|| anyhow!("computed-candidate requester artifact is absent"))?;
        table.validate_requester(requester_artifact)?;
        let requester_record = graph
            .records
            .iter()
            .find(|record| record.source_id == table.requester)
            .ok_or_else(|| anyhow!("computed-candidate requester graph record is absent"))?;
        for candidate in &table.candidates {
            let target_artifact = artifacts
                .get(&candidate.target.0)
                .ok_or_else(|| anyhow!("computed-candidate target artifact is absent"))?;
            if target_artifact.semantics.source_integrity != candidate.target_source_integrity {
                bail!("computed-candidate target source integrity is stale");
            }
            if !requester_record.edges.iter().any(|edge| {
                edge.resolution_kind
                    == ibex_runtime::module_loader::identity::ResolutionKind::DynamicImport
                    && edge.specifier == candidate.specifier
                    && edge.attributes == candidate.attributes
                    && edge.target == candidate.target
            }) {
                bail!("computed-candidate row is absent from the authenticated graph edges");
            }
            if links
                .entry(table.requester.0.clone())
                .or_default()
                .insert(
                    (table.site, candidate.specifier.as_str().to_owned()),
                    candidate.target.0.clone(),
                )
                .is_some()
            {
                bail!("computed-candidate table repeats one site spelling");
            }
        }
    }
    Ok(links)
}

fn prepared_entries<'a>(
    graph: &EmbeddedModuleGraphV1,
    carriers: &'a BTreeMap<String, AdmittedPreparedCarrierV2>,
) -> Result<BTreeMap<SourceId, VerifiedPreparedCarrierEntryV2<'a>>> {
    graph
        .records
        .iter()
        .map(|record| {
            let pair = record.carrier.pair_id.as_str();
            let carrier = carriers
                .get(pair)
                .ok_or_else(|| anyhow!("admitted carrier pair {pair:?} is absent"))?;
            Ok((
                record.source_id.0.clone(),
                carrier.entry(record.carrier.entry_id.as_str())?,
            ))
        })
        .collect()
}

fn native_configs(
    graph: &EmbeddedModuleGraphV1,
) -> Result<BTreeMap<SourceId, NativeModuleRecordConfig>> {
    graph
        .records
        .iter()
        .map(|record| {
            let source_id = record.source_id.0.clone();
            let context = GraphEvaluationContext::new(source_id.clone(), 0, 0, [0], 1)?;
            Ok((
                source_id,
                NativeModuleRecordConfig::new(
                    0,
                    None,
                    context,
                    &record.virtual_source.path,
                    &record.virtual_source.import_meta_url,
                )?,
            ))
        })
        .collect()
}

fn admit_policy(bytes: &[u8], graph_identity: &Digest) -> Result<()> {
    let identity: serde_json::Value = serde_json::from_slice(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../capsec/examples/canonical-policy.canonical.json"
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
            "/../../capsec/registry/capability-definitions.json"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../capsec/registry/policy-rules.json"
        )),
    )?;
    let policy = CanonicalPolicy::load(bytes, &expected, &profile.definitions)?;
    if &policy.graph_identity != graph_identity {
        bail!("embedded policy is bound to a different graph identity");
    }
    Ok(())
}

fn section_bytes<'a>(
    envelope: &'a ibex_sfe_format::AdmittedEnvelopeV1<'a>,
    kind: SectionKindV1,
) -> Result<&'a [u8]> {
    envelope
        .sections()
        .find(|section| section.record.kind == kind)
        .map(|section| section.bytes)
        .ok_or_else(|| anyhow!("required {kind:?} section is absent"))
}

fn decode_canonical_section<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T> {
    let text = std::str::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))?;
    let value = capsec_semantics::strict_json::parse_strict(text)
        .map_err(|error| anyhow!("{label} is not strict JSON: {error}"))?;
    if capsec_semantics::canonical::to_jcs_bytes(&value)? != bytes {
        bail!("{label} is not canonical JCS");
    }
    serde_json::from_value(value).with_context(|| format!("{label} has an invalid shape"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsec_semantics::model::Principal;
    use ibex_runtime::module_loader::artifact::source_integrity;
    use ibex_sfe_format::{
        CompilePlanV1, HermescCompatibilityV1, HermescRecipeV1, COMPILE_PLAN_SCHEMA_V1,
        PACKAGE_PROVENANCE_SCHEMA_V1,
    };

    fn release_contract() -> StubContractV1 {
        let mut contract =
            ibex_runtime::compiled_contract::diagnostic_development_stub_contract().unwrap();
        let archive = source_integrity(b"static archive bundle").unwrap();
        let compiler = source_integrity(b"hermesc").unwrap();
        contract.release_eligible = true;
        contract.profile = "sfe-v1".into();
        contract.target.triple = "aarch64-apple-darwin".into();
        contract.target.minimum_platform = "macos-13.0-arm64".into();
        contract.engine =
            EngineCompatibilityV1::static_hermes("full", archive.as_str(), 96).unwrap();
        contract.hermesc = HermescCompatibilityV1::catalog_artifact(
            compiler.as_str(),
            96,
            HermescRecipeV1::production().digest().unwrap(),
        )
        .unwrap();
        contract
    }

    fn release_provenance(contract: &StubContractV1) -> PackageProvenanceV1 {
        let plan = CompilePlanV1 {
            schema: COMPILE_PLAN_SCHEMA_V1.into(),
            graph_snapshot_digest: source_integrity(b"graph").unwrap().to_string(),
            policy_digest: source_integrity(b"policy").unwrap().to_string(),
            stub_contract_digest: contract.digest().unwrap(),
            catalog_digest: source_integrity(b"catalog").unwrap().to_string(),
            compiler_identity: contract.hermesc.identity().unwrap().into(),
            carrier_encoding: CompileCarrierEncodingV1::HermesBytecode,
            target: contract.target.triple.clone(),
            environment_profile_digest: contract.environment_profile_digest.clone(),
        };
        PackageProvenanceV1 {
            schema: PACKAGE_PROVENANCE_SCHEMA_V1.into(),
            compile_plan_digest: plan.digest().unwrap(),
            compile_plan: plan,
            catalog_sequence: 1,
            catalog_entry_target: contract.target.triple.clone(),
            stub_core_digest: source_integrity(b"stub").unwrap().to_string(),
            producer_identity: "ibex-compile/test".into(),
        }
    }

    #[test]
    fn release_provenance_and_static_hbc_binding_cross_check_contract() {
        let contract = release_contract();
        let provenance = release_provenance(&contract);
        let bytes = provenance.canonical_bytes().unwrap();
        assert!(matches!(
            decode_boot_provenance(&bytes, &contract, &contract.digest().unwrap()).unwrap(),
            BootProvenanceV1::Release(_)
        ));

        let identity = Digest::new(contract.engine.identity()).unwrap();
        let manifest = PreparedModuleCarrierV2 {
            schema: "ibex/module-carrier/2".into(),
            encoding: PreparedCarrierEncodingV2::HermesBytecode {
                engine_binding: PreparedCarrierEngineBindingV2::StaticCompatibility {
                    compatibility_identity: identity,
                },
                bytecode_version: 96,
            },
            carrier_digest: source_integrity(b"carrier").unwrap(),
            defining_principal: Principal::Root {
                identity: NonEmptyString::new("project-root").unwrap(),
            },
            producer_id: NonEmptyString::new("producer").unwrap(),
            producer_binary_digest: source_integrity(b"producer").unwrap(),
            deployment_graph_digest: source_integrity(b"graph").unwrap(),
            entries: Vec::new(),
        };
        assert!(expected_carrier_engine(&contract, &manifest, true).is_ok());

        let mut wrong = manifest;
        wrong.encoding = PreparedCarrierEncodingV2::HermesBytecode {
            engine_binding: PreparedCarrierEngineBindingV2::StaticCompatibility {
                compatibility_identity: source_integrity(b"other engine").unwrap(),
            },
            bytecode_version: 96,
        };
        assert!(expected_carrier_engine(&contract, &wrong, true).is_err());
    }
}
