//! Dedicated dual-mode compiled-executable stub.
//!
//! The image reads no original application source. It authenticates its own
//! envelope, resolved policy, embedded graph, and prepared carrier before an
//! selected runtime evaluates the entry.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use capsec_semantics::model::{Digest, NonEmptyString};
use capsec_semantics::policy::{CanonicalPolicy, ExpectedPolicyIdentity};
use capsec_semantics::registry::ValidatedProfile;
use ibex_runtime::engine::module_runner::{
    preflight_hermes_bytecode, AsyncGraphPoll, CompiledModuleRuntime, ComputedDynamicImportLinks,
    GraphEvaluationContext, NativeAsynchronousGraph, NativeModuleRecordConfig,
    NativeSynchronousGraph,
};
use ibex_runtime::module_loader::artifact::{ArtifactAdmissionV1, ModuleArtifactV1};
use ibex_runtime::module_loader::carrier::{
    AdmittedPreparedCarrierV2, PreparedCarrierAdmissionV2, PreparedCarrierEncodingV2,
    PreparedCarrierEngineBindingV2, PreparedModuleCarrierV2, VerifiedPreparedCarrierEntryV2,
};
use ibex_runtime::module_loader::computed_candidates::ComputedCandidateTableV1;
use ibex_runtime::module_loader::embedded_graph::{EmbeddedCarrierFactV1, EmbeddedModuleGraphV1};
use ibex_runtime::module_loader::graph::{
    ComputedCandidateBinding, ComputedCandidateSiteMap, GraphEdgeKey, SynchronousGraphPlan,
};
use ibex_runtime::module_loader::identity::SourceId;
use ibex_sfe_format::app_bound::{
    admit_executable_v2, ApplicationBindingV1, PackageProvenanceV2, SectionKindV2, StubContractV4,
    STANDALONE_INFO_SCHEMA_V2,
};
use ibex_sfe_format::{
    admit_executable_v1, CompileCarrierEncodingV1, EngineCompatibilityV1, PackageProvenanceV1,
    SectionKindV1, StubContractV3, STANDALONE_INFO_SCHEMA_V1,
};
use serde::Deserialize;

mod environment;
mod process;
mod signals;

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
    AppBound(PackageProvenanceV2),
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
            Self::AppBound(value) => {
                if value.compile_plan.graph_snapshot_digest != graph.graph_identity.as_str() {
                    bail!("app-bound CompilePlanV2 names a different graph snapshot");
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
            Self::Release(_) | Self::AppBound(_) => (
                manifest.producer_id.clone(),
                manifest.producer_binary_digest.clone(),
            ),
        }
    }

    fn is_release(&self) -> bool {
        matches!(self, Self::Release(_) | Self::AppBound(_))
    }
}

struct CompiledContract {
    runtime: StubContractV3,
    canonical: Vec<u8>,
    app_bound: Option<StubContractV4>,
}

struct EnvelopeSection<'a> {
    kind: SectionKindV1,
    id: String,
    pair_id: Option<String>,
    bytes: &'a [u8],
}

struct AdmittedImage<'a> {
    sections: Vec<EnvelopeSection<'a>>,
    application_binding: Option<ApplicationBindingV1>,
}

impl<'a> AdmittedImage<'a> {
    fn section(&self, kind: SectionKindV1) -> Result<&'a [u8]> {
        self.sections
            .iter()
            .find(|section| section.kind == kind)
            .map(|section| section.bytes)
            .ok_or_else(|| anyhow!("required {kind:?} section is absent"))
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
            eprintln!("ibex compiled executable refused: {error:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32> {
    signals::install().context("compiled signal mediation is unavailable")?;
    let environment = environment::captured_environment()
        .context("compiled environment capture/sanitization did not complete")?;
    let boot_mode = environment.boot_mode;
    if boot_mode == environment::CompiledBootMode::CapsecRequested {
        ibex_runtime::host::process::install_compiled_environment_base(environment.broker_base()?)?;
    }
    let process_arguments = process::CapturedProcessArguments::capture(boot_mode)?;
    let compiled = compiled_stub_contract()?;
    let contract = &compiled.runtime;
    let contract_digest = if let Some(app_bound) = &compiled.app_bound {
        app_bound.digest()?
    } else {
        contract.digest()?
    };
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
    let envelope = admit_image(&file, &compiled, &contract_digest)?;
    let embedded_contract = envelope.section(SectionKindV1::StubContract)?;
    if embedded_contract != compiled.canonical {
        bail!("embedded stub contract differs from the contract compiled into the stub");
    }
    let provenance = decode_boot_provenance(
        envelope.section(SectionKindV1::ProvenanceManifest)?,
        contract,
        &contract_digest,
        envelope.application_binding.as_ref(),
    )?;

    let graph_bytes = envelope.section(SectionKindV1::EmbeddedModuleGraph)?;
    let preliminary_graph = EmbeddedModuleGraphV1::decode_canonical(graph_bytes)?;
    if &preliminary_graph.graph_identity != provenance.graph_identity(&preliminary_graph)? {
        bail!("embedded provenance and graph name different snapshots");
    }
    admit_policy(
        envelope.section(SectionKindV1::ResolvedPolicy)?,
        &preliminary_graph.graph_identity,
    )?;

    let authorized_semantic_digests = Arc::new(
        preliminary_graph
            .records
            .iter()
            .map(|record| record.semantic_digest.clone())
            .collect::<BTreeSet<_>>(),
    );
    let mut carrier_manifests = BTreeMap::new();
    let mut admitted_carriers = BTreeMap::new();
    let mut carrier_facts = BTreeMap::new();
    for manifest_section in envelope
        .sections
        .iter()
        .filter(|section| section.kind == SectionKindV1::CarrierManifest)
    {
        let pair = manifest_section
            .pair_id
            .as_deref()
            .ok_or_else(|| anyhow!("carrier manifest has no pair id"))?;
        let payload = envelope
            .sections
            .iter()
            .find(|section| {
                section.kind == SectionKindV1::CarrierPayload
                    && section.pair_id.as_deref() == Some(pair)
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
            expected_carrier_engine(contract, &manifest, provenance.is_release())?;
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
        .sections
        .iter()
        .filter(|section| section.kind == SectionKindV1::CandidateTable)
        .map(|section| {
            let table = ComputedCandidateTableV1::decode_canonical(section.bytes)?;
            if table.digest()?.as_str() != section.id.as_str() {
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
    let (computed_candidates, computed_candidate_sites) =
        admit_computed_candidates(&candidate_tables, &graph, &artifacts)?;
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
    let plan = SynchronousGraphPlan::new_typed_with_computed_candidates(
        plan_records,
        computed_candidate_sites,
    )?;
    let prepared_entries = prepared_entries(&graph, &admitted_carriers)?;
    let configs = native_configs(&graph)?;
    let entry_designation = graph
        .records
        .iter()
        .find(|record| record.source_id == graph.entry)
        .map(|record| record.virtual_source.path.clone())
        .ok_or_else(|| anyhow!("compiled entry designation is absent from the graph"))?;
    let process = process_arguments.bind_entry(entry_designation)?;

    if boot_mode == environment::CompiledBootMode::InformationRequested {
        // The recipient-facing report is produced only after the same complete
        // admission used by both execution postures, and before a Host, Hermes
        // runtime, or application module is constructed.
        // @ref LLP 0047#8-milestone-5--distribution-and-usability
        emit_standalone_information(
            contract,
            &contract_digest,
            &provenance,
            &graph,
            carrier_manifests.len(),
            candidate_tables.len(),
            envelope.application_binding.as_ref(),
        )?;
        return Ok(0);
    }

    if boot_mode == environment::CompiledBootMode::CapsecRequested {
        // Selection is monotonic: an unavailable CapSec path terminates here
        // and never retries the ambient runtime.
        // @ref LLP 0047#capsec-path
        bail!(
            "CapSec requested but target {} has no accepted SFE CapSec advertisement",
            contract.target.triple
        );
    }
    // The ambient compatibility path deliberately makes no confinement claim.
    // Admission above remains identical to the CapSec-selected path.
    // @ref LLP 0047#ambient-path
    ibex_runtime::host::abi::install_host(ibex_runtime::host::Host::compiled_ambient());
    let mut owner = CompiledModuleRuntime::new_ambient()?;
    if let (Some(binding), Some(app_contract)) = (
        envelope.application_binding.as_ref(),
        compiled.app_bound.as_ref(),
    ) {
        let bridge_contract = capsec_semantics::canonical::to_jcs_bytes(&serde_json::json!({
            "schema": "ibex/app-bound-worker-bridge-contract/1",
            "appBindingDigest": binding.digest()?,
            "engineCompatibilityDigest": app_contract.engine.identity(),
            "language": app_contract.external_worker.language_profile,
            "languageDigest": app_contract.external_worker.language_profile_digest,
            "workerPolicy": app_contract.external_worker.worker_policy,
            "workerPolicyDigest": app_contract.external_worker.worker_policy_digest,
            "broker": app_contract.external_worker.broker_protocol,
            "globalsDigest": app_contract.external_worker.global_inventory_digest,
            "defaults": app_contract.external_worker.defaults,
            "maxima": app_contract.external_worker.maxima,
        }))?;
        owner.install_app_bound_worker_bridge(&bridge_contract)?;
    }
    owner.install_compiled_process_metadata(
        &process.exec_path,
        &process.entry_designation,
        &process.invoked_name,
        &process.application_arguments,
        "ambient-compatibility",
    )?;
    let namespace = {
        let runtime = owner.borrow()?;
        let asynchronous = plan
            .asynchronous_evaluation_plan(&graph.entry.0)?
            .is_async_tainted(&graph.entry.0)
            .unwrap_or(false);
        if asynchronous {
            let mut linked = NativeAsynchronousGraph::link_prepared_with_computed_candidates(
                &runtime,
                &plan,
                &graph.entry.0,
                configs,
                &prepared_entries,
                &computed_candidates,
            )?;
            let maximum_idle_graph_polls = linked.schedule().sccs.len().saturating_add(1);
            let mut idle_graph_polls = 0usize;
            loop {
                match linked.poll()? {
                    AsyncGraphPoll::Evaluated => {
                        let namespace = linked.namespace_json(&graph.entry.0)?;
                        while runtime.drive_compiled_tasks_until_progress()? {}
                        break namespace;
                    }
                    AsyncGraphPoll::Suspended => {
                        if runtime.drive_compiled_tasks_until_progress()? {
                            idle_graph_polls = 0;
                        } else {
                            idle_graph_polls = idle_graph_polls.saturating_add(1);
                            if idle_graph_polls > maximum_idle_graph_polls {
                                bail!(
                                    "asynchronous module graph remained suspended without pending host work"
                                );
                            }
                        }
                    }
                }
            }
        } else {
            let mut linked = NativeSynchronousGraph::link_prepared_with_computed_candidates(
                &runtime,
                &plan,
                &graph.entry.0,
                configs,
                &prepared_entries,
                &computed_candidates,
            )?;
            linked.evaluate()?;
            let namespace = linked.namespace_json(&graph.entry.0)?;
            // Imported live bindings remain callback-backed after entry
            // evaluation. Retain the authenticated graph records until every
            // referenced callback has completed, or a post-await access would
            // observe a fabricated stale-import failure.
            // @ref LLP 0029#6-compiled-boot-and-process-semantics
            while runtime.drive_compiled_tasks_until_progress()? {}
            namespace
        }
    };
    if !provenance.is_release() {
        println!("{namespace}");
    }
    owner.drive_compiled_event_loop_to_quiescence()?;
    owner.compiled_process_exit_code()
}

fn emit_standalone_information(
    contract: &StubContractV3,
    contract_digest: &str,
    provenance: &BootProvenanceV1,
    graph: &EmbeddedModuleGraphV1,
    carrier_count: usize,
    candidate_table_count: usize,
    application_binding: Option<&ApplicationBindingV1>,
) -> Result<()> {
    let capsec_availability = if contract.boot.capsec_advertisement_identity.is_empty() {
        "unavailable-no-advertisement"
    } else {
        "contract-advertised"
    };
    let report = serde_json::json!({
        "schema": if application_binding.is_some() { STANDALONE_INFO_SCHEMA_V2 } else { STANDALONE_INFO_SCHEMA_V1 },
        "execution": {
            "applicationEvaluated": false,
        },
        "integrity": {
            "status": "admitted",
            "envelopeSchema": contract.accepted_schemas.envelope,
            "stubContractDigest": contract_digest,
            "graphIdentity": graph.graph_identity,
            "recordCount": graph.records.len(),
            "carrierCount": carrier_count,
            "candidateTableCount": candidate_table_count,
        },
        "boot": {
            "defaultMode": contract.boot.default_mode,
            "capsecSelector": contract.boot.capsec_selector,
            "informationSelector": contract.boot.information_selector,
            "capsecAdvertisementIdentity": contract.boot.capsec_advertisement_identity,
            "capsecAvailability": capsec_availability,
        },
        "target": contract.target,
        "backendInventory": contract.backends,
        "provenanceKind": if provenance.is_release() { "release" } else { "development" },
        "applicationBinding": application_binding,
    });
    let bytes = capsec_semantics::canonical::to_jcs_bytes(&report)?;
    println!(
        "{}",
        std::str::from_utf8(&bytes).expect("canonical JSON is UTF-8")
    );
    Ok(())
}

fn decode_boot_provenance(
    bytes: &[u8],
    contract: &StubContractV3,
    contract_digest: &str,
    application_binding: Option<&ApplicationBindingV1>,
) -> Result<BootProvenanceV1> {
    let value: serde_json::Value = decode_canonical_section(bytes, "provenance")?;
    if application_binding.is_some() {
        let release: PackageProvenanceV2 = serde_json::from_value(value)?;
        if release.canonical_bytes()? != bytes {
            bail!("app-bound package provenance is not canonical");
        }
        let plan = &release.compile_plan;
        let binding_digest = application_binding.expect("checked app binding").digest()?;
        if plan.stub_contract_digest != contract_digest
            || plan.target != contract.target.triple
            || plan.environment_profile_digest != contract.environment_profile_digest
            || plan.compiler_identity != contract.hermesc.identity().unwrap_or_default()
            || plan.carrier_encoding != CompileCarrierEncodingV1::HermesBytecode
            || plan.application_binding_digest != binding_digest
        {
            bail!("app-bound CompilePlanV2 disagrees with admitted executable identities");
        }
        Ok(BootProvenanceV1::AppBound(release))
    } else if value.get("compilePlan").is_some() {
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
    contract: &StubContractV3,
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

#[cfg(all(ibex_release_stub_contract, ibex_app_bound_stub_contract))]
fn compiled_stub_contract() -> Result<CompiledContract> {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/stub-contract.canonical.json"));
    let contract: StubContractV4 = serde_json::from_slice(bytes)?;
    if contract.canonical_bytes()? != bytes {
        bail!("compiled app-bound release stub contract bytes are not canonical");
    }
    ibex_runtime::compiled_contract::validate_app_bound_stub_contract_local_authorities(&contract)?;
    Ok(CompiledContract {
        runtime: project_v4_contract(&contract),
        canonical: bytes.to_vec(),
        app_bound: Some(contract),
    })
}

#[cfg(all(ibex_release_stub_contract, not(ibex_app_bound_stub_contract)))]
fn compiled_stub_contract() -> Result<CompiledContract> {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/stub-contract.canonical.json"));
    let contract: StubContractV3 = serde_json::from_slice(bytes)?;
    if contract.canonical_bytes()? != bytes {
        bail!("compiled release stub contract bytes are not canonical");
    }
    ibex_runtime::compiled_contract::validate_stub_contract_local_authorities(&contract)?;
    Ok(CompiledContract {
        runtime: contract,
        canonical: bytes.to_vec(),
        app_bound: None,
    })
}

#[cfg(not(ibex_release_stub_contract))]
fn compiled_stub_contract() -> Result<CompiledContract> {
    let contract = ibex_runtime::compiled_contract::diagnostic_development_stub_contract()?;
    ibex_runtime::compiled_contract::validate_stub_contract_local_authorities(&contract)?;
    Ok(CompiledContract {
        canonical: contract.canonical_bytes()?,
        runtime: contract,
        app_bound: None,
    })
}

fn project_v4_contract(contract: &StubContractV4) -> StubContractV3 {
    StubContractV3 {
        schema: ibex_sfe_format::STUB_CONTRACT_SCHEMA_V3.into(),
        profile: contract.profile.clone(),
        release_eligible: contract.release_eligible,
        target: contract.target.clone(),
        engine: contract.engine.clone(),
        hermesc: contract.hermesc.clone(),
        accepted_schemas: ibex_sfe_format::StubAcceptedSchemasV1 {
            envelope: ibex_sfe_format::ENVELOPE_SCHEMA_V2.into(),
            entry_designation: contract.accepted_schemas.entry_designation.clone(),
            embedded_graph: contract.accepted_schemas.embedded_graph.clone(),
            authenticated_graph_snapshot: contract
                .accepted_schemas
                .authenticated_graph_snapshot
                .clone(),
            computed_candidates: contract.accepted_schemas.computed_candidates.clone(),
            carrier: contract.accepted_schemas.carrier.clone(),
            canonical_policy: contract.accepted_schemas.canonical_policy.clone(),
            armed_snapshot: contract.accepted_schemas.armed_snapshot.clone(),
            runtime_capsec_projection: contract.accepted_schemas.runtime_capsec_projection.clone(),
            runtime_identity: contract.accepted_schemas.runtime_identity.clone(),
            environment_profile: contract.accepted_schemas.environment_profile.clone(),
        },
        abis: ibex_sfe_format::StubAbisV1 {
            module_runner: contract.abis.module_runner.clone(),
            arming: contract.abis.arming.clone(),
        },
        transform_profile_digest: contract.transform_profile_digest.clone(),
        runtime_capsec_projection_digest: contract.runtime_capsec_projection_digest.clone(),
        runtime_identity_digest: contract.runtime_identity_digest.clone(),
        environment_profile_digest: contract.environment_profile_digest.clone(),
        boot: contract.boot.clone(),
        backends: contract.backends.clone(),
    }
}

fn admit_image<'a>(
    file: &'a [u8],
    contract: &CompiledContract,
    contract_digest: &str,
) -> Result<AdmittedImage<'a>> {
    if contract.app_bound.is_some() {
        let admitted = admit_executable_v2(file, Some(contract_digest))?;
        let mut sections = Vec::with_capacity(admitted.directory.sections.len());
        for row in &admitted.directory.sections {
            let Some(kind) = project_section_kind(row.kind) else {
                continue;
            };
            let start = admitted.stub_len + row.offset as usize;
            let bytes = &file[start..start + row.length as usize];
            sections.push(EnvelopeSection {
                kind,
                id: row.id.clone(),
                pair_id: row.pair_id.clone(),
                bytes,
            });
        }
        let binding_row = admitted
            .directory
            .sections
            .iter()
            .find(|row| row.kind == SectionKindV2::ApplicationBinding)
            .ok_or_else(|| anyhow!("application binding section is absent"))?;
        let binding_start = admitted.stub_len + binding_row.offset as usize;
        let binding_bytes = &file[binding_start..binding_start + binding_row.length as usize];
        let binding: ApplicationBindingV1 =
            decode_canonical_section(binding_bytes, "application binding")?;
        binding.validate()?;
        Ok(AdmittedImage {
            sections,
            application_binding: Some(binding),
        })
    } else {
        let admitted = admit_executable_v1(file, contract_digest)?;
        let sections = admitted
            .directory
            .sections
            .iter()
            .map(|section| EnvelopeSection {
                kind: section.kind,
                id: section.id.clone(),
                pair_id: section.pair_id.clone(),
                bytes: {
                    let start = admitted.stub_len + section.offset as usize;
                    &file[start..start + section.length as usize]
                },
            })
            .collect();
        Ok(AdmittedImage {
            sections,
            application_binding: None,
        })
    }
}

fn project_section_kind(kind: SectionKindV2) -> Option<SectionKindV1> {
    Some(match kind {
        SectionKindV2::StubContract => SectionKindV1::StubContract,
        SectionKindV2::ProvenanceManifest => SectionKindV1::ProvenanceManifest,
        SectionKindV2::EmbeddedModuleGraph => SectionKindV1::EmbeddedModuleGraph,
        SectionKindV2::ResolvedPolicy => SectionKindV1::ResolvedPolicy,
        SectionKindV2::EntryDesignation => SectionKindV1::EntryDesignation,
        SectionKindV2::CandidateTable => SectionKindV1::CandidateTable,
        SectionKindV2::CarrierManifest => SectionKindV1::CarrierManifest,
        SectionKindV2::CarrierPayload => SectionKindV1::CarrierPayload,
        SectionKindV2::ApplicationBinding => return None,
    })
}

fn prepared_artifacts(
    graph: &EmbeddedModuleGraphV1,
    manifests: &BTreeMap<String, PreparedModuleCarrierV2>,
    provenance: &BootProvenanceV1,
    authorized: &Arc<BTreeSet<Digest>>,
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
) -> Result<(ComputedDynamicImportLinks, ComputedCandidateSiteMap)> {
    let mut links = ComputedDynamicImportLinks::new();
    let mut authenticated_sites = ComputedCandidateSiteMap::new();
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
        let table_digest = table.digest()?;
        if !requester_record
            .candidate_table_refs
            .iter()
            .any(|reference| reference.as_str() == table_digest.as_str())
        {
            bail!("computed-candidate table is not referenced by its authenticated requester");
        }
        for candidate in &table.candidates {
            let target_artifact = artifacts
                .get(&candidate.target.0)
                .ok_or_else(|| anyhow!("computed-candidate target artifact is absent"))?;
            if target_artifact.semantics.source_integrity != candidate.target_source_integrity {
                bail!("computed-candidate target source integrity is stale");
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
            if authenticated_sites
                .entry(table.requester.0.clone())
                .or_default()
                .insert(
                    (table.site, candidate.specifier.as_str().to_owned()),
                    ComputedCandidateBinding {
                        target: candidate.target.0.clone(),
                        attributes: candidate.attributes.clone(),
                    },
                )
                .is_some()
            {
                bail!("computed-candidate table repeats one authenticated site spelling");
            }
        }
    }
    Ok((links, authenticated_sites))
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

    fn release_contract() -> StubContractV3 {
        let mut contract =
            ibex_runtime::compiled_contract::diagnostic_development_stub_contract().unwrap();
        let archive = source_integrity(b"static archive bundle").unwrap();
        let compiler = source_integrity(b"hermesc").unwrap();
        contract.release_eligible = true;
        contract.profile = "sfe-v1".into();
        contract.target.triple = "aarch64-apple-darwin".into();
        contract.target.minimum_platform = "macos-13.0-arm64".into();
        contract.backends =
            ibex_sfe_format::StubBackendInventoryV1::release_for_target(&contract.target.triple)
                .unwrap();
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

    fn release_provenance(contract: &StubContractV3) -> PackageProvenanceV1 {
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
            stub_core_reconstruction: ibex_sfe_format::StubCoreReconstructionV1 {
                size: 4,
                macho_linkedit_vmsize: if contract.target.triple == "aarch64-apple-darwin" {
                    Some(0x4000)
                } else {
                    None
                },
            },
            producer_identity: "ibex-compile/test".into(),
        }
    }

    #[test]
    fn release_provenance_and_static_hbc_binding_cross_check_contract() {
        let contract = release_contract();
        let provenance = release_provenance(&contract);
        let bytes = provenance.canonical_bytes().unwrap();
        assert!(matches!(
            decode_boot_provenance(&bytes, &contract, &contract.digest().unwrap(), None).unwrap(),
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
