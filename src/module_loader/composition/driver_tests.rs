use super::*;
use crate::module_loader::identity::ImportAttributes;

use capsec_semantics::model::{PackageLocator, PathComponent, StableId};

use crate::module_loader::artifact::{
    semantics_digest, CanonicalSourceId, ModuleArtifactV1, ModulePayloadV1, ProducerIdentityV1,
};
use crate::module_loader::carrier::{
    PreparedCarrierEncodingV2, PreparedCarrierEngineBindingV2, PreparedCarrierEntryV2,
    PreparedModuleCarrierV3, PREPARED_CARRIER_BYTES_DOMAIN_V1, PREPARED_CARRIER_SCHEMA_V3,
};
use crate::module_loader::computed_candidates::{
    ComputedCandidateTableV2, ComputedCandidateTargetV1, OriginalSourceSpanV1,
    COMPUTED_CANDIDATES_SCHEMA_V2,
};
use crate::module_loader::producer_spike::produce_module_artifact_v1;

const GENERATION: u64 = 7;
const TARGET: &str = "exact-dev:test";

fn javascript_factory_table_bytes(entry_id: &str, artifact: &ModuleArtifactV1) -> Vec<u8> {
    let ModulePayloadV1::Inline { factory_source, .. } = &artifact.payload else {
        panic!("fixture source producer must return an inline factory")
    };
    format!(
        "(function(){{\"use strict\";var table=Object.create(null);Object.defineProperty(table,{},{{value:({factory_source}),enumerable:true}});return Object.freeze(table);}})()",
        serde_json::to_string(entry_id).unwrap(),
    )
    .into_bytes()
}

#[derive(Clone)]
struct FixtureCarrierV1 {
    manifest_file: String,
    bytes_file: String,
    manifest: PreparedModuleCarrierV3,
    bytes: Vec<u8>,
}

struct FixturePackageV1 {
    package: PreparedPackageV1,
    carriers: Vec<FixtureCarrierV1>,
    candidate_files: BTreeMap<String, Vec<u8>>,
}

impl FixturePackageV1 {
    fn new(
        role: CompositionRole,
        definitions: Vec<(
            SourceId,
            &'static str,
            &'static str,
            Vec<PreparedPackageBindingV1>,
        )>,
    ) -> Self {
        let producer_id = NonEmptyString::new("composition-fixture-producer").unwrap();
        let producer_binary_digest = source_integrity(b"composition-fixture-producer").unwrap();
        let placeholder_graph = source_integrity(b"composition-fixture-placeholder").unwrap();
        let mut records = Vec::new();
        let mut carriers = Vec::new();
        for (index, (source_id, entry_id, source, bindings)) in definitions.into_iter().enumerate()
        {
            let source_artifact = produce_module_artifact_v1(
                source_id.clone(),
                entry_id,
                Path::new(entry_id),
                source,
                producer_binary_digest.clone(),
            )
            .unwrap();
            let bytes = javascript_factory_table_bytes(entry_id, &source_artifact);
            let carrier_digest = digest_bytes(PREPARED_CARRIER_BYTES_DOMAIN_V1, &bytes).unwrap();
            let entry_id = NonEmptyString::new(entry_id).unwrap();
            let artifact = ModuleArtifactV1::new_carrier(
                source_artifact.semantics.clone(),
                carrier_digest.clone(),
                entry_id.clone(),
                ProducerIdentityV1::PreparedPackage {
                    producer_id: producer_id.clone(),
                    producer_binary_digest: producer_binary_digest.clone(),
                    package_graph_digest: placeholder_graph.clone(),
                },
            )
            .unwrap();
            records.push(PreparedPackageRecordV1 {
                source_id,
                bindings,
                artifact,
                carrier_index: index,
                entry_id: entry_id.clone(),
            });
            carriers.push(FixtureCarrierV1 {
                manifest_file: format!("carrier-{index}.json"),
                bytes_file: format!("carrier-{index}.bin"),
                manifest: PreparedModuleCarrierV3 {
                    schema: PREPARED_CARRIER_SCHEMA_V3.into(),
                    encoding: PreparedCarrierEncodingV2::JavascriptFactoryTable,
                    carrier_digest,
                    defining_principal: Principal::Root {
                        identity: NonEmptyString::new("temporary-owner").unwrap(),
                    },
                    producer_id: producer_id.clone(),
                    producer_binary_digest: producer_binary_digest.clone(),
                    package_graph_digest: placeholder_graph.clone(),
                    entries: vec![PreparedCarrierEntryV2 {
                        entry_id,
                        semantics: source_artifact.semantics,
                        semantic_digest: source_artifact.semantic_digest,
                    }],
                },
                bytes,
            });
        }
        let mut fixture = Self {
            package: PreparedPackageV1 {
                schema: PREPARED_PACKAGE_SCHEMA_V1.into(),
                role,
                producer_id,
                producer_binary_digest,
                package_graph_digest: placeholder_graph,
                records,
                carriers: Vec::new(),
                candidate_tables: Vec::new(),
                host_bridged_inventory: Vec::new(),
            },
            carriers,
            candidate_files: BTreeMap::new(),
        };
        fixture.resync();
        fixture
    }

    fn resync(&mut self) {
        for record in &mut self.package.records {
            record.artifact.semantic_digest = semantics_digest(&record.artifact.semantics).unwrap();
        }
        self.package.package_graph_digest =
            compute_package_graph_digest_v1(&self.package.records).unwrap();
        self.package.carriers = self
            .carriers
            .iter()
            .map(|carrier| PreparedPackageCarrierIndexV1 {
                manifest_file: carrier.manifest_file.clone(),
                bytes_file: carrier.bytes_file.clone(),
            })
            .collect();
        for (index, carrier) in self.carriers.iter_mut().enumerate() {
            carrier.manifest.schema = PREPARED_CARRIER_SCHEMA_V3.into();
            carrier.manifest.producer_id = self.package.producer_id.clone();
            carrier.manifest.producer_binary_digest = self.package.producer_binary_digest.clone();
            carrier.manifest.package_graph_digest = self.package.package_graph_digest.clone();
            carrier.manifest.carrier_digest =
                digest_bytes(PREPARED_CARRIER_BYTES_DOMAIN_V1, &carrier.bytes).unwrap();
            let bound = self
                .package
                .records
                .iter_mut()
                .filter(|record| record.carrier_index == index)
                .collect::<Vec<_>>();
            let first = bound.first().expect("fixture carrier must be referenced");
            carrier.manifest.defining_principal = first
                .source_id
                .defining_principal()
                .cloned()
                .unwrap_or_else(fixture_root_principal);
            carrier.manifest.entries = bound
                .into_iter()
                .map(|record| {
                    let ModulePayloadV1::Carrier {
                        carrier_digest,
                        entry_id,
                        entry_factory_digest,
                    } = &mut record.artifact.payload
                    else {
                        panic!("fixture record must remain carrier-backed")
                    };
                    *carrier_digest = carrier.manifest.carrier_digest.clone();
                    *entry_id = record.entry_id.clone();
                    *entry_factory_digest = record.artifact.semantics.factory_digest.clone();
                    record.artifact.producer = ProducerIdentityV1::PreparedPackage {
                        producer_id: self.package.producer_id.clone(),
                        producer_binary_digest: self.package.producer_binary_digest.clone(),
                        package_graph_digest: self.package.package_graph_digest.clone(),
                    };
                    PreparedCarrierEntryV2 {
                        entry_id: record.entry_id.clone(),
                        semantics: record.artifact.semantics.clone(),
                        semantic_digest: record.artifact.semantic_digest.clone(),
                    }
                })
                .collect();
            carrier
                .manifest
                .entries
                .sort_by(|left, right| left.entry_id.as_str().cmp(right.entry_id.as_str()));
        }
    }

    fn write(&self, directory: &Path) -> Digest {
        std::fs::create_dir_all(directory).unwrap();
        for carrier in &self.carriers {
            std::fs::write(
                directory.join(&carrier.manifest_file),
                carrier.manifest.encode_canonical().unwrap(),
            )
            .unwrap();
            std::fs::write(directory.join(&carrier.bytes_file), &carrier.bytes).unwrap();
        }
        for (file, bytes) in &self.candidate_files {
            std::fs::write(directory.join(file), bytes).unwrap();
        }
        let bytes = capsec_semantics::canonical::to_jcs_bytes(
            &serde_json::to_value(&self.package).unwrap(),
        )
        .unwrap();
        std::fs::write(directory.join("index.json"), &bytes).unwrap();
        digest_bytes(PREPARED_PACKAGE_ROOT_DOMAIN_V1, &bytes).unwrap()
    }
}

struct CompositionFixtureV1 {
    directory: tempfile::TempDir,
    packages: BTreeMap<CompositionRole, FixturePackageV1>,
    envelope: PreparedCompositionV1,
    commitment: PreparedCompositionCommitmentV1,
    expectations: CompositionVerifierExpectationsV1,
    app_root: SourceId,
    app_lib: SourceId,
    agent_root: Option<SourceId>,
}

impl CompositionFixtureV1 {
    fn new(with_agent: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(directory.path().join("packages")).unwrap();
        let root = fixture_root_principal();
        let app_root = fixture_source_id(&root, "app-root.mjs");
        let app_lib = fixture_source_id(&root, "app-lib.mjs");
        let app = FixturePackageV1::new(
            CompositionRole::App,
            vec![
                (
                    app_root.clone(),
                    "app-root",
                    "import { appValue } from './app-lib.mjs'; globalThis.__compositionOrder.push('app'); globalThis.__compositionAppMain = import.meta.main; export const appResult = appValue;",
                    vec![PreparedPackageBindingV1 {
                        specifier: "./app-lib.mjs".into(),
                        resolution_kind: ResolutionKind::EsmStatic,
                        target: PreparedPackageBindingTargetV1::Local {
                            source_id: app_lib.clone(),
                        },
                    }],
                ),
                (
                    app_lib.clone(),
                    "app-lib",
                    "globalThis.__compositionOrder = globalThis.__compositionOrder || []; globalThis.__compositionOrder.push('lib'); export const appValue = 1;",
                    Vec::new(),
                ),
            ],
        );
        let mut packages = BTreeMap::from([(CompositionRole::App, app)]);
        let agent_root = with_agent.then(|| fixture_source_id(&root, "agent-root.mjs"));
        if let Some(agent_root) = &agent_root {
            packages.insert(
                CompositionRole::Agent,
                FixturePackageV1::new(
                    CompositionRole::Agent,
                    vec![(
                        agent_root.clone(),
                        "agent-root",
                        "import { appValue } from 'app-lib'; globalThis.__compositionOrder.push('agent'); globalThis.__compositionAgentMain = import.meta.main; export function installExactNativeAgentBootstrap() { globalThis.__compositionOrder.push('invoke'); return appValue; }",
                        vec![PreparedPackageBindingV1 {
                            specifier: "app-lib".into(),
                            resolution_kind: ResolutionKind::EsmStatic,
                            target: PreparedPackageBindingTargetV1::External {
                                role: CompositionRole::App,
                                source_id: app_lib.clone(),
                            },
                        }],
                    )],
                ),
            );
        }
        let policy_digest = source_integrity(b"composition-fixture-policy").unwrap();
        let producer_binary_digest = source_integrity(b"composition-fixture-producer").unwrap();
        let placeholder = source_integrity(b"composition-fixture-envelope-placeholder").unwrap();
        let declaration = if with_agent {
            vec!["app".into(), "agent".into()]
        } else {
            vec!["app".into()]
        };
        let mut fixture = Self {
            directory,
            packages,
            envelope: PreparedCompositionV1 {
                schema: PREPARED_COMPOSITION_SCHEMA_V1.into(),
                declaration,
                packages: Vec::new(),
                partition: CompositionPartitionV1 {
                    digest: placeholder.clone(),
                    roles: CompositionPartitionRolesV1::default(),
                },
                union_binding_table: CompositionUnionBindingTableV1 {
                    digest: placeholder.clone(),
                    rows: Vec::new(),
                },
                host_bridged_inventories: Vec::new(),
                alias_table: CompositionAliasTableV1 {
                    digest: placeholder.clone(),
                    rows: Vec::new(),
                },
                agent_boundary: CompositionAgentBoundaryV1 {
                    entry_ids: Vec::new(),
                },
                boot_core_dynamic_follow_list: Vec::new(),
                entry_plan: CompositionEntryPlanV1 {
                    digest: placeholder.clone(),
                    entries: Vec::new(),
                },
                freshness: CompositionFreshnessV1 {
                    session_nonce: "composition-fixture-session".into(),
                    authority_generation: 1,
                    resolver_generation: GENERATION,
                    expires_at_ms: 10_000,
                    policy_digest: policy_digest.clone(),
                    target: TARGET.into(),
                    encoding: "javascript-factory-table".into(),
                    agent_packing: "boot-core-v1".into(),
                    producer: CompositionProducerV1 {
                        id: NonEmptyString::new("composition-fixture-producer").unwrap(),
                        binary_digest: producer_binary_digest.clone(),
                    },
                },
            },
            commitment: PreparedCompositionCommitmentV1 {
                schema: PREPARED_COMPOSITION_COMMITMENT_SCHEMA_V1.into(),
                workflow: "production".into(),
                composition_root_digest: placeholder,
            },
            expectations: CompositionVerifierExpectationsV1 {
                schema: COMPOSITION_VERIFIER_EXPECTATIONS_SCHEMA_V1.into(),
                expected_target: TARGET.into(),
                expected_roles: if with_agent {
                    vec![CompositionRole::App, CompositionRole::Agent]
                } else {
                    vec![CompositionRole::App]
                },
                session_nonce: "composition-fixture-session".into(),
                authority_generation: 1,
                resolver_generation: GENERATION,
                policy_digest,
                // Accepted A2 reserves this mandatory wire field. Deliberately
                // unrelated bytes prove that no v1 predicate consumes it.
                resolver_inventory_digest: source_integrity(b"reserved-unused-input").unwrap(),
                now_unix_ms: 5_000,
            },
            app_root,
            app_lib,
            agent_root,
        };
        fixture.normalize();
        fixture
    }

    fn package_dir(&self, role: CompositionRole) -> std::path::PathBuf {
        self.directory.path().join("packages").join(role.as_str())
    }

    fn write_packages(&mut self) -> BTreeMap<CompositionRole, Digest> {
        let root = self.directory.path().to_path_buf();
        self.packages
            .iter_mut()
            .map(|(role, package)| {
                package.resync();
                (
                    *role,
                    package.write(&root.join("packages").join(role.as_str())),
                )
            })
            .collect()
    }

    fn admitted_packages(
        &self,
        roots: &BTreeMap<CompositionRole, Digest>,
    ) -> BTreeMap<CompositionRole, AdmittedCompositionPackageV1> {
        roots
            .iter()
            .map(|(role, root)| {
                (
                    *role,
                    admit_composition_package_v1(
                        &self.package_dir(*role),
                        *role,
                        root,
                        GENERATION,
                        self.directory.path(),
                        None,
                    )
                    .unwrap(),
                )
            })
            .collect()
    }

    fn normalize(&mut self) {
        let roots = self.write_packages();
        let declaration = declaration_roles_v1(&self.envelope.declaration).unwrap();
        self.envelope.packages = declaration
            .iter()
            .map(|role| CompositionPackageAttestationV1 {
                role: *role,
                package_root: roots[role].clone(),
                producer_generation: GENERATION,
            })
            .collect();
        let admitted = self.admitted_packages(&roots);
        let ownership = ownership_map_v1(&admitted);
        self.envelope.partition = recompute_partition_v1(&declaration, &admitted).unwrap();
        let rows = recompute_union_rows_v1(&admitted, &ownership, &[]).unwrap();
        self.envelope.union_binding_table = CompositionUnionBindingTableV1 {
            digest: digest_canonical_value_v1(PREPARED_UNION_TABLE_DOMAIN_V1, &rows).unwrap(),
            rows,
        };
        self.envelope.host_bridged_inventories = declaration
            .iter()
            .map(|role| {
                let rows = recompute_boundary_rows_v1(&admitted[role]).unwrap();
                let preimage = serde_json::json!({ "role": role, "rows": rows });
                CompositionHostBridgedInventoryV1 {
                    role: *role,
                    digest: digest_canonical_value_v1(
                        PREPARED_BOUNDARY_INVENTORY_DOMAIN_V1,
                        &preimage,
                    )
                    .unwrap(),
                    rows,
                }
            })
            .collect();
        self.envelope.alias_table = CompositionAliasTableV1 {
            digest: digest_canonical_value_v1(
                PREPARED_ALIAS_TABLE_DOMAIN_V1,
                &Vec::<CompositionAliasRowV1>::new(),
            )
            .unwrap(),
            rows: Vec::new(),
        };
        let mut entries = Vec::new();
        if let Some(agent_root) = &self.agent_root {
            entries.push(CompositionEntryDescriptorV1 {
                role: CompositionRole::Agent,
                root: agent_root.encode().unwrap(),
                action: "evaluate-then-invoke".into(),
                export: Some("installExactNativeAgentBootstrap".into()),
            });
        }
        entries.push(CompositionEntryDescriptorV1 {
            role: CompositionRole::App,
            root: self.app_root.encode().unwrap(),
            action: "evaluate".into(),
            export: None,
        });
        self.envelope.entry_plan = CompositionEntryPlanV1 {
            digest: entry_plan_digest_v1(&entries).unwrap(),
            entries,
        };
        self.expectations.expected_roles = declaration;
        self.resign_envelope();
    }

    fn resign_envelope(&mut self) {
        let bytes = capsec_semantics::canonical::to_jcs_bytes(
            &serde_json::to_value(&self.envelope).unwrap(),
        )
        .unwrap();
        std::fs::write(self.directory.path().join("composition.json"), &bytes).unwrap();
        self.commitment.composition_root_digest =
            digest_bytes(PREPARED_COMPOSITION_ROOT_DOMAIN_V1, &bytes).unwrap();
    }

    fn write_envelope_without_resigning(&self) {
        let bytes = capsec_semantics::canonical::to_jcs_bytes(
            &serde_json::to_value(&self.envelope).unwrap(),
        )
        .unwrap();
        std::fs::write(self.directory.path().join("composition.json"), bytes).unwrap();
    }

    fn resync_package_and_resign(&mut self, role: CompositionRole) {
        let directory = self.package_dir(role);
        let package = self.packages.get_mut(&role).unwrap();
        package.resync();
        let root = package.write(&directory);
        self.envelope
            .packages
            .iter_mut()
            .find(|package| package.role == role)
            .unwrap()
            .package_root = root;
        self.resign_envelope();
    }

    fn replace_record_source(&mut self, role: CompositionRole, source_id: &SourceId, source: &str) {
        let package = self.packages.get(&role).unwrap();
        let record = package
            .package
            .records
            .iter()
            .find(|record| &record.source_id == source_id)
            .unwrap();
        let entry_id = record.entry_id.clone();
        let producer_binary_digest = package.package.producer_binary_digest.clone();
        let produced = produce_module_artifact_v1(
            source_id.clone(),
            entry_id.as_str(),
            Path::new(entry_id.as_str()),
            source,
            producer_binary_digest,
        )
        .unwrap();
        let bytes = javascript_factory_table_bytes(entry_id.as_str(), &produced);
        let package = self.packages.get_mut(&role).unwrap();
        let record = package
            .package
            .records
            .iter_mut()
            .find(|record| &record.source_id == source_id)
            .unwrap();
        let carrier_index = record.carrier_index;
        record.artifact.semantics = produced.semantics;
        record.artifact.semantic_digest = produced.semantic_digest;
        package.carriers[carrier_index].bytes = bytes;
        self.resync_package_and_resign(role);
    }

    fn commitment_text(&self) -> String {
        capsec_semantics::canonical::to_jcs(&serde_json::to_value(&self.commitment).unwrap())
            .unwrap()
    }

    fn expectations_text(&self) -> String {
        capsec_semantics::canonical::to_jcs(&serde_json::to_value(&self.expectations).unwrap())
            .unwrap()
    }

    fn run(&self) -> CompositionAdmissionOutcomeV1 {
        self.run_with_engine(None)
    }

    fn run_with_engine(
        &self,
        engine: Option<CommittedHbcEngineExpectationV1>,
    ) -> CompositionAdmissionOutcomeV1 {
        admit_prepared_composition_with_probes_v1(
            self.directory.path(),
            &self.commitment_text(),
            &self.expectations_text(),
            self.directory.path(),
            CompositionChannelProbeV1::Unchecked,
            CompositionEngineProbeV1::Fixed(engine),
        )
    }
}

fn fixture_root_principal() -> Principal {
    Principal::Root {
        identity: NonEmptyString::new("composition-fixture-root").unwrap(),
    }
}

fn fixture_package_principal() -> Principal {
    Principal::Package {
        name: NonEmptyString::new("fixture-agent-package").unwrap(),
        locator: PackageLocator::new("fixture-agent-package@1.0.0").unwrap(),
        integrity: source_integrity(b"fixture-agent-package").unwrap(),
    }
}

fn fixture_source_id(principal: &Principal, name: &str) -> SourceId {
    SourceId::file(principal.clone(), vec![PathComponent::utf8(name).unwrap()]).unwrap()
}

fn refusal(outcome: CompositionAdmissionOutcomeV1) -> (u32, CompositionRefusalCode) {
    let CompositionAdmissionOutcomeV1::Refused(DevUnarmedCompositionStartupReportV1::Refused {
        failure_stage,
        reason_code,
        ..
    }) = outcome
    else {
        panic!("expected a registry refusal, got {outcome:?}")
    };
    (failure_stage, reason_code)
}

fn assert_refusal(
    outcome: CompositionAdmissionOutcomeV1,
    stage: u32,
    code: CompositionRefusalCode,
) {
    assert_eq!(refusal(outcome), (stage, code));
}

fn assert_admitted(outcome: CompositionAdmissionOutcomeV1) {
    assert!(
        matches!(outcome, CompositionAdmissionOutcomeV1::Admitted(_)),
        "expected admission, got {outcome:?}"
    );
}

fn refusal_statuses(
    outcome: CompositionAdmissionOutcomeV1,
    expected_code: CompositionRefusalCode,
) -> Vec<(CompositionRole, CompositionPackageVerificationStatusV1)> {
    let CompositionAdmissionOutcomeV1::Refused(DevUnarmedCompositionStartupReportV1::Refused {
        common,
        reason_code,
        ..
    }) = outcome
    else {
        panic!("expected a registry refusal, got {outcome:?}")
    };
    assert_eq!(reason_code, expected_code);
    common
        .packages
        .into_iter()
        .map(|package| (package.role, package.verification_status))
        .collect()
}

fn assert_i_json_report_counters(value: &Value) {
    for field in [
        "commitmentParseUs",
        "admissionUs",
        "graphLinkUs",
        "agentEvaluateUs",
        "agentInvokeUs",
        "appEvaluateUs",
        "agentEvaluatedRecordCount",
        "appEvaluatedRecordCount",
        "sharedEvaluatedRecordCount",
    ] {
        assert!(
            value[field].as_u64().unwrap() <= I_JSON_MAX_SAFE_INTEGER,
            "report counter {field} is not I-JSON safe"
        );
    }
    for package in value["packages"].as_array().unwrap() {
        for field in [
            "recordCount",
            "carrierCount",
            "hbcCarrierCount",
            "javascriptCarrierCount",
        ] {
            assert!(
                package[field].as_u64().unwrap() <= I_JSON_MAX_SAFE_INTEGER,
                "package counter {field} is not I-JSON safe"
            );
        }
    }
}

#[test]
fn fixture_measured_phase_boundaries_are_total_ordered_host_monotonic_observations() {
    let boundaries = CompositionHostMonotonicPhaseBoundariesV1::measured(
        (100.0, 101.0),
        (101.25, 103.0),
        (104.0, 109.5),
    )
    .expect("ordered finite phase boundaries admit");
    let value = serde_json::to_value(boundaries).unwrap();
    assert_eq!(value["schemaVersion"], "ibex/prepared-phase-boundaries/1");
    assert_eq!(value["clockDomain"], "host-monotonic");
    assert_eq!(value["clockSource"], "mach-absolute-time");
    assert_eq!(value["timingBasis"], "observed-boundary");
    assert_eq!(value["admission"]["startHostMonotonicMs"], 100.0);
    assert_eq!(value["evaluation"]["endHostMonotonicMs"], 109.5);

    assert!(CompositionHostMonotonicPhaseBoundariesV1::measured(
        (100.0, 101.0),
        (100.5, 103.0),
        (104.0, 109.5),
    )
    .is_none());
    assert!(CompositionHostMonotonicPhaseBoundariesV1::measured(
        (100.0, 101.0),
        (101.0, 103.0),
        (104.0, f64::NAN),
    )
    .is_none());
}

struct CompositionStartupFixtureOutcomeV1 {
    status: i32,
    report: Value,
    error: Option<String>,
}

#[allow(clashing_extern_declarations)]
unsafe extern "C" {
    fn ex_hermes_create_diagnostic() -> *mut std::ffi::c_void;
    fn ex_hermes_runtime_nonce(runtime: *mut std::ffi::c_void) -> u64;
    fn ex_hermes_destroy(runtime: *mut std::ffi::c_void);
    fn ex_hermes_eval(
        runtime: *mut std::ffi::c_void,
        data: *const u8,
        len: usize,
        source_url: *const std::ffi::c_char,
        is_bytecode: i32,
        out_value: *mut *mut std::ffi::c_char,
    ) -> i32;
    fn ex_hermes_free_string(value: *mut std::ffi::c_char);
}

struct CompositionTestRuntimeV1 {
    raw: std::ptr::NonNull<std::ffi::c_void>,
}

impl CompositionTestRuntimeV1 {
    fn new() -> Self {
        let raw = std::ptr::NonNull::new(unsafe { ex_hermes_create_diagnostic() }).unwrap();
        Self { raw }
    }

    fn raw_parts(&self) -> (std::ptr::NonNull<std::ffi::c_void>, u64) {
        (self.raw, unsafe {
            ex_hermes_runtime_nonce(self.raw.as_ptr())
        })
    }

    fn eval_text(&self, source: &str, source_label: &str) -> Result<String> {
        let source_label = std::ffi::CString::new(source_label)?;
        let mut output = std::ptr::null_mut();
        let status = unsafe {
            ex_hermes_eval(
                self.raw.as_ptr(),
                source.as_ptr(),
                source.len(),
                source_label.as_ptr(),
                0,
                &mut output,
            )
        };
        let detail = if output.is_null() {
            String::new()
        } else {
            let detail = unsafe { std::ffi::CStr::from_ptr(output) }
                .to_string_lossy()
                .into_owned();
            unsafe { ex_hermes_free_string(output) };
            detail
        };
        if status != 0 {
            bail!("composition fixture probe evaluation refused ({status}): {detail}");
        }
        Ok(detail)
    }
}

impl Drop for CompositionTestRuntimeV1 {
    fn drop(&mut self) {
        unsafe { ex_hermes_destroy(self.raw.as_ptr()) };
    }
}

fn run_composition_startup_fixture_v1(
    fixture: &CompositionFixtureV1,
    runtime: &CompositionTestRuntimeV1,
) -> CompositionStartupFixtureOutcomeV1 {
    use std::ffi::{CStr, CString};

    let (raw, nonce) = runtime.raw_parts();
    let composition_dir = CString::new(fixture.directory.path().to_str().unwrap()).unwrap();
    let commitment = CString::new(fixture.commitment_text()).unwrap();
    let expectations = CString::new(fixture.expectations_text()).unwrap();
    let project_root = CString::new(fixture.directory.path().to_str().unwrap()).unwrap();
    let mut out_report = std::ptr::null_mut();
    let mut out_error = std::ptr::null_mut();
    let status = unsafe {
        crate::module_loader::runner_pipeline::dev_committed_embedder::ibex_dev_unarmed_composition_prepared_startup_v1(
            raw.as_ptr(),
            nonce,
            composition_dir.as_ptr(),
            commitment.as_ptr(),
            expectations.as_ptr(),
            project_root.as_ptr(),
            &mut out_report,
            &mut out_error,
        )
    };
    let take = |pointer: *mut std::ffi::c_char| -> Option<String> {
        if pointer.is_null() {
            return None;
        }
        let text = unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned();
        crate::host::abi::ex_host_free_string(pointer);
        Some(text)
    };
    let report = take(out_report)
        .map(|json| serde_json::from_str(&json).unwrap())
        .expect("composition C entry writes a report on every outcome");
    CompositionStartupFixtureOutcomeV1 {
        status,
        report,
        error: take(out_error),
    }
}

fn rewrite_index_and_recommit(
    fixture: &mut CompositionFixtureV1,
    role: CompositionRole,
    bytes: &[u8],
) {
    std::fs::write(fixture.package_dir(role).join("index.json"), bytes).unwrap();
    let root = digest_bytes(PREPARED_PACKAGE_ROOT_DOMAIN_V1, bytes).unwrap();
    fixture
        .envelope
        .packages
        .iter_mut()
        .find(|package| package.role == role)
        .unwrap()
        .package_root = root;
    fixture.resign_envelope();
}

fn fake_engine(label: &str, bytecode_version: u32) -> CommittedHbcEngineExpectationV1 {
    CommittedHbcEngineExpectationV1 {
        engine_binding: PreparedCarrierEngineBindingV2::LoadedFile {
            binary_digest: source_integrity(label.as_bytes()).unwrap(),
        },
        bytecode_version,
    }
}

fn configure_hbc_carrier(
    fixture: &mut CompositionFixtureV1,
    role: CompositionRole,
    carrier_index: usize,
    engine: &CommittedHbcEngineExpectationV1,
    manifest_version: u32,
    bytes: Vec<u8>,
) {
    let package = fixture.packages.get_mut(&role).unwrap();
    package.carriers[carrier_index].manifest.encoding = PreparedCarrierEncodingV2::HermesBytecode {
        engine_binding: engine.engine_binding.clone(),
        bytecode_version: manifest_version,
    };
    package.carriers[carrier_index].bytes = bytes;
    fixture.resync_package_and_resign(role);
}

#[test]
fn fixture_rows_b12_b13_admit_both_declarations_with_reserved_inventory_input() {
    assert_admitted(CompositionFixtureV1::new(false).run());
    assert_admitted(CompositionFixtureV1::new(true).run());

    // A valid Accepted-v3 composition still admits when the reserved input
    // differs. It must never be reclassified as composition-replayed.
    let mut mismatched = CompositionFixtureV1::new(true);
    mismatched.expectations.resolver_inventory_digest =
        source_integrity(b"different-live-resolver-compiler-inventory").unwrap();
    assert_admitted(mismatched.run());
}

#[test]
fn fixture_a1_composition_c_entry_runs_shared_agent_segment_then_invoke_then_app() {
    let _host_guard = crate::host::abi::host_test_lock();
    crate::host::abi::install_host(crate::host::Host::strict());
    let fixture = CompositionFixtureV1::new(true);
    let runtime = CompositionTestRuntimeV1::new();
    let outcome = run_composition_startup_fixture_v1(&fixture, &runtime);
    assert_eq!(
        outcome.status, 0,
        "composition startup: {:?}",
        outcome.error
    );
    assert_eq!(outcome.report["admissionStatus"], "admitted");
    assert_eq!(outcome.report["agentEvaluatedRecordCount"], 2);
    assert_eq!(outcome.report["appEvaluatedRecordCount"], 1);
    assert_eq!(outcome.report["sharedEvaluatedRecordCount"], 1);
    assert_eq!(outcome.report["agentInvokeReturnedThenable"], false);
    assert_eq!(
        outcome.report["diagnostics"]["compilerIdentityBindingDigestPrefix"],
        digest_prefix(&fixture.envelope.freshness.producer.binary_digest)
    );
    assert_eq!(
        outcome.report["diagnostics"]["schema"],
        "ibex/composition-startup-diagnostics/1"
    );
    assert!(outcome
        .report
        .get("compilerIdentityBindingDigestPrefix")
        .is_none());
    assert!(outcome.report.get("phaseBoundaries").is_none());
    assert!(outcome.report["packages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|package| package["verificationStatus"] == "verified"));
    for package_report in outcome.report["packages"].as_array().unwrap() {
        let role = match package_report["role"].as_str().unwrap() {
            "app" => CompositionRole::App,
            "agent" => CompositionRole::Agent,
            other => panic!("unexpected composition role {other}"),
        };
        let carriers = &fixture.packages[&role].carriers;
        let expected_bytes: usize = carriers.iter().map(|carrier| carrier.bytes.len()).sum();
        let expected_chars: usize = carriers
            .iter()
            .map(|carrier| {
                std::str::from_utf8(&carrier.bytes)
                    .unwrap()
                    .encode_utf16()
                    .count()
            })
            .sum();
        assert_eq!(package_report["embeddedEagerSourceBytes"], expected_bytes);
        assert_eq!(package_report["embeddedEagerSourceChars"], expected_chars);
    }
    assert_i_json_report_counters(&outcome.report);
    #[cfg(target_vendor = "apple")]
    {
        let boundaries = &outcome.report["diagnostics"]["phaseBoundaries"];
        assert_eq!(
            boundaries["schemaVersion"],
            "ibex/prepared-phase-boundaries/1"
        );
        assert_eq!(boundaries["clockDomain"], "host-monotonic");
        assert_eq!(boundaries["clockSource"], "mach-absolute-time");
        assert_eq!(boundaries["timingBasis"], "observed-boundary");
        let endpoint = |phase: &str, edge: &str| {
            boundaries[phase][edge]
                .as_f64()
                .unwrap_or_else(|| panic!("{phase}.{edge} must be a finite timestamp"))
        };
        let admission_start = endpoint("admission", "startHostMonotonicMs");
        let admission_end = endpoint("admission", "endHostMonotonicMs");
        let link_start = endpoint("link", "startHostMonotonicMs");
        let link_end = endpoint("link", "endHostMonotonicMs");
        let evaluation_start = endpoint("evaluation", "startHostMonotonicMs");
        let evaluation_end = endpoint("evaluation", "endHostMonotonicMs");
        assert!(admission_start <= admission_end);
        assert!(admission_end <= link_start);
        assert!(link_start <= link_end);
        assert!(link_end <= evaluation_start);
        assert!(evaluation_start <= evaluation_end);
    }
    #[cfg(not(target_vendor = "apple"))]
    assert!(outcome.report["diagnostics"]["phaseBoundaries"].is_null());

    let probe = runtime
        .eval_text(
            "JSON.stringify({order:globalThis.__compositionOrder,agentMain:globalThis.__compositionAgentMain,appMain:globalThis.__compositionAppMain})",
            "llp0056-composition-order-probe",
        )
        .unwrap();
    let probe: Value = serde_json::from_str(probe.trim()).unwrap();
    assert_eq!(
        probe["order"],
        serde_json::json!(["lib", "agent", "invoke", "app"])
    );
    assert_eq!(probe["agentMain"], false);
    assert_eq!(probe["appMain"], true);
}

#[cfg(target_vendor = "apple")]
#[test]
fn agent_on_evaluation_boundary_encloses_agent_shared_invoke_and_app_segments() {
    let _host_guard = crate::host::abi::host_test_lock();
    crate::host::abi::install_host(crate::host::Host::strict());
    let mut fixture = CompositionFixtureV1::new(true);
    let agent_root = fixture.agent_root.clone().unwrap();
    fixture.replace_record_source(
        CompositionRole::Agent,
        &agent_root,
        "import { appValue } from 'app-lib'; var a=Date.now(); while(Date.now()-a<15){}; globalThis.__compositionOrder.push('agent'); export function installExactNativeAgentBootstrap() { var i=Date.now(); while(Date.now()-i<15){}; globalThis.__compositionOrder.push('invoke'); return appValue; }",
    );
    fixture.normalize();
    let runtime = CompositionTestRuntimeV1::new();
    let outcome = run_composition_startup_fixture_v1(&fixture, &runtime);
    assert_eq!(
        outcome.status, 0,
        "composition startup: {:?}",
        outcome.error
    );
    let boundaries = &outcome.report["diagnostics"]["phaseBoundaries"];
    let evaluation_ms = boundaries["evaluation"]["endHostMonotonicMs"]
        .as_f64()
        .unwrap()
        - boundaries["evaluation"]["startHostMonotonicMs"]
            .as_f64()
            .unwrap();
    let measured_segments_ms = ["agentEvaluateUs", "agentInvokeUs", "appEvaluateUs"]
        .into_iter()
        .map(|field| outcome.report[field].as_u64().unwrap() as f64 / 1_000.0)
        .sum::<f64>();
    assert!(
        evaluation_ms + 0.01 >= measured_segments_ms,
        "outer evaluation boundary {evaluation_ms}ms must contain all agent/shared/invoke/app measurements totaling {measured_segments_ms}ms"
    );
}

#[test]
fn fixture_rows_a4_a5b_a6_a7_a8_enforce_package_topology() {
    let mut p1 = CompositionFixtureV1::new(true);
    p1.packages
        .get_mut(&CompositionRole::Agent)
        .unwrap()
        .package
        .records[0]
        .bindings[0]
        .target = PreparedPackageBindingTargetV1::Local {
        source_id: p1.app_lib.clone(),
    };
    p1.normalize();
    assert_refusal(
        p1.run(),
        5,
        CompositionRefusalCode::LocalAgreementDisagreement,
    );

    let mut app_to_agent = CompositionFixtureV1::new(true);
    inject_app_to_agent_fault(&mut app_to_agent);
    assert_refusal(
        app_to_agent.run(),
        5,
        CompositionRefusalCode::AppReferencesAgent,
    );

    let mut duplicate = CompositionFixtureV1::new(false);
    {
        let app = duplicate.packages.get_mut(&CompositionRole::App).unwrap();
        let mut record = app.package.records[1].clone();
        let mut carrier = app.carriers[1].clone();
        record.entry_id = NonEmptyString::new("app-lib-duplicate-a6").unwrap();
        record.carrier_index = app.carriers.len();
        carrier.manifest_file = "carrier-duplicate-a6.json".into();
        carrier.bytes_file = "carrier-duplicate-a6.bin".into();
        app.package.records.push(record);
        app.carriers.push(carrier);
    }
    duplicate.resync_package_and_resign(CompositionRole::App);
    assert_refusal(
        duplicate.run(),
        4,
        CompositionRefusalCode::IbexDuplicateSourceId,
    );

    let mut overlap = CompositionFixtureV1::new(true);
    {
        let app = overlap.packages.get(&CompositionRole::App).unwrap();
        let mut record = app.package.records[1].clone();
        let mut carrier = app.carriers[1].clone();
        let agent = overlap.packages.get_mut(&CompositionRole::Agent).unwrap();
        record.entry_id = NonEmptyString::new("app-lib-overlap-a7").unwrap();
        record.carrier_index = agent.carriers.len();
        carrier.manifest_file = "carrier-overlap-a7.json".into();
        carrier.bytes_file = "carrier-overlap-a7.bin".into();
        agent.package.records.push(record);
        agent.carriers.push(carrier);
    }
    overlap.normalize();
    assert_refusal(overlap.run(), 4, CompositionRefusalCode::PackageOverlap);

    let mut alias = CompositionFixtureV1::new(true);
    let representative = alias.agent_root.clone().unwrap();
    let alias_id = fixture_source_id(&fixture_root_principal(), "computed-bootstrap-alias-a8")
        .encode()
        .unwrap();
    let row = CompositionAliasRowV1 {
        alias_id,
        representative_source_id: representative.encode().unwrap(),
        representative_source_integrity: source_integrity(b"wrong-alias-evidence").unwrap(),
        import_site_inventory_digest: compute_alias_import_site_inventory_digest(&[]).unwrap(),
    };
    alias.envelope.alias_table = CompositionAliasTableV1 {
        digest: digest_canonical_value_v1(PREPARED_ALIAS_TABLE_DOMAIN_V1, &vec![row.clone()])
            .unwrap(),
        rows: vec![row],
    };
    alias.resign_envelope();
    let CompositionAdmissionOutcomeV1::Refused(DevUnarmedCompositionStartupReportV1::Refused {
        common,
        failure_stage,
        reason_code,
        package_role,
        ..
    }) = alias.run()
    else {
        panic!("expected alias-table refusal")
    };
    assert_eq!(failure_stage, 3);
    assert_eq!(reason_code, CompositionRefusalCode::AliasConflict);
    assert_eq!(package_role, None);
    assert!(common.packages.iter().all(|package| {
        package.verification_status == CompositionPackageVerificationStatusV1::Verified
    }));
}

#[test]
fn fixture_a9_computed_bootstrap_alias_resolves_through_retained_session() {
    let _host_guard = crate::host::abi::host_test_lock();
    crate::host::abi::install_host(crate::host::Host::strict());
    let mut fixture = CompositionFixtureV1::new(true);
    let representative = fixture.agent_root.clone().unwrap();
    let representative_integrity = fixture.packages[&CompositionRole::Agent].package.records[0]
        .artifact
        .semantics
        .source_integrity
        .clone();
    let alias_source = fixture_source_id(&fixture_root_principal(), "computed-bootstrap-alias-a9");
    let row = CompositionAliasRowV1 {
        alias_id: alias_source.encode().unwrap(),
        representative_source_id: representative.encode().unwrap(),
        representative_source_integrity: representative_integrity,
        import_site_inventory_digest: compute_alias_import_site_inventory_digest(&[]).unwrap(),
    };
    fixture.envelope.alias_table = CompositionAliasTableV1 {
        digest: digest_canonical_value_v1(PREPARED_ALIAS_TABLE_DOMAIN_V1, &vec![row.clone()])
            .unwrap(),
        rows: vec![row.clone()],
    };
    fixture.resign_envelope();

    let runtime = CompositionTestRuntimeV1::new();
    let outcome = run_composition_startup_fixture_v1(&fixture, &runtime);
    assert_eq!(outcome.status, 0, "alias composition: {:?}", outcome.error);
    let (raw, nonce) = runtime.raw_parts();
    assert_eq!(
        crate::module_loader::runner_pipeline::dev_committed_embedder::resolve_retained_composition_id_v1(
            raw,
            nonce,
            &row.alias_id,
        ),
        Some(representative.clone())
    );
    assert_eq!(
        crate::module_loader::runner_pipeline::dev_committed_embedder::resolve_retained_composition_id_v1(
            raw,
            nonce,
            &representative.encode().unwrap(),
        ),
        Some(representative)
    );
}

#[test]
fn fixture_a10_dynamic_edges_preserve_literal_locality_and_host_bridges() {
    let mut literal = CompositionFixtureV1::new(false);
    let literal_root = literal.app_root.clone();
    literal.replace_record_source(
        CompositionRole::App,
        &literal_root,
        "export function loadAppLib() { return import('./app-lib.mjs'); }",
    );
    literal
        .packages
        .get_mut(&CompositionRole::App)
        .unwrap()
        .package
        .records[0]
        .bindings = vec![PreparedPackageBindingV1 {
        specifier: "./app-lib.mjs".into(),
        resolution_kind: ResolutionKind::DynamicImport,
        target: PreparedPackageBindingTargetV1::Local {
            source_id: literal.app_lib.clone(),
        },
    }];
    literal.normalize();
    let CompositionAdmissionOutcomeV1::Admitted(literal_admitted) = literal.run() else {
        panic!("within-package literal dynamic import must admit")
    };
    let literal_plan = literal_admitted
        .authorized
        .execution_plan(&literal_admitted.envelope.alias_table.rows)
        .unwrap();
    let literal_linkage = literal_plan
        .linkage_order_for_roots(
            &literal_admitted.authorized.roots,
            &literal_admitted.authorized.allowed_dynamic_bindings,
        )
        .unwrap();
    assert!(literal_linkage.contains(&literal.app_lib));
    assert!(literal_admitted
        .authorized
        .allowed_dynamic_bindings
        .get(&literal.app_root)
        .is_some_and(|bindings| bindings
            .iter()
            .any(|binding| { binding.site.is_none() && binding.specifier == "./app-lib.mjs" })));

    let mut computed = CompositionFixtureV1::new(false);
    let computed_root = computed.app_root.clone();
    computed.replace_record_source(
        CompositionRole::App,
        &computed_root,
        "export function computedBootstrap(specifier) { return import(specifier); }",
    );
    computed
        .packages
        .get_mut(&CompositionRole::App)
        .unwrap()
        .package
        .records[0]
        .bindings
        .clear();
    computed.normalize();
    let CompositionAdmissionOutcomeV1::Admitted(computed_admitted) = computed.run() else {
        panic!("computed bootstrap host bridge must admit")
    };
    assert!(computed_admitted
        .authorized
        .allowed_dynamic_bindings
        .is_empty());
    let computed_plan = computed_admitted
        .authorized
        .execution_plan(&computed_admitted.envelope.alias_table.rows)
        .unwrap();
    assert!(computed_plan
        .dynamic_import_bindings(&computed.app_root)
        .unwrap()
        .is_empty());

    let mut undeclared = CompositionFixtureV1::new(false);
    let undeclared_root = undeclared.app_root.clone();
    undeclared.replace_record_source(
        CompositionRole::App,
        &undeclared_root,
        "export function hostOnly() { return import('./host-only.mjs'); }",
    );
    let module = undeclared.app_root.encode().unwrap();
    let app = undeclared.packages.get_mut(&CompositionRole::App).unwrap();
    app.package.records[0].bindings.clear();
    app.package.host_bridged_inventory = vec![HostBridgedInventoryRowV1 {
        module,
        specifier: "./host-only.mjs".into(),
        reason: HostBridgedReasonV1::TargetIsNotBundleModule,
    }];
    undeclared.normalize();
    let undeclared_outcome = undeclared.run();
    let CompositionAdmissionOutcomeV1::Admitted(undeclared_admitted) = undeclared_outcome else {
        panic!("undeclared literal host bridge must admit: {undeclared_outcome:?}")
    };
    assert!(undeclared_admitted
        .authorized
        .allowed_dynamic_bindings
        .get(&undeclared.app_root)
        .is_none());

    let mut out_of_union = CompositionFixtureV1::new(false);
    let requester = out_of_union.app_root.clone();
    out_of_union.replace_record_source(
        CompositionRole::App,
        &requester,
        "export function computed(specifier) { return import(specifier); }",
    );
    let absent_target = fixture_source_id(
        &fixture_root_principal(),
        "candidate-target-outside-union.mjs",
    );
    let app = out_of_union
        .packages
        .get_mut(&CompositionRole::App)
        .unwrap();
    app.package.records[0].bindings.clear();
    let requester_record = app
        .package
        .records
        .iter()
        .find(|record| record.source_id == requester)
        .unwrap();
    let site = requester_record
        .artifact
        .semantics
        .dynamic_edges
        .iter()
        .find_map(|edge| match edge {
            DynamicEdgeV1::Computed { site } => Some(*site),
            DynamicEdgeV1::Literal { .. } => None,
        })
        .expect("computed fixture has a labeled site");
    let table = ComputedCandidateTableV2 {
        schema: COMPUTED_CANDIDATES_SCHEMA_V2.into(),
        requester: requester_record.artifact.semantics.source_id.clone(),
        requester_source_integrity: requester_record.artifact.semantics.source_integrity.clone(),
        transform_fingerprint_digest: requester_record
            .artifact
            .semantics
            .transform_fingerprint
            .digest()
            .unwrap(),
        site,
        label: StableId::new("out-of-union-host-bridge").unwrap(),
        original_source_span: OriginalSourceSpanV1 { start: 1, end: 2 },
        candidates: vec![ComputedCandidateTargetV1 {
            specifier: NonEmptyString::new("computed-bootstrap-alias").unwrap(),
            attributes: ImportAttributes::default(),
            target: CanonicalSourceId(absent_target),
            target_source_integrity: source_integrity(b"out-of-union-target").unwrap(),
        }],
    };
    let bytes = table.canonical_bytes().unwrap();
    let digest = table.digest().unwrap();
    app.package
        .candidate_tables
        .push(PreparedPackageCandidateTableIndexV1 {
            file: "out-of-union-v2.json".into(),
            digest,
        });
    app.candidate_files
        .insert("out-of-union-v2.json".into(), bytes);
    out_of_union.resync_package_and_resign(CompositionRole::App);
    let outcome = out_of_union.run();
    assert!(
        matches!(outcome, CompositionAdmissionOutcomeV1::Admitted(_)),
        "out-of-union v2 candidate remains host-bridged: {outcome:?}"
    );
}

#[test]
fn fixture_rows_d30_d31_d32_and_d34_union_refusals() {
    let mut absent = CompositionFixtureV1::new(true);
    let missing = fixture_source_id(&fixture_root_principal(), "absent-external-d30.mjs");
    let agent = absent.packages.get_mut(&CompositionRole::Agent).unwrap();
    agent.package.records[0].bindings[0].target = PreparedPackageBindingTargetV1::External {
        role: CompositionRole::App,
        source_id: missing,
    };
    absent.normalize();
    assert_refusal(
        absent.run(),
        6,
        CompositionRefusalCode::ExternalTargetAbsent,
    );

    let mut wrong_owner = CompositionFixtureV1::new(true);
    let agent_root = wrong_owner.agent_root.clone().unwrap();
    let agent = wrong_owner
        .packages
        .get_mut(&CompositionRole::Agent)
        .unwrap();
    agent.package.records[0].bindings[0].target = PreparedPackageBindingTargetV1::External {
        role: CompositionRole::App,
        source_id: agent_root,
    };
    wrong_owner.normalize();
    assert_refusal(
        wrong_owner.run(),
        6,
        CompositionRefusalCode::ExternalOwnerMismatch,
    );

    let mut exports = CompositionFixtureV1::new(true);
    let app_lib = exports.app_lib.clone();
    exports.replace_record_source(
        CompositionRole::App,
        &app_lib,
        "export const differentName = 1;",
    );
    exports.normalize();
    assert_refusal(exports.run(), 6, CompositionRefusalCode::ExportDisagreement);

    let mut union = CompositionFixtureV1::new(true);
    union.envelope.union_binding_table.digest = source_integrity(b"union-d34").unwrap();
    union.resign_envelope();
    assert_refusal(union.run(), 6, CompositionRefusalCode::UnionTableMismatch);
}

#[test]
fn fixture_rows_d35a_d35b_and_order_guarantee_split_entry_failures() {
    let mut order = CompositionFixtureV1::new(true);
    order.envelope.entry_plan.entries.swap(0, 1);
    order.envelope.entry_plan.digest =
        entry_plan_digest_v1(&order.envelope.entry_plan.entries).unwrap();
    order.resign_envelope();
    assert_refusal(order.run(), 7, CompositionRefusalCode::EntryPlanMismatch);

    let mut missing_export = CompositionFixtureV1::new(true);
    let agent_root = missing_export.agent_root.clone().unwrap();
    missing_export.replace_record_source(
        CompositionRole::Agent,
        &agent_root,
        "export function aDifferentAgentEntry() {}",
    );
    missing_export
        .packages
        .get_mut(&CompositionRole::Agent)
        .unwrap()
        .package
        .records[0]
        .bindings
        .clear();
    missing_export.normalize();
    assert_refusal(
        missing_export.run(),
        7,
        CompositionRefusalCode::EntryDescriptorInvalid,
    );

    let mut unknown_action = CompositionFixtureV1::new(true);
    unknown_action.envelope.entry_plan.entries[0].action = "unknown-action".into();
    unknown_action.envelope.entry_plan.digest =
        entry_plan_digest_v1(&unknown_action.envelope.entry_plan.entries).unwrap();
    unknown_action.resign_envelope();
    assert_refusal(
        unknown_action.run(),
        7,
        CompositionRefusalCode::EntryDescriptorInvalid,
    );

    let mut malformed = CompositionFixtureV1::new(true);
    malformed.envelope.entry_plan.entries[0].root = "not-a-source-id".into();
    malformed.envelope.entry_plan.digest =
        entry_plan_digest_v1(&malformed.envelope.entry_plan.entries).unwrap();
    malformed.resign_envelope();
    assert_refusal(
        malformed.run(),
        7,
        CompositionRefusalCode::EntryDescriptorInvalid,
    );

    let mut reaches_app_root = CompositionFixtureV1::new(true);
    let agent_root = reaches_app_root.agent_root.clone().unwrap();
    reaches_app_root.replace_record_source(
        CompositionRole::Agent,
        &agent_root,
        "import { appResult } from 'app-root'; export function installExactNativeAgentBootstrap() { return appResult; }",
    );
    let app_root = reaches_app_root.app_root.clone();
    let agent = reaches_app_root
        .packages
        .get_mut(&CompositionRole::Agent)
        .unwrap();
    agent.package.records[0].bindings = vec![PreparedPackageBindingV1 {
        specifier: "app-root".into(),
        resolution_kind: ResolutionKind::EsmStatic,
        target: PreparedPackageBindingTargetV1::External {
            role: CompositionRole::App,
            source_id: app_root,
        },
    }];
    reaches_app_root.normalize();
    assert_refusal(
        reaches_app_root.run(),
        7,
        CompositionRefusalCode::EntryPlanMismatch,
    );
}

#[test]
fn fixture_d36_async_agent_root_has_no_synchronous_composition_order() {
    let mut fixture = CompositionFixtureV1::new(true);
    let agent_root = fixture.agent_root.clone().unwrap();
    fixture.replace_record_source(
        CompositionRole::Agent,
        &agent_root,
        "import { appValue } from 'app-lib'; await Promise.resolve(appValue); export function installExactNativeAgentBootstrap() { return appValue; }",
    );
    fixture.normalize();
    assert_refusal(
        fixture.run(),
        7,
        CompositionRefusalCode::CompositionRootUnlinked,
    );
}

#[test]
fn fixture_d37_atomic_link_failure_refuses_before_any_record_evaluates() {
    let _host_guard = crate::host::abi::host_test_lock();
    crate::host::abi::install_host(crate::host::Host::strict());
    let mut fixture = CompositionFixtureV1::new(true);
    fixture
        .packages
        .get_mut(&CompositionRole::App)
        .unwrap()
        .carriers[0]
        .bytes = b"this is not a JavaScript factory table (".to_vec();
    fixture.resync_package_and_resign(CompositionRole::App);
    let runtime = CompositionTestRuntimeV1::new();
    let outcome = run_composition_startup_fixture_v1(&fixture, &runtime);
    assert_eq!(outcome.status, 1);
    assert_eq!(outcome.report["admissionStatus"], "refused");
    assert_eq!(outcome.report["failureStage"], 8);
    assert_eq!(outcome.report["reasonCode"], "link-failure");
    assert!(outcome.report["packages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|package| package["verificationStatus"] == "verified"));
    let probe = runtime
        .eval_text(
            "JSON.stringify(globalThis.__compositionOrder || null)",
            "llp0056-link-atomicity-probe",
        )
        .unwrap();
    assert_eq!(probe.trim(), "null");
}

#[test]
fn composition_linker_refuses_a_plan_binding_not_present_in_step6_authority() {
    let fixture = CompositionFixtureV1::new(true);
    let CompositionAdmissionOutcomeV1::Admitted(admitted) = fixture.run() else {
        panic!("authority-binding fixture must admit")
    };
    let mut plan = admitted
        .authorized
        .execution_plan(&admitted.envelope.alias_table.rows)
        .unwrap();
    crate::engine::module_runner::NativeSynchronousGraph::validate_authorized_composition_plan(
        &plan,
        &admitted.authorized,
    )
    .unwrap();
    plan.insert_binding_for_test(
        &fixture.app_root,
        GraphEdgeKey::new("unauthorized-extra-binding", ResolutionKind::DynamicImport),
        fixture.app_lib.clone(),
    );
    let error =
        crate::engine::module_runner::NativeSynchronousGraph::validate_authorized_composition_plan(
            &plan,
            &admitted.authorized,
        )
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("bindings differ from the step-6 authorization capability"));
}

fn assert_startup_error_shape_v1(
    outcome: &CompositionStartupFixtureOutcomeV1,
    phase: &str,
    agent_count: u64,
    app_count: u64,
    shared_count: u64,
) {
    assert_eq!(outcome.status, 2, "startup error: {:?}", outcome.error);
    assert_eq!(outcome.report["admissionStatus"], "admitted-startup-error");
    assert_eq!(outcome.report["startupPhase"], phase);
    assert!(outcome.report.get("reasonCode").is_none());
    assert_eq!(outcome.report["agentEvaluatedRecordCount"], agent_count);
    assert_eq!(outcome.report["appEvaluatedRecordCount"], app_count);
    assert_eq!(outcome.report["sharedEvaluatedRecordCount"], shared_count);
    assert!(outcome.report["errorDetail"].is_string());
    assert!(outcome.report["packages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|package| package["verificationStatus"] == "verified"));
    assert_i_json_report_counters(&outcome.report);
}

#[test]
fn descriptor_startup_errors_are_phase_typed_and_never_reopen_admission() {
    let _host_guard = crate::host::abi::host_test_lock();
    crate::host::abi::install_host(crate::host::Host::strict());

    let mut agent_evaluate = CompositionFixtureV1::new(true);
    let agent_root = agent_evaluate.agent_root.clone().unwrap();
    agent_evaluate.replace_record_source(
        CompositionRole::Agent,
        &agent_root,
        "import { appValue } from 'app-lib'; globalThis.__compositionOrder.push('agent-evaluate-failure'); throw new Error('agent evaluate failed'); export function installExactNativeAgentBootstrap() { return appValue; }",
    );
    agent_evaluate.normalize();
    let runtime = CompositionTestRuntimeV1::new();
    let outcome = run_composition_startup_fixture_v1(&agent_evaluate, &runtime);
    assert_startup_error_shape_v1(&outcome, "agent-evaluate", 1, 0, 1);

    let mut agent_invoke = CompositionFixtureV1::new(true);
    let agent_root = agent_invoke.agent_root.clone().unwrap();
    agent_invoke.replace_record_source(
        CompositionRole::Agent,
        &agent_root,
        "import { appValue } from 'app-lib'; globalThis.__compositionOrder.push('agent'); export function installExactNativeAgentBootstrap() { globalThis.__compositionOrder.push('invoke'); throw new Error('agent invoke failed'); }",
    );
    agent_invoke.normalize();
    let runtime = CompositionTestRuntimeV1::new();
    let outcome = run_composition_startup_fixture_v1(&agent_invoke, &runtime);
    assert_startup_error_shape_v1(&outcome, "agent-invoke", 2, 0, 1);

    let mut non_callable = CompositionFixtureV1::new(true);
    let agent_root = non_callable.agent_root.clone().unwrap();
    non_callable.replace_record_source(
        CompositionRole::Agent,
        &agent_root,
        "import { appValue } from 'app-lib'; globalThis.__compositionOrder.push('agent'); export const installExactNativeAgentBootstrap = appValue;",
    );
    non_callable.normalize();
    let runtime = CompositionTestRuntimeV1::new();
    let outcome = run_composition_startup_fixture_v1(&non_callable, &runtime);
    assert_startup_error_shape_v1(&outcome, "agent-invoke", 2, 0, 1);
    assert!(outcome.report["errorDetail"]
        .as_str()
        .unwrap()
        .contains("not callable"));

    let mut app_evaluate = CompositionFixtureV1::new(true);
    let app_root = app_evaluate.app_root.clone();
    app_evaluate.replace_record_source(
        CompositionRole::App,
        &app_root,
        "import { appValue } from './app-lib.mjs'; globalThis.__compositionOrder.push('app'); throw new Error('app evaluate failed'); export const appResult = appValue;",
    );
    app_evaluate.normalize();
    let runtime = CompositionTestRuntimeV1::new();
    let outcome = run_composition_startup_fixture_v1(&app_evaluate, &runtime);
    assert_startup_error_shape_v1(&outcome, "app-evaluate", 2, 0, 1);
    let probe = runtime
        .eval_text(
            "JSON.stringify(globalThis.__compositionOrder)",
            "llp0056-app-failure-order-probe",
        )
        .unwrap();
    assert_eq!(probe.trim(), r#"["lib","agent","invoke","app"]"#);
}

#[test]
fn descriptor_thenable_is_reported_without_awaiting_or_blocking_app_evaluation() {
    let _host_guard = crate::host::abi::host_test_lock();
    crate::host::abi::install_host(crate::host::Host::strict());
    let mut fixture = CompositionFixtureV1::new(true);
    let agent_root = fixture.agent_root.clone().unwrap();
    fixture.replace_record_source(
        CompositionRole::Agent,
        &agent_root,
        "import { appValue } from 'app-lib'; globalThis.__compositionOrder.push('agent'); export function installExactNativeAgentBootstrap() { globalThis.__compositionOrder.push('invoke'); return { then: function () {} }; }",
    );
    fixture.normalize();
    let runtime = CompositionTestRuntimeV1::new();
    let outcome = run_composition_startup_fixture_v1(&fixture, &runtime);
    assert_eq!(outcome.status, 0, "thenable startup: {:?}", outcome.error);
    assert_eq!(outcome.report["agentInvokeReturnedThenable"], true);
    let probe = runtime
        .eval_text(
            "JSON.stringify(globalThis.__compositionOrder)",
            "llp0056-thenable-order-probe",
        )
        .unwrap();
    assert_eq!(probe.trim(), r#"["lib","agent","invoke","app"]"#);
}

#[test]
fn driver_channel_error_and_step1_sentinel_reports_are_total() {
    let fixture = CompositionFixtureV1::new(false);
    let outcome = admit_prepared_composition_with_probes_v1(
        fixture.directory.path(),
        "{}",
        &fixture.expectations_text(),
        fixture.directory.path(),
        CompositionChannelProbeV1::Unchecked,
        CompositionEngineProbeV1::Fixed(None),
    );
    let CompositionAdmissionOutcomeV1::ChannelError(report) = outcome else {
        panic!("expected channel error")
    };
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["admissionStatus"], "channel-error");
    assert_eq!(value["channelToken"], IBEX_DEV_COMPOSITION_CORRUPT);
    assert_eq!(value["packages"], serde_json::json!([]));
    assert!(value["declaredRoles"].is_null());
    assert_i_json_report_counters(&value);

    std::fs::write(
        fixture.directory.path().join("composition.json"),
        format!("{}\n", serde_json::to_string(&fixture.envelope).unwrap()),
    )
    .unwrap();
    let outcome = fixture.run();
    let CompositionAdmissionOutcomeV1::Refused(report) = outcome else {
        panic!("expected step-1 refusal")
    };
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["failureStage"], 1);
    assert_eq!(value["reasonCode"], "envelope-malformed");
    assert_eq!(value["packages"], serde_json::json!([]));
    assert!(value["compositionRootPrefix"].is_null());
    assert_i_json_report_counters(&value);
}

#[test]
fn report_package_statuses_follow_the_step_transition_rule() {
    let mut step2 = CompositionFixtureV1::new(true);
    step2.expectations.policy_digest = source_integrity(b"step-2-policy-fault").unwrap();
    assert_eq!(
        refusal_statuses(step2.run(), CompositionRefusalCode::CompositionPolicyStale),
        vec![
            (
                CompositionRole::App,
                CompositionPackageVerificationStatusV1::NotChecked,
            ),
            (
                CompositionRole::Agent,
                CompositionPackageVerificationStatusV1::NotChecked,
            ),
        ]
    );

    let step3 = CompositionFixtureV1::new(true);
    let path = step3.package_dir(CompositionRole::Agent).join("index.json");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(b'\n');
    std::fs::write(path, bytes).unwrap();
    assert_eq!(
        refusal_statuses(step3.run(), CompositionRefusalCode::PackageRootMismatch),
        vec![
            (
                CompositionRole::App,
                CompositionPackageVerificationStatusV1::Verified,
            ),
            (
                CompositionRole::Agent,
                CompositionPackageVerificationStatusV1::Refused,
            ),
        ]
    );

    let mut step5 = CompositionFixtureV1::new(true);
    inject_app_to_agent_fault(&mut step5);
    assert_eq!(
        refusal_statuses(step5.run(), CompositionRefusalCode::AppReferencesAgent),
        vec![
            (
                CompositionRole::App,
                CompositionPackageVerificationStatusV1::Refused,
            ),
            (
                CompositionRole::Agent,
                CompositionPackageVerificationStatusV1::Verified,
            ),
        ]
    );

    let mut step6 = CompositionFixtureV1::new(true);
    step6.envelope.union_binding_table.digest = source_integrity(b"step-6-union-fault").unwrap();
    step6.resign_envelope();
    assert_eq!(
        refusal_statuses(step6.run(), CompositionRefusalCode::UnionTableMismatch),
        vec![
            (
                CompositionRole::App,
                CompositionPackageVerificationStatusV1::Verified,
            ),
            (
                CompositionRole::Agent,
                CompositionPackageVerificationStatusV1::Verified,
            ),
        ]
    );

    let admitted = CompositionFixtureV1::new(true).run();
    let CompositionAdmissionOutcomeV1::Admitted(admitted) = admitted else {
        panic!("expected admission, got {admitted:?}")
    };
    let DevUnarmedCompositionStartupReportV1::Admitted { common, .. } = admitted.report else {
        panic!("admitted capability did not retain an admitted report")
    };
    assert!(common.packages.iter().all(|package| {
        package.verification_status == CompositionPackageVerificationStatusV1::Verified
    }));
}

fn observed_registry_refusal_report_v1(
    code: CompositionRefusalCode,
    runtime: &CompositionTestRuntimeV1,
) -> Value {
    let outcome = match code {
        CompositionRefusalCode::EnvelopeMalformed => {
            let fixture = CompositionFixtureV1::new(true);
            let path = fixture.directory.path().join("composition.json");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.push(b'\n');
            std::fs::write(path, bytes).unwrap();
            fixture.run()
        }
        CompositionRefusalCode::CompositionCommitmentMismatch => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.envelope.alias_table.digest =
                source_integrity(b"live-e39-uncommitted-alias-table").unwrap();
            fixture.write_envelope_without_resigning();
            fixture.run()
        }
        CompositionRefusalCode::CompositionReplayed => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.expectations.session_nonce = "live-e39-replay".into();
            fixture.run()
        }
        CompositionRefusalCode::CompositionPolicyStale => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.expectations.policy_digest = source_integrity(b"live-e39-policy").unwrap();
            fixture.run()
        }
        CompositionRefusalCode::IbexTargetProfileMismatch => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.expectations.expected_target = "live-e39-target".into();
            fixture.run()
        }
        CompositionRefusalCode::CompositionUnknownRole => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.envelope.declaration = vec!["app".into(), "unknown".into()];
            fixture.resign_envelope();
            fixture.run()
        }
        CompositionRefusalCode::CompositionDuplicateRole => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.envelope.declaration = vec!["app".into(), "app".into()];
            fixture.resign_envelope();
            fixture.run()
        }
        CompositionRefusalCode::CompositionPackageExtra => {
            let fixture = CompositionFixtureV1::new(true);
            std::fs::create_dir_all(fixture.directory.path().join("packages/extra")).unwrap();
            fixture.run()
        }
        CompositionRefusalCode::CompositionPackageMissing => {
            let fixture = CompositionFixtureV1::new(true);
            std::fs::remove_dir_all(fixture.package_dir(CompositionRole::Agent)).unwrap();
            fixture.run()
        }
        CompositionRefusalCode::CompositionMismatch => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.expectations.expected_roles = vec![CompositionRole::App];
            fixture.run()
        }
        CompositionRefusalCode::PackageRootMismatch => {
            let fixture = CompositionFixtureV1::new(true);
            let path = fixture.package_dir(CompositionRole::App).join("index.json");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.push(b'\n');
            std::fs::write(path, bytes).unwrap();
            fixture.run()
        }
        CompositionRefusalCode::IbexPreparedCommitmentSchema => {
            let mut fixture = CompositionFixtureV1::new(true);
            let path = fixture.package_dir(CompositionRole::App).join("index.json");
            let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            value["schema"] = serde_json::json!("ibex/prepared-package/2");
            let bytes = capsec_semantics::canonical::to_jcs_bytes(&value).unwrap();
            rewrite_index_and_recommit(&mut fixture, CompositionRole::App, &bytes);
            fixture.run()
        }
        CompositionRefusalCode::IbexPackageInventory => {
            let fixture = CompositionFixtureV1::new(true);
            std::fs::write(
                fixture.package_dir(CompositionRole::App).join("unexpected"),
                b"unexpected",
            )
            .unwrap();
            fixture.run()
        }
        CompositionRefusalCode::IbexPreparedCommitmentCorrupt => {
            let mut fixture = CompositionFixtureV1::new(true);
            let path = fixture.package_dir(CompositionRole::App).join("index.json");
            let value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            let bytes = serde_json::to_vec_pretty(&value).unwrap();
            rewrite_index_and_recommit(&mut fixture, CompositionRole::App, &bytes);
            fixture.run()
        }
        CompositionRefusalCode::CarrierIntegrity => {
            let fixture = CompositionFixtureV1::new(true);
            let bytes_file = &fixture.packages[&CompositionRole::App].carriers[0].bytes_file;
            let path = fixture.package_dir(CompositionRole::App).join(bytes_file);
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.push(b'!');
            std::fs::write(path, bytes).unwrap();
            fixture.run()
        }
        CompositionRefusalCode::IbexPrincipalGrouping => {
            let mut fixture = CompositionFixtureV1::new(true);
            let package_principal = fixture_package_principal();
            let removed_files;
            {
                let app = fixture.packages.get_mut(&CompositionRole::App).unwrap();
                let replacement = fixture_source_id(&package_principal, "app-lib.mjs");
                let old = app.package.records[1].source_id.clone();
                app.package.records[1].source_id = replacement.clone();
                app.package.records[1].artifact.semantics.source_id =
                    CanonicalSourceId(replacement.clone());
                for source_id in &mut app.package.records[1]
                    .artifact
                    .semantics
                    .source_map
                    .source_ids
                {
                    if source_id.0 == old {
                        *source_id = CanonicalSourceId(replacement.clone());
                    }
                }
                let PreparedPackageBindingTargetV1::Local { source_id } =
                    &mut app.package.records[0].bindings[0].target
                else {
                    panic!("fixture app edge must be local")
                };
                *source_id = replacement;
                app.package.records[1].carrier_index = 0;
                let removed = app.carriers.remove(1);
                removed_files = (removed.manifest_file, removed.bytes_file);
            }
            std::fs::remove_file(
                fixture
                    .package_dir(CompositionRole::App)
                    .join(&removed_files.0),
            )
            .unwrap();
            std::fs::remove_file(
                fixture
                    .package_dir(CompositionRole::App)
                    .join(&removed_files.1),
            )
            .unwrap();
            fixture.resync_package_and_resign(CompositionRole::App);
            fixture.run()
        }
        CompositionRefusalCode::IbexEncodingIncompatible => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture
                .packages
                .get_mut(&CompositionRole::App)
                .unwrap()
                .carriers[0]
                .bytes = 0x1F1903C103BC1FC6_u64.to_le_bytes().to_vec();
            fixture.resync_package_and_resign(CompositionRole::App);
            fixture.run()
        }
        CompositionRefusalCode::IbexEngineUnavailable => {
            let engine = fake_engine("live-e39-engine", 96);
            let mut fixture = CompositionFixtureV1::new(true);
            configure_hbc_carrier(
                &mut fixture,
                CompositionRole::App,
                0,
                &engine,
                96,
                0x1F1903C103BC1FC6_u64.to_le_bytes().to_vec(),
            );
            fixture.run_with_engine(None)
        }
        CompositionRefusalCode::IbexEngineBindingMismatch => {
            let engine = fake_engine("live-e39-manifest-engine", 96);
            let mut fixture = CompositionFixtureV1::new(true);
            configure_hbc_carrier(
                &mut fixture,
                CompositionRole::App,
                0,
                &engine,
                96,
                0x1F1903C103BC1FC6_u64.to_le_bytes().to_vec(),
            );
            fixture.run_with_engine(Some(fake_engine("live-e39-loaded-engine", 96)))
        }
        CompositionRefusalCode::IbexBytecodePreflight => {
            let engine = fake_engine("live-e39-engine", 96);
            let mut fixture = CompositionFixtureV1::new(true);
            configure_hbc_carrier(
                &mut fixture,
                CompositionRole::App,
                0,
                &engine,
                96,
                0x1F1903C103BC1FC6_u64.to_le_bytes().to_vec(),
            );
            fixture.run_with_engine(Some(engine))
        }
        CompositionRefusalCode::IbexPackageGraphBinding => {
            let fixture = CompositionFixtureV1::new(true);
            let manifest_path = fixture
                .package_dir(CompositionRole::App)
                .join(&fixture.packages[&CompositionRole::App].carriers[0].manifest_file);
            let mut manifest = fixture.packages[&CompositionRole::App].carriers[0]
                .manifest
                .clone();
            manifest.package_graph_digest = source_integrity(b"live-e39-graph").unwrap();
            std::fs::write(manifest_path, manifest.encode_canonical().unwrap()).unwrap();
            fixture.run()
        }
        CompositionRefusalCode::GenerationSplice => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.envelope.packages[1].producer_generation += 1;
            fixture.resign_envelope();
            fixture.run()
        }
        CompositionRefusalCode::AliasConflict => {
            let mut fixture = CompositionFixtureV1::new(true);
            let representative = fixture.agent_root.clone().unwrap();
            let row = CompositionAliasRowV1 {
                alias_id: fixture_source_id(&fixture_root_principal(), "live-e39-alias")
                    .encode()
                    .unwrap(),
                representative_source_id: representative.encode().unwrap(),
                representative_source_integrity: source_integrity(b"wrong-live-e39-evidence")
                    .unwrap(),
                import_site_inventory_digest: compute_alias_import_site_inventory_digest(&[])
                    .unwrap(),
            };
            fixture.envelope.alias_table = CompositionAliasTableV1 {
                digest: digest_canonical_value_v1(
                    PREPARED_ALIAS_TABLE_DOMAIN_V1,
                    &vec![row.clone()],
                )
                .unwrap(),
                rows: vec![row],
            };
            fixture.resign_envelope();
            fixture.run()
        }
        CompositionRefusalCode::PartitionMismatch => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.envelope.partition.digest = source_integrity(b"live-e39-partition").unwrap();
            fixture.resign_envelope();
            fixture.run()
        }
        CompositionRefusalCode::IbexDuplicateSourceId => {
            let mut fixture = CompositionFixtureV1::new(true);
            {
                let app = fixture.packages.get_mut(&CompositionRole::App).unwrap();
                let mut record = app.package.records[1].clone();
                let mut carrier = app.carriers[1].clone();
                record.entry_id = NonEmptyString::new("live-e39-duplicate").unwrap();
                record.carrier_index = app.carriers.len();
                carrier.manifest_file = "live-e39-duplicate.json".into();
                carrier.bytes_file = "live-e39-duplicate.bin".into();
                app.package.records.push(record);
                app.carriers.push(carrier);
            }
            fixture.resync_package_and_resign(CompositionRole::App);
            fixture.run()
        }
        CompositionRefusalCode::PackageOverlap => {
            let mut fixture = CompositionFixtureV1::new(true);
            {
                let app = fixture.packages.get(&CompositionRole::App).unwrap();
                let mut record = app.package.records[1].clone();
                let mut carrier = app.carriers[1].clone();
                let agent = fixture.packages.get_mut(&CompositionRole::Agent).unwrap();
                record.entry_id = NonEmptyString::new("live-e39-overlap").unwrap();
                record.carrier_index = agent.carriers.len();
                carrier.manifest_file = "live-e39-overlap.json".into();
                carrier.bytes_file = "live-e39-overlap.bin".into();
                agent.package.records.push(record);
                agent.carriers.push(carrier);
            }
            fixture.normalize();
            fixture.run()
        }
        CompositionRefusalCode::AppReferencesAgent => {
            let mut fixture = CompositionFixtureV1::new(true);
            inject_app_to_agent_fault(&mut fixture);
            fixture.run()
        }
        CompositionRefusalCode::LocalAgreementDisagreement => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture
                .packages
                .get_mut(&CompositionRole::Agent)
                .unwrap()
                .package
                .records[0]
                .bindings[0]
                .target = PreparedPackageBindingTargetV1::Local {
                source_id: fixture.app_lib.clone(),
            };
            fixture.normalize();
            fixture.run()
        }
        CompositionRefusalCode::UnionTableMismatch => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.envelope.union_binding_table.digest =
                source_integrity(b"live-e39-union").unwrap();
            fixture.resign_envelope();
            fixture.run()
        }
        CompositionRefusalCode::BoundaryInventoryMismatch => {
            let mut fixture = CompositionFixtureV1::new(true);
            let rows = vec![HostBridgedInventoryRowV1 {
                module: fixture.app_root.encode().unwrap(),
                specifier: "./live-e39-invented.mjs".into(),
                reason: HostBridgedReasonV1::TargetIsNotBundleModule,
            }];
            let preimage = serde_json::json!({ "role": CompositionRole::App, "rows": rows });
            fixture.envelope.host_bridged_inventories[0] = CompositionHostBridgedInventoryV1 {
                role: CompositionRole::App,
                digest: digest_canonical_value_v1(PREPARED_BOUNDARY_INVENTORY_DOMAIN_V1, &preimage)
                    .unwrap(),
                rows,
            };
            fixture.resign_envelope();
            fixture.run()
        }
        CompositionRefusalCode::ExternalTargetAbsent => {
            let mut fixture = CompositionFixtureV1::new(true);
            let missing = fixture_source_id(&fixture_root_principal(), "live-e39-absent.mjs");
            fixture
                .packages
                .get_mut(&CompositionRole::Agent)
                .unwrap()
                .package
                .records[0]
                .bindings[0]
                .target = PreparedPackageBindingTargetV1::External {
                role: CompositionRole::App,
                source_id: missing,
            };
            fixture.normalize();
            fixture.run()
        }
        CompositionRefusalCode::ExternalOwnerMismatch => {
            let mut fixture = CompositionFixtureV1::new(true);
            let agent_root = fixture.agent_root.clone().unwrap();
            fixture
                .packages
                .get_mut(&CompositionRole::Agent)
                .unwrap()
                .package
                .records[0]
                .bindings[0]
                .target = PreparedPackageBindingTargetV1::External {
                role: CompositionRole::App,
                source_id: agent_root,
            };
            fixture.normalize();
            fixture.run()
        }
        CompositionRefusalCode::ExportDisagreement => {
            let mut fixture = CompositionFixtureV1::new(true);
            let app_lib = fixture.app_lib.clone();
            fixture.replace_record_source(
                CompositionRole::App,
                &app_lib,
                "export const liveE39DifferentName = 1;",
            );
            fixture.normalize();
            fixture.run()
        }
        CompositionRefusalCode::CrossPrincipalDenied => {
            let mut fixture = CompositionFixtureV1::new(true);
            let package_principal = fixture_package_principal();
            let new_agent_root = fixture_source_id(&package_principal, "live-e39-package-root.mjs");
            {
                let agent = fixture.packages.get_mut(&CompositionRole::Agent).unwrap();
                let mut record = agent.package.records[0].clone();
                let old = record.source_id.clone();
                record.source_id = new_agent_root.clone();
                record.artifact.semantics.source_id = CanonicalSourceId(new_agent_root.clone());
                for source_id in &mut record.artifact.semantics.source_map.source_ids {
                    if source_id.0 == old {
                        *source_id = CanonicalSourceId(new_agent_root.clone());
                    }
                }
                record.entry_id = NonEmptyString::new("live-e39-package-root").unwrap();
                record.carrier_index = agent.carriers.len();
                let mut carrier = agent.carriers[0].clone();
                carrier.manifest_file = "live-e39-package-carrier.json".into();
                carrier.bytes_file = "live-e39-package-carrier.bin".into();
                agent.package.records.push(record);
                agent.carriers.push(carrier);
            }
            fixture.agent_root = Some(new_agent_root);
            fixture.normalize();
            fixture.run()
        }
        CompositionRefusalCode::EntryPlanMismatch => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.envelope.entry_plan.entries.swap(0, 1);
            fixture.envelope.entry_plan.digest =
                entry_plan_digest_v1(&fixture.envelope.entry_plan.entries).unwrap();
            fixture.resign_envelope();
            fixture.run()
        }
        CompositionRefusalCode::EntryDescriptorInvalid => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture.envelope.entry_plan.entries[0].action = "live-e39-unknown-action".into();
            fixture.envelope.entry_plan.digest =
                entry_plan_digest_v1(&fixture.envelope.entry_plan.entries).unwrap();
            fixture.resign_envelope();
            fixture.run()
        }
        CompositionRefusalCode::CompositionRootUnlinked => {
            let mut fixture = CompositionFixtureV1::new(true);
            let agent_root = fixture.agent_root.clone().unwrap();
            fixture.replace_record_source(
                CompositionRole::Agent,
                &agent_root,
                "import { appValue } from 'app-lib'; await Promise.resolve(appValue); export function installExactNativeAgentBootstrap() { return appValue; }",
            );
            fixture.normalize();
            fixture.run()
        }
        CompositionRefusalCode::LinkFailure => {
            let mut fixture = CompositionFixtureV1::new(true);
            fixture
                .packages
                .get_mut(&CompositionRole::App)
                .unwrap()
                .carriers[0]
                .bytes = b"live-e39-invalid-link-factory(".to_vec();
            fixture.resync_package_and_resign(CompositionRole::App);
            let outcome = run_composition_startup_fixture_v1(&fixture, runtime);
            assert_eq!(
                outcome.status, 1,
                "live E-39 link refusal: {:?}",
                outcome.error
            );
            return outcome.report;
        }
    };
    let CompositionAdmissionOutcomeV1::Refused(report) = outcome else {
        panic!(
            "live E-39 fixture for {} did not refuse: {outcome:?}",
            code.as_str()
        )
    };
    serde_json::to_value(report).unwrap()
}

fn expected_registry_refusal_disposition_v1(
    code: CompositionRefusalCode,
) -> (
    Option<CompositionRole>,
    Vec<(CompositionRole, CompositionPackageVerificationStatusV1)>,
) {
    use CompositionPackageVerificationStatusV1::{NotChecked, Refused, Verified};

    let both = |app, agent| vec![(CompositionRole::App, app), (CompositionRole::Agent, agent)];
    match code {
        CompositionRefusalCode::EnvelopeMalformed => (None, Vec::new()),
        code if code.step() == 2 => (None, both(NotChecked, NotChecked)),
        CompositionRefusalCode::PackageRootMismatch
        | CompositionRefusalCode::IbexPreparedCommitmentSchema
        | CompositionRefusalCode::IbexPackageInventory
        | CompositionRefusalCode::IbexPreparedCommitmentCorrupt
        | CompositionRefusalCode::CarrierIntegrity
        | CompositionRefusalCode::IbexPrincipalGrouping
        | CompositionRefusalCode::IbexEncodingIncompatible
        | CompositionRefusalCode::IbexEngineUnavailable
        | CompositionRefusalCode::IbexEngineBindingMismatch
        | CompositionRefusalCode::IbexBytecodePreflight
        | CompositionRefusalCode::IbexPackageGraphBinding => {
            (Some(CompositionRole::App), both(Refused, Verified))
        }
        CompositionRefusalCode::GenerationSplice => {
            (Some(CompositionRole::Agent), both(Verified, Refused))
        }
        CompositionRefusalCode::AliasConflict => (None, both(Verified, Verified)),
        CompositionRefusalCode::IbexDuplicateSourceId
        | CompositionRefusalCode::AppReferencesAgent => {
            (Some(CompositionRole::App), both(Refused, Verified))
        }
        CompositionRefusalCode::LocalAgreementDisagreement => {
            (Some(CompositionRole::Agent), both(Verified, Refused))
        }
        _ => (None, both(Verified, Verified)),
    }
}

#[test]
fn fixture_e39_serializes_every_registry_pair_transition_and_four_tagged_shapes() {
    let _host_guard = crate::host::abi::host_test_lock();
    crate::host::abi::install_host(crate::host::Host::strict());
    let runtime = CompositionTestRuntimeV1::new();
    let admitted = CompositionFixtureV1::new(true).run();
    let CompositionAdmissionOutcomeV1::Admitted(admitted) = admitted else {
        panic!("expected the report-shape fixture to admit")
    };
    let admitted_report = admitted.report;
    let DevUnarmedCompositionStartupReportV1::Admitted { .. } = admitted_report.clone() else {
        panic!("admitted capability carries the admitted report")
    };

    for code in CompositionRefusalCode::ALL {
        let value = observed_registry_refusal_report_v1(code, &runtime);
        assert_eq!(value["admissionStatus"], "refused");
        assert_eq!(value["failureStage"], u32::from(code.step()));
        assert_eq!(value["reasonCode"], code.as_str());
        let expected = expected_registry_refusal_disposition_v1(code);
        let observed_role = match value.get("packageRole").and_then(Value::as_str) {
            Some("app") => Some(CompositionRole::App),
            Some("agent") => Some(CompositionRole::Agent),
            None => None,
            Some(other) => panic!("unexpected live E-39 package role {other}"),
        };
        let observed_statuses = value["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|package| {
                let role: CompositionRole =
                    serde_json::from_value(package["role"].clone()).unwrap();
                let status: CompositionPackageVerificationStatusV1 =
                    serde_json::from_value(package["verificationStatus"].clone()).unwrap();
                (role, status)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            (observed_role, observed_statuses),
            expected,
            "live E-39 disposition differs for {}",
            code.as_str()
        );
        assert!(value.get("startupPhase").is_none());
        assert_i_json_report_counters(&value);
        if code == CompositionRefusalCode::EnvelopeMalformed {
            assert_eq!(value["packages"], serde_json::json!([]));
            assert!(value["declaredRoles"].is_null());
        }
    }

    let channel = serde_json::to_value(composition_embedder_channel_error_report_v1(
        "fixture channel failure",
    ))
    .unwrap();
    assert_eq!(channel["admissionStatus"], "channel-error");
    assert!(channel.get("reasonCode").is_none());

    let admitted = serde_json::to_value(admitted_report.clone()).unwrap();
    assert_eq!(admitted["admissionStatus"], "admitted");
    assert!(admitted.get("failureStage").is_none());
    assert!(admitted.get("reasonCode").is_none());
    assert!(admitted["packages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|package| package["verificationStatus"] == "verified"));

    let startup = serde_json::to_value(admitted_report.into_startup_error(
        CompositionStartupPhaseV1::AgentInvoke,
        "fixture invoke failure".into(),
    ))
    .unwrap();
    assert_eq!(startup["admissionStatus"], "admitted-startup-error");
    assert_eq!(startup["startupPhase"], "agent-invoke");
    assert!(startup.get("failureStage").is_none());
    assert!(startup.get("reasonCode").is_none());
}

#[test]
fn fixture_rows_b14_b15_b16_b17_declaration_refusals() {
    let extra = CompositionFixtureV1::new(false);
    std::fs::create_dir_all(extra.directory.path().join("packages/extra")).unwrap();
    assert_refusal(
        extra.run(),
        2,
        CompositionRefusalCode::CompositionPackageExtra,
    );

    let missing = CompositionFixtureV1::new(true);
    std::fs::remove_dir_all(missing.package_dir(CompositionRole::Agent)).unwrap();
    assert_refusal(
        missing.run(),
        2,
        CompositionRefusalCode::CompositionPackageMissing,
    );

    let mut unknown = CompositionFixtureV1::new(true);
    unknown.envelope.declaration = vec!["app".into(), "unknown".into()];
    unknown.resign_envelope();
    assert_refusal(
        unknown.run(),
        2,
        CompositionRefusalCode::CompositionUnknownRole,
    );

    let mut duplicate = CompositionFixtureV1::new(true);
    duplicate.envelope.declaration = vec!["app".into(), "app".into()];
    duplicate.resign_envelope();
    assert_refusal(
        duplicate.run(),
        2,
        CompositionRefusalCode::CompositionDuplicateRole,
    );
}

#[test]
fn fixture_row_b18_limit_and_limit_plus_one_at_both_surfaces() {
    let mut envelope_limit = CompositionFixtureV1::new(false);
    envelope_limit.envelope.agent_boundary.entry_ids =
        vec!["e".repeat(MAX_COMPOSITION_STRING_BYTES_V1)];
    envelope_limit.resign_envelope();
    assert_admitted(envelope_limit.run());
    envelope_limit.envelope.agent_boundary.entry_ids =
        vec!["e".repeat(MAX_COMPOSITION_STRING_BYTES_V1 + 1)];
    envelope_limit.resign_envelope();
    assert_refusal(
        envelope_limit.run(),
        1,
        CompositionRefusalCode::EnvelopeMalformed,
    );

    let mut package_limit = CompositionFixtureV1::new(false);
    package_limit
        .packages
        .get_mut(&CompositionRole::App)
        .unwrap()
        .package
        .records[0]
        .artifact
        .semantics
        .source_map
        .names = vec!["p".repeat(MAX_COMPOSITION_STRING_BYTES_V1)];
    package_limit.resync_package_and_resign(CompositionRole::App);
    assert_admitted(package_limit.run());
    package_limit
        .packages
        .get_mut(&CompositionRole::App)
        .unwrap()
        .package
        .records[0]
        .artifact
        .semantics
        .source_map
        .names = vec!["p".repeat(MAX_COMPOSITION_STRING_BYTES_V1 + 1)];
    package_limit.resync_package_and_resign(CompositionRole::App);
    assert_refusal(
        package_limit.run(),
        3,
        CompositionRefusalCode::IbexPreparedCommitmentCorrupt,
    );
}

#[test]
fn fixture_row_b19_declaration_live_state_mismatch_both_directions() {
    let mut app = CompositionFixtureV1::new(false);
    app.expectations.expected_roles = vec![CompositionRole::App, CompositionRole::Agent];
    assert_refusal(app.run(), 2, CompositionRefusalCode::CompositionMismatch);

    let mut composed = CompositionFixtureV1::new(true);
    composed.expectations.expected_roles = vec![CompositionRole::App];
    assert_refusal(
        composed.run(),
        2,
        CompositionRefusalCode::CompositionMismatch,
    );
}

#[test]
fn fixture_rows_c20_c21_c22_freshness_and_policy() {
    let mut nonce = CompositionFixtureV1::new(false);
    nonce.envelope.freshness.session_nonce = "replayed".into();
    nonce.resign_envelope();
    assert_refusal(nonce.run(), 2, CompositionRefusalCode::CompositionReplayed);

    let mut expired = CompositionFixtureV1::new(false);
    expired.expectations.now_unix_ms = expired.envelope.freshness.expires_at_ms + 1;
    assert_refusal(
        expired.run(),
        2,
        CompositionRefusalCode::CompositionReplayed,
    );

    let mut resolver = CompositionFixtureV1::new(false);
    resolver.expectations.resolver_generation += 1;
    assert_refusal(
        resolver.run(),
        2,
        CompositionRefusalCode::CompositionReplayed,
    );

    let mut policy = CompositionFixtureV1::new(false);
    policy.expectations.policy_digest = source_integrity(b"stale-policy").unwrap();
    assert_refusal(
        policy.run(),
        2,
        CompositionRefusalCode::CompositionPolicyStale,
    );
}

#[test]
fn fixture_rows_c23_c24_package_and_carrier_tamper() {
    let package = CompositionFixtureV1::new(false);
    let index = package.package_dir(CompositionRole::App).join("index.json");
    let mut bytes = std::fs::read(&index).unwrap();
    bytes.push(b'\n');
    std::fs::write(index, bytes).unwrap();
    assert_refusal(
        package.run(),
        3,
        CompositionRefusalCode::PackageRootMismatch,
    );

    let carrier = CompositionFixtureV1::new(false);
    let bytes_file = &carrier.packages[&CompositionRole::App].carriers[0].bytes_file;
    let path = carrier.package_dir(CompositionRole::App).join(bytes_file);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(b'!');
    std::fs::write(path, bytes).unwrap();
    assert_refusal(carrier.run(), 3, CompositionRefusalCode::CarrierIntegrity);
}

#[test]
fn fixture_rows_c25_c27_c28_c29_envelope_tamper_and_resigning() {
    let mut role_swap = CompositionFixtureV1::new(true);
    role_swap.envelope.packages.swap(0, 1);
    role_swap.resign_envelope();
    assert_refusal(
        role_swap.run(),
        2,
        CompositionRefusalCode::CompositionCommitmentMismatch,
    );

    let mut splice = CompositionFixtureV1::new(true);
    splice.envelope.packages[1].producer_generation += 1;
    splice.resign_envelope();
    let outcome = splice.run();
    let CompositionAdmissionOutcomeV1::Refused(DevUnarmedCompositionStartupReportV1::Refused {
        common,
        reason_code,
        package_role,
        ..
    }) = outcome
    else {
        panic!("expected generation-splice refusal")
    };
    assert_eq!(reason_code, CompositionRefusalCode::GenerationSplice);
    assert_eq!(package_role, Some(CompositionRole::Agent));
    assert_eq!(
        common
            .packages
            .iter()
            .map(|package| (package.role, package.verification_status))
            .collect::<Vec<_>>(),
        vec![
            (
                CompositionRole::App,
                CompositionPackageVerificationStatusV1::Verified,
            ),
            (
                CompositionRole::Agent,
                CompositionPackageVerificationStatusV1::Refused,
            ),
        ]
    );

    let mut inventory = CompositionFixtureV1::new(false);
    let rows = vec![HostBridgedInventoryRowV1 {
        module: inventory.app_root.encode().unwrap(),
        specifier: "./invented.mjs".into(),
        reason: HostBridgedReasonV1::TargetIsNotBundleModule,
    }];
    let preimage = serde_json::json!({ "role": CompositionRole::App, "rows": rows });
    inventory.envelope.host_bridged_inventories[0] = CompositionHostBridgedInventoryV1 {
        role: CompositionRole::App,
        digest: digest_canonical_value_v1(PREPARED_BOUNDARY_INVENTORY_DOMAIN_V1, &preimage)
            .unwrap(),
        rows,
    };
    inventory.resign_envelope();
    assert_refusal(
        inventory.run(),
        6,
        CompositionRefusalCode::BoundaryInventoryMismatch,
    );

    let mut alias = CompositionFixtureV1::new(false);
    alias.envelope.alias_table.digest = source_integrity(b"tampered-alias-table").unwrap();
    alias.write_envelope_without_resigning();
    assert_refusal(
        alias.run(),
        2,
        CompositionRefusalCode::CompositionCommitmentMismatch,
    );
}

#[test]
fn fixture_row_c26_record_migration_reaches_partition_mismatch() {
    let mut fixture = CompositionFixtureV1::new(true);
    let (mut migrated_record, mut migrated_carrier) = {
        let app = fixture.packages.get_mut(&CompositionRole::App).unwrap();
        let index = app
            .package
            .records
            .iter()
            .position(|record| record.source_id == fixture.app_lib)
            .unwrap();
        let record = app.package.records.remove(index);
        let carrier = app.carriers.remove(record.carrier_index);
        for record in &mut app.package.records {
            if record.carrier_index > index {
                record.carrier_index -= 1;
            }
        }
        (record, carrier)
    };
    std::fs::remove_file(
        fixture
            .package_dir(CompositionRole::App)
            .join(&migrated_carrier.manifest_file),
    )
    .unwrap();
    std::fs::remove_file(
        fixture
            .package_dir(CompositionRole::App)
            .join(&migrated_carrier.bytes_file),
    )
    .unwrap();
    let agent = fixture.packages.get_mut(&CompositionRole::Agent).unwrap();
    migrated_record.carrier_index = agent.carriers.len();
    migrated_carrier.manifest_file = "migrated-app-lib.json".into();
    migrated_carrier.bytes_file = "migrated-app-lib.bin".into();
    agent.package.records.push(migrated_record);
    agent.carriers.push(migrated_carrier);
    fixture.resync_package_and_resign(CompositionRole::App);
    fixture.resync_package_and_resign(CompositionRole::Agent);
    assert_refusal(fixture.run(), 4, CompositionRefusalCode::PartitionMismatch);
}

#[test]
fn imported_rows_f_i1_f_i2_f_i3_f_i4_and_candidate_v1_reach_driver() {
    let mut target = CompositionFixtureV1::new(false);
    target.expectations.expected_target = "different-target".into();
    assert_refusal(
        target.run(),
        2,
        CompositionRefusalCode::IbexTargetProfileMismatch,
    );

    let mut schema = CompositionFixtureV1::new(false);
    let path = schema.package_dir(CompositionRole::App).join("index.json");
    let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["schema"] = serde_json::json!("ibex/prepared-package/2");
    let bytes = capsec_semantics::canonical::to_jcs_bytes(&value).unwrap();
    rewrite_index_and_recommit(&mut schema, CompositionRole::App, &bytes);
    assert_refusal(
        schema.run(),
        3,
        CompositionRefusalCode::IbexPreparedCommitmentSchema,
    );

    let inventory = CompositionFixtureV1::new(false);
    std::fs::write(
        inventory
            .package_dir(CompositionRole::App)
            .join("unexpected"),
        b"unexpected",
    )
    .unwrap();
    assert_refusal(
        inventory.run(),
        3,
        CompositionRefusalCode::IbexPackageInventory,
    );

    let mut corrupt = CompositionFixtureV1::new(false);
    let path = corrupt.package_dir(CompositionRole::App).join("index.json");
    let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let bytes = serde_json::to_vec_pretty(&value).unwrap();
    rewrite_index_and_recommit(&mut corrupt, CompositionRole::App, &bytes);
    assert_refusal(
        corrupt.run(),
        3,
        CompositionRefusalCode::IbexPreparedCommitmentCorrupt,
    );

    let mut candidate_v1 = CompositionFixtureV1::new(false);
    let bytes = br#"{"schema":"ibex/computed-candidates/1"}"#.to_vec();
    let digest = source_integrity(&bytes).unwrap();
    let app = candidate_v1
        .packages
        .get_mut(&CompositionRole::App)
        .unwrap();
    app.package
        .candidate_tables
        .push(PreparedPackageCandidateTableIndexV1 {
            file: "candidate-v1.json".into(),
            digest,
        });
    app.candidate_files
        .insert("candidate-v1.json".into(), bytes);
    candidate_v1.resync_package_and_resign(CompositionRole::App);
    assert_refusal(
        candidate_v1.run(),
        3,
        CompositionRefusalCode::IbexPreparedCommitmentSchema,
    );
}

#[test]
fn imported_rows_f_i5_f_i6_f_i10_f_i11_reach_driver() {
    let mut grouping = CompositionFixtureV1::new(false);
    let package_principal = fixture_package_principal();
    let removed_files;
    {
        let app = grouping.packages.get_mut(&CompositionRole::App).unwrap();
        let replacement = fixture_source_id(&package_principal, "app-lib.mjs");
        let old = app.package.records[1].source_id.clone();
        app.package.records[1].source_id = replacement.clone();
        app.package.records[1].artifact.semantics.source_id =
            CanonicalSourceId(replacement.clone());
        for source_id in &mut app.package.records[1]
            .artifact
            .semantics
            .source_map
            .source_ids
        {
            if source_id.0 == old {
                *source_id = CanonicalSourceId(replacement.clone());
            }
        }
        let PreparedPackageBindingTargetV1::Local { source_id } =
            &mut app.package.records[0].bindings[0].target
        else {
            panic!("fixture app edge must be local")
        };
        *source_id = replacement;
        app.package.records[1].carrier_index = 0;
        let removed = app.carriers.remove(1);
        removed_files = (removed.manifest_file, removed.bytes_file);
    }
    std::fs::remove_file(
        grouping
            .package_dir(CompositionRole::App)
            .join(&removed_files.0),
    )
    .unwrap();
    std::fs::remove_file(
        grouping
            .package_dir(CompositionRole::App)
            .join(&removed_files.1),
    )
    .unwrap();
    grouping.resync_package_and_resign(CompositionRole::App);
    assert_refusal(
        grouping.run(),
        3,
        CompositionRefusalCode::IbexPrincipalGrouping,
    );

    let mut encoding = CompositionFixtureV1::new(false);
    encoding
        .packages
        .get_mut(&CompositionRole::App)
        .unwrap()
        .carriers[0]
        .bytes = 0x1F1903C103BC1FC6_u64.to_le_bytes().to_vec();
    encoding.resync_package_and_resign(CompositionRole::App);
    assert_refusal(
        encoding.run(),
        3,
        CompositionRefusalCode::IbexEncodingIncompatible,
    );

    let graph_binding = CompositionFixtureV1::new(false);
    let manifest_path = graph_binding
        .package_dir(CompositionRole::App)
        .join(&graph_binding.packages[&CompositionRole::App].carriers[0].manifest_file);
    let mut manifest = graph_binding.packages[&CompositionRole::App].carriers[0]
        .manifest
        .clone();
    manifest.package_graph_digest = source_integrity(b"wrong-package-graph").unwrap();
    std::fs::write(manifest_path, manifest.encode_canonical().unwrap()).unwrap();
    assert_refusal(
        graph_binding.run(),
        3,
        CompositionRefusalCode::IbexPackageGraphBinding,
    );

    let mut duplicate = CompositionFixtureV1::new(false);
    {
        let app = duplicate.packages.get_mut(&CompositionRole::App).unwrap();
        let mut record = app.package.records[1].clone();
        let mut carrier = app.carriers[1].clone();
        record.entry_id = NonEmptyString::new("app-lib-duplicate").unwrap();
        record.carrier_index = app.carriers.len();
        carrier.manifest_file = "carrier-duplicate.json".into();
        carrier.bytes_file = "carrier-duplicate.bin".into();
        app.package.records.push(record);
        app.carriers.push(carrier);
    }
    duplicate.resync_package_and_resign(CompositionRole::App);
    assert_refusal(
        duplicate.run(),
        4,
        CompositionRefusalCode::IbexDuplicateSourceId,
    );
}

#[test]
fn imported_rows_f_i7_f_i8_f_i9_engine_failures_reach_driver() {
    let manifest_engine = fake_engine("manifest-engine", 96);

    let mut unavailable = CompositionFixtureV1::new(false);
    configure_hbc_carrier(
        &mut unavailable,
        CompositionRole::App,
        0,
        &manifest_engine,
        96,
        0x1F1903C103BC1FC6_u64.to_le_bytes().to_vec(),
    );
    assert_refusal(
        unavailable.run_with_engine(None),
        3,
        CompositionRefusalCode::IbexEngineUnavailable,
    );

    let mut binding = CompositionFixtureV1::new(false);
    configure_hbc_carrier(
        &mut binding,
        CompositionRole::App,
        0,
        &manifest_engine,
        96,
        0x1F1903C103BC1FC6_u64.to_le_bytes().to_vec(),
    );
    assert_refusal(
        binding.run_with_engine(Some(fake_engine("different-engine", 96))),
        3,
        CompositionRefusalCode::IbexEngineBindingMismatch,
    );

    let mut version = CompositionFixtureV1::new(false);
    let mut header_version_96 = vec![0_u8; 128];
    header_version_96[0..8].copy_from_slice(&0x1F1903C103BC1FC6_u64.to_le_bytes());
    header_version_96[8..12].copy_from_slice(&96_u32.to_le_bytes());
    header_version_96[32..36].copy_from_slice(&128_u32.to_le_bytes());
    configure_hbc_carrier(
        &mut version,
        CompositionRole::App,
        0,
        &manifest_engine,
        95,
        header_version_96,
    );
    assert_refusal(
        version.run_with_engine(Some(fake_engine("manifest-engine", 95))),
        3,
        CompositionRefusalCode::IbexPreparedCommitmentCorrupt,
    );

    let mut preflight = CompositionFixtureV1::new(false);
    configure_hbc_carrier(
        &mut preflight,
        CompositionRole::App,
        0,
        &manifest_engine,
        96,
        0x1F1903C103BC1FC6_u64.to_le_bytes().to_vec(),
    );
    assert_refusal(
        preflight.run_with_engine(Some(manifest_engine)),
        3,
        CompositionRefusalCode::IbexBytecodePreflight,
    );
}

#[test]
fn fixture_d33_a2_crossing_external_defining_principals_refuses_row_34() {
    let mut fixture = CompositionFixtureV1::new(true);
    let package_principal = fixture_package_principal();
    let new_agent_root = fixture_source_id(&package_principal, "agent-package-root.mjs");
    {
        let agent = fixture.packages.get_mut(&CompositionRole::Agent).unwrap();
        let mut record = agent.package.records[0].clone();
        let old = record.source_id.clone();
        record.source_id = new_agent_root.clone();
        record.artifact.semantics.source_id = CanonicalSourceId(new_agent_root.clone());
        for source_id in &mut record.artifact.semantics.source_map.source_ids {
            if source_id.0 == old {
                *source_id = CanonicalSourceId(new_agent_root.clone());
            }
        }
        record.entry_id = NonEmptyString::new("agent-package-root").unwrap();
        record.carrier_index = agent.carriers.len();
        let mut carrier = agent.carriers[0].clone();
        carrier.manifest_file = "agent-package-carrier.json".into();
        carrier.bytes_file = "agent-package-carrier.bin".into();
        agent.package.records.push(record);
        agent.carriers.push(carrier);
    }
    fixture.agent_root = Some(new_agent_root);
    fixture.normalize();
    assert_refusal(
        fixture.run(),
        6,
        CompositionRefusalCode::CrossPrincipalDenied,
    );
}

#[test]
fn cross_package_step3_sweep_selects_lower_ordinal_before_role_order() {
    let mut fixture = CompositionFixtureV1::new(true);
    let app_path = fixture.package_dir(CompositionRole::App).join("index.json");
    let mut app_value: Value = serde_json::from_slice(&std::fs::read(&app_path).unwrap()).unwrap();
    app_value["schema"] = serde_json::json!("ibex/prepared-package/2");
    let app_bytes = capsec_semantics::canonical::to_jcs_bytes(&app_value).unwrap();
    rewrite_index_and_recommit(&mut fixture, CompositionRole::App, &app_bytes);

    let agent_path = fixture
        .package_dir(CompositionRole::Agent)
        .join("index.json");
    let mut agent_bytes = std::fs::read(&agent_path).unwrap();
    agent_bytes.push(b'\n');
    std::fs::write(agent_path, agent_bytes).unwrap();

    let outcome = fixture.run();
    let CompositionAdmissionOutcomeV1::Refused(DevUnarmedCompositionStartupReportV1::Refused {
        reason_code,
        package_role,
        ..
    }) = outcome
    else {
        panic!("expected step-3 refusal")
    };
    assert_eq!(reason_code, CompositionRefusalCode::PackageRootMismatch);
    assert_eq!(package_role, Some(CompositionRole::Agent));
}

fn inject_app_to_agent_fault(fixture: &mut CompositionFixtureV1) {
    let agent_root = fixture
        .agent_root
        .clone()
        .expect("step-5 fault requires the agent package");
    let producer_digest = fixture.packages[&CompositionRole::App]
        .package
        .producer_binary_digest
        .clone();
    let source = produce_module_artifact_v1(
        fixture.app_root.clone(),
        "app-root",
        Path::new("app-root"),
        "import { appValue } from './app-lib.mjs'; import { installExactNativeAgentBootstrap } from 'agent-root'; export const appResult = appValue;",
        producer_digest,
    )
    .unwrap();
    let app = fixture.packages.get_mut(&CompositionRole::App).unwrap();
    app.package.records[0].artifact.semantics = source.semantics;
    app.package.records[0].artifact.semantic_digest = source.semantic_digest;
    app.package.records[0]
        .bindings
        .push(PreparedPackageBindingV1 {
            specifier: "agent-root".into(),
            resolution_kind: ResolutionKind::EsmStatic,
            target: PreparedPackageBindingTargetV1::Local {
                source_id: agent_root,
            },
        });
    fixture.resync_package_and_resign(CompositionRole::App);
}

#[test]
fn random_fault_conjunctions_choose_the_lowest_tuple_across_steps_1_through_7() {
    const FAULTS: [(u32, CompositionRefusalCode); 7] = [
        (1, CompositionRefusalCode::EnvelopeMalformed),
        (2, CompositionRefusalCode::CompositionPolicyStale),
        (3, CompositionRefusalCode::PackageRootMismatch),
        (4, CompositionRefusalCode::PartitionMismatch),
        (5, CompositionRefusalCode::AppReferencesAgent),
        (6, CompositionRefusalCode::UnionTableMismatch),
        (7, CompositionRefusalCode::EntryPlanMismatch),
    ];
    let mut masks = (0..FAULTS.len())
        .map(|index| 1_u8 << index)
        .collect::<Vec<_>>();
    let mut state = 0x0056_5eed_u64;
    for _ in 0..48 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let mask = ((state >> 32) as u8) & 0x7f;
        masks.push(mask.max(1));
    }

    for mask in masks {
        let mut fixture = CompositionFixtureV1::new(true);
        if mask & (1 << 4) != 0 {
            inject_app_to_agent_fault(&mut fixture);
        }
        if mask & (1 << 3) != 0 {
            fixture.envelope.partition.digest =
                source_integrity(format!("partition-fault-{mask}").as_bytes()).unwrap();
        }
        if mask & (1 << 5) != 0 {
            fixture.envelope.union_binding_table.digest =
                source_integrity(format!("union-fault-{mask}").as_bytes()).unwrap();
        }
        if mask & (1 << 6) != 0 {
            fixture.envelope.entry_plan.digest =
                source_integrity(format!("entry-fault-{mask}").as_bytes()).unwrap();
        }
        fixture.resign_envelope();
        if mask & (1 << 1) != 0 {
            fixture.expectations.policy_digest =
                source_integrity(format!("policy-fault-{mask}").as_bytes()).unwrap();
        }
        if mask & (1 << 2) != 0 {
            let path = fixture
                .package_dir(CompositionRole::Agent)
                .join("index.json");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.push(b'\n');
            std::fs::write(path, bytes).unwrap();
        }
        if mask & 1 != 0 {
            let path = fixture.directory.path().join("composition.json");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.push(b'\n');
            std::fs::write(path, bytes).unwrap();
        }

        let expected = FAULTS
            .iter()
            .enumerate()
            .find(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, expected)| *expected)
            .unwrap();
        assert_eq!(
            refusal(fixture.run()),
            expected,
            "fault conjunction mask {mask:#09b} selected the wrong precedence tuple"
        );
    }
}

#[test]
fn random_fault_conjunctions_choose_the_lowest_tuple_through_step_8_c_entry() {
    const FAULTS: [(u32, CompositionRefusalCode, Option<CompositionRole>); 11] = [
        (1, CompositionRefusalCode::EnvelopeMalformed, None),
        (2, CompositionRefusalCode::CompositionReplayed, None),
        (2, CompositionRefusalCode::CompositionPolicyStale, None),
        (
            3,
            CompositionRefusalCode::PackageRootMismatch,
            Some(CompositionRole::App),
        ),
        (
            3,
            CompositionRefusalCode::PackageRootMismatch,
            Some(CompositionRole::Agent),
        ),
        (
            3,
            CompositionRefusalCode::IbexPreparedCommitmentSchema,
            Some(CompositionRole::App),
        ),
        (4, CompositionRefusalCode::PartitionMismatch, None),
        (
            5,
            CompositionRefusalCode::AppReferencesAgent,
            Some(CompositionRole::App),
        ),
        (6, CompositionRefusalCode::UnionTableMismatch, None),
        (7, CompositionRefusalCode::EntryPlanMismatch, None),
        (8, CompositionRefusalCode::LinkFailure, None),
    ];
    let _host_guard = crate::host::abi::host_test_lock();
    crate::host::abi::install_host(crate::host::Host::strict());
    let runtime = CompositionTestRuntimeV1::new();
    let mut masks = (0..FAULTS.len())
        .map(|index| 1_u16 << index)
        .collect::<Vec<_>>();
    masks.extend([
        (1 << 1) | (1 << 2),
        (1 << 3) | (1 << 4),
        (1 << 3) | (1 << 5),
        (1 << 4) | (1 << 5),
    ]);
    let mut state = 0x0056_0008_5eed_u64;
    for _ in 0..48 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        masks.push((((state >> 32) as u16) & 0x07ff).max(1));
    }

    for mask in masks {
        let mut fixture = CompositionFixtureV1::new(true);
        if mask & (1 << 10) != 0 {
            fixture
                .packages
                .get_mut(&CompositionRole::App)
                .unwrap()
                .carriers[0]
                .bytes = format!("invalid-link-factory-{mask}(").into_bytes();
            fixture.resync_package_and_resign(CompositionRole::App);
        }
        if mask & (1 << 7) != 0 {
            inject_app_to_agent_fault(&mut fixture);
        }
        if mask & (1 << 6) != 0 {
            fixture.envelope.partition.digest =
                source_integrity(format!("partition-fault-step8-{mask}").as_bytes()).unwrap();
        }
        if mask & (1 << 8) != 0 {
            fixture.envelope.union_binding_table.digest =
                source_integrity(format!("union-fault-step8-{mask}").as_bytes()).unwrap();
        }
        if mask & (1 << 9) != 0 {
            fixture.envelope.entry_plan.digest =
                source_integrity(format!("entry-fault-step8-{mask}").as_bytes()).unwrap();
        }
        fixture.resign_envelope();

        if mask & (1 << 5) != 0 {
            let path = fixture.package_dir(CompositionRole::App).join("index.json");
            let mut value: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            value["schema"] = serde_json::json!("ibex/prepared-package/2");
            let bytes = capsec_semantics::canonical::to_jcs_bytes(&value).unwrap();
            rewrite_index_and_recommit(&mut fixture, CompositionRole::App, &bytes);
        }
        if mask & (1 << 1) != 0 {
            fixture.expectations.session_nonce = format!("replayed-step8-{mask}");
        }
        if mask & (1 << 2) != 0 {
            fixture.expectations.policy_digest =
                source_integrity(format!("policy-fault-step8-{mask}").as_bytes()).unwrap();
        }
        for (index, role) in [(3, CompositionRole::App), (4, CompositionRole::Agent)] {
            if mask & (1 << index) == 0 {
                continue;
            }
            let path = fixture.package_dir(role).join("index.json");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.push(b'\n');
            std::fs::write(path, bytes).unwrap();
        }
        if mask & 1 != 0 {
            let path = fixture.directory.path().join("composition.json");
            let mut bytes = std::fs::read(&path).unwrap();
            bytes.push(b'\n');
            std::fs::write(path, bytes).unwrap();
        }

        let expected = FAULTS
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, expected)| expected)
            .min_by_key(|(step, code, role)| {
                let role_order = match role {
                    Some(CompositionRole::App) => 0,
                    Some(CompositionRole::Agent) => 1,
                    None => 2,
                };
                (*step, code.ordinal(), role_order)
            })
            .copied()
            .unwrap();
        let outcome = run_composition_startup_fixture_v1(&fixture, &runtime);
        assert_eq!(outcome.status, 1, "mask {mask:#010b}: {:?}", outcome.error);
        let observed_role = match outcome.report.get("packageRole").and_then(Value::as_str) {
            Some("app") => Some(CompositionRole::App),
            Some("agent") => Some(CompositionRole::Agent),
            None => None,
            Some(other) => panic!("unexpected package role {other}"),
        };
        assert_eq!(
            (
                outcome.report["failureStage"].as_u64().unwrap() as u32,
                CompositionRefusalCode::ALL
                    .iter()
                    .find(|code| code.as_str() == outcome.report["reasonCode"].as_str().unwrap())
                    .unwrap()
                    .ordinal(),
                observed_role,
            ),
            (expected.0, expected.1.ordinal(), expected.2),
            "fault conjunction mask {mask:#010b} selected the wrong C-entry precedence tuple"
        );
    }
}
