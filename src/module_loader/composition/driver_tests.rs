use super::*;

use capsec_semantics::model::{PackageLocator, PathComponent};

use crate::module_loader::artifact::{
    semantics_digest, CanonicalSourceId, ModuleArtifactV1, ModulePayloadV1, ProducerIdentityV1,
};
use crate::module_loader::carrier::{
    PreparedCarrierEncodingV2, PreparedCarrierEngineBindingV2, PreparedCarrierEntryV2,
    PreparedModuleCarrierV3, PREPARED_CARRIER_BYTES_DOMAIN_V1, PREPARED_CARRIER_SCHEMA_V3,
};
use crate::module_loader::producer_spike::produce_module_artifact_v1;

const GENERATION: u64 = 7;
const TARGET: &str = "exact-dev:test";

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
            let bytes =
                format!("(function(){{return Object.freeze({{{index}:true}});}})()").into_bytes();
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
                    "import { appValue } from './app-lib.mjs'; export const appResult = appValue;",
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
                    "export const appValue = 1;",
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
                        "import { appValue } from 'app-lib'; export function installExactNativeAgentBootstrap() { return appValue; }",
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
                        binary_digest: producer_binary_digest,
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
                // A2 reserves this wire field. Deliberately unrelated bytes
                // prove that no driver predicate consumes it.
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
fn fixture_rows_b12_b13_admit_both_declarations_and_ignore_reserved_input() {
    let mut app = CompositionFixtureV1::new(false);
    app.expectations.resolver_inventory_digest = source_integrity(b"arbitrary-reserved-a").unwrap();
    assert_admitted(app.run());

    let mut composed = CompositionFixtureV1::new(true);
    composed.expectations.resolver_inventory_digest =
        source_integrity(b"arbitrary-reserved-b").unwrap();
    assert_admitted(composed.run());
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
    assert_eq!(package_role, None);
    assert!(common.packages.iter().all(|package| {
        package.verification_status == CompositionPackageVerificationStatusV1::NotChecked
    }));

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
    configure_hbc_carrier(
        &mut version,
        CompositionRole::App,
        0,
        &manifest_engine,
        95,
        0x1F1903C103BC1FC6_u64.to_le_bytes().to_vec(),
    );
    assert_refusal(
        version.run_with_engine(Some(manifest_engine.clone())),
        3,
        CompositionRefusalCode::IbexEngineBindingMismatch,
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
fn a2_crossing_external_defining_principals_refuses_row_34() {
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
