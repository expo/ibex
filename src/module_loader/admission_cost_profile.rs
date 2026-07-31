//! Measurement-only cost profile for committed-publication admission at
//! blog scale (Exact LLP 0413 Phase 3: 51 carriers / 545 records admit in
//! ~166 ms on-device and admission is now the dominant prepared-startup
//! phase, byte-identical between JS and HBC carrier encodings).
//!
//! This module is `#[cfg(test)]`-only and changes NO production semantics:
//! it builds synthetic-but-admissible publications shaped like the Exact
//! adapter-1 blog publication (CommonJS compat-loader records, one shared
//! transform fingerprint, per-record source maps sized to match the real
//! ~7.5 MB index), runs the REAL `admit_committed_publication_v1`
//! end-to-end, and separately times the same verification building blocks
//! (strict JSON parse, JCS re-canonicalization + byte compare, sha256
//! digests, per-record semantic-digest recomputes, authorized-set clones)
//! on the same inputs so the end-to-end cost can be attributed.
//!
//! Every refusal row stays byte-for-byte owned by the production code
//! under test; the profile never re-implements an admission decision.
//! @ref LLP 0042#committed-admission-algorithm — the phases timed here are
//! exactly the algorithm steps 1-5 (+ posture step 6)
//!
//! Run:
//!   cargo test --release admission_cost_profile -- --ignored --nocapture
//! (HERMES_* env as for any ibex-runtime build.)

use std::time::{Duration, Instant};

use super::super::artifact::{
    semantics_digest, source_integrity, CanonicalSourceId, CommonJsExportsV1, ModulePayloadV1,
    ModuleSemanticsV1, ProducerIdentityV1, SourceDialectV1, SourceGoalV1, SourceMapV1,
    TransformFingerprintV1, MODULE_ARTIFACT_FACTORY_DOMAIN_V1, MODULE_ARTIFACT_SEMANTIC_DOMAIN_V1,
};
use super::super::carrier::PREPARED_CARRIER_BYTES_DOMAIN_V1;
use super::*;

const PROFILE_PRODUCER_ID: &str = "exact-vite-adapter-1-profile";
const PROFILE_BYTECODE_VERSION: u32 = 99;

fn digest(label: &str) -> Digest {
    digest_bytes("admission-cost-profile", label.as_bytes()).unwrap()
}

fn non_empty(value: &str) -> NonEmptyString {
    NonEmptyString::new(value).unwrap()
}

struct Shape {
    name: &'static str,
    carriers: usize,
    records: usize,
    /// Source-map `mappings` bytes per record (the index-size driver).
    mapping_bytes: usize,
    /// Factory source bytes per record (the JS-carrier-size driver).
    factory_bytes: usize,
    hbc: bool,
}

/// Records per non-root carrier; the root carrier absorbs the remainder,
/// mirroring the blog publication's large root-app carrier.
fn package_carrier_records(shape: &Shape) -> usize {
    (shape.records / (shape.carriers * 2)).max(1)
}

fn shared_fingerprint() -> TransformFingerprintV1 {
    TransformFingerprintV1 {
        producer: non_empty(PROFILE_PRODUCER_ID),
        parser_version: non_empty("1"),
        transform_version: non_empty("8"),
        hermes_target: non_empty("hermes-1.0"),
        typescript_jsx_options_digest: digest("jsx-options"),
        module_runner_abi: non_empty("exact-compat-loader-cjs-8"),
        hermes_compat_version: non_empty("1"),
        commonjs_detector: non_empty("cjs-module-lexer"),
        commonjs_detector_version: non_empty("1.4.3"),
        output_options_digest: digest("output-options"),
    }
}

fn record_semantics(
    source_id: &SourceId,
    factory_source: &str,
    mapping_bytes: usize,
) -> ModuleSemanticsV1 {
    // Compat-loader CJS record shape: require edges + detector output, no
    // ESM descriptors, VLQ-alphabet mappings sized like real Vite output.
    const MAPPING_PATTERN: &str = "AACA,QAASA,SAAS,EAAG;";
    let mappings = MAPPING_PATTERN.repeat(mapping_bytes / MAPPING_PATTERN.len() + 1)
        [..mapping_bytes]
        .to_owned();
    ModuleSemanticsV1 {
        source_id: CanonicalSourceId(source_id.clone()),
        source_goal: SourceGoalV1::CommonJs,
        dialect: Some(SourceDialectV1::Js),
        source_integrity: source_integrity(factory_source.as_bytes()).unwrap(),
        transform_fingerprint: shared_fingerprint(),
        static_edges: vec![
            StaticEdgeV1::CommonJsRequire {
                specifier: non_empty("./dep-a.js"),
            },
            StaticEdgeV1::CommonJsRequire {
                specifier: non_empty("./dep-b.js"),
            },
            StaticEdgeV1::CommonJsRequire {
                specifier: non_empty("react"),
            },
        ],
        dynamic_edges: Vec::new(),
        export_descriptors: Vec::new(),
        commonjs_exports: Some(CommonJsExportsV1 {
            detector: non_empty("cjs-module-lexer"),
            detector_version: non_empty("1.4.3"),
            names: vec![non_empty("default"), non_empty("named")],
            reexports: Vec::new(),
        }),
        has_top_level_await: false,
        factory_digest: digest_bytes(MODULE_ARTIFACT_FACTORY_DOMAIN_V1, factory_source.as_bytes())
            .unwrap(),
        source_map: SourceMapV1 {
            version: 3,
            source_ids: vec![CanonicalSourceId(source_id.clone())],
            names: Vec::new(),
            mappings,
        },
    }
}

struct BuiltPublication {
    commitment: PreparedGraphCommitmentV1,
    engine: CommittedHbcEngineExpectationV1,
    index_bytes_len: usize,
    manifest_bytes_len: usize,
    carrier_bytes_len: usize,
}

/// Write an admissible publication into `dir` and return the commitment it
/// verifies against. All records share one root principal (principal-facet
/// cost is negligible against record/carrier verification and this keeps
/// the builder free of package-locator plumbing).
fn build_publication(dir: &Path, shape: &Shape) -> BuiltPublication {
    let owner = Principal::Root {
        identity: non_empty("blog-profile-app"),
    };
    let producer_id = non_empty(PROFILE_PRODUCER_ID);
    let producer_binary_digest = digest("producer-binary");
    let deployment_graph_digest = digest("deployment-graph");
    let engine_binding = PreparedCarrierEngineBindingV2::LoadedFile {
        binary_digest: digest("loaded-hermes-engine"),
    };

    let per_package = package_carrier_records(shape);
    let root_records = shape.records - per_package * (shape.carriers - 1);
    assert!(
        root_records >= 1,
        "shape leaves no records for the root carrier"
    );

    let mut index_records = Vec::with_capacity(shape.records);
    let mut index_carriers = Vec::with_capacity(shape.carriers);
    let mut entry_source_id: Option<SourceId> = None;
    let mut manifest_bytes_len = 0usize;
    let mut carrier_bytes_len = 0usize;

    for carrier_index in 0..shape.carriers {
        let record_count = if carrier_index == 0 {
            root_records
        } else {
            per_package
        };
        // Build the member artifacts (inline, in-process producer) that the
        // carrier table is generated from.
        let mut members = Vec::with_capacity(record_count);
        for member in 0..record_count {
            let source_id = SourceId::file(
                owner.clone(),
                vec![
                    PathComponent::utf8("src").unwrap(),
                    PathComponent::utf8(format!("c{carrier_index:02}")).unwrap(),
                    PathComponent::utf8(format!("m{member:04}.js")).unwrap(),
                ],
            )
            .unwrap();
            if entry_source_id.is_none() {
                entry_source_id = Some(source_id.clone());
            }
            let padding = "x".repeat(shape.factory_bytes);
            let factory_source = format!(
                "function(require,module,exports,__filename,__dirname,__ibexDynamicImport){{/*{padding}*/}}"
            );
            let semantics = record_semantics(&source_id, &factory_source, shape.mapping_bytes);
            let artifact = ModuleArtifactV1::new_inline(
                semantics,
                factory_source,
                ProducerIdentityV1::InProcess {
                    producer_id: producer_id.clone(),
                    producer_binary_digest: producer_binary_digest.clone(),
                },
            )
            .unwrap();
            members.push((non_empty(&format!("e{member:04}")), artifact));
        }
        let verified = members
            .iter()
            .map(|(entry_id, artifact)| {
                (
                    entry_id.clone(),
                    artifact
                        .verify_for_admission(&ArtifactAdmissionV1::TrustedInProcess {
                            expected_source_id: artifact.semantics.source_id.0.clone(),
                            expected_source_integrity: artifact.semantics.source_integrity.clone(),
                            expected_producer_id: producer_id.clone(),
                            producer_binary_digest: producer_binary_digest.clone(),
                            transform_fingerprint_digest: artifact
                                .semantics
                                .transform_fingerprint
                                .digest()
                                .unwrap(),
                        })
                        .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let (js_manifest, js_bytes) = PreparedModuleCarrierV2::from_inline_artifacts(
            owner.clone(),
            producer_id.clone(),
            producer_binary_digest.clone(),
            deployment_graph_digest.clone(),
            verified,
        )
        .unwrap();
        let (manifest, bytes) = if shape.hbc {
            // Fabricated Hermes bytecode: admission inspects only the v1
            // header (magic, version, file length) plus the byte digest, so
            // header + padding exercises the identical verification work as
            // compiled bytecode of the same size (~10.5 KB/module mirrors
            // the blog's 5.74 MB over 545 records).
            let len = 128 + record_count * 10_500;
            let mut hbc = vec![0u8; len];
            hbc[0..8].copy_from_slice(&0x1F19_03C1_03BC_1FC6u64.to_le_bytes());
            hbc[8..12].copy_from_slice(&PROFILE_BYTECODE_VERSION.to_le_bytes());
            hbc[32..36].copy_from_slice(&(len as u32).to_le_bytes());
            let manifest = js_manifest
                .bind_hermes_bytecode(&hbc, engine_binding.clone())
                .unwrap();
            (manifest, hbc)
        } else {
            (js_manifest, js_bytes)
        };

        for (member, (entry_id, artifact)) in members.iter().enumerate() {
            let source_id = artifact.semantics.source_id.0.clone();
            // Typed require bindings to sibling records, like the real
            // publication's resolved edges (targets only feed BTreeMap
            // assembly; admission does not chase them).
            let target_member = (member + 1) % record_count;
            let target = SourceId::file(
                owner.clone(),
                vec![
                    PathComponent::utf8("src").unwrap(),
                    PathComponent::utf8(format!("c{carrier_index:02}")).unwrap(),
                    PathComponent::utf8(format!("m{target_member:04}.js")).unwrap(),
                ],
            )
            .unwrap();
            let bindings = ["./dep-a.js", "./dep-b.js", "react"]
                .into_iter()
                .map(|specifier| PreparedGraphBindingV1 {
                    specifier: specifier.to_owned(),
                    resolution_kind: ResolutionKind::CommonJsRequire,
                    target: target.clone(),
                })
                .collect();
            let carrier_artifact = ModuleArtifactV1::new_carrier(
                artifact.semantics.clone(),
                manifest.carrier_digest.clone(),
                entry_id.clone(),
                ProducerIdentityV1::Prepared {
                    producer_id: producer_id.clone(),
                    producer_binary_digest: producer_binary_digest.clone(),
                    deployment_graph_digest: deployment_graph_digest.clone(),
                },
            )
            .unwrap();
            index_records.push(PreparedGraphRecordIndexV1 {
                source_id,
                bindings,
                artifact: carrier_artifact,
                carrier_index,
                entry_id: entry_id.clone(),
            });
        }

        let manifest_file = format!("carrier-{carrier_index:03}.manifest.json");
        let bytes_file = format!(
            "carrier-{carrier_index:03}.{}",
            if shape.hbc { "hbc" } else { "js" }
        );
        let manifest_bytes = manifest.encode_canonical().unwrap();
        manifest_bytes_len += manifest_bytes.len();
        carrier_bytes_len += bytes.len();
        std::fs::write(dir.join(&manifest_file), &manifest_bytes).unwrap();
        std::fs::write(dir.join(&bytes_file), &bytes).unwrap();
        index_carriers.push(PreparedGraphCarrierIndexV1 {
            manifest_file,
            bytes_file,
        });
    }

    let index = PreparedGraphIndexV2 {
        schema: PREPARED_GRAPH_INDEX_SCHEMA_V2.to_owned(),
        entry: entry_source_id.clone().unwrap(),
        producer_binary_digest: producer_binary_digest.clone(),
        deployment_graph_digest: deployment_graph_digest.clone(),
        records: index_records,
        carriers: index_carriers,
        candidate_tables: Vec::new(),
    };
    let index_value = serde_json::to_value(&index).unwrap();
    let index_bytes = capsec_semantics::canonical::to_jcs_bytes(&index_value).unwrap();
    std::fs::write(dir.join("index.json"), &index_bytes).unwrap();

    let (semantic_inventory, principal_set, _, _) = prepared_commitment_facets(&index).unwrap();
    let commitment = PreparedGraphCommitmentV1 {
        schema: "ibex/prepared-graph-commitment/1".to_owned(),
        workflow: "admission-cost-profile".to_owned(),
        target: "dev".to_owned(),
        entry_source_id: non_empty(&entry_source_id.unwrap().encode().unwrap()),
        deployment_graph_digest,
        publication_root_digest: digest_bytes(PREPARED_PUBLICATION_ROOT_DOMAIN_V1, &index_bytes)
            .unwrap(),
        producer: capsec_semantics::arming::PreparedGraphProducerV1 {
            id: producer_id,
            binary_digest: producer_binary_digest,
        },
        semantic_inventory_digest: semantic_inventory,
        principal_set_digest: principal_set,
        policy_digest: digest("policy"),
    };
    BuiltPublication {
        commitment,
        engine: CommittedHbcEngineExpectationV1 {
            engine_binding,
            bytecode_version: PROFILE_BYTECODE_VERSION,
        },
        index_bytes_len: index_bytes.len(),
        manifest_bytes_len,
        carrier_bytes_len,
    }
}

#[derive(Default)]
struct Breakdown {
    io_index: Duration,
    io_manifests: Duration,
    io_carriers: Duration,
    index_parse_strict: Duration,
    index_jcs_recanonicalize: Duration,
    index_root_sha256: Duration,
    index_typed_decode: Duration,
    commitment_facets: Duration,
    file_inventory: Duration,
    carrier_encoding_peek: Duration,
    manifest_parse_strict: Duration,
    manifest_jcs_recanonicalize: Duration,
    manifest_typed_decode: Duration,
    carrier_bytes_sha256: Duration,
    carrier_entry_semantics_to_value: Duration,
    carrier_entry_semantics_jcs: Duration,
    carrier_entry_semantics_sha256: Duration,
    carrier_authorized_membership: Duration,
    carrier_bytes_copy: Duration,
    record_fingerprint_digest_admission: Duration,
    record_fingerprint_digest_verify: Duration,
    record_semantics_digest_validate: Duration,
    record_verify_other: Duration,
    authorized_set_clones: Duration,
    record_assembly: Duration,
}

struct BreakdownCounts {
    sha256_bytes: usize,
    sha256_calls: usize,
    jcs_bytes: usize,
    digest_clones: usize,
}

/// Time the real building blocks of `admit_committed_publication_v1` on the
/// same inputs, in the same order, using the same production functions. The
/// decisions themselves stay owned by the production path (which the
/// end-to-end cell runs unmodified); this pass only attributes its cost.
fn measure_breakdown(
    dir: &Path,
    built: &BuiltPublication,
    hbc: bool,
) -> (Breakdown, BreakdownCounts) {
    let mut b = Breakdown::default();
    let mut sha256_bytes = 0usize;
    let mut sha256_calls = 0usize;
    let mut jcs_bytes = 0usize;
    let mut digest_clones = 0usize;

    // Index: read, strict parse, JCS re-canonicalize + compare, root digest,
    // typed decode.
    let t = Instant::now();
    let index_bytes = read_bounded_prepared_file(
        &dir.join("index.json"),
        MAX_PREPARED_INDEX_BYTES_V1,
        "graph index",
    )
    .unwrap();
    b.io_index = t.elapsed();

    let text = std::str::from_utf8(&index_bytes).unwrap();
    let t = Instant::now();
    let value = capsec_semantics::strict_json::parse_strict(text).unwrap();
    b.index_parse_strict = t.elapsed();

    let t = Instant::now();
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&value).unwrap();
    assert!(canonical == index_bytes);
    b.index_jcs_recanonicalize = t.elapsed();
    jcs_bytes += canonical.len();

    let t = Instant::now();
    let observed_root = digest_bytes(PREPARED_PUBLICATION_ROOT_DOMAIN_V1, &index_bytes).unwrap();
    b.index_root_sha256 = t.elapsed();
    assert!(observed_root == built.commitment.publication_root_digest);
    sha256_bytes += index_bytes.len();
    sha256_calls += 1;

    let t = Instant::now();
    let index: PreparedGraphIndexV2 = serde_json::from_value(value).unwrap();
    b.index_typed_decode = t.elapsed();

    let t = Instant::now();
    let (_, _, authorized, _) = prepared_commitment_facets(&index).unwrap();
    let authorized = Arc::new(authorized);
    b.commitment_facets = t.elapsed();

    let t = Instant::now();
    let expected_files = committed_publication_files(&index).unwrap();
    let mut actual_files = BTreeSet::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        actual_files.insert(entry.unwrap().file_name().into_string().unwrap());
    }
    assert!(actual_files == expected_files);
    b.file_inventory = t.elapsed();

    // Carriers.
    for carrier in &index.carriers {
        let t = Instant::now();
        let manifest_bytes = read_bounded_prepared_file(
            &dir.join(&carrier.manifest_file),
            MAX_PREPARED_MANIFEST_BYTES_V1,
            "carrier manifest",
        )
        .unwrap();
        b.io_manifests += t.elapsed();
        let t = Instant::now();
        let carrier_bytes = read_bounded_prepared_file(
            &dir.join(&carrier.bytes_file),
            MAX_PREPARED_CARRIER_BYTES_V1,
            "carrier bytes",
        )
        .unwrap();
        b.io_carriers += t.elapsed();

        // Phase 3 encoding peek: a full serde_json Value parse per manifest.
        let t = Instant::now();
        let declares_hbc = serde_json::from_slice::<serde_json::Value>(&manifest_bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("encoding")
                    .and_then(|encoding| encoding.get("kind"))
                    .and_then(serde_json::Value::as_str)
                    .map(|kind| kind == "hermes-bytecode")
            })
            .unwrap_or(false);
        b.carrier_encoding_peek += t.elapsed();
        assert_eq!(declares_hbc, hbc);

        let text = std::str::from_utf8(&manifest_bytes).unwrap();
        let t = Instant::now();
        let value = capsec_semantics::strict_json::parse_strict(text).unwrap();
        b.manifest_parse_strict += t.elapsed();

        let t = Instant::now();
        let canonical = capsec_semantics::canonical::to_jcs_bytes(&value).unwrap();
        assert!(canonical == manifest_bytes);
        b.manifest_jcs_recanonicalize += t.elapsed();
        jcs_bytes += canonical.len();

        let t = Instant::now();
        let manifest: PreparedModuleCarrierV2 = serde_json::from_value(value).unwrap();
        b.manifest_typed_decode += t.elapsed();

        // manifest.validate(): carrier-bytes digest + per-entry semantic
        // digest recompute (split into its three stages).
        let t = Instant::now();
        let observed = digest_bytes(PREPARED_CARRIER_BYTES_DOMAIN_V1, &carrier_bytes).unwrap();
        b.carrier_bytes_sha256 += t.elapsed();
        assert!(observed == manifest.carrier_digest);
        sha256_bytes += carrier_bytes.len();
        sha256_calls += 1;

        for entry in &manifest.entries {
            let t = Instant::now();
            let semantics_value = serde_json::to_value(&entry.semantics).unwrap();
            b.carrier_entry_semantics_to_value += t.elapsed();
            let t = Instant::now();
            let semantics_canonical =
                capsec_semantics::canonical::to_jcs_bytes(&semantics_value).unwrap();
            b.carrier_entry_semantics_jcs += t.elapsed();
            jcs_bytes += semantics_canonical.len();
            let t = Instant::now();
            let observed =
                digest_bytes(MODULE_ARTIFACT_SEMANTIC_DOMAIN_V1, &semantics_canonical).unwrap();
            b.carrier_entry_semantics_sha256 += t.elapsed();
            sha256_bytes += semantics_canonical.len();
            sha256_calls += 1;
            assert!(observed == entry.semantic_digest);

            let t = Instant::now();
            assert!(authorized.contains(&entry.semantic_digest));
            b.carrier_authorized_membership += t.elapsed();
        }

        // decode_and_admit's terminal owned-bytes copy.
        let t = Instant::now();
        let copied = carrier_bytes.clone();
        b.carrier_bytes_copy += t.elapsed();
        std::hint::black_box(&copied);

        // Per-carrier admission shares the authorized set (Arc bump since
        // M2 item 6; previously a full BTreeSet clone of every digest).
        let t = Instant::now();
        let cloned = Arc::clone(&authorized);
        b.authorized_set_clones += t.elapsed();
        digest_clones += 1;
        std::hint::black_box(&cloned);
    }

    // Records.
    let producer_id = built.commitment.producer.id.clone();
    for indexed in &index.records {
        // Admission-side fingerprint digest (built into DigestBoundPrepared).
        let t = Instant::now();
        let fp = indexed
            .artifact
            .semantics
            .transform_fingerprint
            .digest()
            .unwrap();
        b.record_fingerprint_digest_admission += t.elapsed();
        sha256_calls += 1;

        // Per-record admission shares the authorized set (Arc bump).
        let t = Instant::now();
        let cloned = Arc::clone(&authorized);
        b.authorized_set_clones += t.elapsed();
        digest_clones += 1;

        let admission = ArtifactAdmissionV1::DigestBoundPrepared {
            expected_source_id: indexed.source_id.clone(),
            expected_source_integrity: indexed.artifact.semantics.source_integrity.clone(),
            expected_producer_id: producer_id.clone(),
            producer_binary_digest: built.commitment.producer.binary_digest.clone(),
            deployment_graph_digest: built.commitment.deployment_graph_digest.clone(),
            expected_carrier_digest: match &indexed.artifact.payload {
                ModulePayloadV1::Carrier { carrier_digest, .. } => carrier_digest.clone(),
                ModulePayloadV1::Inline { .. } => unreachable!(),
            },
            expected_entry_id: indexed.entry_id.clone(),
            authorized_semantic_digests: cloned,
            transform_fingerprint_digest: fp,
        };

        // Full verify_for_admission (validate_structure recomputes the
        // semantic digest once, then the fingerprint digest is recomputed
        // once); time the two recomputes in isolation on the same input and
        // attribute them out of the verify total so nothing double-counts.
        let t = Instant::now();
        indexed.artifact.verify_for_admission(&admission).unwrap();
        let verify_total = t.elapsed();
        let t = Instant::now();
        let _ = semantics_digest(&indexed.artifact.semantics).unwrap();
        let inner_semantics = t.elapsed();
        let t = Instant::now();
        let _ = indexed
            .artifact
            .semantics
            .transform_fingerprint
            .digest()
            .unwrap();
        let inner_fp = t.elapsed();
        b.record_fingerprint_digest_verify += inner_fp;
        b.record_verify_other += verify_total.saturating_sub(inner_semantics + inner_fp);
        // verify_for_admission itself runs both recomputes; account them in
        // their buckets rather than double-counting under "other".
        b.record_semantics_digest_validate += inner_semantics;
        sha256_calls += 2; // the semantic + fingerprint recomputes inside verify

        // Record assembly: typed-binding map + display identity + path.
        let t = Instant::now();
        let mut bindings = BTreeMap::new();
        for binding in &indexed.bindings {
            bindings.insert(
                GraphEdgeKey::new(binding.specifier.clone(), binding.resolution_kind),
                binding.target.clone(),
            );
        }
        let _display = portable_record_display(&indexed.source_id).unwrap();
        b.record_assembly += t.elapsed();
        std::hint::black_box(&bindings);
    }

    (
        b,
        BreakdownCounts {
            sha256_bytes,
            sha256_calls,
            jcs_bytes,
            digest_clones,
        },
    )
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

fn run_cell(shape: &Shape) {
    let dir = tempfile::tempdir().unwrap();
    let project_root = tempfile::tempdir().unwrap();
    let built = build_publication(dir.path(), shape);
    let engine = if shape.hbc { Some(&built.engine) } else { None };

    // Warm pass (also proves the fixture admits green through the REAL path).
    let admitted = admit_committed_publication_v1(
        dir.path(),
        &built.commitment,
        project_root.path(),
        CommittedFingerprintPosture::DevVouchedIndexExternalProducer,
        engine,
    )
    .unwrap();
    assert_eq!(admitted.records.len(), shape.records);
    assert_eq!(admitted.carrier_count, shape.carriers);
    drop(admitted);

    let samples = (0..5)
        .map(|_| {
            let t = Instant::now();
            let admitted = admit_committed_publication_v1(
                dir.path(),
                &built.commitment,
                project_root.path(),
                CommittedFingerprintPosture::DevVouchedIndexExternalProducer,
                engine,
            )
            .unwrap();
            let elapsed = t.elapsed();
            std::hint::black_box(&admitted);
            elapsed
        })
        .collect::<Vec<_>>();
    let end_to_end = median(samples.clone());

    let (b, counts) = measure_breakdown(dir.path(), &built, shape.hbc);

    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    let component_sum = ms(b.io_index)
        + ms(b.io_manifests)
        + ms(b.io_carriers)
        + ms(b.index_parse_strict)
        + ms(b.index_jcs_recanonicalize)
        + ms(b.index_root_sha256)
        + ms(b.index_typed_decode)
        + ms(b.commitment_facets)
        + ms(b.file_inventory)
        + ms(b.carrier_encoding_peek)
        + ms(b.manifest_parse_strict)
        + ms(b.manifest_jcs_recanonicalize)
        + ms(b.manifest_typed_decode)
        + ms(b.carrier_bytes_sha256)
        + ms(b.carrier_entry_semantics_to_value)
        + ms(b.carrier_entry_semantics_jcs)
        + ms(b.carrier_entry_semantics_sha256)
        + ms(b.carrier_authorized_membership)
        + ms(b.carrier_bytes_copy)
        + ms(b.record_fingerprint_digest_admission)
        + ms(b.record_fingerprint_digest_verify)
        + ms(b.record_semantics_digest_validate)
        + ms(b.record_verify_other)
        + ms(b.authorized_set_clones)
        + ms(b.record_assembly);

    eprintln!();
    eprintln!(
        "=== cell {} carriers={} records={} encoding={} mapping_bytes={} ===",
        shape.name,
        shape.carriers,
        shape.records,
        if shape.hbc {
            "hermes-bytecode"
        } else {
            "javascript-factory-table"
        },
        shape.mapping_bytes,
    );
    eprintln!(
        "files: index={:.2}MB manifests={:.2}MB carriers={:.2}MB",
        built.index_bytes_len as f64 / 1e6,
        built.manifest_bytes_len as f64 / 1e6,
        built.carrier_bytes_len as f64 / 1e6,
    );
    eprintln!(
        "end-to-end admit_committed_publication_v1: median {:.1}ms (samples: {})",
        ms(end_to_end),
        samples
            .iter()
            .map(|s| format!("{:.1}", ms(*s)))
            .collect::<Vec<_>>()
            .join(" "),
    );
    let row = |label: &str, d: Duration| {
        eprintln!(
            "  {label:<44} {:>9.2}ms {:>5.1}%",
            ms(d),
            100.0 * ms(d) / ms(end_to_end)
        );
    };
    eprintln!("component attribution (same production functions, same inputs):");
    row("io: index read", b.io_index);
    row("io: manifest reads", b.io_manifests);
    row("io: carrier-bytes reads", b.io_carriers);
    row("index: strict-JSON parse", b.index_parse_strict);
    row(
        "index: JCS re-canonicalize + compare",
        b.index_jcs_recanonicalize,
    );
    row("index: root sha256", b.index_root_sha256);
    row("index: typed decode (from_value)", b.index_typed_decode);
    row("index: commitment facets", b.commitment_facets);
    row("index: file inventory", b.file_inventory);
    row(
        "carriers: encoding peek (Value parse)",
        b.carrier_encoding_peek,
    );
    row(
        "carriers: manifest strict-JSON parse",
        b.manifest_parse_strict,
    );
    row(
        "carriers: manifest JCS re-canon + compare",
        b.manifest_jcs_recanonicalize,
    );
    row("carriers: manifest typed decode", b.manifest_typed_decode);
    row("carriers: bytes sha256", b.carrier_bytes_sha256);
    row(
        "carriers: entry semantics serde to_value",
        b.carrier_entry_semantics_to_value,
    );
    row(
        "carriers: entry semantics JCS",
        b.carrier_entry_semantics_jcs,
    );
    row(
        "carriers: entry semantics sha256",
        b.carrier_entry_semantics_sha256,
    );
    row(
        "carriers: authorized-digest membership",
        b.carrier_authorized_membership,
    );
    row("carriers: owned-bytes copy (to_vec)", b.carrier_bytes_copy);
    row(
        "records: fingerprint digest (admission)",
        b.record_fingerprint_digest_admission,
    );
    row(
        "records: fingerprint digest (verify, 2nd)",
        b.record_fingerprint_digest_verify,
    );
    row(
        "records: semantics digest (validate)",
        b.record_semantics_digest_validate,
    );
    row("records: verify residual (compares)", b.record_verify_other);
    row(
        "authorized-set clones (records+carriers)",
        b.authorized_set_clones,
    );
    row("records: assembly (bindings/display)", b.record_assembly);
    eprintln!(
        "  {:<44} {component_sum:>9.2}ms ({:.1}% of end-to-end; remainder = untimed moves/allocs)",
        "sum(components)",
        100.0 * component_sum / ms(end_to_end)
    );
    eprintln!(
        "counts: sha256 over {:.2}MB in {} calls; JCS-encoded {:.2}MB; authorized-set shares {}",
        counts.sha256_bytes as f64 / 1e6,
        counts.sha256_calls,
        counts.jcs_bytes as f64 / 1e6,
        counts.digest_clones,
    );
}

/// Fast fixture-fidelity gate (runs in the normal suite): the synthetic
/// publication admits green through the real path in both encodings, and a
/// single flipped carrier byte still refuses.
#[test]
fn admission_cost_profile_fixture_admits_and_refuses_tamper() {
    for hbc in [false, true] {
        let shape = Shape {
            name: "smoke",
            carriers: 3,
            records: 12,
            mapping_bytes: 256,
            factory_bytes: 256,
            hbc,
        };
        let dir = tempfile::tempdir().unwrap();
        let project_root = tempfile::tempdir().unwrap();
        let built = build_publication(dir.path(), &shape);
        let engine = if hbc { Some(&built.engine) } else { None };
        let admitted = admit_committed_publication_v1(
            dir.path(),
            &built.commitment,
            project_root.path(),
            CommittedFingerprintPosture::DevVouchedIndexExternalProducer,
            engine,
        )
        .unwrap();
        assert_eq!(admitted.records.len(), 12);
        assert_eq!(admitted.carrier_count, 3);

        // Single-byte tamper in carrier bytes refuses (digest mismatch).
        let bytes_file = dir.path().join(if hbc {
            "carrier-001.hbc"
        } else {
            "carrier-001.js"
        });
        let mut bytes = std::fs::read(&bytes_file).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&bytes_file, &bytes).unwrap();
        let refused = admit_committed_publication_v1(
            dir.path(),
            &built.commitment,
            project_root.path(),
            CommittedFingerprintPosture::DevVouchedIndexExternalProducer,
            engine,
        );
        let Err(error) = refused else {
            panic!("tampered carrier bytes must refuse admission");
        };
        assert!(error
            .to_string()
            .contains("do not match the manifest digest"));
    }
}

/// Decode the published index, apply a "lying producer" mutation, republish
/// it canonically, and return a commitment recomputed over the mutated
/// index (root digest + facets), so admission proceeds past the
/// commitment-root check and the deeper carrier/record checks are the ones
/// under test.
fn republish_mutated_index(
    dir: &Path,
    base: &PreparedGraphCommitmentV1,
    mutate: impl FnOnce(&mut PreparedGraphIndexV2),
) -> PreparedGraphCommitmentV1 {
    let bytes = std::fs::read(dir.join("index.json")).unwrap();
    let mut index: PreparedGraphIndexV2 =
        serde_json::from_value(serde_json::from_slice(&bytes).unwrap()).unwrap();
    mutate(&mut index);
    let value = serde_json::to_value(&index).unwrap();
    let index_bytes = capsec_semantics::canonical::to_jcs_bytes(&value).unwrap();
    std::fs::write(dir.join("index.json"), &index_bytes).unwrap();
    let (semantic_inventory, principal_set, _, _) = prepared_commitment_facets(&index).unwrap();
    let mut commitment = base.clone();
    commitment.publication_root_digest =
        digest_bytes(PREPARED_PUBLICATION_ROOT_DOMAIN_V1, &index_bytes).unwrap();
    commitment.semantic_inventory_digest = semantic_inventory;
    commitment.principal_set_digest = principal_set;
    commitment
}

/// M2 item 2 REQUIRED adversarial fixtures: a publication whose index
/// records and carrier-manifest entries disagree about a module's
/// semantics/digest must refuse exactly as before the semantic-hint
/// recompute-skip landed, with the same diagnostics.
#[test]
fn admission_refuses_mismatched_duplicate_semantics() {
    let shape = Shape {
        name: "mismatched-duplicates",
        carriers: 3,
        records: 12,
        mapping_bytes: 256,
        factory_bytes: 256,
        hbc: false,
    };

    // (a) Two index records SWAP their declared semantic digests: every
    // digest stays in the authorized set and every carrier entry stays
    // self-consistent, so admission reaches the per-record artifact check —
    // the carrier-entry hint pair has equal semantics but a different
    // digest, must NOT skip, and the full recompute refuses.
    {
        let dir = tempfile::tempdir().unwrap();
        let project_root = tempfile::tempdir().unwrap();
        let built = build_publication(dir.path(), &shape);
        let commitment = republish_mutated_index(dir.path(), &built.commitment, |index| {
            let first = index.records[1].artifact.semantic_digest.clone();
            let second = index.records[2].artifact.semantic_digest.clone();
            index.records[1].artifact.semantic_digest = second;
            index.records[2].artifact.semantic_digest = first;
        });
        let refused = admit_committed_publication_v1(
            dir.path(),
            &commitment,
            project_root.path(),
            CommittedFingerprintPosture::DevVouchedIndexExternalProducer,
            None,
        );
        let Err(error) = refused else {
            panic!("swapped semantic digests must refuse admission");
        };
        assert!(
            error
                .to_string()
                .contains("ModuleArtifact semantic digest is stale or tampered"),
            "unexpected refusal: {error:#}"
        );
    }

    // (b) One index record's semantics diverge from its carrier entry with
    // a SELF-CONSISTENT recomputed digest: the carrier entry's digest is no
    // longer in the deployment set and carrier admission refuses before any
    // record-level hint exists.
    {
        let dir = tempfile::tempdir().unwrap();
        let project_root = tempfile::tempdir().unwrap();
        let built = build_publication(dir.path(), &shape);
        let commitment = republish_mutated_index(dir.path(), &built.commitment, |index| {
            let record = &mut index.records[1].artifact;
            record.semantics.source_map.mappings.push('A');
            record.semantic_digest = semantics_digest(&record.semantics).unwrap();
        });
        let refused = admit_committed_publication_v1(
            dir.path(),
            &commitment,
            project_root.path(),
            CommittedFingerprintPosture::DevVouchedIndexExternalProducer,
            None,
        );
        let Err(error) = refused else {
            panic!("index/manifest semantics divergence must refuse admission");
        };
        assert!(
            error
                .to_string()
                .contains("prepared carrier contains a module absent from the deployment graph"),
            "unexpected refusal: {error:#}"
        );
    }
}

/// Direct negatives for the hint API itself: a hint pair only skips the
/// recompute when BOTH the semantics and the declared digest match; every
/// mismatch recomputes and refuses a tampered artifact exactly like the
/// hintless path.
#[test]
fn semantic_hint_never_bypasses_a_tampered_digest() {
    let owner = Principal::Root {
        identity: non_empty("blog-profile-app"),
    };
    let source_id = SourceId::file(
        owner.clone(),
        vec![
            PathComponent::utf8("src").unwrap(),
            PathComponent::utf8("hint.js").unwrap(),
        ],
    )
    .unwrap();
    let semantics = record_semantics(&source_id, "function(){}", 64);
    let other_source_id = SourceId::file(
        owner,
        vec![
            PathComponent::utf8("src").unwrap(),
            PathComponent::utf8("other.js").unwrap(),
        ],
    )
    .unwrap();
    let other_semantics = record_semantics(&other_source_id, "function(){}", 64);

    let carrier_digest = digest("carrier-bytes");
    let mut artifact = ModuleArtifactV1::new_carrier(
        semantics.clone(),
        carrier_digest.clone(),
        non_empty("e0000"),
        ProducerIdentityV1::Prepared {
            producer_id: non_empty(PROFILE_PRODUCER_ID),
            producer_binary_digest: digest("producer-binary"),
            deployment_graph_digest: digest("deployment-graph"),
        },
    )
    .unwrap();
    // Tamper the declared digest to a different well-formed digest.
    let tampered_digest = digest("not-the-semantic-digest");
    artifact.semantic_digest = tampered_digest.clone();
    let admission = ArtifactAdmissionV1::DigestBoundPrepared {
        expected_source_id: artifact.semantics.source_id.0.clone(),
        expected_source_integrity: artifact.semantics.source_integrity.clone(),
        expected_producer_id: non_empty(PROFILE_PRODUCER_ID),
        producer_binary_digest: digest("producer-binary"),
        deployment_graph_digest: digest("deployment-graph"),
        expected_carrier_digest: carrier_digest,
        expected_entry_id: non_empty("e0000"),
        authorized_semantic_digests: Arc::new(BTreeSet::from([tampered_digest.clone()])),
        transform_fingerprint_digest: artifact.semantics.transform_fingerprint.digest().unwrap(),
    };

    let correct_digest = semantics_digest(&semantics).unwrap();
    for (hint_semantics, hint_digest) in [
        // Equal semantics, correct (non-declared) digest: digest mismatch.
        (&semantics, &correct_digest),
        // Different semantics, declared digest: semantics mismatch.
        (&other_semantics, &tampered_digest),
    ] {
        let refused = artifact.verify_for_admission_with_semantic_hint(
            &admission,
            Some((hint_semantics, hint_digest)),
        );
        assert!(
            refused.is_err()
                && refused
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("semantic digest is stale or tampered"),
            "hint must not bypass the tampered-digest refusal"
        );
    }
    // And the hintless path refuses identically.
    assert!(artifact
        .verify_for_admission(&admission)
        .err()
        .unwrap()
        .to_string()
        .contains("semantic digest is stale or tampered"));
}

/// The M1 measurement matrix. Ignored: run explicitly with
/// `cargo test --release admission_cost_profile -- --ignored --nocapture`.
#[test]
#[ignore = "measurement harness; run with --ignored --nocapture (Exact LLP 0413 Phase 3 admission cost)"]
fn admission_cost_profile_blog_scale_matrix() {
    // Blog shape today: 51 carriers / 545 records; index ~7.5 MB, HBC
    // carriers ~5.7 MB, JS carriers ~7.7 MB (Exact Phase 3 M2/M3 receipts).
    let cells = [
        Shape {
            name: "blog-hbc",
            carriers: 51,
            records: 545,
            mapping_bytes: 11_000,
            factory_bytes: 12_000,
            hbc: true,
        },
        Shape {
            name: "blog-js",
            carriers: 51,
            records: 545,
            mapping_bytes: 11_000,
            factory_bytes: 12_000,
            hbc: false,
        },
        // Exact's LLP 0128 graph diet target: fewer records, fewer carriers.
        Shape {
            name: "diet-250r-24c",
            carriers: 24,
            records: 250,
            mapping_bytes: 11_000,
            factory_bytes: 12_000,
            hbc: true,
        },
        // Scaling separators: record count vs carrier count.
        Shape {
            name: "scale-250r-51c",
            carriers: 51,
            records: 250,
            mapping_bytes: 11_000,
            factory_bytes: 12_000,
            hbc: true,
        },
        Shape {
            name: "scale-545r-4c",
            carriers: 4,
            records: 545,
            mapping_bytes: 11_000,
            factory_bytes: 12_000,
            hbc: true,
        },
        // Source-map sensitivity: what admission costs if mappings leave the
        // admission-time semantic payload.
        Shape {
            name: "blog-hbc-no-mappings",
            carriers: 51,
            records: 545,
            mapping_bytes: 0,
            factory_bytes: 12_000,
            hbc: true,
        },
    ];
    for shape in &cells {
        run_cell(shape);
    }
}
