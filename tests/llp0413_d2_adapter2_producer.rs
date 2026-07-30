//! Exact LLP 0413 §9.5 adapter-2 D2 measurement (Exact LLP 0416 Decision
//! record): drive IBEX'S OWN producer over the Vite-exposed target graph,
//! consuming AUTHENTICATED ORIGINAL modules, and emit real
//! `ibex/prepared-module-graph/2` publications at per-principal granularity.
//!
//! Adapter posture (Exact LLP 0413 §9.5 option 2): Vite exposes the target
//! graph (module identity, original file, optimizer-chunk-to-package mapping
//! — exported by the Exact repo's
//! `scripts/llp0413-d2-export-target-graph.mjs`); this driver reads the
//! ORIGINAL sources from disk and produces every artifact through
//! `produce_module_artifact_with_sites_v1` /
//! `produce_commonjs_artifact_with_sites_v1` / `produce_json_artifact_v1` —
//! the same oxc pipeline behind the native module runner — so the transform
//! fingerprint is ibex's own generated configuration and
//! `verify_current_transform_fingerprint_v1` holds by construction (the
//! check adapter-1 publications structurally fail).
//!
//! Gated on `EXACT_LLP0413_D2_TARGET_GRAPH_DIR` (the export root containing
//! `<lane>/target-graph.json`) and `EXACT_LLP0413_D2_OUT_DIR` (publication
//! output root, written as `<lane>/per-principal/publication/` so the
//! unchanged `llp0413_arms_ef_admission` harness can be pointed at it via
//! `EXACT_LLP0413_PUBLICATION_DIR`). Skips silently when unset so ibex CI is
//! unaffected.
//!
//! Bounded-measurement glue, deliberately recorded as findings rather than
//! hidden (Exact LLP 0416 §D2):
//! - the dependency require-closure walk (original package files reached
//!   from each optimizer-chunk's bare specifier) implements a minimal
//!   Node-style CJS resolution (relative joins + package `main`), because
//!   the Vite-exposed graph names only chunk OUTPUTS, not the original
//!   dependency module graph;
//! - the exported graph carries no per-specifier resolution table, so index
//!   records ship empty binding lists — specifier-level binding synthesis
//!   is exactly the Vite-owned resolution surface (aliases, platform
//!   suffixes, virtual modules) the §9.5 comparison is about;
//! - refusals (`.contract`, `.wasm`, quarantined syntax, unresolvable
//!   originals) EXCLUDE the module from the publication and are reported,
//!   mirroring adapter-1's honest-fallback posture.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use capsec_semantics::model::{Digest, NonEmptyString, PackageLocator, PathComponent, Principal};
use ibex_runtime::module_loader::artifact::{
    digest_bytes, source_integrity, ArtifactAdmissionV1, ModuleArtifactV1, StaticEdgeV1,
};
use ibex_runtime::module_loader::carrier::PreparedModuleCarrierV2;
use ibex_runtime::module_loader::identity::SourceId;
use ibex_runtime::module_loader::producer_spike::{
    produce_commonjs_artifact_with_sites_v1, produce_json_artifact_v1,
    produce_module_artifact_with_sites_v1, unsupported_module_runner_reason,
    verify_current_transform_fingerprint_v1,
};

/// Matches `PREPARED_GRAPH_PRODUCER_ID` in
/// `src/module_loader/runner_pipeline.rs` (private const; the wire string is
/// the contract).
const PREPARED_GRAPH_PRODUCER_ID: &str = "ibex-rolldown-module-preparer";
const IN_PROCESS_PRODUCER_ID: &str = "ibex-runtime-oxc";
const ROOT_PRINCIPAL_IDENTITY: &str = "exact-js-dev-root";
const D2_DEPLOYMENT_GRAPH_DOMAIN: &str = "exact:llp0413-d2-deployment-graph:1";
const D2_PRODUCER_BINARY_DOMAIN: &str = "exact:llp0413-d2-producer-binary:1";

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetGraph {
    schema: String,
    lane: String,
    entry_id: String,
    repo_root: String,
    node_modules_root: String,
    lane_module_count: usize,
    modules: Vec<TargetGraphModule>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TargetGraphModule {
    id: String,
    role: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    bare_specifier: Option<String>,
    #[serde(default)]
    src_file: Option<String>,
    #[serde(default)]
    package_name: Option<String>,
    #[serde(default)]
    package_dir: Option<String>,
    #[serde(default)]
    canonical_id: Option<String>,
    #[serde(default)]
    covered_by_closure_of: Option<Vec<String>>,
}

#[derive(Debug, serde::Serialize)]
struct Refusal {
    id: String,
    kind: String,
    error: String,
}

#[derive(Debug, Default, serde::Serialize)]
struct DriverReport {
    lane: String,
    arm: String,
    graph_module_count: usize,
    attempted: usize,
    produced: usize,
    refusals: Vec<Refusal>,
    tla_modules: Vec<String>,
    closure_roots: Vec<String>,
    closure_files_produced: usize,
    closure_unresolved: Vec<String>,
    produced_module_goal: usize,
    produced_commonjs_goal: usize,
    produced_json_goal: usize,
    produce_ms_total: f64,
    per_module_ms_min: f64,
    per_module_ms_median: f64,
    per_module_ms_max: f64,
    construct_ms_total: f64,
    carriers: usize,
    carrier_bytes_total: usize,
    manifest_bytes_total: usize,
    index_bytes: usize,
    jsx_classic_react_missing: Vec<String>,
    principal_table: Vec<(String, usize)>,
    dropped_bundler_helpers: Vec<String>,
    query_duplicates: Vec<String>,
}

struct ProducedModule {
    source_id: SourceId,
    artifact: ModuleArtifactV1,
    principal: Principal,
}

fn repo_relative_components(repo_root: &Path, file: &Path) -> Result<Vec<PathComponent>> {
    let relative = file
        .strip_prefix(repo_root)
        .with_context(|| format!("{} escapes the repo root", file.display()))?;
    relative
        .components()
        .map(|component| {
            PathComponent::utf8(
                component
                    .as_os_str()
                    .to_str()
                    .ok_or_else(|| anyhow!("non-UTF-8 path component"))?,
            )
            .map_err(anyhow::Error::msg)
        })
        .collect()
}

fn package_principal(package_dir: &Path) -> Result<(Principal, String)> {
    let package_json_path = package_dir.join("package.json");
    let package_json_text = std::fs::read_to_string(&package_json_path)
        .with_context(|| format!("read {}", package_json_path.display()))?;
    let package_json: serde_json::Value = serde_json::from_str(&package_json_text)?;
    let name = package_json["name"]
        .as_str()
        .ok_or_else(|| anyhow!("{} has no name", package_json_path.display()))?
        .to_owned();
    let version = package_json["version"].as_str().unwrap_or("0.0.0");
    let principal = Principal::Package {
        name: NonEmptyString::new(name.clone()).map_err(anyhow::Error::msg)?,
        // Dev-fixture provenance, mirroring the adapter-1 producer: the
        // digest of the resolved package.json bytes. Production integrity is
        // ibex's authenticated package provenance.
        integrity: source_integrity(package_json_text.as_bytes())?,
        locator: PackageLocator::new(format!("{name}@{version}")).map_err(anyhow::Error::msg)?,
    };
    Ok((principal, name))
}

/// Minimal Node-style CJS resolution for the dependency require-closure walk
/// (driver glue counted as a finding, not hidden machinery).
fn resolve_cjs_specifier(
    specifier: &str,
    current_dir: &Path,
    node_modules_root: &Path,
) -> Option<PathBuf> {
    fn probe(base: PathBuf) -> Option<PathBuf> {
        if base.is_file() {
            return Some(base);
        }
        let with_js = base.with_extension("js");
        if with_js.is_file() {
            return Some(with_js);
        }
        let index = base.join("index.js");
        if index.is_file() {
            return Some(index);
        }
        None
    }
    if specifier.starts_with("./") || specifier.starts_with("../") {
        let joined = current_dir.join(specifier);
        let normalized = normalize_path(&joined);
        return probe(normalized);
    }
    // Bare specifier: @scope/name[/subpath] or name[/subpath].
    let mut parts = specifier.splitn(if specifier.starts_with('@') { 3 } else { 2 }, '/');
    let package_name = if specifier.starts_with('@') {
        let scope = parts.next()?;
        let name = parts.next()?;
        format!("{scope}/{name}")
    } else {
        parts.next()?.to_owned()
    };
    let subpath = parts.next();
    let package_dir = node_modules_root.join(&package_name);
    match subpath {
        Some(subpath) => probe(package_dir.join(subpath)),
        None => {
            let package_json_text =
                std::fs::read_to_string(package_dir.join("package.json")).ok()?;
            let package_json: serde_json::Value = serde_json::from_str(&package_json_text).ok()?;
            let main = package_json["main"].as_str().unwrap_or("index.js");
            probe(package_dir.join(main))
        }
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            other => normalized.push(other),
        }
    }
    normalized
}

fn nearest_package_dir(file: &Path, node_modules_root: &Path) -> Result<PathBuf> {
    let relative = file
        .strip_prefix(node_modules_root)
        .with_context(|| format!("{} is not under node_modules", file.display()))?;
    let mut components = relative.components();
    let first = components
        .next()
        .ok_or_else(|| anyhow!("empty node_modules-relative path"))?
        .as_os_str()
        .to_str()
        .ok_or_else(|| anyhow!("non-UTF-8 package name"))?
        .to_owned();
    if first.starts_with('@') {
        let second = components
            .next()
            .ok_or_else(|| anyhow!("scoped package without a name"))?
            .as_os_str()
            .to_str()
            .ok_or_else(|| anyhow!("non-UTF-8 package name"))?
            .to_owned();
        Ok(node_modules_root.join(first).join(second))
    } else {
        Ok(node_modules_root.join(first))
    }
}

fn classify_refusal(error: &anyhow::Error) -> &'static str {
    if unsupported_module_runner_reason(error).is_some() {
        "hermes-syntax-quarantine"
    } else {
        "produce-refusal"
    }
}

/// JSX-authored module whose original source never binds `React`: under
/// ibex's pinned CLASSIC JSX runtime the factory references
/// `React.createElement`, which fails at evaluation. Static signal for the
/// §9.5 "one observable meaning" row (Vite's pipeline uses the AUTOMATIC
/// runtime via the exact jsx-dev-runtime shim).
fn jsx_classic_react_missing(original_source: &str, factory_source: &str) -> bool {
    factory_source.contains("React.createElement")
        && !original_source.contains("import React")
        && !original_source.contains("import * as React")
        && !original_source.contains("require(\"react\")")
        && !original_source.contains("require('react')")
}

fn produce_for_lane(
    graph: &TargetGraph,
    out_dir: &Path,
    producer_binary_digest: &Digest,
) -> Result<DriverReport> {
    let repo_root = PathBuf::from(&graph.repo_root);
    let node_modules_root = PathBuf::from(&graph.node_modules_root);
    let mut report = DriverReport {
        lane: graph.lane.clone(),
        arm: "per-principal".to_owned(),
        graph_module_count: graph.lane_module_count,
        ..DriverReport::default()
    };
    let construct_started = Instant::now();

    let root_principal = Principal::Root {
        identity: NonEmptyString::new(ROOT_PRINCIPAL_IDENTITY).map_err(anyhow::Error::msg)?,
    };
    let mut produced: Vec<ProducedModule> = Vec::new();
    let mut produce_samples_ms: Vec<f64> = Vec::new();
    let mut entry_source_id: Option<SourceId> = None;
    let mut visited_closure: BTreeSet<PathBuf> = BTreeSet::new();

    // --- first-party originals + plain node_modules files -----------------
    for module in &graph.modules {
        match module.role.as_str() {
            "first-party" | "dependency-file" => {}
            "dependency-entry" => continue,    // walked below
            "dependency-internal" => continue, // covered by the closure walk
            "bundler-helper" => {
                report.dropped_bundler_helpers.push(module.id.clone());
                continue;
            }
            "query-duplicate" => {
                report.query_duplicates.push(module.id.clone());
                continue;
            }
            other => bail!("unknown target-graph role {other}"),
        }
        report.attempted += 1;
        let file = PathBuf::from(
            module
                .file
                .as_ref()
                .ok_or_else(|| anyhow!("{} has no file", module.id))?,
        );
        let (principal, source_id) = if module.role == "dependency-file" {
            let package_dir = PathBuf::from(
                module
                    .package_dir
                    .as_ref()
                    .ok_or_else(|| anyhow!("{} has no packageDir", module.id))?,
            );
            let (principal, _) = package_principal(&package_dir)?;
            let components = file
                .strip_prefix(&package_dir)
                .with_context(|| format!("{} escapes its package dir", module.id))?
                .components()
                .map(|component| {
                    PathComponent::utf8(
                        component
                            .as_os_str()
                            .to_str()
                            .ok_or_else(|| anyhow!("non-UTF-8 path component"))?,
                    )
                    .map_err(anyhow::Error::msg)
                })
                .collect::<Result<Vec<_>>>()?;
            let source_id = SourceId::file(principal.clone(), components)?;
            (principal, source_id)
        } else {
            let components = repo_relative_components(&repo_root, &file)?;
            let source_id = SourceId::file(root_principal.clone(), components)?;
            (root_principal.clone(), source_id)
        };
        if module.id == graph.entry_id {
            entry_source_id = Some(source_id.clone());
        }
        let source = match std::fs::read_to_string(&file) {
            Ok(source) => source,
            Err(error) => {
                report.refusals.push(Refusal {
                    id: module.id.clone(),
                    kind: "unreadable-original".to_owned(),
                    error: error.to_string(),
                });
                continue;
            }
        };
        let extension = file
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let source_name = module.id.clone();
        let started = Instant::now();
        let result: Result<ModuleArtifactV1> = match extension.as_str() {
            "cjs" => produce_commonjs_artifact_with_sites_v1(
                source_id.clone(),
                &source_name,
                &file,
                &source,
                producer_binary_digest.clone(),
            )
            .map(|produced| {
                report.produced_commonjs_goal += 1;
                produced.artifact
            }),
            "json" => {
                produce_json_artifact_v1(source_id.clone(), &source, producer_binary_digest.clone())
                    .map(|artifact| {
                        report.produced_json_goal += 1;
                        artifact
                    })
            }
            _ => produce_module_artifact_with_sites_v1(
                source_id.clone(),
                &source_name,
                &file,
                &source,
                producer_binary_digest.clone(),
            )
            .map(|produced| {
                report.produced_module_goal += 1;
                produced.artifact
            }),
        };
        let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
        match result {
            Ok(artifact) => {
                produce_samples_ms.push(elapsed_ms);
                if artifact.semantics.has_top_level_await {
                    report.tla_modules.push(module.id.clone());
                }
                if let ibex_runtime::module_loader::artifact::ModulePayloadV1::Inline {
                    factory_source,
                    ..
                } = &artifact.payload
                {
                    if jsx_classic_react_missing(&source, factory_source) {
                        report.jsx_classic_react_missing.push(module.id.clone());
                    }
                }
                produced.push(ProducedModule {
                    source_id,
                    artifact,
                    principal,
                });
            }
            Err(error) => {
                report.refusals.push(Refusal {
                    id: module.id.clone(),
                    kind: classify_refusal(&error).to_owned(),
                    error: format!("{error:#}"),
                });
            }
        }
    }

    // --- dependency require-closure walk from each optimizer-chunk root ----
    let mut queue: Vec<PathBuf> = Vec::new();
    for module in &graph.modules {
        if module.role != "dependency-entry" {
            continue;
        }
        let src = PathBuf::from(
            module
                .src_file
                .as_ref()
                .ok_or_else(|| anyhow!("{} has no srcFile", module.id))?,
        );
        report.closure_roots.push(format!(
            "{} -> {}",
            module.bare_specifier.clone().unwrap_or_default(),
            src.display()
        ));
        queue.push(src);
    }
    while let Some(file) = queue.pop() {
        let file = normalize_path(&file);
        if !visited_closure.insert(file.clone()) {
            continue;
        }
        report.attempted += 1;
        let package_dir = nearest_package_dir(&file, &node_modules_root)?;
        let (principal, _) = package_principal(&package_dir)?;
        let components = file
            .strip_prefix(&package_dir)
            .with_context(|| format!("{} escapes its package dir", file.display()))?
            .components()
            .map(|component| {
                PathComponent::utf8(
                    component
                        .as_os_str()
                        .to_str()
                        .ok_or_else(|| anyhow!("non-UTF-8 path component"))?,
                )
                .map_err(anyhow::Error::msg)
            })
            .collect::<Result<Vec<_>>>()?;
        let source_id = SourceId::file(principal.clone(), components)?;
        let source = std::fs::read_to_string(&file)
            .with_context(|| format!("read original dependency module {}", file.display()))?;
        let source_name = file.display().to_string();
        let started = Instant::now();
        match produce_commonjs_artifact_with_sites_v1(
            source_id.clone(),
            &source_name,
            &file,
            &source,
            producer_binary_digest.clone(),
        ) {
            Ok(produced_artifact) => {
                let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
                produce_samples_ms.push(elapsed_ms);
                report.produced_commonjs_goal += 1;
                report.closure_files_produced += 1;
                let current_dir = file
                    .parent()
                    .ok_or_else(|| anyhow!("dependency module has no parent dir"))?;
                for edge in &produced_artifact.artifact.semantics.static_edges {
                    if let StaticEdgeV1::CommonJsRequire { specifier, .. } = edge {
                        match resolve_cjs_specifier(
                            specifier.as_str(),
                            current_dir,
                            &node_modules_root,
                        ) {
                            Some(target) => queue.push(target),
                            None => report.closure_unresolved.push(format!(
                                "{}: {}",
                                file.display(),
                                specifier.as_str()
                            )),
                        }
                    }
                }
                produced.push(ProducedModule {
                    source_id,
                    artifact: produced_artifact.artifact,
                    principal,
                });
            }
            Err(error) => {
                report.refusals.push(Refusal {
                    id: file.display().to_string(),
                    kind: classify_refusal(&error).to_owned(),
                    error: format!("{error:#}"),
                });
            }
        }
    }

    report.produced = produced.len();
    if !produce_samples_ms.is_empty() {
        let mut sorted = produce_samples_ms.clone();
        sorted.sort_by(|left, right| left.partial_cmp(right).expect("finite"));
        report.per_module_ms_min = sorted[0];
        report.per_module_ms_median = sorted[sorted.len() / 2];
        report.per_module_ms_max = sorted[sorted.len() - 1];
        report.produce_ms_total = sorted.iter().sum();
    }

    // --- dedupe identical semantic digests within one principal ------------
    let mut seen: BTreeSet<(Vec<u8>, String)> = BTreeSet::new();
    let mut unique: Vec<ProducedModule> = Vec::new();
    for module in produced {
        let key = (
            module
                .principal
                .canonical_order_key()
                .map_err(anyhow::Error::msg)?,
            module.artifact.semantic_digest.as_str().to_owned(),
        );
        if seen.insert(key) {
            unique.push(module);
        }
    }
    let produced = unique;

    // --- deployment-graph digest (dev-fixture domain, equality-only) -------
    let mut deployment_rows: Vec<serde_json::Value> = produced
        .iter()
        .map(|module| {
            Ok(serde_json::json!({
                "sourceId": module.source_id.encode()?,
                "sourceIntegrity": module.artifact.semantics.source_integrity.as_str(),
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    deployment_rows.sort_by_key(|row| row["sourceId"].as_str().unwrap_or_default().to_owned());
    let deployment_graph_digest = digest_bytes(
        D2_DEPLOYMENT_GRAPH_DOMAIN,
        &capsec_semantics::canonical::to_jcs_bytes(&serde_json::Value::Array(deployment_rows))
            .map_err(|error| anyhow!("deployment rows canonicalize: {error}"))?,
    )?;

    // --- group per principal and build carriers ----------------------------
    let producer_id =
        NonEmptyString::new(PREPARED_GRAPH_PRODUCER_ID).map_err(anyhow::Error::msg)?;
    let in_process_producer_id =
        NonEmptyString::new(IN_PROCESS_PRODUCER_ID).map_err(anyhow::Error::msg)?;
    let mut grouped: BTreeMap<Vec<u8>, (Principal, Vec<&ProducedModule>)> = BTreeMap::new();
    for module in &produced {
        let key = module
            .principal
            .canonical_order_key()
            .map_err(anyhow::Error::msg)?;
        grouped
            .entry(key)
            .or_insert_with(|| (module.principal.clone(), Vec::new()))
            .1
            .push(module);
    }

    let publication_dir = out_dir
        .join(&graph.lane)
        .join("per-principal")
        .join("publication");
    let _ = std::fs::remove_dir_all(&publication_dir);
    std::fs::create_dir_all(&publication_dir)?;

    let mut carrier_files: Vec<serde_json::Value> = Vec::new();
    let mut record_rows: Vec<(String, serde_json::Value)> = Vec::new();
    for (carrier_index, (_, (principal, members))) in grouped.iter().enumerate() {
        let verified_entries = members
            .iter()
            .map(|module| {
                let admission = ArtifactAdmissionV1::TrustedInProcess {
                    expected_source_id: module.source_id.clone(),
                    expected_source_integrity: module.artifact.semantics.source_integrity.clone(),
                    expected_producer_id: in_process_producer_id.clone(),
                    producer_binary_digest: producer_binary_digest.clone(),
                    transform_fingerprint_digest: module
                        .artifact
                        .semantics
                        .transform_fingerprint
                        .digest()?,
                };
                let verified = module.artifact.verify_for_admission(&admission)?;
                let entry_id = NonEmptyString::new(module.artifact.semantic_digest.as_str())
                    .map_err(anyhow::Error::msg)?;
                Ok((entry_id, verified, *module))
            })
            .collect::<Result<Vec<_>>>()?;
        let (manifest, bytes) = PreparedModuleCarrierV2::from_inline_artifacts(
            principal.clone(),
            producer_id.clone(),
            producer_binary_digest.clone(),
            deployment_graph_digest.clone(),
            verified_entries
                .iter()
                .map(|(entry_id, verified, _)| (entry_id.clone(), *verified)),
        )?;
        let manifest_file = format!("carrier-{carrier_index}.json");
        let bytes_file = format!("carrier-{carrier_index}.js");
        let manifest_bytes = manifest.encode_canonical()?;
        report.carrier_bytes_total += bytes.len();
        report.manifest_bytes_total += manifest_bytes.len();
        std::fs::write(publication_dir.join(&manifest_file), &manifest_bytes)?;
        std::fs::write(publication_dir.join(&bytes_file), &bytes)?;
        for (entry_id, _, module) in &verified_entries {
            let prepared = manifest.prepared_artifact(entry_id.as_str())?;
            record_rows.push((
                module.source_id.encode()?,
                serde_json::json!({
                    "sourceId": serde_json::to_value(&module.source_id)?,
                    "bindings": [],
                    "artifact": serde_json::to_value(&prepared)?,
                    "carrierIndex": carrier_index,
                    "entryId": entry_id.as_str(),
                }),
            ));
        }
        carrier_files.push(serde_json::json!({
            "manifestFile": manifest_file,
            "bytesFile": bytes_file,
        }));
        report
            .principal_table
            .push((format!("{principal:?}"), members.len()));
    }
    report.carriers = carrier_files.len();

    record_rows.sort_by(|left, right| left.0.cmp(&right.0));
    let entry_source_id = entry_source_id.ok_or_else(|| {
        anyhow!(
            "lane entry {} was not among first-party modules",
            graph.entry_id
        )
    })?;
    let index = serde_json::json!({
        "schema": "ibex/prepared-module-graph/2",
        "entry": serde_json::to_value(&entry_source_id)?,
        "producerBinaryDigest": producer_binary_digest.as_str(),
        "deploymentGraphDigest": deployment_graph_digest.as_str(),
        "records": record_rows.into_iter().map(|(_, row)| row).collect::<Vec<_>>(),
        "carriers": carrier_files,
        "candidateTables": [],
    });
    let index_bytes = capsec_semantics::canonical::to_jcs_bytes(&index)
        .map_err(|error| anyhow!("index canonicalize: {error}"))?;
    report.index_bytes = index_bytes.len();
    std::fs::write(publication_dir.join("index.json"), &index_bytes)?;

    report.construct_ms_total = construct_started.elapsed().as_secs_f64() * 1_000.0;
    let report_json = serde_json::to_string_pretty(&report)?;
    std::fs::write(
        out_dir
            .join(&graph.lane)
            .join("per-principal")
            .join("driver-report.json"),
        format!("{report_json}\n"),
    )?;
    Ok(report)
}

fn producer_binary_digest_v1() -> Result<Digest> {
    // Deterministic per pinned toolchain identity: the generated transform
    // configuration digest + crate version. Admission equality-checks this
    // value; nothing derives trust from its preimage in this fixture.
    let identity = format!(
        "ibex-runtime/{}+{}",
        env!("CARGO_PKG_VERSION"),
        ibex_runtime::module_loader::producer_spike::module_artifact_transform_cache_tag_v1(),
    );
    digest_bytes(D2_PRODUCER_BINARY_DOMAIN, identity.as_bytes())
}

#[test]
fn produces_adapter2_publications_from_authenticated_originals() -> Result<()> {
    let Some(graph_dir) = std::env::var_os("EXACT_LLP0413_D2_TARGET_GRAPH_DIR") else {
        eprintln!(
            "llp0413_d2_adapter2_producer: skipped (EXACT_LLP0413_D2_TARGET_GRAPH_DIR unset; \
             export target graphs with the Exact repo's \
             scripts/llp0413-d2-export-target-graph.mjs)"
        );
        return Ok(());
    };
    let out_dir = PathBuf::from(
        std::env::var_os("EXACT_LLP0413_D2_OUT_DIR")
            .ok_or_else(|| anyhow!("EXACT_LLP0413_D2_OUT_DIR must be set with the graph dir"))?,
    );
    let graph_dir = PathBuf::from(graph_dir);
    let producer_binary_digest = producer_binary_digest_v1()?;

    let mut lanes = Vec::new();
    for entry in std::fs::read_dir(&graph_dir)? {
        let lane_dir = entry?.path();
        let graph_file = lane_dir.join("target-graph.json");
        if graph_file.is_file() {
            lanes.push(graph_file);
        }
    }
    lanes.sort();
    if lanes.is_empty() {
        bail!("no <lane>/target-graph.json under {}", graph_dir.display());
    }

    for graph_file in lanes {
        let graph: TargetGraph = serde_json::from_str(&std::fs::read_to_string(&graph_file)?)
            .with_context(|| format!("decode {}", graph_file.display()))?;
        if graph.schema != "exact/llp0413-d2-target-graph/1" {
            bail!("unexpected target-graph schema {}", graph.schema);
        }
        let report = produce_for_lane(&graph, &out_dir, &producer_binary_digest)?;
        println!(
            "{}: {}/{} modules produced ({} refusals, {} TLA, {} closure files), \
             {} carriers, carriers {}B, index {}B, produce {:.1}ms, construct {:.1}ms",
            report.lane,
            report.produced,
            report.graph_module_count,
            report.refusals.len(),
            report.tla_modules.len(),
            report.closure_files_produced,
            report.carriers,
            report.carrier_bytes_total,
            report.index_bytes,
            report.produce_ms_total,
            report.construct_ms_total,
        );
    }
    Ok(())
}

/// The check adapter-1 structurally fails (Exact LLP 0416 R2): every record
/// in every emitted adapter-2 publication satisfies transform-fingerprint
/// CURRENCY against ibex's active generated configuration — because the
/// artifacts were produced BY that configuration. Mirrors the
/// `load_prepared_source_graph_v1` admission-time check.
#[test]
fn adapter2_publications_satisfy_current_transform_fingerprint() -> Result<()> {
    let Some(out_dir) = std::env::var_os("EXACT_LLP0413_D2_OUT_DIR") else {
        eprintln!("llp0413_d2_adapter2_producer: fingerprint check skipped (EXACT_LLP0413_D2_OUT_DIR unset)");
        return Ok(());
    };
    let out_dir = PathBuf::from(out_dir);
    let mut checked_records = 0_usize;
    let mut publications = 0_usize;
    for lane in std::fs::read_dir(&out_dir)? {
        let lane = lane?.path();
        if !lane.is_dir() {
            continue;
        }
        for arm in std::fs::read_dir(&lane)? {
            let publication = arm?.path().join("publication");
            let index_file = publication.join("index.json");
            if !index_file.is_file() {
                continue;
            }
            publications += 1;
            let index: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&index_file)?)?;
            for record in index["records"]
                .as_array()
                .ok_or_else(|| anyhow!("index has no records"))?
            {
                let artifact: ModuleArtifactV1 =
                    serde_json::from_value(record["artifact"].clone())?;
                verify_current_transform_fingerprint_v1(&artifact.semantics).with_context(
                    || {
                        format!(
                            "record {} in {} fails fingerprint currency",
                            record["entryId"],
                            index_file.display()
                        )
                    },
                )?;
                checked_records += 1;
            }
        }
    }
    if publications == 0 {
        bail!("no publications under {}", out_dir.display());
    }
    println!(
        "fingerprint currency holds for {checked_records} records across {publications} publications"
    );
    Ok(())
}
