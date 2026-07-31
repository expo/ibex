//! Exact LLP 0413 Phase 1 arms E/F: admit externally produced (Exact Vite
//! adapter-option-1) prepared publications through the REAL carrier and
//! artifact admission path.
//!
//! Gated on `EXACT_LLP0413_PUBLICATION_DIR` — the Exact driver's output root
//! (`.exact-startup-receipts/llp0413-arms-ef/`, containing
//! `<lane>/<arm>/publication/` directories written by
//! `scripts/produce-prepared-graph-publication.mjs` in the Exact repo).
//! Skips silently when unset so ibex CI is unaffected.
//!
//! Trust posture of this harness: admission expectations (producer identity,
//! deployment graph, authorized semantic-digest set, per-record source
//! identity/integrity) are taken from the publication's OWN index — the
//! LLP 0042 committed-admission shape, in which the canonical index bytes
//! are vouched for by an external commitment. The commitment root check
//! itself is the Exact M4 fixture; this test proves the layer below it:
//! given a vouched index, ibex's real decoders accept the publication and
//! refuse tampered or cross-principal carriers. Transform-fingerprint
//! CURRENCY (`verify_current_transform_fingerprint_v1`) is deliberately NOT
//! asserted: adapter-1 fingerprints name Exact's Vite/esbuild toolchain,
//! not ibex's pinned producer — the recorded LLP 0413 §9.5 seam.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use capsec_semantics::model::{Digest, NonEmptyString, Principal};
use ibex_runtime::module_loader::artifact::{
    digest_bytes, ArtifactAdmissionV1, ModuleArtifactV1, ProducerIdentityV1,
};
use ibex_runtime::module_loader::carrier::{
    AdmittedPreparedCarrierV2, PreparedCarrierAdmissionV2, PreparedCarrierEncodingV2,
    PreparedModuleCarrierV2, PREPARED_CARRIER_BYTES_DOMAIN_V1,
};
use ibex_runtime::module_loader::identity::SourceId;

struct PublicationRecord {
    source_id: SourceId,
    artifact: ModuleArtifactV1,
    carrier_index: usize,
    entry_id: String,
}

struct LoadedPublication {
    label: String,
    records: Vec<PublicationRecord>,
    /// (manifest bytes, carrier bytes), index-aligned with the index's
    /// `carriers` array.
    carriers: Vec<(Vec<u8>, Vec<u8>)>,
    producer_binary_digest: Digest,
    deployment_graph_digest: Digest,
}

fn discover_publications(root: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for lane in std::fs::read_dir(root)? {
        let lane = lane?.path();
        if !lane.is_dir() {
            continue;
        }
        for arm in std::fs::read_dir(&lane)? {
            let arm = arm?.path();
            let publication = arm.join("publication");
            if publication.join("index.json").is_file() {
                found.push(publication);
            }
        }
    }
    found.sort();
    if found.is_empty() {
        bail!(
            "no <lane>/<arm>/publication/index.json under {}",
            root.display()
        );
    }
    Ok(found)
}

fn load_publication(dir: &Path) -> Result<LoadedPublication> {
    let index_bytes = std::fs::read(dir.join("index.json"))?;
    let index: serde_json::Value = serde_json::from_slice(&index_bytes)?;
    if index["schema"] != "ibex/prepared-module-graph/2" {
        bail!("unexpected index schema {:?}", index["schema"]);
    }
    let producer_binary_digest = Digest::new(
        index["producerBinaryDigest"]
            .as_str()
            .ok_or_else(|| anyhow!("index has no producerBinaryDigest"))?,
    )
    .map_err(anyhow::Error::msg)?;
    let deployment_graph_digest = Digest::new(
        index["deploymentGraphDigest"]
            .as_str()
            .ok_or_else(|| anyhow!("index has no deploymentGraphDigest"))?,
    )
    .map_err(anyhow::Error::msg)?;

    let mut records = Vec::new();
    for record in index["records"]
        .as_array()
        .ok_or_else(|| anyhow!("index has no records"))?
    {
        let source_id: SourceId = serde_json::from_value(record["sourceId"].clone())
            .context("index record sourceId does not decode")?;
        let artifact: ModuleArtifactV1 = serde_json::from_value(record["artifact"].clone())
            .context("index record artifact does not decode as ModuleArtifactV1")?;
        let carrier_index = usize::try_from(
            record["carrierIndex"]
                .as_u64()
                .ok_or_else(|| anyhow!("record has no carrierIndex"))?,
        )?;
        let entry_id = record["entryId"]
            .as_str()
            .ok_or_else(|| anyhow!("record has no entryId"))?
            .to_owned();
        records.push(PublicationRecord {
            source_id,
            artifact,
            carrier_index,
            entry_id,
        });
    }

    let mut carriers = Vec::new();
    for carrier in index["carriers"]
        .as_array()
        .ok_or_else(|| anyhow!("index has no carriers"))?
    {
        let manifest_file = carrier["manifestFile"]
            .as_str()
            .ok_or_else(|| anyhow!("carrier has no manifestFile"))?;
        let bytes_file = carrier["bytesFile"]
            .as_str()
            .ok_or_else(|| anyhow!("carrier has no bytesFile"))?;
        carriers.push((
            std::fs::read(dir.join(manifest_file))
                .with_context(|| format!("read {manifest_file}"))?,
            std::fs::read(dir.join(bytes_file)).with_context(|| format!("read {bytes_file}"))?,
        ));
    }

    Ok(LoadedPublication {
        label: dir.display().to_string(),
        records,
        carriers,
        producer_binary_digest,
        deployment_graph_digest,
    })
}

impl LoadedPublication {
    fn expected_producer_id(&self) -> Result<NonEmptyString> {
        for record in &self.records {
            if let ProducerIdentityV1::Prepared { producer_id, .. } = &record.artifact.producer {
                return Ok(producer_id.clone());
            }
        }
        bail!("publication has no prepared-producer record");
    }

    fn root_principal(&self) -> Result<Principal> {
        self.records
            .iter()
            .filter_map(|record| record.source_id.defining_principal())
            .find(|principal| principal.is_root())
            .cloned()
            .ok_or_else(|| anyhow!("publication has no root principal"))
    }

    fn authorized_semantic_digests(&self) -> std::sync::Arc<BTreeSet<Digest>> {
        std::sync::Arc::new(
            self.records
                .iter()
                .map(|record| record.artifact.semantic_digest.clone())
                .collect(),
        )
    }

    /// Expected defining principal per carrier, derived from the index
    /// records that reference it (builtin records charge the root principal,
    /// mirroring `prepared_record_principal`).
    fn expected_carrier_principals(&self) -> Result<BTreeMap<usize, Principal>> {
        let root = self.root_principal()?;
        let mut principals: BTreeMap<usize, Principal> = BTreeMap::new();
        for record in &self.records {
            let principal = record
                .source_id
                .defining_principal()
                .cloned()
                .unwrap_or_else(|| root.clone());
            if let Some(existing) = principals.get(&record.carrier_index) {
                if existing != &principal {
                    bail!(
                        "index assigns two defining principals to carrier {}",
                        record.carrier_index
                    );
                }
            } else {
                principals.insert(record.carrier_index, principal);
            }
        }
        Ok(principals)
    }

    /// Admission expectations for one carrier. For `hermes-bytecode`
    /// carriers the expected engine binding and bytecode version are taken
    /// from the carrier manifest itself: in production/committed admission
    /// these come from the LOADED engine identity, so this harness does not
    /// prove engine-identity pinning — it proves the header inspection
    /// (magic, version, declared length vs actual bytes), digest, and
    /// version-consistency checks against real emitted bytecode.
    fn admission_for(
        &self,
        principal: Principal,
        manifest_bytes: &[u8],
    ) -> Result<PreparedCarrierAdmissionV2> {
        let manifest: PreparedModuleCarrierV2 = serde_json::from_slice(manifest_bytes)
            .context("carrier manifest does not decode for admission expectations")?;
        let (expected_engine_binding, expected_bytecode_version) = match &manifest.encoding {
            PreparedCarrierEncodingV2::JavascriptFactoryTable => (None, None),
            PreparedCarrierEncodingV2::HermesBytecode {
                engine_binding,
                bytecode_version,
            } => (Some(engine_binding.clone()), Some(*bytecode_version)),
        };
        Ok(PreparedCarrierAdmissionV2 {
            expected_principal: principal,
            expected_producer_id: self.expected_producer_id()?,
            producer_binary_digest: self.producer_binary_digest.clone(),
            deployment_graph_digest: self.deployment_graph_digest.clone(),
            authorized_semantic_digests: self.authorized_semantic_digests(),
            expected_engine_binding,
            expected_bytecode_version,
        })
    }
}

fn admit_publication(publication: &LoadedPublication) -> Result<()> {
    let principals = publication.expected_carrier_principals()?;
    let mut admitted = Vec::with_capacity(publication.carriers.len());
    for (carrier_index, (manifest_bytes, carrier_bytes)) in publication.carriers.iter().enumerate()
    {
        let principal = principals
            .get(&carrier_index)
            .ok_or_else(|| anyhow!("carrier {carrier_index} has no referencing record"))?
            .clone();
        let admission = publication.admission_for(principal, manifest_bytes)?;
        admitted.push(
            AdmittedPreparedCarrierV2::decode_and_admit(manifest_bytes, carrier_bytes, &admission)
                .with_context(|| format!("carrier {carrier_index} refused admission"))?,
        );
    }

    let authorized = publication.authorized_semantic_digests();
    let expected_producer_id = publication.expected_producer_id()?;
    for record in &publication.records {
        let carrier = admitted
            .get(record.carrier_index)
            .ok_or_else(|| anyhow!("record names an unadmitted carrier"))?;
        let entry = carrier.entry(&record.entry_id)?;

        // Cross-check: the index's artifact must equal the artifact derived
        // from the admitted carrier entry itself.
        let derived = carrier.manifest().prepared_artifact(&record.entry_id)?;
        if derived != record.artifact {
            bail!(
                "index artifact for entry {} differs from the carrier-derived artifact",
                record.entry_id
            );
        }
        if entry.entry().semantic_digest != record.artifact.semantic_digest {
            bail!("carrier entry semantic digest differs from the index record");
        }

        // Full REAL artifact admission (structure, semantics validation,
        // semantic-digest recompute, payload/carrier binding, producer and
        // deployment match, authorization membership).
        let entry_id = NonEmptyString::new(record.entry_id.clone()).map_err(anyhow::Error::msg)?;
        record
            .artifact
            .verify_for_admission(&ArtifactAdmissionV1::DigestBoundPrepared {
                expected_source_id: record.source_id.clone(),
                expected_source_integrity: record.artifact.semantics.source_integrity.clone(),
                expected_producer_id: expected_producer_id.clone(),
                producer_binary_digest: publication.producer_binary_digest.clone(),
                deployment_graph_digest: publication.deployment_graph_digest.clone(),
                expected_carrier_digest: carrier.manifest().carrier_digest.clone(),
                expected_entry_id: entry_id,
                authorized_semantic_digests: authorized.clone(),
                transform_fingerprint_digest: record
                    .artifact
                    .semantics
                    .transform_fingerprint
                    .digest()?,
            })
            .with_context(|| format!("artifact admission refused entry {}", record.entry_id))?;
    }
    println!(
        "admitted {}: {} carriers, {} records",
        publication.label,
        admitted.len(),
        publication.records.len()
    );
    Ok(())
}

/// A flipped manifest byte must refuse somewhere on the REAL admission join:
/// either `decode_and_admit` itself, or — when the flip lands inside an
/// `entryId` spelling, which this layer deliberately does not digest-bind —
/// the vouched-index entry lookup, where records name entries by the index's
/// own spellings. Admission through BOTH layers is the failure this probe
/// exists to catch (see
/// issues/closed/20260729-hbc-carrier-manifest-entryid-tamper-latitude.md).
fn assert_manifest_flip_refused_at_join(
    publication: &LoadedPublication,
    manifest_bytes: &[u8],
    carrier_bytes: &[u8],
    admission: &PreparedCarrierAdmissionV2,
    position: usize,
    label: &str,
) -> Result<()> {
    let mut tampered_manifest = manifest_bytes.to_vec();
    tampered_manifest[position] ^= 0x01;
    let Ok(admitted) =
        AdmittedPreparedCarrierV2::decode_and_admit(&tampered_manifest, carrier_bytes, admission)
    else {
        return Ok(());
    };
    let carrier_records = publication
        .records
        .iter()
        .filter(|record| record.carrier_index == 0)
        .collect::<Vec<_>>();
    if carrier_records.is_empty() {
        bail!("carrier 0 has no index records to join against");
    }
    let join_refuses = carrier_records.iter().any(|record| {
        admitted.entry(&record.entry_id).is_err()
            || admitted
                .manifest()
                .prepared_artifact(&record.entry_id)
                .is_err()
    });
    if !join_refuses {
        bail!(
            "tampered carrier manifest ({label}, byte {position}) was admitted \
             through the full index join"
        );
    }
    Ok(())
}

fn assert_tamper_refusals(publication: &LoadedPublication) -> Result<()> {
    let principals = publication.expected_carrier_principals()?;
    let (manifest_bytes, carrier_bytes) = publication
        .carriers
        .first()
        .ok_or_else(|| anyhow!("publication has no carriers"))?;
    let principal = principals
        .get(&0)
        .ok_or_else(|| anyhow!("carrier 0 has no principal"))?
        .clone();
    let admission = publication.admission_for(principal, manifest_bytes)?;

    // One flipped byte in the carrier payload refuses before any factory is
    // reachable.
    let mut tampered_bytes = carrier_bytes.clone();
    let middle = tampered_bytes.len() / 2;
    tampered_bytes[middle] ^= 0x01;
    if AdmittedPreparedCarrierV2::decode_and_admit(manifest_bytes, &tampered_bytes, &admission)
        .is_ok()
    {
        bail!("tampered carrier bytes were admitted");
    }

    // The historical positional probe, now asserted against the full join
    // rather than decode_and_admit alone: at manifest.len()/2 the flipped
    // byte can land inside an entryId digest string and stay strict-JSON,
    // canonical, and digest-consistent at this layer.
    assert_manifest_flip_refused_at_join(
        publication,
        manifest_bytes,
        carrier_bytes,
        &admission,
        manifest_bytes.len() / 2,
        "positional middle byte",
    )?;

    // Deterministic digest-checked probe: a flip inside the carrier_digest
    // value must refuse at decode itself (recompute mismatch), independent
    // of the index join.
    let digest_marker = b"\"carrier_digest\":\"sha256-";
    let digest_at = find_subslice(manifest_bytes, digest_marker)
        .ok_or_else(|| anyhow!("manifest has no carrier_digest field"))?
        + digest_marker.len()
        + 4;
    let mut tampered_manifest = manifest_bytes.clone();
    tampered_manifest[digest_at] ^= 0x01;
    if AdmittedPreparedCarrierV2::decode_and_admit(&tampered_manifest, carrier_bytes, &admission)
        .is_ok()
    {
        bail!("carrier_digest flip was admitted at decode");
    }

    // Deterministic entryId probes: flip the middle byte of every index
    // record's entryId spelling inside the manifest. decode_and_admit is
    // allowed to accept these (entry ids are index-join-bound, not
    // digest-bound here); the join must refuse.
    for record in publication
        .records
        .iter()
        .filter(|record| record.carrier_index == 0)
    {
        let quoted = format!("\"{}\"", record.entry_id);
        let Some(at) = find_subslice(manifest_bytes, quoted.as_bytes()) else {
            bail!(
                "carrier 0 manifest does not spell index entry {}",
                record.entry_id
            );
        };
        assert_manifest_flip_refused_at_join(
            publication,
            manifest_bytes,
            carrier_bytes,
            &admission,
            at + 1 + record.entry_id.len() / 2,
            &format!("entryId {}", record.entry_id),
        )?;
    }
    println!("tamper refusals hold for {}", publication.label);
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// LLP 0413 §14 item 16: a carrier whose entries span two defining
/// principals must refuse, even when every digest is locally consistent.
fn assert_multi_principal_refusal(publication: &LoadedPublication) -> Result<()> {
    let mut manifests = Vec::new();
    for (manifest_bytes, _) in &publication.carriers {
        manifests.push(serde_json::from_slice::<PreparedModuleCarrierV2>(
            manifest_bytes,
        )?);
    }
    let (host_index, donor_index) = {
        let mut pair = None;
        'outer: for (i, left) in manifests.iter().enumerate() {
            for (j, right) in manifests.iter().enumerate() {
                if i != j && left.defining_principal != right.defining_principal {
                    pair = Some((i, j));
                    break 'outer;
                }
            }
        }
        pair.ok_or_else(|| anyhow!("publication has only one defining principal"))?
    };

    let mut spliced = manifests[host_index].clone();
    spliced
        .entries
        .push(manifests[donor_index].entries[0].clone());
    spliced
        .entries
        .sort_by(|left, right| left.entry_id.as_str().cmp(right.entry_id.as_str()));
    // Keep the manifest locally self-consistent: bytes digest matches, entry
    // semantic digests are genuine — only the cross-principal fact is wrong.
    let bytes = b"(function(){\"use strict\";return Object.freeze(Object.create(null));})()";
    spliced.carrier_digest = digest_bytes(PREPARED_CARRIER_BYTES_DOMAIN_V1, bytes)?;
    let spliced_manifest_bytes = spliced.encode_canonical()?;

    let admission =
        publication.admission_for(spliced.defining_principal.clone(), &spliced_manifest_bytes)?;
    match AdmittedPreparedCarrierV2::decode_and_admit(&spliced_manifest_bytes, bytes, &admission) {
        Ok(_) => bail!("multi-principal carrier was admitted"),
        Err(error) => {
            let message = format!("{error:#}");
            if !message.contains("crosses its defining principal") {
                bail!("multi-principal carrier refused for the wrong reason: {message}");
            }
        }
    }
    println!(
        "§14 item 16 multi-principal refusal holds for {}",
        publication.label
    );
    Ok(())
}

#[test]
fn admits_exact_adapter1_publications_and_refuses_tampering() -> Result<()> {
    let Some(root) = std::env::var_os("EXACT_LLP0413_PUBLICATION_DIR") else {
        eprintln!(
            "llp0413_arms_ef_admission: skipped (EXACT_LLP0413_PUBLICATION_DIR unset; \
             produce publications with the Exact repo's \
             scripts/produce-prepared-graph-publication.mjs)"
        );
        return Ok(());
    };
    let root = PathBuf::from(root);
    let mut multi_principal_checked = false;
    for dir in discover_publications(&root)? {
        let publication = load_publication(&dir)?;
        admit_publication(&publication)?;
        assert_tamper_refusals(&publication)?;
        match assert_multi_principal_refusal(&publication) {
            Ok(()) => multi_principal_checked = true,
            Err(error) if format!("{error:#}").contains("only one defining principal") => {}
            Err(error) => return Err(error),
        }
    }
    if !multi_principal_checked {
        bail!("no publication offered two defining principals for the §14 item 16 fixture");
    }
    Ok(())
}
