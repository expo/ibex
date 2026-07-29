//! Exact LLP 0413 §5.7 / LLP 0042, M4: production-shaped prepared-graph
//! commitment fixture — the substitution-refusal gate at the publication
//! root, proven with ibex's REAL strict-JSON, JCS, and digest code.
//!
//! Gated on `EXACT_LLP0413_PUBLICATION_DIR` (the Exact arms E/F output root;
//! each `<lane>/<arm>/` holds `publication/` plus the production-shaped
//! `commitment.json` written by the Exact repo's
//! `scripts/emit-prepared-graph-commitment.mjs`). Skips silently when unset.
//!
//! Scope honesty: `load_prepared_graph_committed_v1` (LLP 0042's committed
//! admission) is NOT implemented in ibex yet, so this test implements the
//! commitment's step-1/2/3 discipline at fixture level — retained exact
//! bytes, strict-JSON parse, JCS-canonicality byte-compare, root digest in
//! `ibex:prepared-publication-root:1`, and the semantic-inventory /
//! principal-set facet cross-checks — and proves the adversarial gate:
//! a FULLY SELF-CONSISTENT substituted publication (a genuine sibling
//! publication whose every cache-local digest verifies, produced by the
//! same producer for the same deployment graph) is refused at the root
//! check with a COMMITMENT-MISMATCH diagnostic, distinct from byte
//! corruption. Committed admission itself remains ibex implementation work
//! (tracked in issues/20260728-prepared-graph-independent-commitment.md).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ibex_runtime::module_loader::artifact::digest_bytes;
use ibex_runtime::module_loader::identity::SourceId;

const PUBLICATION_ROOT_DOMAIN: &str = "ibex:prepared-publication-root:1";
const SEMANTIC_INVENTORY_DOMAIN: &str = "ibex:prepared-semantic-inventory:1";
const PRINCIPAL_SET_DOMAIN: &str = "ibex:prepared-principal-set:1";

/// Outcome classification for the fixture-level root check: refusals must
/// name WHY (LLP 0042 adversarial gate 1: "the diagnostic MUST name
/// commitment mismatch, not byte corruption").
#[derive(Debug, PartialEq, Eq)]
enum RootCheck {
    Accepted,
    CommitmentMismatch,
    Corrupt(String),
}

fn root_check(index_bytes: &[u8], expected_root_digest: &str) -> Result<RootCheck> {
    // Step 2 of LLP 0042 committed admission, fixture level: strict JSON,
    // canonical JCS byte-equality, then the domain-separated root digest.
    let text = match std::str::from_utf8(index_bytes) {
        Ok(text) => text,
        Err(_) => return Ok(RootCheck::Corrupt("index is not UTF-8".into())),
    };
    let value = match capsec_semantics::strict_json::parse_strict(text) {
        Ok(value) => value,
        Err(error) => return Ok(RootCheck::Corrupt(format!("not strict JSON: {error}"))),
    };
    let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
        .map_err(|error| anyhow!("cannot canonicalize index: {error}"))?;
    if canonical != index_bytes {
        return Ok(RootCheck::Corrupt("index bytes are not canonical JCS".into()));
    }
    let observed = digest_bytes(PUBLICATION_ROOT_DOMAIN, index_bytes)?;
    if observed.as_str() != expected_root_digest {
        return Ok(RootCheck::CommitmentMismatch);
    }
    Ok(RootCheck::Accepted)
}

struct CommitmentFixture {
    label: String,
    lane_dir: PathBuf,
    commitment: serde_json::Value,
    index_bytes: Vec<u8>,
}

fn discover_fixtures(root: &Path) -> Result<Vec<CommitmentFixture>> {
    let mut fixtures = Vec::new();
    for lane in std::fs::read_dir(root)? {
        let lane = lane?.path();
        if !lane.is_dir() {
            continue;
        }
        for arm in std::fs::read_dir(&lane)? {
            let arm = arm?.path();
            let commitment_file = arm.join("commitment.json");
            let index_file = arm.join("publication").join("index.json");
            if !commitment_file.is_file() || !index_file.is_file() {
                continue;
            }
            let commitment: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&commitment_file)?)
                    .context("commitment.json does not parse")?;
            if commitment["schema"] != "ibex/prepared-graph-commitment/1"
                || commitment["workflow"] != "production"
            {
                bail!("{} is not a production-shaped commitment", commitment_file.display());
            }
            fixtures.push(CommitmentFixture {
                label: arm.display().to_string(),
                lane_dir: lane.clone(),
                commitment,
                index_bytes: std::fs::read(&index_file)?,
            });
        }
    }
    fixtures.sort_by(|left, right| left.label.cmp(&right.label));
    if fixtures.is_empty() {
        bail!("no <lane>/<arm>/commitment.json under {}", root.display());
    }
    Ok(fixtures)
}

/// Recompute the commitment's derived facets from the index (LLP 0042
/// committed-admission step 3), independently of the Exact emitter.
fn recompute_facets(index_bytes: &[u8]) -> Result<(String, String, String, String, String)> {
    let index: serde_json::Value = serde_json::from_slice(index_bytes)?;
    let records = index["records"]
        .as_array()
        .ok_or_else(|| anyhow!("index has no records"))?;

    let mut semantic_digests = BTreeSet::new();
    let mut principal_keys: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut root_principal: Option<serde_json::Value> = None;
    for record in records {
        let digest = record["artifact"]["semanticDigest"]
            .as_str()
            .ok_or_else(|| anyhow!("record has no semanticDigest"))?;
        semantic_digests.insert(digest.to_owned());
        let source_id: SourceId = serde_json::from_value(record["sourceId"].clone())?;
        if let Some(principal) = source_id.defining_principal() {
            if principal.is_root() {
                root_principal = Some(serde_json::to_value(principal)?);
            }
        }
    }
    let root_principal =
        root_principal.ok_or_else(|| anyhow!("publication has no root principal"))?;
    for record in records {
        let source_id: SourceId = serde_json::from_value(record["sourceId"].clone())?;
        let principal_value = match source_id.defining_principal() {
            Some(principal) => serde_json::to_value(principal)?,
            None => root_principal.clone(),
        };
        principal_keys.insert(capsec_semantics::canonical::to_jcs_bytes(&principal_value)?);
    }

    let inventory_value = serde_json::Value::Array(
        semantic_digests
            .into_iter()
            .map(serde_json::Value::String)
            .collect(),
    );
    let inventory_bytes = capsec_semantics::canonical::to_jcs_bytes(&inventory_value)?;
    let semantic_inventory_digest =
        digest_bytes(SEMANTIC_INVENTORY_DOMAIN, &inventory_bytes)?.as_str().to_owned();

    // The set is ordered by each principal's canonical JCS encoding
    // (Principal::canonical_order_key); the digested value is the JCS array
    // of the principal objects in that order.
    let principals_joined = {
        let mut joined = Vec::new();
        joined.push(b'[');
        for (position, key) in principal_keys.iter().enumerate() {
            if position > 0 {
                joined.push(b',');
            }
            joined.extend_from_slice(key);
        }
        joined.push(b']');
        joined
    };
    let principal_set_digest =
        digest_bytes(PRINCIPAL_SET_DOMAIN, &principals_joined)?.as_str().to_owned();

    let entry_source_id: SourceId = serde_json::from_value(index["entry"].clone())?;
    Ok((
        semantic_inventory_digest,
        principal_set_digest,
        entry_source_id.encode().map_err(|error| anyhow!("{error}"))?,
        index["deploymentGraphDigest"]
            .as_str()
            .ok_or_else(|| anyhow!("index has no deploymentGraphDigest"))?
            .to_owned(),
        index["producerBinaryDigest"]
            .as_str()
            .ok_or_else(|| anyhow!("index has no producerBinaryDigest"))?
            .to_owned(),
    ))
}

#[test]
fn commitment_root_refuses_self_consistent_substitution() -> Result<()> {
    let Some(root) = std::env::var_os("EXACT_LLP0413_PUBLICATION_DIR") else {
        eprintln!(
            "llp0413_prepared_commitment_fixture: skipped \
             (EXACT_LLP0413_PUBLICATION_DIR unset)"
        );
        return Ok(());
    };
    let fixtures = discover_fixtures(&PathBuf::from(root))?;

    let mut substitutions_checked = 0usize;
    for fixture in &fixtures {
        let expected_root = fixture.commitment["publicationRootDigest"]
            .as_str()
            .ok_or_else(|| anyhow!("commitment has no publicationRootDigest"))?;

        // 1. The genuine publication passes the root check and every facet
        // cross-check, recomputed here with ibex's real JCS/digest code.
        let genuine = root_check(&fixture.index_bytes, expected_root)?;
        if genuine != RootCheck::Accepted {
            bail!("genuine publication failed its own commitment: {:?} ({})", genuine, fixture.label);
        }
        let (inventory, principal_set, entry, deployment, producer_binary) =
            recompute_facets(&fixture.index_bytes)?;
        if fixture.commitment["semanticInventoryDigest"] != *inventory
            || fixture.commitment["principalSetDigest"] != *principal_set
            || fixture.commitment["entrySourceId"] != *entry
            || fixture.commitment["deploymentGraphDigest"] != *deployment
            || fixture.commitment["producer"]["binaryDigest"] != *producer_binary
        {
            bail!("commitment facets disagree with the index recompute ({})", fixture.label);
        }

        // 2. Corruption is diagnosed as corruption, not commitment mismatch.
        let mut corrupted = fixture.index_bytes.clone();
        let middle = corrupted.len() / 2;
        corrupted[middle] ^= 0x01;
        match root_check(&corrupted, expected_root)? {
            RootCheck::Corrupt(_) | RootCheck::CommitmentMismatch => {}
            RootCheck::Accepted => bail!("corrupted index passed the root check"),
        }
        // A flipped byte inside a JSON string stays strict+canonical, so
        // either classification can occur; a TRUNCATED index must always
        // classify as corrupt.
        let truncated = &fixture.index_bytes[..fixture.index_bytes.len() - 1];
        match root_check(truncated, expected_root)? {
            RootCheck::Corrupt(_) => {}
            other => bail!("truncated index misclassified: {other:?}"),
        }

        // 3. THE GATE (LLP 0042 adversarial fixtures 1-2): substitute a
        // fully self-consistent sibling publication — same lane, same
        // producer, same deployment graph, every cache-local digest correct
        // (the M2/M3 admission tests prove that) — and require refusal at
        // the root check, classified as COMMITMENT MISMATCH, not
        // corruption. Nothing inside the cache can compensate: the sibling
        // is canonical JCS, so only the independent root digest refuses it.
        for donor in &fixtures {
            if donor.label == fixture.label || donor.lane_dir != fixture.lane_dir {
                continue;
            }
            match root_check(&donor.index_bytes, expected_root)? {
                RootCheck::CommitmentMismatch => substitutions_checked += 1,
                other => bail!(
                    "substituted publication {} against commitment {} classified as {other:?} \
                     (must be CommitmentMismatch)",
                    donor.label,
                    fixture.label
                ),
            }
        }
        println!("commitment fixture holds for {}", fixture.label);
    }
    if substitutions_checked == 0 {
        bail!("no sibling publication pairs were available for the substitution gate");
    }
    println!("substitution refusals: {substitutions_checked} pairs, all commitment-mismatch");
    Ok(())
}
