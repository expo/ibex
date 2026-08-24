//! Canonical, site-specific computed-dynamic-import candidate tables.
//!
//! Tables are deployment sidecars rather than ModuleArtifact fields. Their
//! canonical-byte digest is both the embedded graph reference and the SFE
//! section id, so graph identity authenticates the complete table without
//! reopening resolution at invocation time.
//! @ref LLP 0028#2-disposition-of-the-legacy-window-interop-shapes

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use capsec_semantics::graph_snapshot::GraphCandidateSetV1;
use capsec_semantics::model::{Digest, NonEmptyString, StableId};
use serde::{Deserialize, Serialize};

use super::artifact::{source_integrity, CanonicalSourceId, ModuleArtifactV1};
use super::identity::ImportAttributes;

pub const COMPUTED_CANDIDATES_SCHEMA_V1: &str = "ibex/computed-candidates/1";
pub const COMPUTED_CANDIDATES_SCHEMA_V2: &str = "ibex/computed-candidates/2";
const MAX_I_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginalSourceSpanV1 {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputedCandidateTargetV1 {
    pub specifier: NonEmptyString,
    pub attributes: ImportAttributes,
    pub target: CanonicalSourceId,
    pub target_source_integrity: Digest,
}

/// One table per labeled computed site. Keeping the sidecar at site
/// granularity makes its digest a direct non-escalation key: widening one site
/// cannot accidentally widen another site in the same requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputedCandidateTableV1 {
    pub schema: String,
    pub requester: CanonicalSourceId,
    pub requester_source_integrity: Digest,
    pub transform_fingerprint_digest: Digest,
    pub site: u32,
    pub generation: u64,
    pub label: StableId,
    pub original_source_span: OriginalSourceSpanV1,
    pub candidates: Vec<ComputedCandidateTargetV1>,
}

/// Generation-free candidate table for package-aware compositions.
///
/// The O-1 byte authority has not landed this row. LLP 0056 fixes the v2
/// shape as v1 minus `generation`; admission authenticates these wire bytes
/// before stamping the envelope generation into `ComputedCandidateTableV1`.
// @ref LLP 0056#43-the-package-index--ibexprepared-package1 — generation has exactly one serialized carrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputedCandidateTableV2 {
    pub schema: String,
    pub requester: CanonicalSourceId,
    pub requester_source_integrity: Digest,
    pub transform_fingerprint_digest: Digest,
    pub site: u32,
    pub label: StableId,
    pub original_source_span: OriginalSourceSpanV1,
    pub candidates: Vec<ComputedCandidateTargetV1>,
}

impl ComputedCandidateTableV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(self)?)
            .map_err(anyhow::Error::from)
    }

    pub fn digest(&self) -> Result<Digest> {
        source_integrity(&self.canonical_bytes()?)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("computed-candidate table is not UTF-8")?;
        let value = capsec_semantics::strict_json::parse_strict(text).map_err(|error| {
            anyhow::anyhow!("computed-candidate table is not strict JSON: {error}")
        })?;
        if capsec_semantics::canonical::to_jcs_bytes(&value)? != bytes {
            bail!("computed-candidate table is not canonical JCS");
        }
        let table: Self = serde_json::from_value(value)
            .context("computed-candidate table has an invalid shape")?;
        table.validate()?;
        Ok(table)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != COMPUTED_CANDIDATES_SCHEMA_V1 {
            bail!("unsupported computed-candidate table schema");
        }
        if self.generation == 0 || self.generation > MAX_I_JSON_INTEGER {
            bail!("computed-candidate generation is outside the I-JSON integer range");
        }
        if self.original_source_span.start >= self.original_source_span.end {
            bail!("computed-candidate original-source span is empty or reversed");
        }
        if self.candidates.is_empty() {
            bail!("computed-candidate table must contain at least one candidate");
        }
        let mut previous: Option<Vec<u8>> = None;
        let mut spellings = BTreeSet::new();
        for candidate in &self.candidates {
            ImportAttributes::new(candidate.attributes.entries().clone())?;
            if !spellings.insert(candidate.specifier.as_str()) {
                bail!("computed-candidate spellings must be unique");
            }
            let bytes =
                capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(candidate)?)?;
            if previous.as_ref().is_some_and(|previous| previous >= &bytes) {
                bail!("computed candidates must be strictly ordered by canonical bytes");
            }
            previous = Some(bytes);
        }
        Ok(())
    }

    pub fn validate_requester(&self, artifact: &ModuleArtifactV1) -> Result<()> {
        if self.requester != artifact.semantics.source_id
            || self.requester_source_integrity != artifact.semantics.source_integrity
            || self.transform_fingerprint_digest != artifact.semantics.transform_fingerprint.digest()?
            || !artifact.semantics.dynamic_edges.iter().any(|edge| {
                matches!(edge, super::artifact::DynamicEdgeV1::Computed { site } if *site == self.site)
            })
        {
            bail!("computed-candidate table is stale for its requester artifact");
        }
        Ok(())
    }

    pub fn graph_projection(&self) -> Result<GraphCandidateSetV1> {
        Ok(GraphCandidateSetV1 {
            id: NonEmptyString::new(self.digest()?.as_str()).map_err(anyhow::Error::msg)?,
            requester: self.requester.0.encode()?,
            label: NonEmptyString::new(self.label.as_str()).map_err(anyhow::Error::msg)?,
            candidates: self
                .candidates
                .iter()
                .map(|candidate| candidate.specifier.clone())
                .collect(),
        })
    }
}

impl ComputedCandidateTableV2 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(self)?)
            .map_err(anyhow::Error::from)
    }

    pub fn digest(&self) -> Result<Digest> {
        source_integrity(&self.canonical_bytes()?)
    }

    /// Decode after inspecting the schema identifier, so a v1 table in a
    /// composition package is an unsupported-schema refusal rather than a v2
    /// unknown-field/corruption refusal.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("computed-candidate table is not UTF-8")?;
        let value = capsec_semantics::strict_json::parse_strict(text).map_err(|error| {
            anyhow::anyhow!("computed-candidate table is not strict JSON: {error}")
        })?;
        if capsec_semantics::canonical::to_jcs_bytes(&value)? != bytes {
            bail!("computed-candidate table is not canonical JCS");
        }
        let schema = value
            .get("schema")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("computed-candidate table has no schema identifier"))?;
        if schema != COMPUTED_CANDIDATES_SCHEMA_V2 {
            bail!("unsupported computed-candidate table schema {schema:?}");
        }
        let table: Self = serde_json::from_value(value)
            .context("computed-candidate table has an invalid shape")?;
        table.validate()?;
        Ok(table)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != COMPUTED_CANDIDATES_SCHEMA_V2 {
            bail!("unsupported computed-candidate table schema");
        }
        validate_candidate_body(
            self.original_source_span,
            &self.candidates,
            "computed-candidate",
        )
    }

    pub fn validate_requester(&self, artifact: &ModuleArtifactV1) -> Result<()> {
        if self.requester != artifact.semantics.source_id
            || self.requester_source_integrity != artifact.semantics.source_integrity
            || self.transform_fingerprint_digest
                != artifact.semantics.transform_fingerprint.digest()?
            || !artifact.semantics.dynamic_edges.iter().any(|edge| {
                matches!(edge, super::artifact::DynamicEdgeV1::Computed { site } if *site == self.site)
            })
        {
            bail!("computed-candidate table is stale for its requester artifact");
        }
        Ok(())
    }

    /// Stamp the envelope-attested generation only after wire authentication.
    pub fn stamp_generation(&self, generation: u64) -> Result<ComputedCandidateTableV1> {
        if generation == 0 || generation > MAX_I_JSON_INTEGER {
            bail!("computed-candidate generation is outside the I-JSON integer range");
        }
        Ok(ComputedCandidateTableV1 {
            schema: COMPUTED_CANDIDATES_SCHEMA_V1.into(),
            requester: self.requester.clone(),
            requester_source_integrity: self.requester_source_integrity.clone(),
            transform_fingerprint_digest: self.transform_fingerprint_digest.clone(),
            site: self.site,
            generation,
            label: self.label.clone(),
            original_source_span: self.original_source_span,
            candidates: self.candidates.clone(),
        })
    }
}

fn validate_candidate_body(
    original_source_span: OriginalSourceSpanV1,
    candidates: &[ComputedCandidateTargetV1],
    label: &str,
) -> Result<()> {
    if original_source_span.start >= original_source_span.end {
        bail!("{label} original-source span is empty or reversed");
    }
    if candidates.is_empty() {
        bail!("{label} table must contain at least one candidate");
    }
    let mut previous: Option<Vec<u8>> = None;
    let mut spellings = BTreeSet::new();
    for candidate in candidates {
        ImportAttributes::new(candidate.attributes.entries().clone())?;
        if !spellings.insert(candidate.specifier.as_str()) {
            bail!("{label} spellings must be unique");
        }
        let bytes = capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(candidate)?)?;
        if previous.as_ref().is_some_and(|previous| previous >= &bytes) {
            bail!("{label} candidates must be strictly ordered by canonical bytes");
        }
        previous = Some(bytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_loader::identity::SourceId;
    use capsec_semantics::digest::compute_domain_digest;
    use capsec_semantics::model::{PathComponent, Principal};

    fn digest(tag: u8) -> Digest {
        Digest::new(
            compute_domain_digest(
                "ibex:candidate-test:1",
                &serde_json::json!({"tag": tag}),
                &[],
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn source(name: &str) -> CanonicalSourceId {
        CanonicalSourceId(
            SourceId::file(
                Principal::Root {
                    identity: NonEmptyString::new("root").unwrap(),
                },
                vec![PathComponent::utf8(name).unwrap()],
            )
            .unwrap(),
        )
    }

    fn golden_table() -> ComputedCandidateTableV1 {
        ComputedCandidateTableV1 {
            schema: COMPUTED_CANDIDATES_SCHEMA_V1.into(),
            requester: source("entry.mjs"),
            requester_source_integrity: digest(1),
            transform_fingerprint_digest: digest(2),
            site: 0,
            generation: 1,
            label: StableId::new("routes").unwrap(),
            original_source_span: OriginalSourceSpanV1 { start: 4, end: 42 },
            candidates: vec![ComputedCandidateTargetV1 {
                specifier: NonEmptyString::new("./a.mjs").unwrap(),
                attributes: ImportAttributes::default(),
                target: source("a.mjs"),
                target_source_integrity: digest(3),
            }],
        }
    }

    #[test]
    fn canonical_digest_is_the_graph_reference() {
        let table = golden_table();
        let bytes = table.canonical_bytes().unwrap();
        let checked_in = include_str!("../../tests/fixtures/computed-candidates-v1.golden.json")
            .strip_suffix('\n')
            .unwrap();
        assert_eq!(bytes, checked_in.as_bytes());
        assert_eq!(
            ComputedCandidateTableV1::decode_canonical(&bytes).unwrap(),
            table
        );
        assert_eq!(
            table.graph_projection().unwrap().id.as_str(),
            table.digest().unwrap().as_str()
        );
    }

    #[test]
    fn fingerprint_domain_rotation_invalidates_the_requester_binding() {
        let authored = "const name = './a.mjs'; export const value = import(name, { with: { 'ibex:site': 'routes' } });";
        let produced = crate::module_loader::producer_spike::produce_module_artifact_with_sites_v1(
            source("entry.mjs").0,
            "entry.mjs",
            std::path::Path::new("entry.mjs"),
            authored,
            digest(9),
        )
        .unwrap();
        let mut table = ComputedCandidateTableV1 {
            requester: produced.artifact.semantics.source_id.clone(),
            requester_source_integrity: produced.artifact.semantics.source_integrity.clone(),
            transform_fingerprint_digest: produced
                .artifact
                .semantics
                .transform_fingerprint
                .digest()
                .unwrap(),
            original_source_span: produced.dynamic_import_sites[0]
                .original_source_span
                .clone(),
            ..golden_table()
        };
        table.validate_requester(&produced.artifact).unwrap();
        let before = table.digest().unwrap();
        table.transform_fingerprint_digest = digest(8);
        assert!(table.validate_requester(&produced.artifact).is_err());
        assert_ne!(table.digest().unwrap(), before);
    }

    #[test]
    fn v2_authenticates_generation_free_bytes_before_stamping() {
        let v1 = golden_table();
        let v2 = ComputedCandidateTableV2 {
            schema: COMPUTED_CANDIDATES_SCHEMA_V2.into(),
            requester: v1.requester.clone(),
            requester_source_integrity: v1.requester_source_integrity.clone(),
            transform_fingerprint_digest: v1.transform_fingerprint_digest.clone(),
            site: v1.site,
            label: v1.label.clone(),
            original_source_span: v1.original_source_span,
            candidates: v1.candidates.clone(),
        };
        let bytes = v2.canonical_bytes().unwrap();
        let digest = source_integrity(&bytes).unwrap();
        let decoded = ComputedCandidateTableV2::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded.digest().unwrap(), digest);
        assert!(serde_json::from_slice::<serde_json::Value>(&bytes)
            .unwrap()
            .get("generation")
            .is_none());

        let stamped = decoded.stamp_generation(42).unwrap();
        assert_eq!(stamped.generation, 42);
        assert_eq!(stamped.schema, COMPUTED_CANDIDATES_SCHEMA_V1);
        assert!(
            ComputedCandidateTableV2::decode_canonical(&v1.canonical_bytes().unwrap()).is_err()
        );
    }
}
