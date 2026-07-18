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
const MAX_I_JSON_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}
