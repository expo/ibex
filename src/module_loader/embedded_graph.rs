//! Path-independent module graph embedded in a single-file executable.
//!
//! This is deliberately distinct from the path-bearing prepared graph cache:
//! admission consumes authenticated envelope facts and never reopens source
//! files from the original checkout.
//! @ref LLP 0029#2-executable-layout-stub-envelope-footer — embedded identities and carrier pairs are path-independent and authenticated

use std::collections::{BTreeMap, BTreeSet};

use capsec_semantics::graph_snapshot::{
    AuthenticatedGraphSnapshotV1, GraphCandidateSetV1, GraphEdgeV1, GraphEntryDesignationV1,
    GraphNodeV1, GraphResolutionKindV1, AUTHENTICATED_GRAPH_SNAPSHOT_SCHEMA_V1,
};
use capsec_semantics::model::Principal;
use capsec_semantics::model::{Digest, NonEmptyString};
use serde::{Deserialize, Serialize};

use super::artifact::CanonicalSourceId;
use super::identity::{ConditionSet, ImportAttributes, ResolutionKind};

pub const EMBEDDED_MODULE_GRAPH_SCHEMA_V1: &str = "ibex/embedded-module-graph/1";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("EMG001 embedded graph is not canonical strict JSON: {0}")]
    Encoding(String),
    #[error("EMG002 embedded graph contract is invalid: {0}")]
    Contract(String),
    #[error("EMG003 embedded graph carrier binding is invalid: {0}")]
    Carrier(String),
    #[error("EMG004 embedded graph candidate-table binding is invalid: {0}")]
    Candidate(String),
    #[error("EMG005 embedded graph identity is invalid: {0}")]
    Identity(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmbeddedModuleGraphV1 {
    pub schema: String,
    pub graph_identity: Digest,
    pub entry: CanonicalSourceId,
    pub records: Vec<EmbeddedModuleRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmbeddedModuleRecordV1 {
    pub source_id: CanonicalSourceId,
    pub source_integrity: Digest,
    pub semantic_digest: Digest,
    pub carrier: EmbeddedCarrierBindingV1,
    pub edges: Vec<EmbeddedModuleEdgeV1>,
    pub virtual_source: VirtualSourceLabelV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_table_refs: Vec<NonEmptyString>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmbeddedCarrierBindingV1 {
    pub pair_id: NonEmptyString,
    pub entry_id: NonEmptyString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmbeddedModuleEdgeV1 {
    pub specifier: NonEmptyString,
    pub resolution_kind: ResolutionKind,
    pub conditions: ConditionSet,
    pub attributes: ImportAttributes,
    pub target: CanonicalSourceId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VirtualSourceLabelV1 {
    pub path: String,
    pub import_meta_url: String,
    pub filename: String,
    pub dirname: String,
    pub source_map_label: String,
}

impl VirtualSourceLabelV1 {
    pub fn new(path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        validate_virtual_path(&path)?;
        let dirname = path
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .filter(|parent| !parent.is_empty())
            .ok_or_else(|| Error::Contract("virtual source label has no directory".into()))?
            .to_owned();
        let url = format!("file://{}", percent_encode_path(&path));
        Ok(Self {
            filename: path.clone(),
            dirname,
            source_map_label: url.clone(),
            import_meta_url: url,
            path,
        })
    }

    fn validate(&self) -> Result<()> {
        let expected = Self::new(self.path.clone())?;
        if self != &expected {
            return Err(Error::Contract(format!(
                "virtual source label {:?} has non-derived observable spellings",
                self.path
            )));
        }
        Ok(())
    }
}

/// Facts extracted from an already authenticated carrier manifest/payload pair.
/// The envelope/manifest admission layer supplies these; this graph layer then
/// proves the record ↔ pair ↔ entry bijection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedCarrierFactV1 {
    pub source_id: CanonicalSourceId,
    pub semantic_digest: Digest,
    pub entry_id: NonEmptyString,
}

impl EmbeddedModuleGraphV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_contract()?;
        let value =
            serde_json::to_value(self).map_err(|error| Error::Encoding(error.to_string()))?;
        capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| Error::Encoding(error.to_string()))
    }

    pub fn decode_and_admit(
        bytes: &[u8],
        carriers: &BTreeMap<String, EmbeddedCarrierFactV1>,
        candidate_sets: &[GraphCandidateSetV1],
    ) -> Result<Self> {
        let graph = Self::decode_canonical(bytes)?;
        graph.validate_external_bindings(carriers, candidate_sets)?;
        let snapshot = graph.authenticated_snapshot(candidate_sets.to_vec())?;
        if snapshot
            .identity()
            .map_err(|error| Error::Identity(error.to_string()))?
            != graph.graph_identity
        {
            return Err(Error::Identity(
                "declared graph identity disagrees with authenticated projection".into(),
            ));
        }
        Ok(graph)
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        let text =
            std::str::from_utf8(bytes).map_err(|error| Error::Encoding(error.to_string()))?;
        let value = capsec_semantics::strict_json::parse_strict(text)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        if canonical != bytes {
            return Err(Error::Encoding("graph bytes are not JCS".into()));
        }
        let graph: Self =
            serde_json::from_value(value).map_err(|error| Error::Encoding(error.to_string()))?;
        graph.validate_contract()?;
        Ok(graph)
    }

    pub fn validate_contract(&self) -> Result<()> {
        if self.schema != EMBEDDED_MODULE_GRAPH_SCHEMA_V1 {
            return Err(Error::Contract("unsupported embedded graph schema".into()));
        }
        if self.records.is_empty() {
            return Err(Error::Contract("embedded graph has no records".into()));
        }
        let entry_wire = self
            .entry
            .0
            .encode()
            .map_err(|error| Error::Contract(error.to_string()))?;
        let mut previous_source: Option<String> = None;
        let mut sources = BTreeSet::new();
        let mut pairs = BTreeSet::new();
        for record in &self.records {
            let source_wire = record
                .source_id
                .0
                .encode()
                .map_err(|error| Error::Contract(error.to_string()))?;
            if previous_source
                .as_deref()
                .is_some_and(|previous| previous >= source_wire.as_str())
            {
                return Err(Error::Contract(
                    "records must be strictly ordered by canonical SourceId".into(),
                ));
            }
            previous_source = Some(source_wire.clone());
            sources.insert(source_wire);
            if !pairs.insert(record.carrier.pair_id.as_str()) {
                return Err(Error::Carrier(
                    "v1 requires one distinct carrier pair per module record".into(),
                ));
            }
            record.virtual_source.validate()?;
            validate_edges(&record.edges)?;
            validate_sorted_unique_nonempty(
                &record.candidate_table_refs,
                "candidate-table references",
            )?;
        }
        if !sources.contains(&entry_wire) {
            return Err(Error::Contract(
                "entry SourceId is absent from records".into(),
            ));
        }
        for record in &self.records {
            for edge in &record.edges {
                let target = edge
                    .target
                    .0
                    .encode()
                    .map_err(|error| Error::Contract(error.to_string()))?;
                if !sources.contains(&target) {
                    return Err(Error::Contract(format!(
                        "edge {:?} targets a SourceId outside the embedded graph",
                        edge.specifier.as_str()
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_external_bindings(
        &self,
        carriers: &BTreeMap<String, EmbeddedCarrierFactV1>,
        candidate_sets: &[GraphCandidateSetV1],
    ) -> Result<()> {
        let expected_pairs = self
            .records
            .iter()
            .map(|record| record.carrier.pair_id.as_str())
            .collect::<BTreeSet<_>>();
        let actual_pairs = carriers.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if expected_pairs != actual_pairs {
            return Err(Error::Carrier(
                "graph records and admitted carrier pairs are not bijective".into(),
            ));
        }
        let mut referenced_candidates = BTreeSet::new();
        for record in &self.records {
            let pair = record.carrier.pair_id.as_str();
            let carrier = carriers
                .get(pair)
                .ok_or_else(|| Error::Carrier(format!("carrier pair {pair:?} is absent")))?;
            if carrier.source_id != record.source_id
                || carrier.semantic_digest != record.semantic_digest
                || carrier.entry_id != record.carrier.entry_id
            {
                return Err(Error::Carrier(format!(
                    "carrier pair {pair:?} disagrees with its graph record"
                )));
            }
            referenced_candidates.extend(
                record
                    .candidate_table_refs
                    .iter()
                    .map(|value| value.as_str().to_owned()),
            );
        }
        let candidate_table_ids = candidate_sets
            .iter()
            .map(|row| row.id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        if referenced_candidates != candidate_table_ids {
            return Err(Error::Candidate(
                "candidate-table sections and graph references are not bijective".into(),
            ));
        }
        Ok(())
    }

    pub fn authenticated_snapshot(
        &self,
        candidate_sets: Vec<GraphCandidateSetV1>,
    ) -> Result<AuthenticatedGraphSnapshotV1> {
        let mut packages = self
            .records
            .iter()
            .filter_map(|record| match record.source_id.0.defining_principal() {
                Some(principal @ Principal::Package { .. }) => Some(principal.clone()),
                Some(Principal::Root { .. }) | None => None,
                Some(_) => None,
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        packages.sort_by_key(|package| {
            capsec_semantics::canonical::to_jcs_bytes(
                &serde_json::to_value(package).expect("principal serializes"),
            )
            .expect("principal canonicalizes")
        });
        let nodes = self
            .records
            .iter()
            .map(|record| {
                Ok(GraphNodeV1 {
                    source_id: record
                        .source_id
                        .0
                        .encode()
                        .map_err(|error| Error::Identity(error.to_string()))?,
                    source_integrity: record.source_integrity.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut edges = self
            .records
            .iter()
            .flat_map(|record| {
                record.edges.iter().map(move |edge| {
                    Ok(GraphEdgeV1 {
                        requester: record
                            .source_id
                            .0
                            .encode()
                            .map_err(|error| Error::Identity(error.to_string()))?,
                        specifier: edge.specifier.clone(),
                        resolution_kind: match edge.resolution_kind {
                            ResolutionKind::EsmStatic => GraphResolutionKindV1::EsmStatic,
                            ResolutionKind::DynamicImport => GraphResolutionKindV1::DynamicImport,
                            ResolutionKind::CommonJsRequire => {
                                GraphResolutionKindV1::CommonJsRequire
                            }
                            ResolutionKind::Entry => {
                                return Err(Error::Identity(
                                    "entry resolution kind cannot appear as an edge".into(),
                                ));
                            }
                        },
                        conditions: edge
                            .conditions
                            .names()
                            .map(|name| {
                                NonEmptyString::new(name)
                                    .expect("validated condition remains non-empty")
                            })
                            .collect(),
                        attributes: edge.attributes.entries().clone(),
                        target: edge
                            .target
                            .0
                            .encode()
                            .map_err(|error| Error::Identity(error.to_string()))?,
                    })
                })
            })
            .collect::<Result<Vec<_>>>()?;
        edges.sort_by_key(|edge| {
            capsec_semantics::canonical::to_jcs_bytes(
                &serde_json::to_value(edge).expect("edge serializes"),
            )
            .expect("edge canonicalizes")
        });
        let snapshot = AuthenticatedGraphSnapshotV1 {
            schema: AUTHENTICATED_GRAPH_SNAPSHOT_SCHEMA_V1.into(),
            entry: GraphEntryDesignationV1 {
                name: "main".into(),
                source_id: self
                    .entry
                    .0
                    .encode()
                    .map_err(|error| Error::Identity(error.to_string()))?,
            },
            nodes,
            packages,
            edges,
            candidate_sets,
        };
        snapshot
            .validate()
            .map_err(|error| Error::Identity(error.to_string()))?;
        Ok(snapshot)
    }
}

fn validate_edges(edges: &[EmbeddedModuleEdgeV1]) -> Result<()> {
    let mut previous: Option<Vec<u8>> = None;
    for edge in edges {
        if edge.specifier.as_str().trim().is_empty()
            || edge.resolution_kind == ResolutionKind::Entry
        {
            return Err(Error::Contract(
                "embedded graph edge request is invalid".into(),
            ));
        }
        let conditions = edge.conditions.names().collect::<Vec<_>>();
        if conditions.is_empty()
            || conditions.windows(2).any(|pair| pair[0] >= pair[1])
            || conditions
                .iter()
                .any(|name| name.is_empty() || *name == "default")
        {
            return Err(Error::Contract(
                "edge conditions must be sorted, unique, and canonical".into(),
            ));
        }
        let required = ConditionSet::for_kind(edge.resolution_kind);
        if required
            .names()
            .any(|required| conditions.binary_search(&required).is_err())
        {
            return Err(Error::Contract(
                "edge conditions omit a required resolution condition".into(),
            ));
        }
        let attributes = edge.attributes.entries();
        if attributes
            .iter()
            .any(|(key, value)| key != "type" || value != "json")
        {
            return Err(Error::Contract(
                "edge import attributes are unsupported".into(),
            ));
        }
        let value =
            serde_json::to_value(edge).map_err(|error| Error::Contract(error.to_string()))?;
        let key = capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| Error::Contract(error.to_string()))?;
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return Err(Error::Contract(
                "edges must be strictly ordered by canonical request bytes".into(),
            ));
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_sorted_unique_nonempty(values: &[NonEmptyString], label: &str) -> Result<()> {
    if values
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(Error::Contract(format!(
            "{label} must be strictly ordered and unique"
        )));
    }
    Ok(())
}

fn validate_virtual_path(path: &str) -> Result<()> {
    if !path.starts_with("/app/")
        || path.contains('\0')
        || path
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(Error::Contract(format!(
            "virtual source path {path:?} is not canonical under /app"
        )));
    }
    Ok(())
}

fn percent_encode_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsec_semantics::model::{PackageLocator, PathComponent, Principal};

    fn digest(tag: u8) -> Digest {
        super::super::artifact::digest_bytes("ibex:embedded-graph-test:1", &[tag]).unwrap()
    }

    fn source_ids() -> Vec<CanonicalSourceId> {
        let root = Principal::Root {
            identity: NonEmptyString::new("portable-project").unwrap(),
        };
        let package = Principal::Package {
            name: NonEmptyString::new("dep").unwrap(),
            locator: PackageLocator::new("dep@1.0.0").unwrap(),
            integrity: digest(b'P'),
        };
        let mut sources = vec![
            CanonicalSourceId(
                super::super::identity::SourceId::file(
                    root,
                    vec![PathComponent::utf8("entry.mjs").unwrap()],
                )
                .unwrap(),
            ),
            CanonicalSourceId(
                super::super::identity::SourceId::file(
                    package,
                    vec![PathComponent::utf8("index.js").unwrap()],
                )
                .unwrap(),
            ),
            CanonicalSourceId(
                super::super::identity::SourceId::builtin("ibex-runtime", "exact:fs").unwrap(),
            ),
            CanonicalSourceId(
                super::super::identity::SourceId::synthetic("fixture-session", "ibex:stdin")
                    .unwrap(),
            ),
        ];
        sources.sort_by_key(|source| source.0.encode().unwrap());
        sources
    }

    fn fixture() -> (
        EmbeddedModuleGraphV1,
        BTreeMap<String, EmbeddedCarrierFactV1>,
    ) {
        let sources = source_ids();
        let entry = sources
            .iter()
            .find(|source| {
                matches!(
                    &source.0,
                    super::super::identity::SourceId::File {
                        principal: Principal::Root { .. },
                        ..
                    }
                )
            })
            .unwrap()
            .clone();
        let mut records = sources
            .iter()
            .enumerate()
            .map(|(index, source_id)| {
                let pair = NonEmptyString::new(format!("module-{index:02}")).unwrap();
                let entry_id = NonEmptyString::new(format!("entry-{index:02}")).unwrap();
                EmbeddedModuleRecordV1 {
                    source_id: source_id.clone(),
                    source_integrity: digest(b'A' + index as u8),
                    semantic_digest: digest(b'K' + index as u8),
                    carrier: EmbeddedCarrierBindingV1 {
                        pair_id: pair,
                        entry_id,
                    },
                    edges: Vec::new(),
                    virtual_source: VirtualSourceLabelV1::new(format!(
                        "/app/modules/{index:02}/module name.js"
                    ))
                    .unwrap(),
                    candidate_table_refs: Vec::new(),
                }
            })
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.source_id.0.encode().unwrap());
        let target = records
            .iter()
            .find(|record| {
                matches!(
                    &record.source_id.0,
                    super::super::identity::SourceId::File {
                        principal: Principal::Package { .. },
                        ..
                    }
                )
            })
            .unwrap()
            .source_id
            .clone();
        records
            .iter_mut()
            .find(|record| record.source_id == entry)
            .unwrap()
            .edges
            .push(EmbeddedModuleEdgeV1 {
                specifier: NonEmptyString::new("dep").unwrap(),
                resolution_kind: ResolutionKind::EsmStatic,
                conditions: ConditionSet::for_kind(ResolutionKind::EsmStatic),
                attributes: ImportAttributes::default(),
                target,
            });
        let carriers = records
            .iter()
            .map(|record| {
                (
                    record.carrier.pair_id.as_str().to_owned(),
                    EmbeddedCarrierFactV1 {
                        source_id: record.source_id.clone(),
                        semantic_digest: record.semantic_digest.clone(),
                        entry_id: record.carrier.entry_id.clone(),
                    },
                )
            })
            .collect();
        let mut graph = EmbeddedModuleGraphV1 {
            schema: EMBEDDED_MODULE_GRAPH_SCHEMA_V1.into(),
            graph_identity: digest(b'Z'),
            entry,
            records,
        };
        graph.graph_identity = graph
            .authenticated_snapshot(Vec::new())
            .unwrap()
            .identity()
            .unwrap();
        (graph, carriers)
    }

    #[test]
    fn all_source_id_variants_round_trip_without_host_paths() {
        let (graph, carriers) = fixture();
        let bytes = graph.canonical_bytes().unwrap();
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/embedded-module-graph-v1.golden.json"
        ))
        .unwrap();
        assert_eq!(serde_json::to_value(&graph).unwrap(), golden["graph"]);
        let admitted = EmbeddedModuleGraphV1::decode_and_admit(&bytes, &carriers, &[]).unwrap();
        assert_eq!(admitted, graph);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("/Users/") && !text.contains("checkout"));
        assert!(text.contains("file:///app/modules/00/module%20name.js"));
    }

    #[test]
    fn carrier_candidate_and_virtual_label_drift_refuse() {
        let (graph, mut carriers) = fixture();
        let bytes = graph.canonical_bytes().unwrap();
        carriers.remove("module-00");
        assert!(matches!(
            EmbeddedModuleGraphV1::decode_and_admit(&bytes, &carriers, &[]),
            Err(Error::Carrier(_))
        ));

        let (mut graph, carriers) = fixture();
        graph.records[0].candidate_table_refs = vec![NonEmptyString::new("computed-0").unwrap()];
        let bytes = graph.canonical_bytes().unwrap();
        assert!(matches!(
            EmbeddedModuleGraphV1::decode_and_admit(&bytes, &carriers, &[]),
            Err(Error::Candidate(_))
        ));

        let (mut graph, _) = fixture();
        graph.records[0].virtual_source.import_meta_url = "file:///host/secret.js".into();
        assert!(matches!(graph.canonical_bytes(), Err(Error::Contract(_))));
    }
}
