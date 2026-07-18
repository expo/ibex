//! Canonical authenticated module-graph snapshot and digest projection.
//!
//! Policy, prepared carriers, and executable envelopes bind this one
//! path-independent inventory rather than independently hashing partial graphs.
//! @ref LLP 0029#1-command-surface-and-producer-pipeline

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::digest::compute_domain_digest;
use crate::error::{Error, Result};
use crate::model::{Digest, NonEmptyString, PathComponent, Principal};

pub const AUTHENTICATED_GRAPH_SNAPSHOT_SCHEMA_V1: &str = "ibex/authenticated-graph-snapshot/1";
pub const AUTHENTICATED_GRAPH_SNAPSHOT_DOMAIN_V1: &str = "ibex/authenticated-graph-snapshot/1";
const SOURCE_ID_PREFIX_V1: &str = "ibex-source-id-v1:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticatedGraphSnapshotV1 {
    pub schema: String,
    pub entry: GraphEntryDesignationV1,
    pub nodes: Vec<GraphNodeV1>,
    pub packages: Vec<Principal>,
    pub edges: Vec<GraphEdgeV1>,
    pub candidate_sets: Vec<GraphCandidateSetV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphEntryDesignationV1 {
    pub name: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphNodeV1 {
    pub source_id: String,
    pub source_integrity: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GraphResolutionKindV1 {
    EsmStatic,
    DynamicImport,
    CommonJsRequire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphEdgeV1 {
    pub requester: String,
    pub specifier: NonEmptyString,
    pub resolution_kind: GraphResolutionKindV1,
    pub conditions: Vec<NonEmptyString>,
    pub attributes: BTreeMap<String, String>,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphCandidateSetV1 {
    pub id: NonEmptyString,
    pub requester: String,
    pub label: NonEmptyString,
    pub candidates: Vec<NonEmptyString>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum PortableSourceIdV1 {
    File {
        principal: Principal,
        path: Vec<PathComponent>,
    },
    Builtin {
        domain: NonEmptyString,
        source_key: NonEmptyString,
    },
    Synthetic {
        session_identity: NonEmptyString,
        source_identity: NonEmptyString,
    },
}

impl AuthenticatedGraphSnapshotV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        crate::canonical::to_jcs_bytes(&serde_json::to_value(self).map_err(|error| {
            Error::InvalidCanonicalData {
                path: "$".into(),
                message: error.to_string(),
            }
        })?)
    }

    pub fn identity(&self) -> Result<Digest> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(|error| Error::InvalidCanonicalData {
            path: "$".into(),
            message: error.to_string(),
        })?;
        Digest::new(compute_domain_digest(
            AUTHENTICATED_GRAPH_SNAPSHOT_DOMAIN_V1,
            &value,
            &[],
        )?)
        .map_err(|message| Error::InvalidCanonicalData {
            path: "$".into(),
            message,
        })
    }

    pub fn decode_strict(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|error| Error::InvalidCanonicalData {
            path: "$".into(),
            message: error.to_string(),
        })?;
        let value = crate::strict_json::parse_strict(text)?;
        if crate::canonical::to_jcs_bytes(&value)? != bytes {
            return invalid("$", "authenticated graph snapshot is not JCS");
        }
        let snapshot: Self =
            serde_json::from_value(value).map_err(|error| Error::InvalidCanonicalData {
                path: "$".into(),
                message: error.to_string(),
            })?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != AUTHENTICATED_GRAPH_SNAPSHOT_SCHEMA_V1 {
            return invalid(
                "$/schema",
                "unsupported authenticated graph snapshot schema",
            );
        }
        if self.entry.name != "main" {
            return invalid("$/entry/name", "v1 requires the main entry designation");
        }
        validate_source_id_wire(&self.entry.source_id)?;
        if self.nodes.is_empty() {
            return invalid("$/nodes", "authenticated graph snapshot has no nodes");
        }

        let mut sources = BTreeSet::new();
        let mut package_principals = BTreeSet::new();
        let mut previous_source: Option<&str> = None;
        for node in &self.nodes {
            if previous_source.is_some_and(|previous| previous >= node.source_id.as_str()) {
                return invalid("$/nodes", "nodes must be strictly ordered by SourceId");
            }
            previous_source = Some(&node.source_id);
            let decoded = validate_source_id_wire(&node.source_id)?;
            if let PortableSourceIdV1::File {
                principal: Principal::Package { .. },
                ..
            } = decoded
            {
                package_principals.insert(decoded_principal(&decoded).unwrap().clone());
            }
            sources.insert(node.source_id.as_str());
        }
        if !sources.contains(self.entry.source_id.as_str()) {
            return invalid(
                "$/entry/sourceId",
                "entry SourceId is absent from graph nodes",
            );
        }

        let mut previous_package: Option<Vec<u8>> = None;
        let mut declared_packages = BTreeSet::new();
        for package in &self.packages {
            if !matches!(package, Principal::Package { .. }) {
                return invalid(
                    "$/packages",
                    "package inventory contains a non-package principal",
                );
            }
            let bytes = crate::canonical::to_jcs_bytes(&serde_json::to_value(package).map_err(
                |error| Error::InvalidCanonicalData {
                    path: "$/packages".into(),
                    message: error.to_string(),
                },
            )?)?;
            if previous_package
                .as_ref()
                .is_some_and(|previous| previous >= &bytes)
            {
                return invalid(
                    "$/packages",
                    "packages must be strictly ordered by canonical bytes",
                );
            }
            previous_package = Some(bytes);
            declared_packages.insert(package.clone());
        }
        if declared_packages != package_principals {
            return invalid(
                "$/packages",
                "package inventory must exactly equal package principals in node SourceIds",
            );
        }

        validate_edges(&self.edges, &sources)?;
        validate_candidate_sets(&self.candidate_sets, &sources)?;
        Ok(())
    }
}

pub fn encode_source_id_value(value: &serde_json::Value) -> Result<String> {
    let source: PortableSourceIdV1 =
        serde_json::from_value(value.clone()).map_err(|error| Error::InvalidCanonicalData {
            path: "sourceId".into(),
            message: error.to_string(),
        })?;
    validate_decoded_source_id(&source)?;
    let canonical = crate::canonical::to_jcs_bytes(value)?;
    Ok(format!(
        "{SOURCE_ID_PREFIX_V1}{}",
        URL_SAFE_NO_PAD.encode(canonical)
    ))
}

fn validate_source_id_wire(encoded: &str) -> Result<PortableSourceIdV1> {
    let payload =
        encoded
            .strip_prefix(SOURCE_ID_PREFIX_V1)
            .ok_or_else(|| Error::InvalidCanonicalData {
                path: "sourceId".into(),
                message: "unsupported SourceId wire version".into(),
            })?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Error::InvalidCanonicalData {
            path: "sourceId".into(),
            message: "SourceId payload is not canonical base64url".into(),
        })?;
    if URL_SAFE_NO_PAD.encode(&bytes) != payload {
        return invalid("sourceId", "SourceId payload is not canonical base64url");
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| Error::InvalidCanonicalData {
        path: "sourceId".into(),
        message: error.to_string(),
    })?;
    let value = crate::strict_json::parse_strict(text)?;
    if crate::canonical::to_jcs_bytes(&value)? != bytes {
        return invalid("sourceId", "SourceId payload is not JCS");
    }
    let source: PortableSourceIdV1 =
        serde_json::from_value(value).map_err(|error| Error::InvalidCanonicalData {
            path: "sourceId".into(),
            message: error.to_string(),
        })?;
    validate_decoded_source_id(&source)?;
    Ok(source)
}

fn validate_decoded_source_id(source: &PortableSourceIdV1) -> Result<()> {
    match source {
        PortableSourceIdV1::File { principal, path } => {
            if !matches!(
                principal,
                Principal::Root { .. } | Principal::Package { .. }
            ) || path.is_empty()
                || path.iter().any(|component| !component.is_canonical())
            {
                return invalid(
                    "sourceId",
                    "file SourceId requires a root/package principal and canonical path",
                );
            }
        }
        PortableSourceIdV1::Builtin { .. } | PortableSourceIdV1::Synthetic { .. } => {}
    }
    Ok(())
}

fn decoded_principal(source: &PortableSourceIdV1) -> Option<&Principal> {
    match source {
        PortableSourceIdV1::File { principal, .. } => Some(principal),
        PortableSourceIdV1::Builtin { .. } | PortableSourceIdV1::Synthetic { .. } => None,
    }
}

fn validate_edges(edges: &[GraphEdgeV1], sources: &BTreeSet<&str>) -> Result<()> {
    let mut previous: Option<Vec<u8>> = None;
    for edge in edges {
        validate_source_id_wire(&edge.requester)?;
        validate_source_id_wire(&edge.target)?;
        if !sources.contains(edge.requester.as_str()) || !sources.contains(edge.target.as_str()) {
            return invalid("$/edges", "edge endpoint is absent from graph nodes");
        }
        validate_conditions(edge)?;
        if edge
            .attributes
            .iter()
            .any(|(key, value)| key != "type" || value != "json")
        {
            return invalid("$/edges/attributes", "unsupported import attributes");
        }
        let bytes =
            crate::canonical::to_jcs_bytes(&serde_json::to_value(edge).map_err(|error| {
                Error::InvalidCanonicalData {
                    path: "$/edges".into(),
                    message: error.to_string(),
                }
            })?)?;
        if previous.as_ref().is_some_and(|previous| previous >= &bytes) {
            return invalid(
                "$/edges",
                "edges must be strictly ordered by canonical bytes",
            );
        }
        previous = Some(bytes);
    }
    Ok(())
}

fn validate_conditions(edge: &GraphEdgeV1) -> Result<()> {
    if edge.conditions.is_empty()
        || edge
            .conditions
            .windows(2)
            .any(|pair| pair[0].as_str() >= pair[1].as_str())
        || edge
            .conditions
            .iter()
            .any(|condition| condition.as_str() == "default")
    {
        return invalid(
            "$/edges/conditions",
            "conditions must be sorted, unique, and omit default",
        );
    }
    let required = match edge.resolution_kind {
        GraphResolutionKindV1::CommonJsRequire => ["node", "require"],
        GraphResolutionKindV1::EsmStatic | GraphResolutionKindV1::DynamicImport => {
            ["import", "node"]
        }
    };
    if required.iter().any(|required| {
        edge.conditions
            .binary_search_by(|condition| condition.as_str().cmp(required))
            .is_err()
    }) {
        return invalid("$/edges/conditions", "required conditions are absent");
    }
    Ok(())
}

fn validate_candidate_sets(rows: &[GraphCandidateSetV1], sources: &BTreeSet<&str>) -> Result<()> {
    let mut previous: Option<Vec<u8>> = None;
    let mut ids = BTreeSet::new();
    for row in rows {
        validate_source_id_wire(&row.requester)?;
        if !sources.contains(row.requester.as_str()) {
            return invalid(
                "$/candidateSets/requester",
                "candidate requester is absent from graph nodes",
            );
        }
        if !ids.insert(row.id.as_str())
            || row
                .candidates
                .windows(2)
                .any(|pair| pair[0].as_str() >= pair[1].as_str())
        {
            return invalid(
                "$/candidateSets",
                "candidate rows and candidates must be ordered and unique",
            );
        }
        let bytes =
            crate::canonical::to_jcs_bytes(&serde_json::to_value(row).map_err(|error| {
                Error::InvalidCanonicalData {
                    path: "$/candidateSets".into(),
                    message: error.to_string(),
                }
            })?)?;
        if previous.as_ref().is_some_and(|previous| previous >= &bytes) {
            return invalid(
                "$/candidateSets",
                "candidate sets must be strictly ordered by canonical bytes",
            );
        }
        previous = Some(bytes);
    }
    Ok(())
}

fn invalid<T>(path: &str, message: &str) -> Result<T> {
    Err(Error::InvalidCanonicalData {
        path: path.into(),
        message: message.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(tag: u8) -> Digest {
        let value = serde_json::json!({"tag": tag});
        Digest::new(compute_domain_digest("ibex:graph-snapshot-test:1", &value, &[]).unwrap())
            .unwrap()
    }

    fn source(value: serde_json::Value) -> String {
        encode_source_id_value(&value).unwrap()
    }

    fn fixture() -> AuthenticatedGraphSnapshotV1 {
        let root = serde_json::json!({"kind":"root","identity":"portable-project"});
        let package = Principal::Package {
            name: NonEmptyString::new("dep").unwrap(),
            locator: crate::model::PackageLocator::new("dep@1.0.0").unwrap(),
            integrity: digest(9),
        };
        let entry = source(serde_json::json!({
            "kind":"file",
            "principal": root,
            "path":[{"encoding":"utf8","value":"entry.mjs"}]
        }));
        let dependency = source(serde_json::json!({
            "kind":"file",
            "principal": package,
            "path":[{"encoding":"utf8","value":"index.js"}]
        }));
        let builtin = source(serde_json::json!({
            "kind":"builtin",
            "domain":"ibex-runtime",
            "source_key":"exact:fs"
        }));
        let mut nodes = vec![entry.clone(), dependency.clone(), builtin]
            .into_iter()
            .enumerate()
            .map(|(index, source_id)| GraphNodeV1 {
                source_id,
                source_integrity: digest(20 + index as u8),
            })
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.source_id.cmp(&right.source_id));
        let mut packages = vec![package];
        packages.sort_by_key(|package| {
            crate::canonical::to_jcs_bytes(&serde_json::to_value(package).unwrap()).unwrap()
        });
        AuthenticatedGraphSnapshotV1 {
            schema: AUTHENTICATED_GRAPH_SNAPSHOT_SCHEMA_V1.into(),
            entry: GraphEntryDesignationV1 {
                name: "main".into(),
                source_id: entry.clone(),
            },
            nodes,
            packages,
            edges: vec![GraphEdgeV1 {
                requester: entry.clone(),
                specifier: NonEmptyString::new("dep").unwrap(),
                resolution_kind: GraphResolutionKindV1::EsmStatic,
                conditions: ["import", "node"]
                    .into_iter()
                    .map(|value| NonEmptyString::new(value).unwrap())
                    .collect(),
                attributes: BTreeMap::new(),
                target: dependency,
            }],
            candidate_sets: vec![GraphCandidateSetV1 {
                id: NonEmptyString::new("computed-0000").unwrap(),
                requester: entry,
                label: NonEmptyString::new("plugin").unwrap(),
                candidates: ["dep", "node:path"]
                    .into_iter()
                    .map(|value| NonEmptyString::new(value).unwrap())
                    .collect(),
            }],
        }
    }

    #[test]
    fn deterministic_identity_and_strict_round_trip() {
        let snapshot = fixture();
        let bytes = snapshot.canonical_bytes().unwrap();
        assert_eq!(
            AuthenticatedGraphSnapshotV1::decode_strict(&bytes).unwrap(),
            snapshot
        );
        assert_eq!(snapshot.identity().unwrap(), snapshot.identity().unwrap());

        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/authenticated-graph-snapshot-v1.golden.json"
        ))
        .unwrap();
        let golden_snapshot: AuthenticatedGraphSnapshotV1 =
            serde_json::from_value(golden["snapshot"].clone()).unwrap();
        assert_eq!(
            golden_snapshot.identity().unwrap().as_str(),
            golden["expectedIdentity"].as_str().unwrap()
        );
    }

    #[test]
    fn package_edge_and_candidate_mutations_refuse() {
        let mut missing_package = fixture();
        missing_package.packages.clear();
        assert!(missing_package.validate().is_err());

        let mut alien_edge = fixture();
        alien_edge.edges[0].target = source(serde_json::json!({
            "kind":"synthetic",
            "session_identity":"session",
            "source_identity":"ibex:stdin"
        }));
        assert!(alien_edge.validate().is_err());

        let mut unordered = fixture();
        unordered.candidate_sets[0].candidates.reverse();
        assert!(unordered.validate().is_err());
    }
}
