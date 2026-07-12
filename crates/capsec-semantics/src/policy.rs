//! Strict canonical review-policy ingestion.
//!
//! A production policy is authenticated as a complete typed artifact before
//! it can be projected into an armed snapshot. Field-picking from generic JSON
//! would allow stale vocabulary or registry semantics to cross that boundary.
//! @ref LLP 0021#policy-forms-and-digests

use serde::{Deserialize, Serialize};

use crate::canonical::to_jcs_bytes;
use crate::digest::{compute_domain_digest, POLICY_DOMAIN};
use crate::model::{AuthoritySelector, Digest, NonEmptyString, Principal, StableId};
use crate::registry::{DefinitionSet, Globality, Lifecycle, PROFILE, SEMANTIC_CORE};
use crate::strict_json::parse_slice_strict;
use crate::{Error, Result};

pub const POLICY_SCHEMA: &str = "ibex/capsec-policy/1";

#[derive(Clone, Debug)]
pub struct ExpectedPolicyIdentity {
    pub profile: String,
    pub semantic_core: String,
    pub vocab_digest: Digest,
    pub registry_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalPolicy {
    pub policy_schema: String,
    pub caps_vocab: String,
    pub semantic_core: String,
    pub vocab_digest: Digest,
    pub registry_digest: Digest,
    pub policy_digest: Digest,
    pub purpose: String,
    pub mode: String,
    pub principals: Vec<CanonicalPrincipalPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalPrincipalPolicy {
    pub principal: Principal,
    pub floor: Vec<CanonicalAuthorityRow>,
    pub denials: Vec<CanonicalAuthorityRow>,
    pub escalation_ceiling: Vec<CanonicalAuthorityRow>,
    pub imports: CanonicalImports,
    pub endowments: Vec<StableId>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalAuthorityRow {
    pub authority: AuthoritySelector,
    pub provenance: Vec<AuthorityProvenance>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProvenanceKind {
    Direct,
    ImportSite,
    Delegation,
    MacroExpansion,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityProvenance {
    pub kind: ProvenanceKind,
    pub source: NonEmptyString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<StableId>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalImports {
    pub builtins: Vec<NonEmptyString>,
    pub packages: Vec<NonEmptyString>,
}

impl CanonicalPolicy {
    pub fn load(
        bytes: &[u8],
        expected: &ExpectedPolicyIdentity,
        definitions: &DefinitionSet,
    ) -> Result<Self> {
        let value = parse_slice_strict(bytes)?;
        let computed = compute_domain_digest(POLICY_DOMAIN, &value, &["policyDigest".to_string()])?;
        let policy: Self = serde_json::from_value(value)
            .map_err(|error| Error::InvalidModel(format!("invalid canonical policy: {error}")))?;
        policy.validate(expected, definitions, &computed)?;
        Ok(policy)
    }

    pub fn validate(
        &self,
        expected: &ExpectedPolicyIdentity,
        definitions: &DefinitionSet,
        computed_digest: &str,
    ) -> Result<()> {
        require("policySchema", &self.policy_schema, POLICY_SCHEMA)?;
        require("capsVocab", &self.caps_vocab, PROFILE)?;
        require("semanticCore", &self.semantic_core, SEMANTIC_CORE)?;
        require("capsVocab", &self.caps_vocab, &expected.profile)?;
        require("semanticCore", &self.semantic_core, &expected.semantic_core)?;
        if self.vocab_digest != expected.vocab_digest {
            return refused("canonical policy vocabulary digest is stale");
        }
        if self.registry_digest != expected.registry_digest {
            return refused("canonical policy registry digest is stale");
        }
        if self.policy_digest.as_str() != computed_digest {
            return refused("canonical policy digest is stale or tampered");
        }
        require("purpose", &self.purpose, "production")?;
        require("mode", &self.mode, "enforce")?;

        require_sorted_by_canonical(
            &self.principals,
            |row| serde_json::to_value(&row.principal),
            "policy principals",
        )?;
        for row in &self.principals {
            if !row.principal.is_package() {
                return refused("canonical policy may contain only package principals");
            }
            validate_rows(&row.floor, definitions, true, false, "floor")?;
            validate_rows(&row.denials, definitions, false, false, "denials")?;
            validate_rows(
                &row.escalation_ceiling,
                definitions,
                true,
                true,
                "escalation ceiling",
            )?;
            require_sorted_unique(&row.imports.builtins, "builtin imports")?;
            require_sorted_unique(&row.imports.packages, "package imports")?;
            require_sorted_unique(&row.endowments, "endowments")?;
        }
        Ok(())
    }
}

fn validate_rows(
    rows: &[CanonicalAuthorityRow],
    definitions: &DefinitionSet,
    positive: bool,
    dynamic: bool,
    label: &str,
) -> Result<()> {
    require_sorted_by_canonical(rows, |row| serde_json::to_value(&row.authority), label)?;
    for row in rows {
        if row.provenance.is_empty() {
            return refused(format!("{label} authority has no provenance"));
        }
        require_sorted_by_canonical(
            &row.provenance,
            |entry| serde_json::to_value(entry),
            "authority provenance",
        )?;
        let definition = definitions.validate_selector(&row.authority)?;
        if positive && definition.lifecycle != Lifecycle::Authorable {
            return refused(format!("{label} references a non-authorable action"));
        }
        if dynamic
            && (!definition.channels.dynamic
                || definition.static_only
                || definition.globality == Globality::Terminal)
        {
            return refused("escalation ceiling references a closed dynamic channel");
        }
    }
    Ok(())
}

fn require_sorted_by_canonical<T>(
    rows: &[T],
    value: impl Fn(&T) -> serde_json::Result<serde_json::Value>,
    label: &str,
) -> Result<()> {
    let keys = rows
        .iter()
        .map(|row| {
            let value = value(row).map_err(|error| Error::InvalidCanonicalData {
                path: label.to_owned(),
                message: error.to_string(),
            })?;
            to_jcs_bytes(&value)
        })
        .collect::<Result<Vec<_>>>()?;
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return refused(format!("{label} must be canonically sorted and unique"));
    }
    Ok(())
}

fn require_sorted_unique<T: Ord>(rows: &[T], label: &str) -> Result<()> {
    if rows.windows(2).any(|pair| pair[0] >= pair[1]) {
        return refused(format!("{label} must be sorted and unique"));
    }
    Ok(())
}

fn require(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        refused(format!("canonical policy {field} differs from {expected}"))
    }
}

fn refused<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::ArmRefused(message.into()))
}
