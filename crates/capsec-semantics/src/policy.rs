//! Strict canonical review-policy ingestion.
//!
//! A production policy is authenticated as a complete typed artifact before
//! it can be projected into an armed snapshot. Field-picking from generic JSON
//! would allow stale vocabulary or registry semantics to cross that boundary.
//! @ref LLP 0021#policy-forms-and-digests

use serde::{Deserialize, Serialize};

use crate::canonical::to_jcs_bytes;
use crate::digest::{compute_domain_digest, POLICY_DOMAIN};
use crate::model::{
    AuthoritySelector, Digest, LogicalRoot, NonEmptyString, PackageLocator, PathComponent,
    Principal, StableId,
};
use crate::registry::{DefinitionSet, Globality, Lifecycle, PROFILE, SEMANTIC_CORE};
use crate::strict_json::parse_slice_strict;
use crate::{Error, Result};

pub const POLICY_SCHEMA: &str = "ibex/capsec-policy/2";

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
    pub graph_identity: Digest,
    pub entry_identity: CanonicalEntryIdentity,
    pub target_profile: CanonicalTargetProfile,
    pub mount_profile: CanonicalMountProfile,
    pub root_ceiling: Vec<CanonicalAuthorityRow>,
    pub computed_candidates: CanonicalComputedCandidates,
    pub principals: Vec<CanonicalPrincipalPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalEntryIdentity {
    pub root: CanonicalEntryRoot,
    pub components: Vec<PathComponent>,
    pub source_integrity: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanonicalEntryRoot {
    Project,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CanonicalTargetProfile {
    Source {
        profile: NonEmptyString,
    },
    Compiled {
        profile: NonEmptyString,
        #[serde(rename = "targetTriple")]
        target_triple: NonEmptyString,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanonicalMountProfile {
    ProjectV1,
    CompiledAppWorkV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalComputedCandidates {
    pub schema: String,
    pub declarations: Vec<CanonicalCandidateDeclaration>,
    pub package_closure_opt_ins: Vec<CanonicalPackageClosureOptIn>,
    pub materialized_sites: Vec<CanonicalMaterializedCandidateSite>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalCandidateDeclaration {
    pub requester: NonEmptyString,
    pub label: StableId,
    pub specifiers: Vec<NonEmptyString>,
    pub package_closures: Vec<PackageLocator>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPackageClosureOptIn {
    pub package: PackageLocator,
    pub provenance: Vec<AuthorityProvenance>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalMaterializedCandidateSite {
    pub requester: NonEmptyString,
    pub label: StableId,
    pub candidates: Vec<NonEmptyString>,
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

        if self.entry_identity.components.is_empty()
            || self
                .entry_identity
                .components
                .iter()
                .any(|component| !component.is_canonical())
        {
            return refused("canonical policy entry identity is not a normalized project path");
        }
        if let CanonicalTargetProfile::Compiled { target_triple, .. } = &self.target_profile {
            let triple = target_triple.as_str();
            if !triple.contains('-')
                || !triple
                    .bytes()
                    .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
            {
                return refused("canonical policy target triple is not normalized");
            }
        }
        // @ref LLP 0023#13-compiled-mount-profile-app-optional-work-and-unset-cwd
        match (&self.target_profile, self.mount_profile) {
            (CanonicalTargetProfile::Source { .. }, CanonicalMountProfile::ProjectV1)
            | (CanonicalTargetProfile::Compiled { .. }, CanonicalMountProfile::CompiledAppWorkV1) =>
                {}
            _ => return refused("canonical policy target and mount profiles disagree"),
        }
        validate_rows(&self.root_ceiling, definitions, true, false, "root ceiling")?;
        if matches!(self.target_profile, CanonicalTargetProfile::Compiled { .. }) {
            validate_compiled_roots(&self.root_ceiling, "root ceiling")?;
        }
        validate_computed_candidates(&self.computed_candidates)?;

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
            if matches!(self.target_profile, CanonicalTargetProfile::Compiled { .. }) {
                validate_compiled_roots(&row.floor, "floor")?;
                validate_compiled_roots(&row.denials, "denials")?;
                validate_compiled_roots(&row.escalation_ceiling, "escalation ceiling")?;
            }
            require_sorted_unique(&row.imports.builtins, "builtin imports")?;
            require_sorted_unique(&row.imports.packages, "package imports")?;
            require_sorted_unique(&row.endowments, "endowments")?;
        }
        Ok(())
    }
}

fn validate_compiled_roots(rows: &[CanonicalAuthorityRow], label: &str) -> Result<()> {
    for row in rows {
        for root in [
            LogicalRoot::Project,
            LogicalRoot::Package,
            LogicalRoot::Home,
            LogicalRoot::Tmp,
        ] {
            if row.authority.resource.contains_logical_root(root) {
                return refused(format!(
                    "compiled {label} references the unavailable {root:?} logical root; use app, work, or an explicit absolute binding"
                ));
            }
        }
    }
    Ok(())
}

fn validate_computed_candidates(candidates: &CanonicalComputedCandidates) -> Result<()> {
    require(
        "computedCandidates.schema",
        &candidates.schema,
        "ibex/computed-candidate-manifest/1",
    )?;
    require_sorted_by_canonical(
        &candidates.declarations,
        |row| serde_json::to_value(row),
        "computed-candidate declarations",
    )?;
    require_sorted_by_canonical(
        &candidates.package_closure_opt_ins,
        |row| serde_json::to_value(row),
        "computed-candidate package closure opt-ins",
    )?;
    require_sorted_by_canonical(
        &candidates.materialized_sites,
        |row| serde_json::to_value(row),
        "materialized computed-candidate sites",
    )?;

    let opt_ins = candidates
        .package_closure_opt_ins
        .iter()
        .map(|row| row.package.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for row in &candidates.package_closure_opt_ins {
        if row.provenance.is_empty() {
            return refused("computed-candidate package opt-in has no provenance");
        }
        require_sorted_by_canonical(
            &row.provenance,
            |entry| serde_json::to_value(entry),
            "computed-candidate package opt-in provenance",
        )?;
    }
    let materialized = candidates
        .materialized_sites
        .iter()
        .map(|row| ((row.requester.as_str(), row.label.as_str()), row))
        .collect::<std::collections::BTreeMap<_, _>>();
    if materialized.len() != candidates.materialized_sites.len()
        || materialized.len() != candidates.declarations.len()
    {
        return refused(
            "computed-candidate requester labels must be unique and fully materialized",
        );
    }
    let mut declaration_keys = std::collections::BTreeSet::new();
    for declaration in &candidates.declarations {
        require_sorted_unique(&declaration.specifiers, "computed-candidate specifiers")?;
        require_sorted_unique(
            &declaration.package_closures,
            "computed-candidate package closures",
        )?;
        if !declaration_keys.insert((declaration.requester.as_str(), declaration.label.as_str())) {
            return refused("computed-candidate declarations repeat a requester label");
        }
        if declaration
            .package_closures
            .iter()
            .any(|package| !opt_ins.contains(package.as_str()))
        {
            return refused("computed-candidate package closure lacks package opt-in");
        }
        let row = materialized
            .get(&(declaration.requester.as_str(), declaration.label.as_str()))
            .ok_or_else(|| {
                Error::ArmRefused("computed-candidate site is not materialized".into())
            })?;
        require_sorted_unique(&row.candidates, "materialized computed candidates")?;
        if declaration
            .specifiers
            .iter()
            .any(|specifier| row.candidates.binary_search(specifier).is_err())
        {
            return refused("materialized computed-candidate site omits a declared specifier");
        }
    }
    Ok(())
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
