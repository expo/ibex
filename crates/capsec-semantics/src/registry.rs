//! Product-provided capability definition validation.
//!
//! The semantic core deliberately does not compile Ibex action names into an
//! enum. A loaded, validated definition set is the only source of known
//! actions, so adding a future definition cannot make an old policy row match
//! by family or prefix. @ref LLP 0021#typed-resources-and-initial-vocabulary

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::canonical::DigestContract;
use crate::model::{
    ActionId, ClosedSurfaceClass, EnvironmentTarget, StdioSourceKind, StdioStream, StorageStore,
};
use crate::strict_json::parse_slice_strict;
use crate::{Error, Result};

pub const DEFINITIONS_SCHEMA: &str = "ibex/capsec-definitions/1";
pub const PROFILE: &str = "ibex/capsec/1";
pub const SEMANTIC_CORE: &str = "capsec/semantics/1";
pub const SELECTOR_SCHEMA: &str = "ibex/capsec-selector/1";
pub const OCCURRENCE_SCHEMA: &str = "ibex/capsec-occurrence/1";
pub const RULES_SCHEMA: &str = "ibex/capsec-rules/1";

const REQUIRED_CACHE_KEY_FIELDS: &[&str] = &[
    "action",
    "armedSnapshotDigest",
    "dynamicGeneration",
    "effectOwner",
    "handleGeneration",
    "negativeGeneration",
    "policyDigest",
    "principalSet",
    "registryDigest",
    "resourceCanonicalBytes",
    "stage",
    "vocabDigest",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapabilityDefinitionsDocument {
    pub definitions_schema: String,
    pub profile: String,
    pub semantic_core: String,
    pub definitions: Vec<CapabilityDefinition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CapabilityDefinition {
    pub id: ActionId,
    pub lifecycle: Lifecycle,
    pub stability: Stability,
    pub globality: Globality,
    pub resource_kinds: Vec<ResourceKind>,
    pub selector_schema: String,
    pub occurrence_schema: String,
    pub normalization_profile: String,
    pub channels: AuthorityChannels,
    pub static_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_constraints: Option<SelectorConstraints>,
    pub risk: Risk,
    pub description: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Lifecycle {
    Authorable,
    DenyOnly,
    Planned,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stability {
    Stable,
    Provisional,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Globality {
    Resource,
    SharedProcessRead,
    SharedProcessMutation,
    Terminal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    Camera,
    Clipboard,
    ClosedSurface,
    ConnectEndpoint,
    ConnectUnix,
    DeviceLocation,
    DnsQuery,
    EnvironmentName,
    Executable,
    FetchEndpoint,
    ListenInet,
    ListenUnix,
    Microphone,
    PathExact,
    PathTree,
    Stdio,
    StorageNamespace,
    SystemInfo,
}

impl ResourceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Camera => "camera",
            Self::Clipboard => "clipboard",
            Self::ClosedSurface => "closed-surface",
            Self::ConnectEndpoint => "connect-endpoint",
            Self::ConnectUnix => "connect-unix",
            Self::DeviceLocation => "device-location",
            Self::DnsQuery => "dns-query",
            Self::EnvironmentName => "environment-name",
            Self::Executable => "executable",
            Self::FetchEndpoint => "fetch-endpoint",
            Self::ListenInet => "listen-inet",
            Self::ListenUnix => "listen-unix",
            Self::Microphone => "microphone",
            Self::PathExact => "path-exact",
            Self::PathTree => "path-tree",
            Self::Stdio => "stdio",
            Self::StorageNamespace => "storage-namespace",
            Self::SystemInfo => "system-info",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityChannels {
    pub dynamic: bool,
    pub handle: bool,
    pub synthesis: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SelectorConstraints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_surface_classes: Option<Vec<ClosedSurfaceClass>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_targets: Option<Vec<EnvironmentTarget>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdio_streams: Option<Vec<StdioStream>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdio_source_kinds: Option<Vec<StdioSourceKind>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_stores: Option<Vec<StorageStore>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Risk {
    pub base_tier: u8,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DefinitionSet {
    definitions: BTreeMap<String, CapabilityDefinition>,
}

/// The policy-rules fields the neutral semantic core must authenticate before
/// arming. Product classifier details remain opaque data but cannot replace or
/// reorder any core decision stratum.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyRulesDocument {
    pub rules_schema: String,
    pub profile: String,
    pub semantic_core: String,
    pub core_ownership: Value,
    pub execution: Value,
    pub digest_contract: Value,
    pub decision_precedence: Vec<DecisionStratumId>,
    pub decision_strata: Vec<DecisionStratumRule>,
    pub principal_semantics: Value,
    pub effect_semantics: Value,
    pub normalization_profiles: Vec<NormalizationProfile>,
    pub handles: Value,
    pub dynamic_authority: Value,
    pub cache_key_fields: Vec<String>,
    pub resource_rules: Value,
    pub classifier_rules: Value,
    pub initial_profile: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionStratumId {
    ArmValidity,
    Attribution,
    LifecycleAndTargetClosure,
    ProtectedResourceGuards,
    ProcessCeiling,
    PrincipalDenial,
    RevocationNegativeGeneration,
    QuarantineDeny,
    DefinitionAndEdgePositivePredicates,
    StaticFloor,
    BearerHandle,
    DynamicSession,
    ImplicitPackageSelf,
    AmbientRoot,
    MissingAuthorityMode,
}

pub const DECISION_PRECEDENCE: [DecisionStratumId; 15] = [
    DecisionStratumId::ArmValidity,
    DecisionStratumId::Attribution,
    DecisionStratumId::LifecycleAndTargetClosure,
    DecisionStratumId::ProtectedResourceGuards,
    DecisionStratumId::ProcessCeiling,
    DecisionStratumId::PrincipalDenial,
    DecisionStratumId::RevocationNegativeGeneration,
    DecisionStratumId::QuarantineDeny,
    DecisionStratumId::DefinitionAndEdgePositivePredicates,
    DecisionStratumId::StaticFloor,
    DecisionStratumId::BearerHandle,
    DecisionStratumId::DynamicSession,
    DecisionStratumId::ImplicitPackageSelf,
    DecisionStratumId::AmbientRoot,
    DecisionStratumId::MissingAuthorityMode,
];

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecisionStratumRule {
    pub id: DecisionStratumId,
    pub scope: DecisionScope,
    pub cases: Vec<DecisionCase>,
    pub default_outcome: DecisionRuleOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionScope {
    Arming,
    Effect,
    Principal,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionCase {
    pub when: String,
    pub outcome: DecisionRuleOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionRuleOutcome {
    Continue,
    RefuseArming,
    Deny,
    AllowPrincipal,
    AllowPrincipalWithWouldDenyEvidence,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizationProfile {
    pub id: String,
    pub selector: String,
    pub occurrence: String,
    pub matcher: String,
    pub subset: String,
}

#[derive(Clone, Debug)]
pub struct ValidatedProfile {
    pub definitions: DefinitionSet,
    pub digest_contract: DigestContract,
    pub normalization_profiles: BTreeSet<String>,
}

impl ValidatedProfile {
    /// Strictly parse and jointly validate the two product-provided semantic
    /// registry documents. Duplicate keys and unsafe numbers fail before typed
    /// deserialization.
    pub fn from_json(definitions: &[u8], rules: &[u8]) -> Result<Self> {
        let definitions: CapabilityDefinitionsDocument =
            serde_json::from_value(parse_slice_strict(definitions)?)
                .map_err(|error| Error::InvalidRegistry(error.to_string()))?;
        let rules: PolicyRulesDocument = serde_json::from_value(parse_slice_strict(rules)?)
            .map_err(|error| Error::InvalidRegistry(error.to_string()))?;
        let (digest_contract, normalization_profiles) = validate_policy_rules(&rules)?;
        let definitions = DefinitionSet::validate(definitions, &normalization_profiles)?;
        Ok(Self {
            definitions,
            digest_contract,
            normalization_profiles,
        })
    }
}

impl DefinitionSet {
    pub fn validate(
        document: CapabilityDefinitionsDocument,
        normalization_profiles: &BTreeSet<String>,
    ) -> Result<Self> {
        require_exact(
            "definitionsSchema",
            &document.definitions_schema,
            DEFINITIONS_SCHEMA,
        )?;
        require_exact("profile", &document.profile, PROFILE)?;
        require_exact("semanticCore", &document.semantic_core, SEMANTIC_CORE)?;
        if document.definitions.is_empty() {
            return invalid("definition set must not be empty");
        }

        let mut definitions = BTreeMap::new();
        let mut prior_id: Option<&ActionId> = None;
        for definition in &document.definitions {
            validate_definition(definition, normalization_profiles)?;
            if let Some(prior) = prior_id {
                if prior >= &definition.id {
                    return invalid(format!(
                        "definitions must be strictly sorted and unique: {prior:?} then {:?}",
                        definition.id
                    ));
                }
            }
            prior_id = Some(&definition.id);
        }
        for definition in document.definitions {
            definitions.insert(definition.id.to_string(), definition);
        }
        Ok(Self { definitions })
    }

    pub fn get(&self, action: &str) -> Result<&CapabilityDefinition> {
        self.definitions
            .get(action)
            .ok_or_else(|| Error::UnknownAction(action.to_owned()))
    }

    pub fn contains(&self, action: &str) -> bool {
        self.definitions.contains_key(action)
    }

    pub fn len(&self) -> usize {
        self.definitions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&str, &CapabilityDefinition)> {
        self.definitions
            .iter()
            .map(|(action, definition)| (action.as_str(), definition))
    }
}

fn validate_policy_rules(
    rules: &PolicyRulesDocument,
) -> Result<(DigestContract, BTreeSet<String>)> {
    require_exact("rulesSchema", &rules.rules_schema, RULES_SCHEMA)?;
    require_exact("profile", &rules.profile, PROFILE)?;
    require_exact("semanticCore", &rules.semantic_core, SEMANTIC_CORE)?;

    require_json(
        &rules.core_ownership,
        "/rustCratePath",
        &json!("crates/capsec-semantics"),
    )?;
    require_json(
        &rules.core_ownership,
        "/secondConsumerRule",
        &json!("consume-this-source-or-explicitly-move-ownership-never-copy"),
    )?;
    require_json(&rules.execution, "/durableMode", &json!("enforce"))?;
    require_json(&rules.execution, "/publicPermissive", &json!(false))?;
    require_json(&rules.execution, "/publicOff", &json!(false))?;
    require_json(
        &rules.execution,
        "/missingPolicy",
        &json!("canonical-empty-enforce"),
    )?;
    require_json(
        &rules.execution,
        "/incompleteTarget",
        &json!("refuse-before-code"),
    )?;
    require_json(
        &rules.execution,
        "/deputyIntersection",
        &json!("all-actions-structural"),
    )?;

    if rules.decision_precedence.as_slice() != DECISION_PRECEDENCE {
        return invalid("decisionPrecedence differs from capsec/semantics/1");
    }
    if rules.decision_strata.len() != DECISION_PRECEDENCE.len() {
        return invalid("decisionStrata must contain exactly 15 rows");
    }
    for (index, rule) in rules.decision_strata.iter().enumerate() {
        let expected = expected_stratum(index);
        if rule.id != DECISION_PRECEDENCE[index]
            || rule.scope != expected.0
            || rule.default_outcome != expected.2
            || rule.cases.len() != expected.1.len()
        {
            return invalid(format!(
                "decisionStrata[{index}] differs from frozen precedence"
            ));
        }
        for (case, (expected_when, expected_outcome)) in
            rule.cases.iter().zip(expected.1.into_iter())
        {
            if case.when != expected_when || case.outcome != expected_outcome {
                return invalid(format!(
                    "decisionStrata[{index}] case differs from frozen semantics"
                ));
            }
        }
    }

    require_json(
        &rules.principal_semantics,
        "/transparentFramePrincipal",
        &json!({"kind":"runtime","identity":"ibex-runtime-internal"}),
    )?;
    require_json(
        &rules.principal_semantics,
        "/missingOrAmbiguous",
        &json!("deny"),
    )?;
    require_json(
        &rules.principal_semantics,
        "/combination",
        &json!("deduplicated-JCS-sorted-intersection"),
    )?;
    require_json(
        &rules.effect_semantics,
        "/principalCombination",
        &json!("intersection"),
    )?;
    require_json(
        &rules.effect_semantics,
        "/decisionSet",
        &json!("conjunction"),
    )?;
    require_json(
        &rules.effect_semantics,
        "/lateDiscovery",
        &json!("reauthorize-before-next-effect"),
    )?;
    require_json(&rules.effect_semantics, "/missingFacts", &json!("deny"))?;
    require_json(&rules.effect_semantics, "/speculation", &json!("forbidden"))?;
    require_json(
        &rules.handles,
        "/negativeRecheck",
        &json!("every-use-and-stage"),
    )?;
    require_json(
        &rules.handles,
        "/attenuation",
        &json!("same-action-strict-resource-subset"),
    )?;
    require_json(
        &rules.handles,
        "/containmentContext",
        &json!("same-armed-snapshot-and-same-logical-root-binding-owner"),
    )?;
    require_json(
        &rules.dynamic_authority,
        "/ceiling",
        &json!("canonical-static-escalation-ceiling"),
    )?;
    require_json(
        &rules.dynamic_authority,
        "/modeFallbackMayGrant",
        &json!(false),
    )?;
    require_json(
        &rules.dynamic_authority,
        "/revocation",
        &json!("negative-generation-before-positive"),
    )?;
    require_json(
        &rules.resource_rules,
        "/positiveActions",
        &json!("explicit-no-wildcards"),
    )?;
    require_json(
        &rules.initial_profile,
        "/defaultFlipGate",
        &json!(
            "flip-after-one-advertised-target-is-complete-and-refuse-on-every-incomplete-target"
        ),
    )?;
    if rules
        .classifier_rules
        .as_object()
        .is_none_or(|object| object.is_empty())
    {
        return invalid("classifierRules must be a non-empty object");
    }

    let actual_cache_fields = rules
        .cache_key_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if actual_cache_fields != REQUIRED_CACHE_KEY_FIELDS {
        return invalid("cacheKeyFields differs from the frozen minimum cache identity");
    }

    if rules.normalization_profiles.is_empty() {
        return invalid("normalizationProfiles must not be empty");
    }
    let mut normalization_profiles = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for profile in &rules.normalization_profiles {
        for (field, value) in [
            ("id", &profile.id),
            ("selector", &profile.selector),
            ("occurrence", &profile.occurrence),
            ("matcher", &profile.matcher),
            ("subset", &profile.subset),
        ] {
            if !is_stable_id(value) {
                return invalid(format!(
                    "normalization profile {} has invalid {field} value {value:?}",
                    profile.id
                ));
            }
        }
        if previous.is_some_and(|previous| previous >= profile.id.as_str()) {
            return invalid("normalizationProfiles must be sorted and unique");
        }
        previous = Some(&profile.id);
        normalization_profiles.insert(profile.id.clone());
    }

    let digest_contract: DigestContract = serde_json::from_value(rules.digest_contract.clone())
        .map_err(|error| Error::InvalidRegistry(error.to_string()))?;
    digest_contract.validate()?;
    Ok((digest_contract, normalization_profiles))
}

fn expected_stratum(
    index: usize,
) -> (
    DecisionScope,
    Vec<(&'static str, DecisionRuleOutcome)>,
    DecisionRuleOutcome,
) {
    use DecisionRuleOutcome::{
        AllowPrincipal, AllowPrincipalWithWouldDenyEvidence, Continue, Deny, RefuseArming,
    };
    use DecisionScope::{Arming, Effect, Principal};
    match index {
        0 => (
            Arming,
            vec![("profile-digest-target-or-structure-mismatch", RefuseArming)],
            Continue,
        ),
        1 => (
            Effect,
            vec![("no-user-missing-or-ambiguous-attribution", Deny)],
            Continue,
        ),
        2 => (
            Effect,
            vec![
                ("incomplete-or-unadvertised-target-cell", RefuseArming),
                ("deny-only-planned-or-closed-cell", Deny),
            ],
            Continue,
        ),
        3 => (
            Effect,
            vec![("protected-object-or-always-denied-peer-match", Deny)],
            Continue,
        ),
        4 => (
            Effect,
            vec![("bounded-ceiling-does-not-contain-effect", Deny)],
            Continue,
        ),
        5 => (
            Principal,
            vec![("principal-denial-contains-effect", Deny)],
            Continue,
        ),
        6 => (
            Principal,
            vec![("source-revoked-or-generation-stale", Deny)],
            Continue,
        ),
        7 => (Principal, vec![("principal-is-quarantine", Deny)], Continue),
        8 => (
            Effect,
            vec![("normalization-or-positive-predicate-fails", Deny)],
            Continue,
        ),
        9 => (
            Principal,
            vec![("static-floor-contains-effect", AllowPrincipal)],
            Continue,
        ),
        10 => (
            Principal,
            vec![("valid-possessed-handle-contains-effect", AllowPrincipal)],
            Continue,
        ),
        11 => (
            Principal,
            vec![(
                "valid-session-grant-within-static-ceiling-contains-effect",
                AllowPrincipal,
            )],
            Continue,
        ),
        12 => (
            Principal,
            vec![(
                "generated-package-self-rule-contains-effect",
                AllowPrincipal,
            )],
            Continue,
        ),
        13 => (
            Principal,
            vec![("principal-is-authenticated-root", AllowPrincipal)],
            Continue,
        ),
        14 => (
            Principal,
            vec![
                (
                    "workflow-is-diagnostic-audit",
                    AllowPrincipalWithWouldDenyEvidence,
                ),
                ("workflow-is-production-enforce", Deny),
            ],
            Deny,
        ),
        _ => unreachable!("validated decision-stratum index"),
    }
}

fn require_json(root: &Value, pointer: &str, expected: &Value) -> Result<()> {
    match root.pointer(pointer) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => invalid(format!(
            "policy rule {pointer} must be {expected}, received {actual}"
        )),
        None => invalid(format!("policy rule {pointer} is missing")),
    }
}

fn validate_definition(
    definition: &CapabilityDefinition,
    normalization_profiles: &BTreeSet<String>,
) -> Result<()> {
    require_exact(
        "selectorSchema",
        &definition.selector_schema,
        SELECTOR_SCHEMA,
    )?;
    require_exact(
        "occurrenceSchema",
        &definition.occurrence_schema,
        OCCURRENCE_SCHEMA,
    )?;
    if !is_stable_id(&definition.normalization_profile)
        || !normalization_profiles.contains(&definition.normalization_profile)
    {
        return invalid(format!(
            "{} references unknown normalization profile {:?}",
            definition.id, definition.normalization_profile
        ));
    }
    if definition.description.is_empty() {
        return invalid(format!("{} has an empty description", definition.id));
    }
    if definition.risk.base_tier > 4 {
        return invalid(format!("{} has risk tier above 4", definition.id));
    }
    validate_sorted_unique_nonempty_strings(
        &definition.risk.reasons,
        &format!("{}.risk.reasons", definition.id),
        false,
    )?;
    validate_sorted_unique(
        &definition.resource_kinds,
        &format!("{}.resourceKinds", definition.id),
    )?;
    if definition.lifecycle == Lifecycle::Authorable && definition.resource_kinds.is_empty() {
        return invalid(format!(
            "authorable definition {} must declare a resource kind",
            definition.id
        ));
    }
    let channels_closed = !definition.channels.dynamic
        && !definition.channels.handle
        && !definition.channels.synthesis;
    if matches!(
        definition.lifecycle,
        Lifecycle::DenyOnly | Lifecycle::Planned
    ) && !channels_closed
    {
        return invalid(format!(
            "non-authorable definition {} cannot expose runtime authority channels",
            definition.id
        ));
    }
    if definition.static_only && !channels_closed {
        return invalid(format!(
            "static-only definition {} cannot expose runtime authority channels",
            definition.id
        ));
    }
    if definition.globality == Globality::Terminal && (!definition.static_only || !channels_closed)
    {
        return invalid(format!(
            "terminal definition {} must be static-only with closed channels",
            definition.id
        ));
    }
    if definition.channels.synthesis
        && (!definition.channels.dynamic || !definition.channels.handle)
    {
        return invalid(format!(
            "synthesizable definition {} must also permit dynamic and handle channels",
            definition.id
        ));
    }
    if let Some(constraints) = &definition.selector_constraints {
        if constraints.closed_surface_classes.is_none()
            && constraints.environment_targets.is_none()
            && constraints.stdio_streams.is_none()
            && constraints.stdio_source_kinds.is_none()
            && constraints.storage_stores.is_none()
        {
            return invalid(format!(
                "{} has an empty selectorConstraints object",
                definition.id
            ));
        }
        for (field, values) in [
            (
                "closedSurfaceClasses",
                constraints.closed_surface_classes.as_ref().map(|v| v.len()),
            ),
            (
                "environmentTargets",
                constraints.environment_targets.as_ref().map(|v| v.len()),
            ),
            (
                "stdioStreams",
                constraints.stdio_streams.as_ref().map(|v| v.len()),
            ),
            (
                "stdioSourceKinds",
                constraints.stdio_source_kinds.as_ref().map(|v| v.len()),
            ),
            (
                "storageStores",
                constraints.storage_stores.as_ref().map(|v| v.len()),
            ),
        ] {
            if values == Some(0) {
                return invalid(format!(
                    "{}.selectorConstraints.{field} must not be empty",
                    definition.id
                ));
            }
        }
        if let Some(values) = &constraints.closed_surface_classes {
            validate_wire_sorted_unique(
                values,
                &format!("{}.selectorConstraints.closedSurfaceClasses", definition.id),
            )?;
        }
        if let Some(values) = &constraints.environment_targets {
            validate_wire_sorted_unique(
                values,
                &format!("{}.selectorConstraints.environmentTargets", definition.id),
            )?;
        }
        if let Some(values) = &constraints.stdio_streams {
            validate_wire_sorted_unique(
                values,
                &format!("{}.selectorConstraints.stdioStreams", definition.id),
            )?;
        }
        if let Some(values) = &constraints.stdio_source_kinds {
            validate_wire_sorted_unique(
                values,
                &format!("{}.selectorConstraints.stdioSourceKinds", definition.id),
            )?;
        }
        if let Some(values) = &constraints.storage_stores {
            validate_wire_sorted_unique(
                values,
                &format!("{}.selectorConstraints.storageStores", definition.id),
            )?;
        }
    }
    Ok(())
}

fn require_exact(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        invalid(format!("{field} must be {expected:?}, received {actual:?}"))
    }
}

fn is_stable_id(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
        && !matches!(value.as_bytes().first(), Some(b'.' | b'_' | b'/' | b'-'))
        && !matches!(value.as_bytes().last(), Some(b'.' | b'_' | b'/' | b'-'))
        && !value
            .as_bytes()
            .windows(2)
            .any(|pair| matches!(pair, [b'.' | b'_' | b'/' | b'-', b'.' | b'_' | b'/' | b'-']))
}

fn validate_sorted_unique<T: Ord>(values: &[T], label: &str) -> Result<()> {
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return invalid(format!("{label} must be strictly sorted and unique"));
    }
    Ok(())
}

fn validate_wire_sorted_unique<T: Serialize>(values: &[T], label: &str) -> Result<()> {
    let encoded = values
        .iter()
        .map(serde_json::to_string)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| Error::InvalidRegistry(error.to_string()))?;
    validate_sorted_unique(&encoded, label)
}

fn validate_sorted_unique_nonempty_strings(
    values: &[String],
    label: &str,
    require_nonempty_set: bool,
) -> Result<()> {
    if require_nonempty_set && values.is_empty() {
        return invalid(format!("{label} must not be empty"));
    }
    if values.iter().any(String::is_empty) {
        return invalid(format!("{label} contains an empty string"));
    }
    validate_sorted_unique(values, label)
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::InvalidRegistry(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles() -> BTreeSet<String> {
        ["path.v1".to_owned()].into_iter().collect()
    }

    fn definition(id: &str) -> CapabilityDefinition {
        CapabilityDefinition {
            id: ActionId::new(id).expect("test action id"),
            lifecycle: Lifecycle::Authorable,
            stability: Stability::Stable,
            globality: Globality::Resource,
            resource_kinds: vec![ResourceKind::PathExact],
            selector_schema: SELECTOR_SCHEMA.to_owned(),
            occurrence_schema: OCCURRENCE_SCHEMA.to_owned(),
            normalization_profile: "path.v1".to_owned(),
            channels: AuthorityChannels {
                dynamic: true,
                handle: true,
                synthesis: false,
            },
            static_only: false,
            selector_constraints: None,
            risk: Risk {
                base_tier: 1,
                reasons: vec!["filesystem.read".to_owned()],
            },
            description: "Read one path".to_owned(),
        }
    }

    fn document(definitions: Vec<CapabilityDefinition>) -> CapabilityDefinitionsDocument {
        CapabilityDefinitionsDocument {
            definitions_schema: DEFINITIONS_SCHEMA.to_owned(),
            profile: PROFILE.to_owned(),
            semantic_core: SEMANTIC_CORE.to_owned(),
            definitions,
        }
    }

    #[test]
    fn future_action_does_not_change_exact_lookup() {
        let original = DefinitionSet::validate(document(vec![definition("fs:read")]), &profiles())
            .expect("valid definitions");
        let expanded = DefinitionSet::validate(
            document(vec![definition("fs:read"), definition("fs:write")]),
            &profiles(),
        )
        .expect("valid expanded definitions");
        assert!(original.contains("fs:read"));
        assert!(expanded.contains("fs:read"));
        assert!(!original.contains("fs:write"));
        assert!(!expanded.contains("fs:*"));
        assert!(expanded.get("fs").is_err());
    }

    #[test]
    fn rejects_family_wildcards_and_unsorted_rows() {
        assert!(ActionId::new("fs:*").is_err());
        assert!(DefinitionSet::validate(
            document(vec![definition("fs:write"), definition("fs:read")]),
            &profiles(),
        )
        .is_err());
    }

    #[test]
    fn denies_runtime_channels_for_non_authorable_lifecycles() {
        let mut denied = definition("ffi:load");
        denied.lifecycle = Lifecycle::DenyOnly;
        assert!(DefinitionSet::validate(document(vec![denied]), &profiles()).is_err());
    }
}
