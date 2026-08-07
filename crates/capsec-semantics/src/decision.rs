//! Typed, conjunctive CapSec decision evaluation.
//!
//! The evaluator is implemented without a legacy string-policy fallback. It
//! performs all hard-deny strata across the complete decision set before
//! considering any positive source, then intersects every constrained
//! principal and conjoins every effect.
//! @ref LLP 0021#decision-staging-and-principal-semantics — exact precedence,
//! principal intersection, conjunction, and audit placement
//! @ref LLP 0021#handles-dynamic-authority-and-generations — negative-before-
//! positive ordering and generation-bound authority

use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use serde::{Deserialize, Serialize};

use crate::cache::GenerationSet;
use crate::containment::{
    selector_matches_occurrence_after_stage_validation, try_compare_authority_containment,
    validate_occurrence_stage_facts, AuthorityPolarity, Containment, ContainmentContext,
    PeerClassifier,
};
use crate::model::{
    ActionId, DecisionSet, Digest, EffectOccurrence, Generation, LogicalPath, NonEmptyString,
    ObjectIdentity, OccurrenceResource, Principal, StableId,
};
use crate::path_alias::PathAliasCanonicalizers;
use crate::registry::{
    DecisionStratumId, DefinitionSet, Globality, Lifecycle, PrincipalConstraint, ResourceKind,
    PROFILE, SEMANTIC_CORE,
};
use crate::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SemanticIdentity {
    pub profile: String,
    pub semantic_core: String,
    pub vocab_digest: Digest,
    pub registry_digest: Digest,
    pub policy_digest: Digest,
    pub armed_snapshot_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetArmState {
    CompleteAdvertised,
    ScopedAdvertised,
    Incomplete,
    Unadvertised,
}

#[derive(Clone, Debug)]
pub struct ArmInputs {
    pub expected_identity: SemanticIdentity,
    pub loaded_identity: SemanticIdentity,
    pub target: TargetArmState,
    pub structure_valid: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundAuthority {
    pub source_id: NonEmptyString,
    pub selector: crate::model::AuthoritySelector,
    pub armed_snapshot_digest: Digest,
    pub package_root_owner: Option<Principal>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityCeiling {
    Unbounded,
    Bounded(Vec<BoundAuthority>),
}

impl Default for AuthorityCeiling {
    fn default() -> Self {
        Self::Bounded(Vec::new())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PrincipalPolicy {
    pub denials: Vec<BoundAuthority>,
    pub static_floor: Vec<BoundAuthority>,
    pub escalation_ceiling: AuthorityCeiling,
    pub implicit_package_self: Vec<BoundAuthority>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Revocation {
    pub principal: Principal,
    pub authority: BoundAuthority,
    pub generation: Generation,
    pub ancestor_ids: Vec<NonEmptyString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BearerHandle {
    pub handle_id: NonEmptyString,
    pub owner: Principal,
    pub holder: Principal,
    pub authority: BoundAuthority,
    pub observed_negative_generation: Generation,
    pub published_handle_generation: Generation,
    pub ancestor_ids: Vec<NonEmptyString>,
    pub operation_id: Option<NonEmptyString>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicGrant {
    pub grant_id: NonEmptyString,
    pub principal: Principal,
    pub authority: BoundAuthority,
    pub observed_negative_generation: Generation,
    pub published_dynamic_generation: Generation,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ProtectedObjectGuard {
    pub action: ActionId,
    pub object: ObjectIdentity,
    /// `None` retains the legacy exact-object artifact guard. Authenticated
    /// package source always supplies a verification generation, so the guard
    /// cannot be confused by object-number reuse.
    /// @ref LLP 0023#42-authenticated-package-source-is-immutable
    pub verification_generation: Option<NonEmptyString>,
}

/// Arm-validated authority that retains its publication identity across cheap
/// clones. Mutation uses copy-on-write, so a changed value necessarily has a
/// different identity and cannot be published into an existing verified
/// context.
///
/// @ref LLP 0021#policy-forms-and-digests — the armed snapshot is immutable
/// after authentication
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImmutableAuthority<T>(Arc<T>);

impl<T> ImmutableAuthority<T> {
    fn same_publication_identity(&self, other: &Self) -> bool {
        #[cfg(test)]
        note_immutable_authority_identity_comparison();
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> From<T> for ImmutableAuthority<T> {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}

impl<T> Deref for ImmutableAuthority<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Clone> DerefMut for ImmutableAuthority<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionAuthorityState {
    pub generations: GenerationSet,
    pub process_ceiling: ImmutableAuthority<AuthorityCeiling>,
    pub root_ceiling: ImmutableAuthority<AuthorityCeiling>,
    pub bootstrap_floor: ImmutableAuthority<Vec<BoundAuthority>>,
    pub protected_objects: ImmutableAuthority<Vec<ProtectedObjectGuard>>,
    pub protected_resources: ImmutableAuthority<Vec<BoundAuthority>>,
    pub principal_policies: ImmutableAuthority<BTreeMap<Principal, PrincipalPolicy>>,
    pub revocations: Vec<Revocation>,
    pub handles: Vec<BearerHandle>,
    pub dynamic_grants: Vec<DynamicGrant>,
}

#[derive(Clone, Debug)]
pub struct VerifiedDecisionContext {
    identity: SemanticIdentity,
    definitions: DefinitionSet,
    authority: DecisionAuthorityState,
    path_canonicalizers: PathAliasCanonicalizers,
    bootstrap_phase_token: Arc<AtomicBool>,
}

impl VerifiedDecisionContext {
    pub fn arm(
        inputs: ArmInputs,
        definitions: DefinitionSet,
        authority: DecisionAuthorityState,
    ) -> Result<Self> {
        Self::arm_with_path_canonicalizers(
            inputs,
            definitions,
            authority,
            // The neutral constructor is safe for non-path profiles only.
            // Any path occurrence fails closed unless the caller uses the
            // snapshot-bound constructor with a total volume table.
            PathAliasCanonicalizers::default(),
        )
    }

    pub fn arm_with_path_canonicalizers(
        inputs: ArmInputs,
        definitions: DefinitionSet,
        authority: DecisionAuthorityState,
        path_canonicalizers: PathAliasCanonicalizers,
    ) -> Result<Self> {
        if !inputs.structure_valid {
            return arm_refused("armed snapshot structure is invalid");
        }
        if inputs.expected_identity != inputs.loaded_identity {
            return arm_refused("loaded semantic identity or digest differs from the expected one");
        }
        if inputs.loaded_identity.profile != PROFILE
            || inputs.loaded_identity.semantic_core != SEMANTIC_CORE
        {
            return arm_refused("loaded profile or semantic-core identity is unknown");
        }
        if !matches!(
            inputs.target,
            TargetArmState::CompleteAdvertised | TargetArmState::ScopedAdvertised
        ) {
            return arm_refused("target is incomplete or unadvertised");
        }
        validate_authority_state(&inputs.loaded_identity, &definitions, &authority)?;
        Ok(Self {
            identity: inputs.loaded_identity,
            definitions,
            authority,
            path_canonicalizers,
            bootstrap_phase_token: Arc::new(AtomicBool::new(true)),
        })
    }

    pub fn identity(&self) -> &SemanticIdentity {
        &self.identity
    }

    pub fn definitions(&self) -> &DefinitionSet {
        &self.definitions
    }

    pub fn authority(&self) -> &DecisionAuthorityState {
        &self.authority
    }

    /// Irreversibly destroy the evaluator's bootstrap-phase authority token.
    /// Clones share one monotonic token, so application callbacks retained
    /// across the transition cannot regain bootstrap authority.
    /// @ref LLP 0029#4-compiled-mode-authority — bootstrap authority ends before application evaluation
    pub fn seal_bootstrap_phase(&self) -> bool {
        self.bootstrap_phase_token.swap(false, Ordering::AcqRel)
    }

    pub fn bootstrap_phase_active(&self) -> bool {
        self.bootstrap_phase_token.load(Ordering::Acquire)
    }

    /// Canonicalize an already principal-projected occurrence before deriving
    /// its decision-cache bytes. Live adapters project first, canonicalize
    /// second, and retain their separate display spelling.
    pub fn canonicalize_occurrence_for_cache(
        &self,
        occurrence: &EffectOccurrence,
        principal: &Principal,
    ) -> Result<EffectOccurrence> {
        if !occurrence.constrained_principals.contains(principal) {
            return arm_refused("cache canonicalization principal is not constrained");
        }
        let mut canonical = occurrence.clone();
        canonical.resource = self
            .path_canonicalizers
            .canonicalize_occurrence(&occurrence.resource, principal)?;
        Ok(canonical)
    }

    /// Publish a newly validated live authority state while preserving the
    /// authenticated semantic identity and definition set.
    pub fn with_authority(&self, authority: DecisionAuthorityState) -> Result<Self> {
        if !authority
            .process_ceiling
            .same_publication_identity(&self.authority.process_ceiling)
            || !authority
                .root_ceiling
                .same_publication_identity(&self.authority.root_ceiling)
            || !authority
                .bootstrap_floor
                .same_publication_identity(&self.authority.bootstrap_floor)
            || !authority
                .protected_objects
                .same_publication_identity(&self.authority.protected_objects)
            || !authority
                .protected_resources
                .same_publication_identity(&self.authority.protected_resources)
            || !authority
                .principal_policies
                .same_publication_identity(&self.authority.principal_policies)
        {
            return arm_refused("live publication attempted to replace immutable authority");
        }
        validate_live_authority_state(&self.identity, &self.definitions, &authority)?;
        Ok(Self {
            identity: self.identity.clone(),
            definitions: self.definitions.clone(),
            authority,
            path_canonicalizers: self.path_canonicalizers.clone(),
            bootstrap_phase_token: self.bootstrap_phase_token.clone(),
        })
    }

    /// A bearer handle may be minted only from an authority the owner already
    /// holds in its immutable static floor. This deliberately excludes ambient
    /// root fallback and dynamic/handle re-export; re-attenuation is modeled by
    /// an explicit parent handle at publication time.
    pub fn static_authority_covers(
        &self,
        owner: &Principal,
        selector: &crate::model::AuthoritySelector,
        package_root_owner: Option<&Principal>,
    ) -> Result<bool> {
        let definition = self.definitions.get(selector.action.as_str())?;
        if definition.lifecycle != Lifecycle::Authorable || !definition.channels.handle {
            return Ok(false);
        }
        let Some(policy) = self.authority.principal_policies.get(owner) else {
            return Ok(false);
        };
        for denial in &policy.denials {
            let context = ContainmentContext {
                same_snapshot: denial.armed_snapshot_digest == self.identity.armed_snapshot_digest,
                same_package_root_owner: package_owner_equal_to(denial, package_root_owner),
            };
            // A minted handle must not cover any authority the owner's static
            // policy explicitly denies. Checking only whether the denial
            // contains the requested selector misses the inverse shape: a
            // broad requested handle can contain a narrower denied subtree and
            // thereby launder that denial to its holder. Test both directions;
            // either containment relationship means the requested authority
            // includes denied authority and therefore cannot be delegated.
            // @ref LLP 0021#handles-dynamic-authority-and-generations — denial
            // strata remain effective across voluntary delegation.
            let denial_contains_request = matches!(
                try_compare_authority_containment(&denial.selector, selector, &context)?,
                Containment::Equal | Containment::StrictSubset
            );
            let request_contains_denial = matches!(
                try_compare_authority_containment(selector, &denial.selector, &context)?,
                Containment::Equal | Containment::StrictSubset
            );
            if denial_contains_request || request_contains_denial {
                return Ok(false);
            }
        }
        for authority in &policy.static_floor {
            let context = ContainmentContext {
                same_snapshot: authority.armed_snapshot_digest
                    == self.identity.armed_snapshot_digest,
                same_package_root_owner: package_owner_equal_to(authority, package_root_owner),
            };
            if matches!(
                try_compare_authority_containment(&authority.selector, selector, &context)?,
                Containment::Equal | Containment::StrictSubset
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn package_owner_equal_to(authority: &BoundAuthority, owner: Option<&Principal>) -> bool {
    match (&authority.package_root_owner, owner) {
        (None, None) => true,
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Workflow {
    ProductionEnforce,
    DiagnosticAudit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetCellDisposition {
    Complete,
    Closed,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectGate {
    pub coverage_edge_id: StableId,
    pub target_cell: TargetCellDisposition,
    pub definition_and_edge_predicates_satisfied: bool,
}

/// Authenticated logical-path views for path effects, indexed first by effect
/// and then by constrained principal. This is deliberately not part of the wire
/// decision-set schema: only the host adapter has the absolute path and armed
/// root bindings needed to construct it safely.
#[derive(Clone, Debug, Default)]
pub struct PrincipalPathProjections {
    by_effect: Vec<BTreeMap<Principal, LogicalPath>>,
}

impl PrincipalPathProjections {
    pub fn new(by_effect: Vec<BTreeMap<Principal, LogicalPath>>) -> Self {
        Self { by_effect }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionOutcome {
    Allow,
    AllowWithWouldDenyEvidence,
    Deny,
    RefuseArming,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionReason {
    InvalidAttribution,
    UnknownAction,
    LifecycleClosed,
    ResourceKindMismatch,
    TargetCellClosed,
    TargetCellIncomplete,
    ProtectedResource,
    ProcessCeiling,
    RootAuthorityCeiling,
    PrincipalDenial,
    Revoked,
    Quarantine,
    InvalidOccurrenceFacts,
    DefinitionOrEdgePredicate,
    BootstrapFloor,
    StaticFloor,
    BearerHandle,
    DynamicSession,
    ImplicitPackageSelf,
    AmbientRoot,
    MissingAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionEvidence {
    pub effect_index: usize,
    pub principal: Option<Principal>,
    pub stratum: DecisionStratumId,
    pub reason: DecisionReason,
    pub source_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub outcome: DecisionOutcome,
    pub decisive_stratum: Option<DecisionStratumId>,
    pub evidence: Vec<DecisionEvidence>,
}

/// Complete evidence envelope emitted by an immutable decision context. It
/// keeps actor, effect owner, constrained principals, stage, authority source,
/// loaded semantic identity, and generations distinct instead of flattening
/// them into one ambient package label.
/// @ref LLP 0021#wp8--port-handles-dynamic-authority-and-audit-evidence
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredDecisionEvidence {
    pub identity: SemanticIdentity,
    pub generations: GenerationSet,
    pub operation_id: NonEmptyString,
    pub stage: crate::model::Stage,
    pub actor: Principal,
    pub effect_owners: Vec<Principal>,
    pub constrained_principals: Vec<Principal>,
    pub outcome: DecisionOutcome,
    pub evidence: Vec<DecisionEvidence>,
}

pub fn structure_decision_evidence(
    context: &VerifiedDecisionContext,
    set: &DecisionSet,
    decision: &Decision,
) -> StructuredDecisionEvidence {
    StructuredDecisionEvidence {
        identity: context.identity.clone(),
        generations: context.authority.generations,
        operation_id: set.operation_id.clone(),
        stage: set.context.stage,
        actor: set.context.actor.clone(),
        effect_owners: set
            .effects
            .iter()
            .map(|effect| effect.effect_owner.clone())
            .collect(),
        constrained_principals: set.context.constrained_principals.clone(),
        outcome: decision.outcome,
        evidence: decision.evidence.clone(),
    }
}

#[derive(Clone, Debug)]
struct PendingPrincipal {
    effect_index: usize,
    principal: Principal,
    authorization: Option<DecisionEvidence>,
    would_deny: bool,
}

/// Evaluate a complete known-stage decision set. Callers must invoke this same
/// function again when a later-stage fact appears; the cache layer refuses to
/// reuse repeat/cleanup decisions.
pub fn evaluate_decision_set<C: PeerClassifier>(
    context: &VerifiedDecisionContext,
    set: &DecisionSet,
    gates: &[EffectGate],
    workflow: Workflow,
    classifier: &C,
) -> Result<Decision> {
    evaluate_decision_set_inner(context, set, gates, None, workflow, classifier)
}

/// Evaluate a path-bearing decision set using the separately authenticated
/// view of that path for every constrained principal.
pub fn evaluate_decision_set_with_path_projections<C: PeerClassifier>(
    context: &VerifiedDecisionContext,
    set: &DecisionSet,
    gates: &[EffectGate],
    projections: &PrincipalPathProjections,
    workflow: Workflow,
    classifier: &C,
) -> Result<Decision> {
    evaluate_decision_set_inner(context, set, gates, Some(projections), workflow, classifier)
}

fn evaluate_decision_set_inner<C: PeerClassifier>(
    context: &VerifiedDecisionContext,
    set: &DecisionSet,
    gates: &[EffectGate],
    projections: Option<&PrincipalPathProjections>,
    workflow: Workflow,
    classifier: &C,
) -> Result<Decision> {
    if set.effects.is_empty() || gates.len() != set.effects.len() {
        return Ok(hard_decision(
            DecisionOutcome::Deny,
            DecisionStratumId::Attribution,
            0,
            None,
            DecisionReason::InvalidAttribution,
            None,
        ));
    }
    if set
        .context
        .presented_handle_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || set.context.presented_handle_ids.iter().any(|presented| {
            !context.authority.handles.iter().any(|handle| {
                &handle.handle_id == presented
                    && set.context.constrained_principals.contains(&handle.holder)
            })
        })
    {
        return Ok(hard_decision(
            DecisionOutcome::Deny,
            DecisionStratumId::Attribution,
            0,
            None,
            DecisionReason::InvalidAttribution,
            None,
        ));
    }
    let occurrences = set.occurrences();
    let projected_occurrences =
        materialize_path_projections(&occurrences, projections, &context.path_canonicalizers)?;

    // 2. Attribution — validate the factored context across every effect.
    for (effect_index, occurrence) in occurrences.iter().enumerate() {
        if !occurrence.principal_context_is_valid() {
            return Ok(hard_decision(
                DecisionOutcome::Deny,
                DecisionStratumId::Attribution,
                effect_index,
                None,
                DecisionReason::InvalidAttribution,
                None,
            ));
        }
    }

    // 3. Incomplete targets refuse before any deny-only lifecycle result.
    for (effect_index, gate) in gates.iter().enumerate() {
        if gate.target_cell == TargetCellDisposition::Incomplete {
            return Ok(hard_decision(
                DecisionOutcome::RefuseArming,
                DecisionStratumId::LifecycleAndTargetClosure,
                effect_index,
                None,
                DecisionReason::TargetCellIncomplete,
                Some(gate.coverage_edge_id.as_str().to_owned()),
            ));
        }
    }

    // 3. Lifecycle and target closure.
    for (effect_index, (occurrence, gate)) in occurrences.iter().zip(gates).enumerate() {
        let definition = match context.definitions.get(occurrence.action.as_str()) {
            Ok(definition) => definition,
            Err(_) => {
                return Ok(hard_decision(
                    DecisionOutcome::Deny,
                    DecisionStratumId::LifecycleAndTargetClosure,
                    effect_index,
                    None,
                    DecisionReason::UnknownAction,
                    Some(gate.coverage_edge_id.as_str().to_owned()),
                ))
            }
        };
        if definition.lifecycle != Lifecycle::Authorable {
            return Ok(hard_decision(
                DecisionOutcome::Deny,
                DecisionStratumId::LifecycleAndTargetClosure,
                effect_index,
                None,
                DecisionReason::LifecycleClosed,
                Some(gate.coverage_edge_id.as_str().to_owned()),
            ));
        }
        let Some(requested) = occurrence.resource.requested_selector_resource() else {
            return Ok(hard_decision(
                DecisionOutcome::Deny,
                DecisionStratumId::LifecycleAndTargetClosure,
                effect_index,
                None,
                DecisionReason::ResourceKindMismatch,
                Some(gate.coverage_edge_id.as_str().to_owned()),
            ));
        };
        if !definition
            .resource_kinds
            .iter()
            .any(|kind| kind.as_str() == requested.kind_name())
        {
            return Ok(hard_decision(
                DecisionOutcome::Deny,
                DecisionStratumId::LifecycleAndTargetClosure,
                effect_index,
                None,
                DecisionReason::ResourceKindMismatch,
                Some(gate.coverage_edge_id.as_str().to_owned()),
            ));
        }
        match gate.target_cell {
            TargetCellDisposition::Complete => {}
            TargetCellDisposition::Closed => {
                return Ok(hard_decision(
                    DecisionOutcome::Deny,
                    DecisionStratumId::LifecycleAndTargetClosure,
                    effect_index,
                    None,
                    DecisionReason::TargetCellClosed,
                    Some(gate.coverage_edge_id.as_str().to_owned()),
                ))
            }
            TargetCellDisposition::Incomplete => unreachable!("handled before lifecycle checks"),
        }
    }

    // 4. Protected-resource guards.
    for (effect_index, occurrence) in occurrences.iter().enumerate() {
        if context
            .authority
            .protected_objects
            .iter()
            .any(|guard| protected_object_matches(guard, occurrence))
        {
            return Ok(hard_decision(
                DecisionOutcome::Deny,
                DecisionStratumId::ProtectedResourceGuards,
                effect_index,
                None,
                DecisionReason::ProtectedResource,
                None,
            ));
        }
        for principal in &occurrence.constrained_principals {
            let principal_occurrence = occurrence_for_principal(
                &occurrences,
                &projected_occurrences,
                effect_index,
                principal,
            );
            if let Some(denial) = first_matching_authority(
                &context.authority.protected_resources,
                principal_occurrence,
                principal,
                &context.identity.armed_snapshot_digest,
                AuthorityPolarity::Denial,
                classifier,
            )? {
                return Ok(hard_decision(
                    DecisionOutcome::Deny,
                    DecisionStratumId::ProtectedResourceGuards,
                    effect_index,
                    Some(principal.clone()),
                    DecisionReason::ProtectedResource,
                    Some(denial.source_id.as_str().to_owned()),
                ));
            }
        }
    }

    // 5. Process ceiling, separately against each constrained package root.
    for (effect_index, occurrence) in occurrences.iter().enumerate() {
        for principal in &occurrence.constrained_principals {
            let principal_occurrence = occurrence_for_principal(
                &occurrences,
                &projected_occurrences,
                effect_index,
                principal,
            );
            if !ceiling_allows(
                &context.authority.process_ceiling,
                principal_occurrence,
                principal,
                &context.identity.armed_snapshot_digest,
                classifier,
            )? {
                return Ok(hard_decision(
                    DecisionOutcome::Deny,
                    DecisionStratumId::ProcessCeiling,
                    effect_index,
                    Some(principal.clone()),
                    DecisionReason::ProcessCeiling,
                    None,
                ));
            }
        }
    }

    // 6. Root-only ceiling. This constrains AmbientRoot without applying the
    // entry declaration to unrelated package principals.
    // @ref LLP 0029#4-compiled-mode-authority — root policy must not be
    // widened by package needs or reused as the whole-process envelope.
    for (effect_index, occurrence) in occurrences.iter().enumerate() {
        for principal in occurrence
            .constrained_principals
            .iter()
            .filter(|principal| principal.is_root())
        {
            let principal_occurrence = occurrence_for_principal(
                &occurrences,
                &projected_occurrences,
                effect_index,
                principal,
            );
            if !ceiling_allows(
                &context.authority.root_ceiling,
                principal_occurrence,
                principal,
                &context.identity.armed_snapshot_digest,
                classifier,
            )? {
                return Ok(hard_decision(
                    DecisionOutcome::Deny,
                    DecisionStratumId::RootAuthorityCeiling,
                    effect_index,
                    Some(principal.clone()),
                    DecisionReason::RootAuthorityCeiling,
                    None,
                ));
            }
        }
    }

    // 7. Principal denials.
    for (effect_index, occurrence) in occurrences.iter().enumerate() {
        for principal in &occurrence.constrained_principals {
            let principal_occurrence = occurrence_for_principal(
                &occurrences,
                &projected_occurrences,
                effect_index,
                principal,
            );
            let denials = context
                .authority
                .principal_policies
                .get(principal)
                .map(|policy| policy.denials.as_slice())
                .unwrap_or_default();
            if let Some(denial) = first_matching_authority(
                denials,
                principal_occurrence,
                principal,
                &context.identity.armed_snapshot_digest,
                AuthorityPolarity::Denial,
                classifier,
            )? {
                return Ok(hard_decision(
                    DecisionOutcome::Deny,
                    DecisionStratumId::PrincipalDenial,
                    effect_index,
                    Some(principal.clone()),
                    DecisionReason::PrincipalDenial,
                    Some(denial.source_id.as_str().to_owned()),
                ));
            }
        }
    }

    // 7. Revocation and negative generation.
    for (effect_index, occurrence) in occurrences.iter().enumerate() {
        for revocation in &context.authority.revocations {
            if !occurrence
                .constrained_principals
                .contains(&revocation.principal)
            {
                continue;
            }
            let principal_occurrence = occurrence_for_principal(
                &occurrences,
                &projected_occurrences,
                effect_index,
                &revocation.principal,
            );
            if authority_matches(
                &revocation.authority,
                principal_occurrence,
                &revocation.principal,
                &context.identity.armed_snapshot_digest,
                AuthorityPolarity::Denial,
                classifier,
            )? {
                return Ok(hard_decision(
                    DecisionOutcome::Deny,
                    DecisionStratumId::RevocationNegativeGeneration,
                    effect_index,
                    Some(revocation.principal.clone()),
                    DecisionReason::Revoked,
                    Some(revocation.authority.source_id.as_str().to_owned()),
                ));
            }
        }
    }

    // 8. Quarantine is never a positive principal.
    for (effect_index, occurrence) in occurrences.iter().enumerate() {
        if let Some(principal) = occurrence
            .constrained_principals
            .iter()
            .find(|principal| principal.is_quarantine())
        {
            return Ok(hard_decision(
                DecisionOutcome::Deny,
                DecisionStratumId::QuarantineDeny,
                effect_index,
                Some(principal.clone()),
                DecisionReason::Quarantine,
                None,
            ));
        }
    }

    // 9. Definition/coverage predicates and all stage-sensitive facts.
    for (effect_index, (occurrence, gate)) in occurrences.iter().zip(gates).enumerate() {
        if validate_occurrence_stage_facts(occurrence).is_err() {
            return Ok(hard_decision(
                DecisionOutcome::Deny,
                DecisionStratumId::DefinitionAndEdgePositivePredicates,
                effect_index,
                None,
                DecisionReason::InvalidOccurrenceFacts,
                Some(gate.coverage_edge_id.as_str().to_owned()),
            ));
        }
        let Some(requested) = occurrence.resource.requested_selector_resource() else {
            return Ok(hard_decision(
                DecisionOutcome::Deny,
                DecisionStratumId::DefinitionAndEdgePositivePredicates,
                effect_index,
                None,
                DecisionReason::InvalidOccurrenceFacts,
                Some(gate.coverage_edge_id.as_str().to_owned()),
            ));
        };
        let definition = match context
            .definitions
            .validate_requested_resource(&occurrence.action, &requested)
        {
            Ok(definition) => definition,
            Err(_) => {
                return Ok(hard_decision(
                    DecisionOutcome::Deny,
                    DecisionStratumId::DefinitionAndEdgePositivePredicates,
                    effect_index,
                    None,
                    DecisionReason::DefinitionOrEdgePredicate,
                    Some(gate.coverage_edge_id.as_str().to_owned()),
                ));
            }
        };
        if definition.principal_constraint == Some(PrincipalConstraint::RootOnly) {
            if let Some(non_root) = occurrence
                .constrained_principals
                .iter()
                .find(|principal| !principal.is_root())
            {
                return Ok(hard_decision(
                    DecisionOutcome::Deny,
                    DecisionStratumId::DefinitionAndEdgePositivePredicates,
                    effect_index,
                    Some(non_root.clone()),
                    DecisionReason::DefinitionOrEdgePredicate,
                    Some(gate.coverage_edge_id.as_str().to_owned()),
                ));
            }
        }
        if !gate.definition_and_edge_predicates_satisfied {
            return Ok(hard_decision(
                DecisionOutcome::Deny,
                DecisionStratumId::DefinitionAndEdgePositivePredicates,
                effect_index,
                None,
                DecisionReason::DefinitionOrEdgePredicate,
                Some(gate.coverage_edge_id.as_str().to_owned()),
            ));
        }
    }

    let mut pending = occurrences
        .iter()
        .enumerate()
        .flat_map(|(effect_index, occurrence)| {
            occurrence
                .constrained_principals
                .iter()
                .cloned()
                .map(move |principal| PendingPrincipal {
                    effect_index,
                    principal,
                    authorization: None,
                    would_deny: false,
                })
        })
        .collect::<Vec<_>>();

    // 10. Bootstrap authority is available only while the evaluator-owned,
    // monotonic phase token remains live. Wire input cannot present this token.
    if context.bootstrap_phase_active() {
        for pending_row in pending
            .iter_mut()
            .filter(|row| row.authorization.is_none() && row.principal.is_root())
        {
            let occurrence = occurrence_for_principal(
                &occurrences,
                &projected_occurrences,
                pending_row.effect_index,
                &pending_row.principal,
            );
            if let Some(authority) = first_matching_authority(
                &context.authority.bootstrap_floor,
                occurrence,
                &pending_row.principal,
                &context.identity.armed_snapshot_digest,
                AuthorityPolarity::Positive,
                classifier,
            )? {
                pending_row.authorization = Some(positive_evidence(
                    pending_row,
                    DecisionStratumId::BootstrapFloor,
                    DecisionReason::BootstrapFloor,
                    authority.source_id.as_str(),
                ));
            }
        }
    }

    // 11. Static floor.
    fill_from_policy_authorities(
        &mut pending,
        &occurrences,
        &projected_occurrences,
        context,
        classifier,
        |policy| &policy.static_floor,
        DecisionStratumId::StaticFloor,
        DecisionReason::StaticFloor,
    )?;

    // 12. Bearer handles and operation leases.
    for pending_row in pending.iter_mut().filter(|row| row.authorization.is_none()) {
        let occurrence = occurrence_for_principal(
            &occurrences,
            &projected_occurrences,
            pending_row.effect_index,
            &pending_row.principal,
        );
        for handle in &context.authority.handles {
            if !set.context.presented_handle_ids.contains(&handle.handle_id)
                || handle.holder != pending_row.principal
                || handle.observed_negative_generation != context.authority.generations.negative
                || handle.published_handle_generation != context.authority.generations.handle
                || handle
                    .operation_id
                    .as_ref()
                    .is_some_and(|operation| operation.as_str() != set.operation_id.as_str())
            {
                continue;
            }
            if authority_matches(
                &handle.authority,
                occurrence,
                &pending_row.principal,
                &context.identity.armed_snapshot_digest,
                AuthorityPolarity::Positive,
                classifier,
            )? {
                pending_row.authorization = Some(positive_evidence(
                    pending_row,
                    DecisionStratumId::BearerHandle,
                    DecisionReason::BearerHandle,
                    handle.handle_id.as_str(),
                ));
                break;
            }
        }
    }

    // 13. Dynamic session authority, already verified within its static ceiling.
    for pending_row in pending.iter_mut().filter(|row| row.authorization.is_none()) {
        let occurrence = occurrence_for_principal(
            &occurrences,
            &projected_occurrences,
            pending_row.effect_index,
            &pending_row.principal,
        );
        for grant in &context.authority.dynamic_grants {
            if grant.principal != pending_row.principal
                || grant.observed_negative_generation != context.authority.generations.negative
                || grant.published_dynamic_generation != context.authority.generations.dynamic
            {
                continue;
            }
            if authority_matches(
                &grant.authority,
                occurrence,
                &pending_row.principal,
                &context.identity.armed_snapshot_digest,
                AuthorityPolarity::Positive,
                classifier,
            )? {
                pending_row.authorization = Some(positive_evidence(
                    pending_row,
                    DecisionStratumId::DynamicSession,
                    DecisionReason::DynamicSession,
                    grant.grant_id.as_str(),
                ));
                break;
            }
        }
    }

    // 14. Generated implicit package-self authority.
    fill_from_policy_authorities(
        &mut pending,
        &occurrences,
        &projected_occurrences,
        context,
        classifier,
        |policy| &policy.implicit_package_self,
        DecisionStratumId::ImplicitPackageSelf,
        DecisionReason::ImplicitPackageSelf,
    )?;

    // 15. Ambient authenticated root (still after every denial). Effects in
    // the bootstrap floor are deliberately excluded: the evaluator-owned
    // token is their only ambient credential, so a callback retained beyond
    // sealing cannot borrow ordinary root fallback for the same effect.
    for pending_row in pending
        .iter_mut()
        .filter(|row| row.authorization.is_none() && row.principal.is_root())
    {
        let occurrence = occurrence_for_principal(
            &occurrences,
            &projected_occurrences,
            pending_row.effect_index,
            &pending_row.principal,
        );
        if first_matching_authority(
            &context.authority.bootstrap_floor,
            occurrence,
            &pending_row.principal,
            &context.identity.armed_snapshot_digest,
            AuthorityPolarity::Positive,
            classifier,
        )?
        .is_some()
        {
            continue;
        }
        pending_row.authorization = Some(DecisionEvidence {
            effect_index: pending_row.effect_index,
            principal: Some(pending_row.principal.clone()),
            stratum: DecisionStratumId::AmbientRoot,
            reason: DecisionReason::AmbientRoot,
            source_id: None,
        });
    }

    // 16. Missing authority mode. Audit can relax only this final case.
    for pending_row in pending.iter_mut().filter(|row| row.authorization.is_none()) {
        match workflow {
            Workflow::ProductionEnforce => {
                return Ok(hard_decision(
                    DecisionOutcome::Deny,
                    DecisionStratumId::MissingAuthorityMode,
                    pending_row.effect_index,
                    Some(pending_row.principal.clone()),
                    DecisionReason::MissingAuthority,
                    None,
                ))
            }
            Workflow::DiagnosticAudit => {
                pending_row.would_deny = true;
                pending_row.authorization = Some(DecisionEvidence {
                    effect_index: pending_row.effect_index,
                    principal: Some(pending_row.principal.clone()),
                    stratum: DecisionStratumId::MissingAuthorityMode,
                    reason: DecisionReason::MissingAuthority,
                    source_id: None,
                });
            }
        }
    }

    let would_deny = pending.iter().any(|row| row.would_deny);
    Ok(Decision {
        outcome: if would_deny {
            DecisionOutcome::AllowWithWouldDenyEvidence
        } else {
            DecisionOutcome::Allow
        },
        decisive_stratum: would_deny.then_some(DecisionStratumId::MissingAuthorityMode),
        evidence: pending
            .into_iter()
            .filter_map(|row| row.authorization)
            .collect(),
    })
}

fn materialize_path_projections(
    occurrences: &[EffectOccurrence],
    projections: Option<&PrincipalPathProjections>,
    canonicalizers: &PathAliasCanonicalizers,
) -> Result<Vec<BTreeMap<Principal, EffectOccurrence>>> {
    if let Some(projections) = projections {
        if projections.by_effect.len() != occurrences.len() {
            return arm_refused("path projections do not align with the effect set");
        }
    }

    occurrences
        .iter()
        .enumerate()
        .map(|(effect_index, occurrence)| {
            let supplied = projections.map(|projections| &projections.by_effect[effect_index]);
            let OccurrenceResource::PathOccurrence { requested, .. } = &occurrence.resource else {
                if supplied.is_some_and(|paths| !paths.is_empty()) {
                    return arm_refused("non-path effect has path projections");
                }
                // Executable and Unix-socket occurrences can also carry a
                // principal-relative package path. Their adapters do not yet
                // supply enough authenticated paths to rewrite every nested
                // field, so a deputy decision must refuse rather than reuse the
                // actor's Package-rooted selector for another principal.
                // @ref LLP 0021#decision-staging-and-principal-semantics
                if occurrence.constrained_principals.len() > 1
                    && occurrence
                        .resource
                        .requested_selector_resource()
                        .is_some_and(|resource| resource.contains_package_logical_root())
                {
                    return arm_refused(
                        "multi-principal package-root resource lacks authenticated projections",
                    );
                }
                return occurrence
                    .constrained_principals
                    .iter()
                    .map(|principal| {
                        let mut canonical = occurrence.clone();
                        canonical.resource = canonicalizers
                            .canonicalize_occurrence(&occurrence.resource, principal)?;
                        Ok((principal.clone(), canonical))
                    })
                    .collect();
            };

            let paths = if let Some(paths) = supplied {
                paths
            } else {
                if occurrence.constrained_principals.len() > 1 {
                    return arm_refused(
                        "multi-principal path decision lacks authenticated projections",
                    );
                }
                return occurrence
                    .constrained_principals
                    .iter()
                    .map(|principal| {
                        let mut canonical = occurrence.clone();
                        canonical.resource = canonicalizers
                            .canonicalize_occurrence(&occurrence.resource, principal)?;
                        Ok((principal.clone(), canonical))
                    })
                    .collect();
            };
            if paths.len() != occurrence.constrained_principals.len()
                || occurrence
                    .constrained_principals
                    .iter()
                    .any(|principal| !paths.contains_key(principal))
            {
                return arm_refused(
                    "path projection principals differ from the constrained principal set",
                );
            }
            if paths
                .values()
                .any(|projected_path| !projected_path.is_canonical())
            {
                return arm_refused("path projection is not canonical");
            }
            if paths.iter().any(|(principal, projected_path)| {
                projected_path.root == crate::model::LogicalRoot::Package && !principal.is_package()
            }) {
                return arm_refused("package path projection belongs to a non-package principal");
            }
            if paths
                .get(&occurrence.actor)
                .is_some_and(|actor_path| actor_path != requested)
            {
                return arm_refused("actor path differs from its authenticated projection");
            }

            paths
                .iter()
                .map(|(principal, path)| {
                    let mut projected = occurrence.clone();
                    let OccurrenceResource::PathOccurrence { requested, .. } =
                        &mut projected.resource
                    else {
                        unreachable!("path occurrence changed while projecting")
                    };
                    *requested = path.clone();
                    projected.resource =
                        canonicalizers.canonicalize_occurrence(&projected.resource, principal)?;
                    Ok((principal.clone(), projected))
                })
                .collect()
        })
        .collect()
}

fn occurrence_for_principal<'a>(
    occurrences: &'a [EffectOccurrence],
    projected_occurrences: &'a [BTreeMap<Principal, EffectOccurrence>],
    effect_index: usize,
    principal: &Principal,
) -> &'a EffectOccurrence {
    projected_occurrences[effect_index]
        .get(principal)
        .unwrap_or(&occurrences[effect_index])
}

#[cfg(test)]
std::thread_local! {
    static IMMUTABLE_AUTHORITY_IDENTITY_COMPARISONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static IMMUTABLE_AUTHORITY_VALIDATION_PASSES: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_immutable_authority_identity_comparison() {
    IMMUTABLE_AUTHORITY_IDENTITY_COMPARISONS.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
fn reset_immutable_authority_test_counts() {
    IMMUTABLE_AUTHORITY_IDENTITY_COMPARISONS.with(|count| count.set(0));
    IMMUTABLE_AUTHORITY_VALIDATION_PASSES.with(|count| count.set(0));
}

#[cfg(test)]
fn immutable_authority_test_counts() -> (usize, usize) {
    let comparisons = IMMUTABLE_AUTHORITY_IDENTITY_COMPARISONS.with(std::cell::Cell::get);
    let validations = IMMUTABLE_AUTHORITY_VALIDATION_PASSES.with(std::cell::Cell::get);
    (comparisons, validations)
}

fn validate_authority_state(
    identity: &SemanticIdentity,
    definitions: &DefinitionSet,
    state: &DecisionAuthorityState,
) -> Result<()> {
    validate_immutable_authority_state(identity, definitions, state)?;
    validate_live_authority_state(identity, definitions, state)
}

fn validate_immutable_authority_state(
    identity: &SemanticIdentity,
    definitions: &DefinitionSet,
    state: &DecisionAuthorityState,
) -> Result<()> {
    #[cfg(test)]
    IMMUTABLE_AUTHORITY_VALIDATION_PASSES.with(|count| count.set(count.get() + 1));
    validate_ceiling(
        &state.process_ceiling,
        identity,
        definitions,
        true,
        "process ceiling",
    )?;
    validate_ceiling(
        &state.root_ceiling,
        identity,
        definitions,
        true,
        "root authority ceiling",
    )?;
    validate_authority_rows(
        &state.bootstrap_floor,
        identity,
        definitions,
        true,
        "bootstrap floor",
    )?;
    if state
        .protected_objects
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return arm_refused("protected object guards must be sorted and unique");
    }
    validate_authority_rows(
        &state.protected_resources,
        identity,
        definitions,
        false,
        "protected resources",
    )?;
    for (principal, policy) in state.principal_policies.iter() {
        if principal.is_transparent_runtime_frame() {
            return arm_refused("transparent runtime principal has a policy row");
        }
        validate_authority_rows(&policy.denials, identity, definitions, false, "denials")?;
        validate_authority_rows(
            &policy.static_floor,
            identity,
            definitions,
            true,
            "static floor",
        )?;
        validate_ceiling(
            &policy.escalation_ceiling,
            identity,
            definitions,
            true,
            "escalation ceiling",
        )?;
        validate_authority_rows(
            &policy.implicit_package_self,
            identity,
            definitions,
            true,
            "implicit package-self",
        )?;
    }

    Ok(())
}

fn validate_live_authority_state(
    identity: &SemanticIdentity,
    definitions: &DefinitionSet,
    state: &DecisionAuthorityState,
) -> Result<()> {
    validate_sorted_by(
        &state.revocations,
        |row| row.authority.source_id.as_str(),
        "revocations",
    )?;
    for revocation in &state.revocations {
        if revocation.generation != state.generations.negative {
            return arm_refused("revocation record has a stale negative generation");
        }
        validate_sorted_nonempty_ids(&revocation.ancestor_ids, "revocation ancestors")?;
        validate_bound_authority(&revocation.authority, identity, definitions, false)?;
    }

    validate_sorted_by(&state.handles, |row| row.handle_id.as_str(), "handles")?;
    for handle in &state.handles {
        if handle.observed_negative_generation != state.generations.negative
            || handle.published_handle_generation != state.generations.handle
        {
            return arm_refused("handle record has stale generations");
        }
        if handle.owner.is_transparent_runtime_frame()
            || handle.holder.is_transparent_runtime_frame()
            || handle.owner.is_quarantine()
            || handle.holder.is_quarantine()
        {
            return arm_refused(
                "handle owner and holder must be non-transparent, non-quarantine principals",
            );
        }
        validate_sorted_nonempty_ids(&handle.ancestor_ids, "handle ancestors")?;
        validate_bound_authority(&handle.authority, identity, definitions, true)?;
        let definition = definitions.get(handle.authority.selector.action.as_str())?;
        if !definition.channels.handle {
            return arm_refused("handle authority uses an action with a closed handle channel");
        }
    }

    validate_sorted_by(
        &state.dynamic_grants,
        |row| row.grant_id.as_str(),
        "dynamic grants",
    )?;
    for grant in &state.dynamic_grants {
        if grant.observed_negative_generation != state.generations.negative
            || grant.published_dynamic_generation != state.generations.dynamic
        {
            return arm_refused("dynamic grant has stale generations");
        }
        validate_bound_authority(&grant.authority, identity, definitions, true)?;
        let definition = definitions.get(grant.authority.selector.action.as_str())?;
        if !definition.channels.dynamic
            || definition.static_only
            || definition.globality == Globality::Terminal
        {
            return arm_refused("dynamic grant uses a forbidden action lifecycle/channel");
        }
        let within_ceiling = match state.principal_policies.get(&grant.principal) {
            Some(policy) => {
                ceiling_contains_selector(&policy.escalation_ceiling, &grant.authority)?
            }
            None => false,
        };
        if !within_ceiling {
            return arm_refused("dynamic grant exceeds its canonical static escalation ceiling");
        }
    }
    Ok(())
}

fn protected_object_matches(guard: &ProtectedObjectGuard, occurrence: &EffectOccurrence) -> bool {
    if guard.action != occurrence.action {
        return false;
    }
    match &occurrence.resource {
        // @ref LLP 0021#decision-staging-and-principal-semantics — an exact
        // protected object guards the object targeted by the occurrence. The
        // retained parent is an ancestry/staging fact, not an implicit subtree
        // selector; protected directory entries and package trees are modeled
        // explicitly by path-tree guards.
        OccurrenceResource::PathOccurrence {
            final_object,
            final_object_generation,
            ..
        } => {
            final_object.as_ref() == Some(&guard.object)
                && guard
                    .verification_generation
                    .as_ref()
                    .is_none_or(|expected| final_object_generation.as_ref() == Some(expected))
        }
        OccurrenceResource::ExecutableOccurrence {
            executable_object,
            interpreter_object,
            ..
        } => [executable_object.as_ref(), interpreter_object.as_ref()]
            .into_iter()
            .flatten()
            .any(|object| object == &guard.object),
        _ => false,
    }
}

fn validate_ceiling(
    ceiling: &AuthorityCeiling,
    identity: &SemanticIdentity,
    definitions: &DefinitionSet,
    positive: bool,
    label: &str,
) -> Result<()> {
    if let AuthorityCeiling::Bounded(authorities) = ceiling {
        validate_authority_rows(authorities, identity, definitions, positive, label)?;
    }
    Ok(())
}

fn validate_authority_rows(
    authorities: &[BoundAuthority],
    identity: &SemanticIdentity,
    definitions: &DefinitionSet,
    positive: bool,
    label: &str,
) -> Result<()> {
    validate_sorted_by(authorities, |row| row.source_id.as_str(), label)?;
    for authority in authorities {
        validate_bound_authority(authority, identity, definitions, positive)?;
    }
    Ok(())
}

fn validate_bound_authority(
    authority: &BoundAuthority,
    identity: &SemanticIdentity,
    definitions: &DefinitionSet,
    positive: bool,
) -> Result<()> {
    let definition = definitions.validate_selector(&authority.selector)?;
    if authority.armed_snapshot_digest != identity.armed_snapshot_digest {
        return arm_refused("authority row belongs to a different armed snapshot");
    }
    let has_package_root = authority.selector.resource.contains_package_logical_root();
    match (&authority.package_root_owner, has_package_root) {
        (Some(owner), true) if owner.is_package() => {}
        (None, false) => {}
        _ => return arm_refused("authority has an invalid package-root owner binding"),
    }
    if positive && definition.lifecycle != Lifecycle::Authorable {
        return arm_refused("positive authority references a non-authorable definition");
    }
    Ok(())
}

fn validate_sorted_by<T>(rows: &[T], key: impl Fn(&T) -> &str, label: &str) -> Result<()> {
    if rows.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        return arm_refused(format!("{label} must be sorted and unique"));
    }
    Ok(())
}

fn validate_sorted_nonempty_ids(ids: &[NonEmptyString], label: &str) -> Result<()> {
    if ids
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return arm_refused(format!("{label} must be sorted and unique"));
    }
    Ok(())
}

fn ceiling_contains_selector(ceiling: &AuthorityCeiling, child: &BoundAuthority) -> Result<bool> {
    match ceiling {
        AuthorityCeiling::Unbounded => Ok(true),
        AuthorityCeiling::Bounded(parents) => {
            for parent in parents {
                let context = ContainmentContext {
                    same_snapshot: parent.armed_snapshot_digest == child.armed_snapshot_digest,
                    same_package_root_owner: package_owner_equal(parent, child),
                };
                if matches!(
                    try_compare_authority_containment(&parent.selector, &child.selector, &context,)?,
                    Containment::Equal | Containment::StrictSubset
                ) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn package_owner_equal(parent: &BoundAuthority, child: &BoundAuthority) -> bool {
    let package_root = parent.selector.resource.contains_package_logical_root()
        || child.selector.resource.contains_package_logical_root();
    !package_root || parent.package_root_owner == child.package_root_owner
}

fn ceiling_allows<C: PeerClassifier>(
    ceiling: &AuthorityCeiling,
    occurrence: &EffectOccurrence,
    principal: &Principal,
    armed_snapshot_digest: &Digest,
    classifier: &C,
) -> Result<bool> {
    match ceiling {
        AuthorityCeiling::Unbounded => Ok(true),
        AuthorityCeiling::Bounded(authorities) => Ok(first_matching_authority(
            authorities,
            occurrence,
            principal,
            armed_snapshot_digest,
            AuthorityPolarity::Positive,
            classifier,
        )?
        .is_some()),
    }
}

fn first_matching_authority<'a, C: PeerClassifier>(
    authorities: &'a [BoundAuthority],
    occurrence: &EffectOccurrence,
    principal: &Principal,
    armed_snapshot_digest: &Digest,
    polarity: AuthorityPolarity,
    classifier: &C,
) -> Result<Option<&'a BoundAuthority>> {
    for authority in authorities {
        if authority_matches(
            authority,
            occurrence,
            principal,
            armed_snapshot_digest,
            polarity,
            classifier,
        )? {
            return Ok(Some(authority));
        }
    }
    Ok(None)
}

fn authority_matches<C: PeerClassifier>(
    authority: &BoundAuthority,
    occurrence: &EffectOccurrence,
    _principal: &Principal,
    armed_snapshot_digest: &Digest,
    polarity: AuthorityPolarity,
    classifier: &C,
) -> Result<bool> {
    let requested = occurrence.resource.requested_selector_resource();
    let has_package_root = authority.selector.resource.contains_package_logical_root()
        || requested
            .as_ref()
            .is_some_and(|resource| resource.contains_package_logical_root());
    let expected_owner = if occurrence.effect_owner.is_package() {
        Some(&occurrence.effect_owner)
    } else {
        None
    };
    let containment = ContainmentContext {
        same_snapshot: &authority.armed_snapshot_digest == armed_snapshot_digest,
        same_package_root_owner: !has_package_root
            || authority.package_root_owner.as_ref() == expected_owner,
    };
    selector_matches_occurrence_after_stage_validation(
        &authority.selector,
        occurrence,
        &containment,
        polarity,
        classifier,
    )
}

#[allow(clippy::too_many_arguments)]
fn fill_from_policy_authorities<C: PeerClassifier>(
    pending: &mut [PendingPrincipal],
    occurrences: &[EffectOccurrence],
    projected_occurrences: &[BTreeMap<Principal, EffectOccurrence>],
    context: &VerifiedDecisionContext,
    classifier: &C,
    select: impl Fn(&PrincipalPolicy) -> &[BoundAuthority],
    stratum: DecisionStratumId,
    reason: DecisionReason,
) -> Result<()> {
    for pending_row in pending.iter_mut().filter(|row| row.authorization.is_none()) {
        let Some(policy) = context
            .authority
            .principal_policies
            .get(&pending_row.principal)
        else {
            continue;
        };
        let occurrence = occurrence_for_principal(
            occurrences,
            projected_occurrences,
            pending_row.effect_index,
            &pending_row.principal,
        );
        if let Some(authority) = first_matching_authority(
            select(policy),
            occurrence,
            &pending_row.principal,
            &context.identity.armed_snapshot_digest,
            AuthorityPolarity::Positive,
            classifier,
        )? {
            pending_row.authorization = Some(positive_evidence(
                pending_row,
                stratum,
                reason,
                authority.source_id.as_str(),
            ));
        }
    }
    Ok(())
}

fn positive_evidence(
    pending: &PendingPrincipal,
    stratum: DecisionStratumId,
    reason: DecisionReason,
    source_id: &str,
) -> DecisionEvidence {
    DecisionEvidence {
        effect_index: pending.effect_index,
        principal: Some(pending.principal.clone()),
        stratum,
        reason,
        source_id: Some(source_id.to_owned()),
    }
}

fn hard_decision(
    outcome: DecisionOutcome,
    stratum: DecisionStratumId,
    effect_index: usize,
    principal: Option<Principal>,
    reason: DecisionReason,
    source_id: Option<String>,
) -> Decision {
    Decision {
        outcome,
        decisive_stratum: Some(stratum),
        evidence: vec![DecisionEvidence {
            effect_index,
            principal,
            stratum,
            reason,
            source_id,
        }],
    }
}

fn arm_refused<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::ArmRefused(message.into()))
}

#[allow(dead_code)]
fn _resource_kind_marker(_: ResourceKind) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AuthoritySelector, DecisionContext, DecisionSetSchema, Effect, EffectCombination,
        IpAddress, PeerClass, SafeUint,
    };
    use crate::registry::ValidatedProfile;
    use serde::Deserialize;
    use serde_json::json;
    use std::collections::BTreeSet;

    const ZERO_DIGEST: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[derive(Deserialize)]
    struct Occurrences {
        occurrences: Vec<EffectOccurrence>,
    }

    fn package(name: &str) -> Principal {
        serde_json::from_value(json!({
            "kind": "package",
            "name": name,
            "integrity": ZERO_DIGEST,
            "locator": format!("{name}@1.0.0")
        }))
        .unwrap()
    }

    fn definitions() -> DefinitionSet {
        let mut definitions: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../capsec/registry/capability-definitions.json"
        ))
        .unwrap();
        definitions["definitions"]
            .as_array_mut()
            .unwrap()
            .retain(|definition| {
                matches!(
                    definition["id"].as_str(),
                    Some("env:read" | "fs:read" | "fs:write" | "process:signal")
                )
            });
        ValidatedProfile::from_json(
            &serde_json::to_vec(&definitions).unwrap(),
            include_bytes!("../../../capsec/registry/policy-rules.json"),
        )
        .unwrap()
        .definitions
    }

    fn identity() -> SemanticIdentity {
        let digest = Digest::new(ZERO_DIGEST).unwrap();
        SemanticIdentity {
            profile: PROFILE.to_owned(),
            semantic_core: SEMANTIC_CORE.to_owned(),
            vocab_digest: digest.clone(),
            registry_digest: digest.clone(),
            policy_digest: digest.clone(),
            armed_snapshot_digest: digest,
        }
    }

    fn empty_authority() -> DecisionAuthorityState {
        DecisionAuthorityState {
            generations: GenerationSet {
                negative: SafeUint::ZERO,
                dynamic: SafeUint::ZERO,
                handle: SafeUint::ZERO,
            },
            process_ceiling: AuthorityCeiling::Unbounded.into(),
            root_ceiling: AuthorityCeiling::Unbounded.into(),
            bootstrap_floor: vec![].into(),
            protected_objects: vec![].into(),
            protected_resources: vec![].into(),
            principal_policies: BTreeMap::new().into(),
            revocations: vec![],
            handles: vec![],
            dynamic_grants: vec![],
        }
    }

    fn test_path_canonicalizers(
        authority: &DecisionAuthorityState,
    ) -> crate::path_alias::PathAliasCanonicalizers {
        use crate::model::{LogicalPath, LogicalRoot, ObjectPlatform, PathComponent};
        use crate::path_alias::{
            BoundVolumePathCanonicalizer, PathAliasCanonicalizerIdentity,
            PathCanonicalizerRootBinding,
        };

        let volume = NonEmptyString::new("dev-1").unwrap();
        let mut package_principals = authority
            .principal_policies
            .keys()
            .filter(|principal| principal.is_package())
            .cloned()
            .collect::<BTreeSet<_>>();
        let examples: Occurrences = serde_json::from_slice(include_bytes!(
            "../../../capsec/examples/effect-occurrences.canonical.json"
        ))
        .unwrap();
        for occurrence in examples.occurrences {
            package_principals.extend(
                std::iter::once(occurrence.actor)
                    .chain(std::iter::once(occurrence.effect_owner))
                    .chain(occurrence.constrained_principals)
                    .filter(|principal| principal.is_package()),
            );
        }
        let mut bindings = vec![PathCanonicalizerRootBinding {
            logical_root: LogicalRoot::Project,
            owner: None,
            logical_path: None,
            host_path: LogicalPath {
                root: LogicalRoot::Absolute,
                components: vec![PathComponent::utf8("project").unwrap()],
                host_bound: Some(true),
            },
            platform: ObjectPlatform::Unix,
            volume: volume.clone(),
        }];
        bindings.extend(
            package_principals
                .into_iter()
                .enumerate()
                .map(|(index, principal)| PathCanonicalizerRootBinding {
                    logical_root: LogicalRoot::Package,
                    owner: Some(principal),
                    logical_path: None,
                    host_path: LogicalPath {
                        root: LogicalRoot::Absolute,
                        components: vec![
                            PathComponent::utf8("project").unwrap(),
                            PathComponent::utf8(format!("package-{index}")).unwrap(),
                        ],
                        host_bound: Some(true),
                    },
                    platform: ObjectPlatform::Unix,
                    volume: volume.clone(),
                }),
        );
        crate::path_alias::PathAliasCanonicalizers::bind(
            vec![BoundVolumePathCanonicalizer {
                platform: ObjectPlatform::Unix,
                volume,
                identity: PathAliasCanonicalizerIdentity::ByteIdentityV1,
            }],
            bindings,
        )
        .unwrap()
    }

    fn arm(authority: DecisionAuthorityState) -> Result<VerifiedDecisionContext> {
        let identity = identity();
        let path_canonicalizers = test_path_canonicalizers(&authority);
        VerifiedDecisionContext::arm_with_path_canonicalizers(
            ArmInputs {
                expected_identity: identity.clone(),
                loaded_identity: identity,
                target: TargetArmState::CompleteAdvertised,
                structure_valid: true,
            },
            definitions(),
            authority,
            path_canonicalizers,
        )
    }

    #[test]
    fn scoped_arm_marker_preserves_incomplete_gate_semantics() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<TargetArmState>();

        let authority = empty_authority();
        let identity = identity();
        let scoped = VerifiedDecisionContext::arm_with_path_canonicalizers(
            ArmInputs {
                expected_identity: identity.clone(),
                loaded_identity: identity,
                target: TargetArmState::ScopedAdvertised,
                structure_valid: true,
            },
            definitions(),
            authority,
            test_path_canonicalizers(&empty_authority()),
        )
        .unwrap();
        let occurrence = env_occurrence();
        let mut incomplete = gate();
        incomplete.target_cell = TargetCellDisposition::Incomplete;
        let decision = evaluate_decision_set(
            &scoped,
            &set_from(&occurrence),
            &[incomplete],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::RefuseArming);
        assert_eq!(
            decision.evidence[0].reason,
            DecisionReason::TargetCellIncomplete
        );
    }

    #[test]
    fn neutral_arm_without_a_bound_volume_table_refuses_path_decisions() {
        let identity = identity();
        let context = VerifiedDecisionContext::arm(
            ArmInputs {
                expected_identity: identity.clone(),
                loaded_identity: identity,
                target: TargetArmState::CompleteAdvertised,
                structure_valid: true,
            },
            definitions(),
            empty_authority(),
        )
        .unwrap();
        let occurrence = occurrence_named("fs:read");
        assert!(matches!(
            evaluate_decision_set(
                &context,
                &set_from(&occurrence),
                &[gate()],
                Workflow::ProductionEnforce,
                &|_| Some(PeerClass::Public),
            ),
            Err(Error::AliasCanonicalizationRefused(message))
                if message.contains("no bound-volume canonicalizer")
        ));
    }

    fn env_occurrence() -> EffectOccurrence {
        occurrence_named("env:read")
    }

    fn occurrence_named(action: &str) -> EffectOccurrence {
        let examples: Occurrences = serde_json::from_slice(include_bytes!(
            "../../../capsec/examples/effect-occurrences.canonical.json"
        ))
        .unwrap();
        examples
            .occurrences
            .into_iter()
            .find(|row| row.action.as_str() == action)
            .unwrap()
    }

    fn set_from(occurrence: &EffectOccurrence) -> DecisionSet {
        DecisionSet {
            decision_set_schema: DecisionSetSchema::V1,
            operation_id: NonEmptyString::new("operation-1").unwrap(),
            atomicity_group: StableId::new("test.group").unwrap(),
            combination: EffectCombination::Conjunction,
            context: DecisionContext {
                stage: occurrence.stage,
                actor: occurrence.actor.clone(),
                constrained_principals: occurrence.constrained_principals.clone(),
                presented_handle_ids: Vec::new(),
            },
            effects: vec![Effect {
                action: occurrence.action.clone(),
                effect_owner: occurrence.effect_owner.clone(),
                resource: occurrence.resource.clone(),
            }],
        }
    }

    fn gate() -> EffectGate {
        EffectGate {
            coverage_edge_id: StableId::new("test.edge").unwrap(),
            target_cell: TargetCellDisposition::Complete,
            definition_and_edge_predicates_satisfied: true,
        }
    }

    fn authority(occurrence: &EffectOccurrence, id: &str) -> BoundAuthority {
        BoundAuthority {
            source_id: NonEmptyString::new(id).unwrap(),
            selector: AuthoritySelector {
                action: occurrence.action.clone(),
                resource: occurrence.resource.requested_selector_resource().unwrap(),
            },
            armed_snapshot_digest: identity().armed_snapshot_digest,
            package_root_owner: None,
        }
    }

    fn classifier(_: IpAddress) -> Option<PeerClass> {
        Some(PeerClass::Public)
    }

    fn root(name: &str) -> Principal {
        serde_json::from_value(json!({ "kind": "root", "identity": name })).unwrap()
    }

    fn root_occurrence(mut occurrence: EffectOccurrence) -> EffectOccurrence {
        let principal = root("project-root");
        occurrence.actor = principal.clone();
        occurrence.effect_owner = principal.clone();
        occurrence.constrained_principals = vec![principal];
        occurrence
    }

    fn package_tree_authority(action: &str, owner: Principal, source_id: &str) -> BoundAuthority {
        BoundAuthority {
            source_id: NonEmptyString::new(source_id).unwrap(),
            selector: serde_json::from_value(json!({
                "cap": action,
                "resource": {
                    "kind": "path-tree",
                    "path": {"root": "package", "components": []}
                }
            }))
            .unwrap(),
            armed_snapshot_digest: identity().armed_snapshot_digest,
            package_root_owner: Some(owner),
        }
    }

    #[test]
    fn audit_relaxes_only_missing_authority() {
        let occurrence = env_occurrence();
        let context = arm(empty_authority()).unwrap();
        let decision = evaluate_decision_set(
            &context,
            &set_from(&occurrence),
            &[gate()],
            Workflow::DiagnosticAudit,
            &classifier,
        )
        .unwrap();
        assert_eq!(
            decision.outcome,
            DecisionOutcome::AllowWithWouldDenyEvidence
        );
        assert_eq!(
            decision.evidence[0].reason,
            DecisionReason::MissingAuthority
        );

        let mut closed = gate();
        closed.target_cell = TargetCellDisposition::Closed;
        let decision = evaluate_decision_set(
            &context,
            &set_from(&occurrence),
            &[closed],
            Workflow::DiagnosticAudit,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(
            decision.evidence[0].reason,
            DecisionReason::TargetCellClosed
        );
    }

    #[test]
    fn bounded_root_ceiling_constrains_ambient_root() {
        let occurrence = root_occurrence(env_occurrence());
        let mut state = empty_authority();
        state.root_ceiling = AuthorityCeiling::Bounded(Vec::new()).into();
        let context = arm(state).unwrap();
        let decision = evaluate_decision_set(
            &context,
            &set_from(&occurrence),
            &[gate()],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(
            decision.decisive_stratum,
            Some(DecisionStratumId::RootAuthorityCeiling)
        );
        assert_eq!(
            decision.evidence[0].reason,
            DecisionReason::RootAuthorityCeiling
        );
    }

    #[test]
    fn root_ceiling_does_not_constrain_package_floor() {
        let occurrence = env_occurrence();
        let principal = occurrence.effect_owner.clone();
        let mut state = empty_authority();
        state.root_ceiling = AuthorityCeiling::Bounded(Vec::new()).into();
        state.principal_policies.insert(
            principal,
            PrincipalPolicy {
                static_floor: vec![authority(&occurrence, "package-floor")],
                ..PrincipalPolicy::default()
            },
        );
        let context = arm(state).unwrap();
        let decision = evaluate_decision_set(
            &context,
            &set_from(&occurrence),
            &[gate()],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert!(decision
            .evidence
            .iter()
            .any(|row| row.stratum == DecisionStratumId::StaticFloor));
    }

    #[test]
    fn root_ceiling_allows_only_declared_root_effects() {
        let occurrence = root_occurrence(env_occurrence());
        let mut state = empty_authority();
        state.root_ceiling =
            AuthorityCeiling::Bounded(vec![authority(&occurrence, "root-ceiling-env")]).into();
        let context = arm(state).unwrap();
        let decision = evaluate_decision_set(
            &context,
            &set_from(&occurrence),
            &[gate()],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert!(decision
            .evidence
            .iter()
            .any(|row| row.stratum == DecisionStratumId::AmbientRoot));
    }

    #[test]
    fn bootstrap_floor_is_destroyed_once_for_all_retained_contexts() {
        let occurrence = root_occurrence(env_occurrence());
        let mut state = empty_authority();
        state.root_ceiling =
            AuthorityCeiling::Bounded(vec![authority(&occurrence, "root-ceiling-env")]).into();
        state.bootstrap_floor = vec![authority(&occurrence, "bootstrap-env")].into();
        let context = arm(state).unwrap();
        let retained = context.clone();

        let active = evaluate_decision_set(
            &context,
            &set_from(&occurrence),
            &[gate()],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(active.outcome, DecisionOutcome::Allow);
        assert_eq!(active.evidence[0].reason, DecisionReason::BootstrapFloor);
        assert_eq!(
            active.evidence[0].source_id.as_deref(),
            Some("bootstrap-env")
        );

        assert!(context.seal_bootstrap_phase());
        assert!(!retained.bootstrap_phase_active());
        assert!(!retained.seal_bootstrap_phase());
        let sealed = evaluate_decision_set(
            &retained,
            &set_from(&occurrence),
            &[gate()],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(sealed.outcome, DecisionOutcome::Deny);
        assert_eq!(sealed.evidence[0].reason, DecisionReason::MissingAuthority);
    }

    #[test]
    fn principal_denial_precedes_static_floor() {
        let occurrence = env_occurrence();
        let principal = occurrence.effect_owner.clone();
        let mut state = empty_authority();
        state.principal_policies.insert(
            principal,
            PrincipalPolicy {
                denials: vec![authority(&occurrence, "deny")],
                static_floor: vec![authority(&occurrence, "floor")],
                ..PrincipalPolicy::default()
            },
        );
        let context = arm(state).unwrap();
        let set = set_from(&occurrence);
        let decision = evaluate_decision_set(
            &context,
            &set,
            &[gate()],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.evidence[0].reason, DecisionReason::PrincipalDenial);
        let structured = structure_decision_evidence(&context, &set, &decision);
        assert_eq!(structured.identity, *context.identity());
        assert_eq!(structured.stage, occurrence.stage);
        assert_eq!(structured.actor, occurrence.actor);
        assert_eq!(structured.effect_owners, vec![occurrence.effect_owner]);
        assert_eq!(
            structured.constrained_principals,
            occurrence.constrained_principals
        );
        assert_eq!(structured.evidence[0].source_id.as_deref(), Some("deny"));
    }

    #[test]
    fn broad_static_floor_cannot_delegate_over_a_narrower_denial() {
        let principal = package("delegating-package");
        let broad: AuthoritySelector = serde_json::from_value(json!({
            "cap": "fs:read",
            "resource": {
                "kind": "path-tree",
                "path": {"root": "project", "components": []}
            }
        }))
        .unwrap();
        let denied: AuthoritySelector = serde_json::from_value(json!({
            "cap": "fs:read",
            "resource": {
                "kind": "path-exact",
                "path": {
                    "root": "project",
                    "components": [{"encoding": "utf8", "value": "secret.txt"}]
                }
            }
        }))
        .unwrap();
        let allowed: AuthoritySelector = serde_json::from_value(json!({
            "cap": "fs:read",
            "resource": {
                "kind": "path-exact",
                "path": {
                    "root": "project",
                    "components": [{"encoding": "utf8", "value": "public.txt"}]
                }
            }
        }))
        .unwrap();
        let bind = |selector: AuthoritySelector, source_id: &str| BoundAuthority {
            source_id: NonEmptyString::new(source_id).unwrap(),
            selector,
            armed_snapshot_digest: identity().armed_snapshot_digest,
            package_root_owner: None,
        };
        let mut state = empty_authority();
        state.principal_policies.insert(
            principal.clone(),
            PrincipalPolicy {
                denials: vec![bind(denied, "denial")],
                static_floor: vec![bind(broad.clone(), "floor")],
                ..PrincipalPolicy::default()
            },
        );
        let context = arm(state).unwrap();

        assert!(context
            .static_authority_covers(&principal, &allowed, None)
            .unwrap());
        assert!(!context
            .static_authority_covers(&principal, &broad, None)
            .unwrap());
    }

    #[test]
    fn effects_conjoin_and_principal_dimensions_intersect() {
        let occurrence = env_occurrence();
        let first = occurrence.effect_owner.clone();
        let second = package("other-package");
        let mut principals = vec![first.clone(), second.clone()];
        crate::model::sort_and_dedup_principals(&mut principals).unwrap();
        let mut set = set_from(&occurrence);
        set.context.constrained_principals = principals;
        set.effects.push(set.effects[0].clone());
        let mut state = empty_authority();
        state.principal_policies.insert(
            first,
            PrincipalPolicy {
                static_floor: vec![authority(&occurrence, "floor")],
                ..PrincipalPolicy::default()
            },
        );
        let decision = evaluate_decision_set(
            &arm(state).unwrap(),
            &set,
            &[gate(), gate()],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.evidence[0].principal.as_ref(), Some(&second));
        assert_eq!(
            decision.evidence[0].reason,
            DecisionReason::MissingAuthority
        );
    }

    #[test]
    fn mixed_principal_order_and_package_root_owner_preserve_deputy_intersection() {
        let mut occurrence = occurrence_named("fs:read");
        let owner = occurrence.effect_owner.clone();
        let deputy = package("other-package");
        let root = root("project-root");
        let project_path = LogicalPath {
            root: crate::model::LogicalRoot::Project,
            components: vec![
                crate::model::PathComponent::utf8("node_modules").unwrap(),
                crate::model::PathComponent::utf8("reader-lib").unwrap(),
                crate::model::PathComponent::utf8("config").unwrap(),
                crate::model::PathComponent::utf8("app.json").unwrap(),
            ],
            host_bound: None,
        };
        if let OccurrenceResource::PathOccurrence { requested, .. } = &mut occurrence.resource {
            requested.root = crate::model::LogicalRoot::Package;
        } else {
            unreachable!();
        }
        let mut principals = vec![owner.clone(), deputy.clone(), root.clone()];
        principals.sort_by_key(|principal| principal.canonical_sort_key().unwrap());
        occurrence.constrained_principals = principals.clone();
        let mut set = set_from(&occurrence);
        set.context.constrained_principals = principals;

        let mut state = empty_authority();
        for (index, principal) in [owner.clone(), deputy.clone(), root.clone()]
            .into_iter()
            .enumerate()
        {
            let row = if principal == owner {
                let mut row = authority(&occurrence, &format!("floor-{index}"));
                row.package_root_owner = Some(owner.clone());
                row
            } else {
                BoundAuthority {
                    source_id: NonEmptyString::new(format!("floor-{index}")).unwrap(),
                    selector: AuthoritySelector {
                        action: occurrence.action.clone(),
                        resource: crate::model::SelectorResource::PathTree {
                            path: project_path.clone(),
                        },
                    },
                    armed_snapshot_digest: identity().armed_snapshot_digest,
                    package_root_owner: None,
                }
            };
            state.principal_policies.insert(
                principal,
                PrincipalPolicy {
                    static_floor: vec![row],
                    ..PrincipalPolicy::default()
                },
            );
        }
        let package_path = match &occurrence.resource {
            OccurrenceResource::PathOccurrence { requested, .. } => requested.clone(),
            _ => unreachable!(),
        };
        let projections = BTreeMap::from([
            (owner, package_path),
            (deputy, project_path.clone()),
            (root, project_path),
        ]);
        let decision = evaluate_decision_set_with_path_projections(
            &arm(state).unwrap(),
            &set,
            &[gate()],
            &PrincipalPathProjections::new(vec![projections]),
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn incomplete_target_refuses_before_deny_only_lifecycle() {
        let occurrence = env_occurrence();
        let mut set = set_from(&occurrence);
        let mut deny_only = set.effects[0].clone();
        deny_only.action = ActionId::new("process:signal").unwrap();
        set.effects = vec![deny_only, set.effects[0].clone()];
        let mut incomplete = gate();
        incomplete.target_cell = TargetCellDisposition::Incomplete;
        let decision = evaluate_decision_set(
            &arm(empty_authority()).unwrap(),
            &set,
            &[gate(), incomplete],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::RefuseArming);
        assert_eq!(
            decision.evidence[0].reason,
            DecisionReason::TargetCellIncomplete
        );
        assert_eq!(decision.evidence[0].effect_index, 1);
    }

    #[test]
    fn malformed_stage_facts_do_not_jump_ahead_of_principal_denials() {
        let occurrence = occurrence_named("fs:read");
        let principal = occurrence.effect_owner.clone();
        let mut malformed = set_from(&occurrence);
        malformed.context.stage = crate::model::Stage::Requested;
        let mut state = empty_authority();
        state.principal_policies.insert(
            principal,
            PrincipalPolicy {
                denials: vec![authority(&occurrence, "deny")],
                ..PrincipalPolicy::default()
            },
        );
        let decision = evaluate_decision_set(
            &arm(state).unwrap(),
            &malformed,
            &[gate()],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.evidence[0].reason, DecisionReason::PrincipalDenial);
    }

    #[test]
    fn unknown_action_and_malformed_stage_facts_deny_consistently() {
        let context = arm(empty_authority()).unwrap();
        let occurrence = env_occurrence();
        let mut unknown = set_from(&occurrence);
        unknown.effects[0].action = ActionId::new("future:action").unwrap();
        let decision = evaluate_decision_set(
            &context,
            &unknown,
            &[gate()],
            Workflow::DiagnosticAudit,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.evidence[0].reason, DecisionReason::UnknownAction);

        let mut malformed = set_from(&occurrence_named("fs:read"));
        malformed.context.stage = crate::model::Stage::Requested;
        let decision = evaluate_decision_set(
            &context,
            &malformed,
            &[gate()],
            Workflow::DiagnosticAudit,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(
            decision.evidence[0].reason,
            DecisionReason::InvalidOccurrenceFacts
        );
    }

    #[test]
    fn package_path_authority_uses_each_constrained_principals_projection() {
        let first = package("a-package");
        let second = package("b-package");
        let mut constrained = vec![first.clone(), second.clone()];
        constrained.sort_by_key(|principal| {
            crate::canonical::to_jcs_bytes(&serde_json::to_value(principal).unwrap()).unwrap()
        });
        let component = |value: &str| crate::model::PathComponent::utf8(value).unwrap();
        let occurrence = EffectOccurrence {
            action: ActionId::new("fs:read").unwrap(),
            stage: crate::model::Stage::Requested,
            actor: first.clone(),
            effect_owner: first.clone(),
            constrained_principals: constrained.clone(),
            resource: OccurrenceResource::PathOccurrence {
                requested: LogicalPath {
                    root: crate::model::LogicalRoot::Package,
                    components: vec![component("index.js")],
                    host_bound: None,
                },
                follow_mode: crate::model::FollowMode::FollowFinal,
                object_state: crate::model::ObjectState::Unknown,
                parent_object: None,
                final_object: None,
                final_object_generation: None,
                retained_handle: None,
            },
        };
        let mut state = empty_authority();
        for principal in [&first, &second] {
            let mut static_floor = vec![package_tree_authority(
                "fs:read",
                principal.clone(),
                "floor.package",
            )];
            if principal == &first {
                static_floor.push(BoundAuthority {
                    source_id: NonEmptyString::new("floor.project").unwrap(),
                    selector: serde_json::from_value(json!({
                        "cap": "fs:read",
                        "resource": {
                            "kind": "path-tree",
                            "path": {
                                "root": "project",
                                "components": [
                                    {"encoding": "utf8", "value": "node_modules"},
                                    {"encoding": "utf8", "value": "b-package"}
                                ]
                            }
                        }
                    }))
                    .unwrap(),
                    armed_snapshot_digest: identity().armed_snapshot_digest,
                    package_root_owner: None,
                });
            }
            state.principal_policies.insert(
                principal.clone(),
                PrincipalPolicy {
                    static_floor,
                    ..PrincipalPolicy::default()
                },
            );
        }
        let context = arm(state).unwrap();
        let set = set_from(&occurrence);

        assert!(matches!(
            evaluate_decision_set(
                &context,
                &set,
                &[gate()],
                Workflow::ProductionEnforce,
                &classifier,
            ),
            Err(Error::ArmRefused(message))
                if message.contains("lacks authenticated projections")
        ));

        let mut incomplete = BTreeMap::new();
        incomplete.insert(
            first.clone(),
            LogicalPath {
                root: crate::model::LogicalRoot::Package,
                components: vec![component("index.js")],
                host_bound: None,
            },
        );
        assert!(matches!(
            evaluate_decision_set_with_path_projections(
                &context,
                &set,
                &[gate()],
                &PrincipalPathProjections::new(vec![incomplete]),
                Workflow::ProductionEnforce,
                &classifier,
            ),
            Err(Error::ArmRefused(message))
                if message.contains("differ from the constrained principal set")
        ));

        let mut paths = BTreeMap::new();
        paths.insert(
            first.clone(),
            LogicalPath {
                root: crate::model::LogicalRoot::Package,
                components: vec![component("index.js")],
                host_bound: None,
            },
        );
        paths.insert(
            second.clone(),
            LogicalPath {
                root: crate::model::LogicalRoot::Project,
                components: vec![
                    component("node_modules"),
                    component("a-package"),
                    component("index.js"),
                ],
                host_bound: None,
            },
        );
        let decision = evaluate_decision_set_with_path_projections(
            &context,
            &set,
            &[gate()],
            &PrincipalPathProjections::new(vec![paths]),
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(decision.evidence[0].principal.as_ref(), Some(&second));
        assert_eq!(
            decision.evidence[0].reason,
            DecisionReason::MissingAuthority
        );

        let second_occurrence = EffectOccurrence {
            actor: second.clone(),
            effect_owner: second.clone(),
            resource: OccurrenceResource::PathOccurrence {
                requested: LogicalPath {
                    root: crate::model::LogicalRoot::Package,
                    components: vec![component("index.js")],
                    host_bound: None,
                },
                follow_mode: crate::model::FollowMode::FollowFinal,
                object_state: crate::model::ObjectState::Unknown,
                parent_object: None,
                final_object: None,
                final_object_generation: None,
                retained_handle: None,
            },
            ..occurrence
        };
        let mut second_paths = BTreeMap::new();
        second_paths.insert(
            first,
            LogicalPath {
                root: crate::model::LogicalRoot::Project,
                components: vec![
                    component("node_modules"),
                    component("b-package"),
                    component("index.js"),
                ],
                host_bound: None,
            },
        );
        second_paths.insert(
            second,
            LogicalPath {
                root: crate::model::LogicalRoot::Package,
                components: vec![component("index.js")],
                host_bound: None,
            },
        );
        let allowed = evaluate_decision_set_with_path_projections(
            &context,
            &set_from(&second_occurrence),
            &[gate()],
            &PrincipalPathProjections::new(vec![second_paths]),
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(allowed.outcome, DecisionOutcome::Allow);
    }

    #[test]
    fn unprojected_package_executable_and_unix_socket_deputies_refuse() {
        let examples: Occurrences = serde_json::from_slice(include_bytes!(
            "../../../capsec/examples/effect-occurrences.canonical.json"
        ))
        .unwrap();
        let package_path = json!({
            "root": "package",
            "components": [{"encoding": "utf8", "value": "target"}]
        });

        for requested_kind in ["executable", "connect-unix", "listen-unix"] {
            let mut occurrence = examples
                .occurrences
                .iter()
                .find(|occurrence| {
                    occurrence.resource.requested_kind_name() == Some(requested_kind)
                })
                .unwrap_or_else(|| panic!("missing {requested_kind} occurrence"))
                .clone();
            let mut resource = serde_json::to_value(&occurrence.resource).unwrap();
            if requested_kind == "executable" {
                resource["requested"]["path"] = package_path.clone();
            } else {
                resource["requested"]["address"]["path"] = package_path.clone();
            }
            occurrence.resource = serde_json::from_value(resource).unwrap();

            let deputy = package(&format!("{requested_kind}-deputy"));
            occurrence.constrained_principals.push(deputy);
            occurrence.constrained_principals.sort_by_key(|principal| {
                crate::canonical::to_jcs_bytes(&serde_json::to_value(principal).unwrap()).unwrap()
            });

            assert!(matches!(
                evaluate_decision_set(
                    &arm(empty_authority()).unwrap(),
                    &set_from(&occurrence),
                    &[gate()],
                    Workflow::ProductionEnforce,
                    &classifier,
                ),
                Err(Error::ArmRefused(message))
                    if message.contains("package-root resource lacks authenticated projections")
            ));
        }
    }

    #[test]
    fn package_tree_protection_precedes_package_write_authority() {
        let principal = package("protected-package");
        let component = crate::model::PathComponent::utf8("lib.js").unwrap();
        let occurrence = EffectOccurrence {
            action: ActionId::new("fs:write").unwrap(),
            stage: crate::model::Stage::Requested,
            actor: principal.clone(),
            effect_owner: principal.clone(),
            constrained_principals: vec![principal.clone()],
            resource: OccurrenceResource::PathOccurrence {
                requested: LogicalPath {
                    root: crate::model::LogicalRoot::Package,
                    components: vec![component],
                    host_bound: None,
                },
                follow_mode: crate::model::FollowMode::FollowFinal,
                object_state: crate::model::ObjectState::Existing,
                parent_object: None,
                final_object: None,
                final_object_generation: None,
                retained_handle: None,
            },
        };
        let mut state = empty_authority();
        state.protected_resources = vec![package_tree_authority(
            "fs:write",
            principal.clone(),
            "protected",
        )]
        .into();
        state.principal_policies.insert(
            principal.clone(),
            PrincipalPolicy {
                static_floor: vec![package_tree_authority("fs:write", principal, "floor")],
                ..PrincipalPolicy::default()
            },
        );
        let decision = evaluate_decision_set(
            &arm(state).unwrap(),
            &set_from(&occurrence),
            &[gate()],
            Workflow::ProductionEnforce,
            &classifier,
        )
        .unwrap();
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(
            decision.evidence[0].reason,
            DecisionReason::ProtectedResource
        );
        assert_eq!(
            decision.decisive_stratum,
            Some(DecisionStratumId::ProtectedResourceGuards)
        );
    }

    #[test]
    fn exact_object_guard_protects_the_target_not_every_child_of_a_directory() {
        let principal = package("protected-object-package");
        let guarded: ObjectIdentity = serde_json::from_value(json!({
            "platform": "unix",
            "volume": "dev:test",
            "file": "ino:guarded-directory"
        }))
        .unwrap();
        let child: ObjectIdentity = serde_json::from_value(json!({
            "platform": "unix",
            "volume": "dev:test",
            "file": "ino:child"
        }))
        .unwrap();
        let guard = ProtectedObjectGuard {
            action: ActionId::new("fs:write").unwrap(),
            object: guarded.clone(),
            verification_generation: None,
        };
        let mut occurrence = EffectOccurrence {
            action: ActionId::new("fs:write").unwrap(),
            stage: crate::model::Stage::Commit,
            actor: principal.clone(),
            effect_owner: principal.clone(),
            constrained_principals: vec![principal],
            resource: OccurrenceResource::PathOccurrence {
                requested: LogicalPath {
                    root: crate::model::LogicalRoot::Project,
                    components: vec![crate::model::PathComponent::utf8("app.js").unwrap()],
                    host_bound: None,
                },
                follow_mode: crate::model::FollowMode::FollowFinal,
                object_state: crate::model::ObjectState::Existing,
                parent_object: Some(guarded.clone()),
                final_object: Some(child),
                final_object_generation: None,
                retained_handle: Some(NonEmptyString::new("fd:child").unwrap()),
            },
        };

        assert!(!protected_object_matches(&guard, &occurrence));
        let OccurrenceResource::PathOccurrence { final_object, .. } = &mut occurrence.resource
        else {
            unreachable!("fixture is a path occurrence")
        };
        *final_object = Some(guarded);
        assert!(protected_object_matches(&guard, &occurrence));

        let generation_guard = ProtectedObjectGuard {
            verification_generation: Some(
                NonEmptyString::new("apple-st-gen:authenticated").unwrap(),
            ),
            ..guard
        };
        assert!(
            !protected_object_matches(&generation_guard, &occurrence),
            "an object number without its authenticated generation must not match"
        );
        match &mut occurrence.resource {
            OccurrenceResource::PathOccurrence {
                final_object_generation,
                ..
            } => {
                *final_object_generation = Some(NonEmptyString::new("apple-st-gen:stale").unwrap());
            }
            _ => unreachable!("fixture is a path occurrence"),
        }
        assert!(
            !protected_object_matches(&generation_guard, &occurrence),
            "a reused object number with a different generation must not match"
        );
        match &mut occurrence.resource {
            OccurrenceResource::PathOccurrence {
                final_object_generation,
                ..
            } => {
                *final_object_generation = generation_guard.verification_generation.clone();
            }
            _ => unreachable!("fixture is a path occurrence"),
        }
        assert!(protected_object_matches(&generation_guard, &occurrence));
    }

    #[test]
    fn live_publication_cost_is_independent_of_large_immutable_policy_state() {
        const IMMUTABLE_POLICY_ROWS: usize = 4_096;

        let mut state = empty_authority();
        for index in 0..IMMUTABLE_POLICY_ROWS {
            state.principal_policies.insert(
                package(&format!("immutable-policy-{index:04}")),
                PrincipalPolicy::default(),
            );
        }
        let context = arm(state).unwrap();

        reset_immutable_authority_test_counts();
        let mut publication = context.authority().clone();
        publication.generations.dynamic = SafeUint::new(1).unwrap();
        let published = context.with_authority(publication).unwrap();

        assert_eq!(
            published.authority().principal_policies.len(),
            IMMUTABLE_POLICY_ROWS
        );
        assert_eq!(
            immutable_authority_test_counts(),
            (6, 0),
            "publication must compare six immutable identities and must not revalidate policy rows",
        );

        reset_immutable_authority_test_counts();
        let mut tampered = published.authority().clone();
        tampered.principal_policies.insert(
            package("immutable-policy-tamper"),
            PrincipalPolicy::default(),
        );
        assert!(matches!(
            published.with_authority(tampered),
            Err(Error::ArmRefused(message))
                if message.contains("replace immutable authority")
        ));
        assert_eq!(
            immutable_authority_test_counts(),
            (6, 0),
            "copy-on-write tamper must refuse by identity without scanning immutable rows",
        );
    }

    #[test]
    fn live_publication_still_fully_validates_changed_rows() {
        let occurrence = env_occurrence();
        let principal = occurrence.effect_owner.clone();
        let mut state = empty_authority();
        state.principal_policies.insert(
            principal.clone(),
            PrincipalPolicy {
                escalation_ceiling: AuthorityCeiling::Unbounded,
                ..PrincipalPolicy::default()
            },
        );
        let context = arm(state).unwrap();

        reset_immutable_authority_test_counts();
        let mut publication = context.authority().clone();
        publication.generations.dynamic = SafeUint::new(2).unwrap();
        publication.dynamic_grants.push(DynamicGrant {
            grant_id: NonEmptyString::new("stale-live-grant").unwrap(),
            principal,
            authority: authority(&occurrence, "stale-live-authority"),
            observed_negative_generation: SafeUint::ZERO,
            published_dynamic_generation: SafeUint::new(1).unwrap(),
        });

        assert!(matches!(
            context.with_authority(publication),
            Err(Error::ArmRefused(message)) if message.contains("stale generations")
        ));
        assert_eq!(immutable_authority_test_counts(), (6, 0));
    }

    #[test]
    fn stale_dynamic_grant_refuses_arming() {
        let occurrence = env_occurrence();
        let principal = occurrence.effect_owner.clone();
        let mut state = empty_authority();
        state.generations.dynamic = SafeUint::new(2).unwrap();
        state.principal_policies.insert(
            principal.clone(),
            PrincipalPolicy {
                escalation_ceiling: AuthorityCeiling::Unbounded,
                ..PrincipalPolicy::default()
            },
        );
        state.dynamic_grants.push(DynamicGrant {
            grant_id: NonEmptyString::new("grant-1").unwrap(),
            principal,
            authority: authority(&occurrence, "dynamic-authority"),
            observed_negative_generation: SafeUint::ZERO,
            published_dynamic_generation: SafeUint::new(1).unwrap(),
        });
        assert!(matches!(arm(state), Err(Error::ArmRefused(_))));
    }
}
