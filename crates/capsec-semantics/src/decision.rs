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

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cache::GenerationSet;
use crate::containment::{
    selector_matches_occurrence_after_stage_validation, try_compare_authority_containment,
    validate_occurrence_stage_facts, AuthorityPolarity, Containment, ContainmentContext,
    PeerClassifier,
};
use crate::model::{
    ActionId, DecisionSet, Digest, EffectOccurrence, Generation, NonEmptyString, ObjectIdentity,
    OccurrenceResource, Principal, StableId,
};
use crate::registry::{
    DecisionStratumId, DefinitionSet, Globality, Lifecycle, ResourceKind, PROFILE, SEMANTIC_CORE,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionAuthorityState {
    pub generations: GenerationSet,
    pub process_ceiling: AuthorityCeiling,
    pub protected_objects: Vec<ProtectedObjectGuard>,
    pub protected_resources: Vec<BoundAuthority>,
    pub principal_policies: BTreeMap<Principal, PrincipalPolicy>,
    pub revocations: Vec<Revocation>,
    pub handles: Vec<BearerHandle>,
    pub dynamic_grants: Vec<DynamicGrant>,
}

#[derive(Clone, Debug)]
pub struct VerifiedDecisionContext {
    identity: SemanticIdentity,
    definitions: DefinitionSet,
    authority: DecisionAuthorityState,
}

impl VerifiedDecisionContext {
    pub fn arm(
        inputs: ArmInputs,
        definitions: DefinitionSet,
        authority: DecisionAuthorityState,
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
        if inputs.target != TargetArmState::CompleteAdvertised {
            return arm_refused("target is incomplete or unadvertised");
        }
        validate_authority_state(&inputs.loaded_identity, &definitions, &authority)?;
        Ok(Self {
            identity: inputs.loaded_identity,
            definitions,
            authority,
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

    /// Publish a newly validated live authority state while preserving the
    /// authenticated semantic identity and definition set.
    pub fn with_authority(&self, authority: DecisionAuthorityState) -> Result<Self> {
        if authority.process_ceiling != self.authority.process_ceiling
            || authority.protected_objects != self.authority.protected_objects
            || authority.protected_resources != self.authority.protected_resources
            || authority.principal_policies != self.authority.principal_policies
        {
            return arm_refused("live publication attempted to replace immutable authority");
        }
        validate_live_authority_state(&self.identity, &self.definitions, &authority)?;
        Ok(Self {
            identity: self.identity.clone(),
            definitions: self.definitions.clone(),
            authority,
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
    PrincipalDenial,
    Revoked,
    Quarantine,
    InvalidOccurrenceFacts,
    DefinitionOrEdgePredicate,
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
            if let Some(denial) = first_matching_authority(
                &context.authority.protected_resources,
                occurrence,
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
            if !ceiling_allows(
                &context.authority.process_ceiling,
                occurrence,
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

    // 6. Principal denials.
    for (effect_index, occurrence) in occurrences.iter().enumerate() {
        for principal in &occurrence.constrained_principals {
            let denials = context
                .authority
                .principal_policies
                .get(principal)
                .map(|policy| policy.denials.as_slice())
                .unwrap_or_default();
            if let Some(denial) = first_matching_authority(
                denials,
                occurrence,
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
            if authority_matches(
                &revocation.authority,
                occurrence,
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
        if context
            .definitions
            .validate_requested_resource(&occurrence.action, &requested)
            .is_err()
        {
            return Ok(hard_decision(
                DecisionOutcome::Deny,
                DecisionStratumId::DefinitionAndEdgePositivePredicates,
                effect_index,
                None,
                DecisionReason::DefinitionOrEdgePredicate,
                Some(gate.coverage_edge_id.as_str().to_owned()),
            ));
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

    // 10. Static floor.
    fill_from_policy_authorities(
        &mut pending,
        &occurrences,
        context,
        classifier,
        |policy| &policy.static_floor,
        DecisionStratumId::StaticFloor,
        DecisionReason::StaticFloor,
    )?;

    // 11. Bearer handles and operation leases.
    for pending_row in pending.iter_mut().filter(|row| row.authorization.is_none()) {
        let occurrence = &occurrences[pending_row.effect_index];
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

    // 12. Dynamic session authority, already verified within its static ceiling.
    for pending_row in pending.iter_mut().filter(|row| row.authorization.is_none()) {
        let occurrence = &occurrences[pending_row.effect_index];
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

    // 13. Generated implicit package-self authority.
    fill_from_policy_authorities(
        &mut pending,
        &occurrences,
        context,
        classifier,
        |policy| &policy.implicit_package_self,
        DecisionStratumId::ImplicitPackageSelf,
        DecisionReason::ImplicitPackageSelf,
    )?;

    // 14. Ambient authenticated root (still after every denial).
    for pending_row in pending
        .iter_mut()
        .filter(|row| row.authorization.is_none() && row.principal.is_root())
    {
        pending_row.authorization = Some(DecisionEvidence {
            effect_index: pending_row.effect_index,
            principal: Some(pending_row.principal.clone()),
            stratum: DecisionStratumId::AmbientRoot,
            reason: DecisionReason::AmbientRoot,
            source_id: None,
        });
    }

    // 15. Missing authority mode. Audit can relax only this final case.
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
    validate_ceiling(
        &state.process_ceiling,
        identity,
        definitions,
        true,
        "process ceiling",
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
    for (principal, policy) in &state.principal_policies {
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
        OccurrenceResource::PathOccurrence {
            parent_object,
            final_object,
            ..
        } => [parent_object.as_ref(), final_object.as_ref()]
            .into_iter()
            .flatten()
            .any(|object| object == &guard.object),
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
        if let Some(authority) = first_matching_authority(
            select(policy),
            &occurrences[pending_row.effect_index],
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
                    Some("env:read" | "fs:read" | "process:signal")
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
            process_ceiling: AuthorityCeiling::Unbounded,
            protected_objects: vec![],
            protected_resources: vec![],
            principal_policies: BTreeMap::new(),
            revocations: vec![],
            handles: vec![],
            dynamic_grants: vec![],
        }
    }

    fn arm(authority: DecisionAuthorityState) -> Result<VerifiedDecisionContext> {
        let identity = identity();
        VerifiedDecisionContext::arm(
            ArmInputs {
                expected_identity: identity.clone(),
                loaded_identity: identity,
                target: TargetArmState::CompleteAdvertised,
                structure_valid: true,
            },
            definitions(),
            authority,
        )
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
        principals.sort_by_key(|principal| principal.canonical_sort_key().unwrap());
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
        for (index, principal) in [owner.clone(), deputy, root].into_iter().enumerate() {
            let mut row = authority(&occurrence, &format!("floor-{index}"));
            row.package_root_owner = Some(owner.clone());
            state.principal_policies.insert(
                principal,
                PrincipalPolicy {
                    static_floor: vec![row],
                    ..PrincipalPolicy::default()
                },
            );
        }
        let decision = evaluate_decision_set(
            &arm(state).unwrap(),
            &set,
            &[gate()],
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
