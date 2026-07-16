//! CapSec rev2 authorization for authenticated module-graph operations.
//!
//! Module reachability is an immutable armed-snapshot dimension, not an
//! authorable host capability. Host effects performed by a factory continue
//! to enter the ordinary CapSec `DecisionSet` ingress at their native effect
//! boundaries. This module supplies the corresponding typed graph decision
//! set and an unforgeable, generation-bound receipt which must exist before a
//! loader may probe, read, reuse, or compile a target.
//! @ref LLP 0021#module-initialization-and-trusted-source-acquisition
//! @ref LLP 0026#4-native-graph-owner-and-hermes-runner

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use capsec_semantics::arming::{ArmedSnapshot, SnapshotGenerations};
use capsec_semantics::canonical::to_jcs_bytes;
use capsec_semantics::model::{
    principal_set_is_canonical, DecisionContext, Digest, NonEmptyString, Principal, StableId, Stage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::identity::{ConditionSet, ImportAttributes, ResolutionKind, SourceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GraphOperationKind {
    StaticImport,
    ReExport,
    DynamicImport,
    LiteralRequire,
    ComputedRequire,
    JsonLoad,
    SourceAcquisition,
    CacheRead,
    PreparedCarrierRead,
    CompileFactory,
    InstantiateFactory,
    ExecuteFactory,
}

impl GraphOperationKind {
    fn coverage_edge_id(self) -> &'static str {
        match self {
            Self::StaticImport | Self::ReExport | Self::JsonLoad => {
                "surface.loader.esm.module.1nqe17q"
            }
            Self::DynamicImport => "surface.loader.dynamic.import.1n0l635",
            Self::LiteralRequire | Self::ComputedRequire => {
                "surface.loader.commonjs.module.13o3pbt"
            }
            Self::SourceAcquisition => {
                "surface.loader.module.runner.trusted.source.acquisition.0bstk81"
            }
            Self::CacheRead => "surface.loader.module.runner.cache.access.0xf8bln",
            Self::PreparedCarrierRead => {
                "surface.loader.module.runner.prepared.carrier.access.1iok9a9"
            }
            Self::CompileFactory => "surface.host.abi.ex.hermes.module.compile.factory.0iy3wyo",
            Self::InstantiateFactory => {
                "surface.host.abi.ex.hermes.module.record.instantiate.043epyu"
            }
            Self::ExecuteFactory => "surface.host.abi.ex.hermes.module.record.run.execute.07z0pon",
        }
    }

    fn is_edge(self) -> bool {
        matches!(
            self,
            Self::StaticImport
                | Self::ReExport
                | Self::DynamicImport
                | Self::LiteralRequire
                | Self::ComputedRequire
                | Self::JsonLoad
        )
    }
}

/// Complete authenticated context for one graph decision. Unlike the Hermes
/// carrier, these are semantic principals rather than runtime-local integers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphAuthorityContext {
    pub requesting_record: SourceId,
    pub actor: Principal,
    pub effect_owner: Principal,
    pub schedule_time_identity: Principal,
    pub constrained_principals: Vec<Principal>,
    pub stage: Stage,
    pub graph_generation: u64,
}

impl GraphAuthorityContext {
    pub fn new(
        requesting_record: SourceId,
        actor: Principal,
        effect_owner: Principal,
        schedule_time_identity: Principal,
        mut constrained_principals: Vec<Principal>,
        stage: Stage,
        graph_generation: u64,
    ) -> Result<Self> {
        constrained_principals.sort_by(|left, right| {
            let left = to_jcs_bytes(&serde_json::to_value(left).expect("principal serializes"))
                .expect("principal canonicalizes");
            let right = to_jcs_bytes(&serde_json::to_value(right).expect("principal serializes"))
                .expect("principal canonicalizes");
            left.cmp(&right)
        });
        constrained_principals.dedup();
        let value = Self {
            requesting_record,
            actor,
            effect_owner,
            schedule_time_identity,
            constrained_principals,
            stage,
            graph_generation,
        };
        value.validate()?;
        Ok(value)
    }

    /// Factory initialization starts a record-owned task. Importer frames
    /// above this boundary deliberately do not constrain once-per-generation
    /// initialization; the defining principal remains fully constrained.
    pub fn initialization(record: SourceId, graph_generation: u64) -> Result<Self> {
        let principal = record
            .defining_principal()
            .cloned()
            .ok_or_else(|| anyhow!("factory initialization needs a defining principal"))?;
        Self::initialization_as(record, principal, graph_generation)
    }

    pub fn initialization_as(
        record: SourceId,
        principal: Principal,
        graph_generation: u64,
    ) -> Result<Self> {
        Self::new(
            record,
            principal.clone(),
            principal.clone(),
            principal.clone(),
            vec![principal],
            Stage::Commit,
            graph_generation,
        )
    }

    fn validate(&self) -> Result<()> {
        if self.graph_generation == 0 {
            bail!("graph authority context generation must be nonzero");
        }
        let requester = match self.requesting_record.defining_principal() {
            Some(principal) => principal,
            None if matches!(&self.requesting_record, SourceId::Builtin { .. })
                && self.effect_owner.is_root() =>
            {
                &self.effect_owner
            }
            None => bail!("graph operation requester has no defining principal"),
        };
        if requester != &self.effect_owner {
            bail!("graph operation effect owner is not the requesting record owner");
        }
        if !principal_set_is_canonical(&self.constrained_principals)
            || !self.constrained_principals.contains(&self.actor)
            || !self.constrained_principals.contains(&self.effect_owner)
            || !self
                .constrained_principals
                .contains(&self.schedule_time_identity)
        {
            bail!(
                "graph constrained-principal set is noncanonical or omits actor, owner, or schedule identity"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphOperationResource {
    pub requester: SourceId,
    pub target: SourceId,
    pub specifier: NonEmptyString,
    pub resolution_kind: ResolutionKind,
    pub conditions: ConditionSet,
    pub attributes: ImportAttributes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_integrity: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrier_digest: Option<Digest>,
}

/// Normative graph decision-set shape. Its resource is an exact authenticated
/// import edge; any host effects caused by the operation are separate ordinary
/// semantic-core `DecisionSet`s evaluated at those effect boundaries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GraphDecisionSet {
    pub operation_id: NonEmptyString,
    pub atomicity_group: StableId,
    pub authorization_gate_id: StableId,
    pub coverage_edge_id: StableId,
    pub kind: GraphOperationKind,
    /// The exact semantic-core context projection used by ordinary effect
    /// decisions caused by this graph operation.
    pub decision_context: DecisionContext,
    pub context: GraphAuthorityContext,
    pub resource: GraphOperationResource,
}

impl GraphDecisionSet {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: GraphOperationKind,
        context: GraphAuthorityContext,
        target: SourceId,
        specifier: impl Into<String>,
        resolution_kind: ResolutionKind,
        conditions: ConditionSet,
        attributes: ImportAttributes,
        source_integrity: Option<Digest>,
        carrier_digest: Option<Digest>,
    ) -> Result<Self> {
        context.validate()?;
        let specifier = NonEmptyString::new(specifier.into()).map_err(anyhow::Error::msg)?;
        let resource = GraphOperationResource {
            requester: context.requesting_record.clone(),
            target,
            specifier,
            resolution_kind,
            conditions,
            attributes,
            source_integrity,
            carrier_digest,
        };
        let kind_matches_resolution = match kind {
            GraphOperationKind::StaticImport => {
                resolution_kind == ResolutionKind::EsmStatic && resource.attributes.is_empty()
            }
            GraphOperationKind::ReExport => {
                resolution_kind == ResolutionKind::EsmStatic
                    && (resource.attributes.is_empty() || resource.attributes.asserts_json())
            }
            GraphOperationKind::DynamicImport => {
                resolution_kind == ResolutionKind::DynamicImport && resource.attributes.is_empty()
            }
            GraphOperationKind::LiteralRequire | GraphOperationKind::ComputedRequire => {
                resolution_kind == ResolutionKind::CommonJsRequire && resource.attributes.is_empty()
            }
            GraphOperationKind::JsonLoad => resource.attributes.asserts_json(),
            GraphOperationKind::SourceAcquisition
            | GraphOperationKind::CacheRead
            | GraphOperationKind::PreparedCarrierRead
            | GraphOperationKind::CompileFactory
            | GraphOperationKind::InstantiateFactory
            | GraphOperationKind::ExecuteFactory => true,
        };
        if !kind_matches_resolution {
            bail!("module operation kind disagrees with resolution semantics");
        }
        let stage_is_valid = match kind {
            GraphOperationKind::StaticImport
            | GraphOperationKind::ReExport
            | GraphOperationKind::DynamicImport
            | GraphOperationKind::LiteralRequire
            | GraphOperationKind::ComputedRequire
            | GraphOperationKind::JsonLoad => context.stage == Stage::Requested,
            GraphOperationKind::CacheRead => context.stage == Stage::Repeat,
            GraphOperationKind::SourceAcquisition
            | GraphOperationKind::PreparedCarrierRead
            | GraphOperationKind::CompileFactory
            | GraphOperationKind::InstantiateFactory
            | GraphOperationKind::ExecuteFactory => context.stage == Stage::Commit,
        };
        if !stage_is_valid {
            bail!("module operation kind disagrees with authorization stage");
        }
        let canonical = to_jcs_bytes(&serde_json::to_value((&kind, &context, &resource))?)?;
        let digest = Sha256::digest(canonical)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(Self {
            operation_id: NonEmptyString::new(format!("module-graph:{digest}"))
                .map_err(anyhow::Error::msg)?,
            atomicity_group: StableId::new(format!("module-graph.{digest}"))
                .map_err(anyhow::Error::msg)?,
            authorization_gate_id: StableId::new(
                "surface.loader.module.runner.edge.authorization.0qnrmj5",
            )
            .map_err(anyhow::Error::msg)?,
            coverage_edge_id: StableId::new(kind.coverage_edge_id()).map_err(anyhow::Error::msg)?,
            kind,
            decision_context: DecisionContext {
                stage: context.stage,
                actor: context.actor.clone(),
                constrained_principals: context.constrained_principals.clone(),
                // Import-edge and trusted-loader authority is non-delegable;
                // bearer handles cannot widen graph reachability.
                presented_handle_ids: Vec::new(),
            },
            context,
            resource,
        })
    }
}

/// Small interface used by tests and by the immutable armed snapshot. It does
/// not expose a mutable allowlist or any source-reading capability.
pub trait GraphImportPolicy {
    fn snapshot_digest(&self) -> &Digest;
    fn snapshot_generations(&self) -> SnapshotGenerations;
    fn authenticates_module_edge(
        &self,
        importer: &Principal,
        request_specifier: &str,
        imported: &Principal,
        resolution_kind: &str,
        conditions: &[String],
        attributes: &BTreeMap<String, String>,
    ) -> bool;
}

impl GraphImportPolicy for ArmedSnapshot {
    fn snapshot_digest(&self) -> &Digest {
        self.digest()
    }

    fn snapshot_generations(&self) -> SnapshotGenerations {
        self.generations()
    }

    fn authenticates_module_edge(
        &self,
        importer: &Principal,
        request_specifier: &str,
        imported: &Principal,
        resolution_kind: &str,
        conditions: &[String],
        attributes: &BTreeMap<String, String>,
    ) -> bool {
        ArmedSnapshot::authenticates_module_edge(
            self,
            importer,
            request_specifier,
            imported,
            resolution_kind,
            conditions,
            attributes,
        )
    }
}

/// Opaque proof that one exact operation was authorized by one immutable
/// snapshot identity and graph generation.
#[derive(Clone, Debug)]
pub struct AuthorizedGraphOperation {
    decision: GraphDecisionSet,
    snapshot_digest: Digest,
    generations: SnapshotGenerations,
}

impl AuthorizedGraphOperation {
    pub fn decision(&self) -> &GraphDecisionSet {
        &self.decision
    }
}

pub struct ModuleGraphAuthorizer<'policy, P: GraphImportPolicy> {
    policy: &'policy P,
}

impl<'policy, P: GraphImportPolicy> ModuleGraphAuthorizer<'policy, P> {
    pub fn new(policy: &'policy P) -> Self {
        Self { policy }
    }

    pub fn authorize(&self, decision: GraphDecisionSet) -> Result<AuthorizedGraphOperation> {
        self.authorize_if_allowed(decision)?
            .ok_or_else(|| anyhow!("module operation denied by authenticated package graph"))
    }

    /// Validate an exact dynamic candidate without turning policy denial into
    /// an entry-link failure. A denied candidate gets no receipt and therefore
    /// cannot be installed in the native call-time table; if its branch is
    /// taken, `import()` returns a rejected promise.
    pub fn authorize_if_allowed(
        &self,
        decision: GraphDecisionSet,
    ) -> Result<Option<AuthorizedGraphOperation>> {
        decision.context.validate()?;
        let expected_context = DecisionContext {
            stage: decision.context.stage,
            actor: decision.context.actor.clone(),
            constrained_principals: decision.context.constrained_principals.clone(),
            presented_handle_ids: Vec::new(),
        };
        if decision.decision_context != expected_context {
            bail!("graph decision semantic context is missing or disagrees with attribution");
        }
        if decision.resource.requester != decision.context.requesting_record {
            bail!("graph decision resource requester disagrees with its context");
        }
        let importer = match decision.resource.requester.defining_principal() {
            Some(principal) => principal,
            None if matches!(&decision.resource.requester, SourceId::Builtin { .. }) => {
                &decision.context.effect_owner
            }
            None => bail!("graph requester has no authenticated principal"),
        };
        // A builtin SourceId is host-owned rather than package-owned. Its
        // public spelling and source key were already authenticated against
        // the immutable snapshot by the no-probe host resolver; treating the
        // resulting exact target as importer-owned here prevents inventing a
        // forgeable pseudo-principal while retaining the typed graph receipt.
        let imported = match decision.resource.target.defining_principal() {
            Some(principal) => principal,
            None if matches!(&decision.resource.target, SourceId::Builtin { .. }) => importer,
            None => bail!("graph target has no authenticated principal"),
        };
        if decision.kind.is_edge() && importer != imported {
            let conditions = decision
                .resource
                .conditions
                .names()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if !self.policy.authenticates_module_edge(
                importer,
                decision.resource.specifier.as_str(),
                imported,
                decision.resource.resolution_kind.wire_name(),
                &conditions,
                decision.resource.attributes.entries(),
            ) {
                return Ok(None);
            }
        } else if importer != imported {
            bail!("cache, carrier, and factory operations cannot change record ownership");
        }
        Ok(Some(AuthorizedGraphOperation {
            decision,
            snapshot_digest: self.policy.snapshot_digest().clone(),
            generations: self.policy.snapshot_generations(),
        }))
    }

    /// Derive a non-delegable source/cache/carrier receipt from an already
    /// authorized exact edge. Co-resident entries cannot be substituted.
    pub fn authorize_access(
        &self,
        edge: &AuthorizedGraphOperation,
        kind: GraphOperationKind,
        source_integrity: Option<Digest>,
        carrier_digest: Option<Digest>,
    ) -> Result<AuthorizedGraphOperation> {
        if !edge.decision.kind.is_edge() {
            bail!("trusted-loader access requires an authorized import edge");
        }
        if !matches!(
            kind,
            GraphOperationKind::SourceAcquisition
                | GraphOperationKind::CacheRead
                | GraphOperationKind::PreparedCarrierRead
        ) {
            bail!("operation is not a trusted-loader access");
        }
        let integrity_shape_is_valid = match kind {
            GraphOperationKind::SourceAcquisition | GraphOperationKind::CacheRead => {
                source_integrity.is_some() && carrier_digest.is_none()
            }
            GraphOperationKind::PreparedCarrierRead => {
                source_integrity.is_some() && carrier_digest.is_some()
            }
            _ => false,
        };
        if !integrity_shape_is_valid {
            bail!("trusted-loader access is missing its exact source or carrier integrity");
        }
        if edge.snapshot_digest != *self.policy.snapshot_digest()
            || edge.generations != self.policy.snapshot_generations()
        {
            bail!("module edge receipt belongs to stale authority");
        }
        let resource = &edge.decision.resource;
        let mut context = edge.decision.context.clone();
        context.stage = if kind == GraphOperationKind::CacheRead {
            Stage::Repeat
        } else {
            Stage::Commit
        };
        let decision = GraphDecisionSet::new(
            kind,
            context,
            resource.target.clone(),
            resource.specifier.as_str(),
            resource.resolution_kind,
            resource.conditions.clone(),
            resource.attributes.clone(),
            source_integrity,
            carrier_digest,
        )?;
        Ok(AuthorizedGraphOperation {
            decision,
            snapshot_digest: edge.snapshot_digest.clone(),
            generations: edge.generations,
        })
    }

    /// Single no-probe entry for a cold source, cache hit, or prepared
    /// carrier. A denied edge cannot invoke `access`.
    pub fn authorize_then_access<T>(
        &self,
        edge_decision: GraphDecisionSet,
        access_kind: GraphOperationKind,
        source_integrity: Digest,
        carrier_digest: Option<Digest>,
        access: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let target = edge_decision.resource.target.clone();
        let graph_generation = edge_decision.context.graph_generation;
        let edge = self.authorize(edge_decision)?;
        let receipt =
            self.authorize_access(&edge, access_kind, Some(source_integrity), carrier_digest)?;
        self.with_authorized_access(&receipt, access_kind, &target, graph_generation, access)
    }

    /// Execute the source/cache/carrier action only after its exact receipt is
    /// revalidated. The closure boundary makes the no-probe ordering testable.
    pub fn with_authorized_access<T>(
        &self,
        receipt: &AuthorizedGraphOperation,
        expected_kind: GraphOperationKind,
        expected_target: &SourceId,
        graph_generation: u64,
        access: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        if receipt.snapshot_digest != *self.policy.snapshot_digest()
            || receipt.generations != self.policy.snapshot_generations()
        {
            bail!("module authorization receipt belongs to stale authority");
        }
        if receipt.decision.kind != expected_kind
            || &receipt.decision.resource.target != expected_target
            || receipt.decision.context.graph_generation != graph_generation
        {
            bail!("module authorization receipt does not cover this exact access");
        }
        access()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use capsec_semantics::model::{Generation, PackageLocator, PathComponent};
    use std::cell::Cell;

    fn digest(label: &str) -> Digest {
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(label));
        Digest::new(format!("sha256-{encoded}")).unwrap()
    }

    fn principal(name: &str) -> Principal {
        Principal::Package {
            name: NonEmptyString::new(name).unwrap(),
            integrity: digest(name),
            locator: PackageLocator::new(format!("{name}@1.0.0")).unwrap(),
        }
    }

    fn source(owner: Principal, name: &str) -> SourceId {
        SourceId::file(owner, vec![PathComponent::utf8(name).unwrap()]).unwrap()
    }

    #[derive(Clone)]
    struct Policy {
        digest: Digest,
        generations: SnapshotGenerations,
        allow: bool,
    }

    impl GraphImportPolicy for Policy {
        fn snapshot_digest(&self) -> &Digest {
            &self.digest
        }

        fn snapshot_generations(&self) -> SnapshotGenerations {
            self.generations
        }

        fn authenticates_module_edge(
            &self,
            _importer: &Principal,
            specifier: &str,
            _imported: &Principal,
            resolution_kind: &str,
            conditions: &[String],
            attributes: &BTreeMap<String, String>,
        ) -> bool {
            self.allow
                && specifier == "dep"
                && resolution_kind == "esm-static"
                && conditions == ["import", "node"]
                && attributes.is_empty()
        }
    }

    fn generations(value: u64) -> SnapshotGenerations {
        let value = Generation::new(value).unwrap();
        SnapshotGenerations {
            policy: value,
            negative: value,
            dynamic: value,
            handle: value,
        }
    }

    fn decision(actor: Principal, target: SourceId) -> GraphDecisionSet {
        let requester = source(actor.clone(), "entry.mjs");
        GraphDecisionSet::new(
            GraphOperationKind::StaticImport,
            GraphAuthorityContext::new(
                requester,
                actor.clone(),
                actor.clone(),
                actor.clone(),
                vec![actor],
                Stage::Requested,
                7,
            )
            .unwrap(),
            target,
            "dep",
            ResolutionKind::EsmStatic,
            ConditionSet::for_kind(ResolutionKind::EsmStatic),
            ImportAttributes::default(),
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn exact_edge_authorizes_before_source_access() {
        let importer = principal("app");
        let target = source(principal("dep"), "index.mjs");
        let policy = Policy {
            digest: digest("snapshot"),
            generations: generations(1),
            allow: true,
        };
        let authorizer = ModuleGraphAuthorizer::new(&policy);
        let edge = authorizer
            .authorize(decision(importer, target.clone()))
            .unwrap();
        let receipt = authorizer
            .authorize_access(
                &edge,
                GraphOperationKind::SourceAcquisition,
                Some(digest("source")),
                None,
            )
            .unwrap();
        let accessed = Cell::new(false);
        authorizer
            .with_authorized_access(
                &receipt,
                GraphOperationKind::SourceAcquisition,
                &target,
                7,
                || {
                    accessed.set(true);
                    Ok(())
                },
            )
            .unwrap();
        assert!(accessed.get());
    }

    #[test]
    fn denial_wrong_owner_missing_attribution_and_no_probe_fail_closed() {
        let importer = principal("app");
        let target = source(principal("dep"), "index.mjs");
        let denied = Policy {
            digest: digest("snapshot"),
            generations: generations(1),
            allow: false,
        };
        let probed = Cell::new(false);
        assert!(ModuleGraphAuthorizer::new(&denied)
            .authorize_if_allowed(decision(importer.clone(), target.clone()))
            .unwrap()
            .is_none());
        assert!(ModuleGraphAuthorizer::new(&denied)
            .authorize_then_access(
                decision(importer.clone(), target.clone()),
                GraphOperationKind::SourceAcquisition,
                digest("source"),
                None,
                || {
                    probed.set(true);
                    Ok(())
                },
            )
            .is_err());
        assert!(!probed.get(), "authorization must not touch the source");

        let requester = source(importer.clone(), "entry.mjs");
        assert!(GraphAuthorityContext::new(
            requester.clone(),
            importer.clone(),
            principal("wrong"),
            importer.clone(),
            vec![importer.clone()],
            Stage::Requested,
            7,
        )
        .is_err());
        assert!(GraphAuthorityContext::new(
            requester,
            importer.clone(),
            importer.clone(),
            principal("scheduler"),
            vec![importer],
            Stage::Requested,
            7,
        )
        .is_err());
    }

    #[test]
    fn receipts_bind_cache_carrier_target_generation_and_immutable_authority() {
        let importer = principal("app");
        let target = source(principal("dep"), "index.mjs");
        let policy = Policy {
            digest: digest("snapshot"),
            generations: generations(1),
            allow: true,
        };
        let authorizer = ModuleGraphAuthorizer::new(&policy);
        let edge = authorizer
            .authorize(decision(importer, target.clone()))
            .unwrap();
        let receipt = authorizer
            .authorize_access(
                &edge,
                GraphOperationKind::PreparedCarrierRead,
                Some(digest("source")),
                Some(digest("carrier")),
            )
            .unwrap();
        authorizer
            .with_authorized_access(
                &receipt,
                GraphOperationKind::PreparedCarrierRead,
                &target,
                7,
                || Ok(()),
            )
            .unwrap();
        let cache = authorizer
            .authorize_access(
                &edge,
                GraphOperationKind::CacheRead,
                Some(digest("cache-entry")),
                None,
            )
            .unwrap();
        authorizer
            .with_authorized_access(&cache, GraphOperationKind::CacheRead, &target, 7, || Ok(()))
            .unwrap();
        assert!(authorizer
            .with_authorized_access(&receipt, GraphOperationKind::CacheRead, &target, 7, || Ok(
                ()
            ))
            .is_err());
        assert!(authorizer
            .with_authorized_access(
                &receipt,
                GraphOperationKind::PreparedCarrierRead,
                &source(principal("other"), "co-resident.mjs"),
                7,
                || Ok(())
            )
            .is_err());
        assert!(authorizer
            .with_authorized_access(
                &receipt,
                GraphOperationKind::PreparedCarrierRead,
                &target,
                8,
                || Ok(())
            )
            .is_err());

        let changed = Policy {
            digest: policy.digest.clone(),
            generations: generations(2),
            allow: true,
        };
        assert!(ModuleGraphAuthorizer::new(&changed)
            .with_authorized_access(
                &receipt,
                GraphOperationKind::PreparedCarrierRead,
                &target,
                7,
                || Ok(())
            )
            .is_err());
    }

    #[test]
    fn initialization_context_is_autonomous_and_record_owned() {
        let owner = principal("dep");
        let context =
            GraphAuthorityContext::initialization(source(owner.clone(), "index.mjs"), 9).unwrap();
        assert_eq!(context.actor, owner);
        assert_eq!(context.actor, context.effect_owner);
        assert_eq!(context.actor, context.schedule_time_identity);
        assert_eq!(context.constrained_principals, vec![context.actor.clone()]);
    }
}
