// GENERATED FILE - DO NOT EDIT.
// Generator: bun run generate:composition-refusals
// Vendored source: tests/fixtures/prepared-composition/v1/refusals.generated.json
// @ref LLP 0056#63-registry-mechanics-parity-generated-halves

/// Closed composition-admission refusal vocabulary in registry ordinal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompositionRefusalCode {
    /// Registry ordinal 1: envelope-malformed.
    EnvelopeMalformed,
    /// Registry ordinal 2: composition-commitment-mismatch.
    CompositionCommitmentMismatch,
    /// Registry ordinal 3: composition-replayed.
    CompositionReplayed,
    /// Registry ordinal 4: composition-policy-stale.
    CompositionPolicyStale,
    /// Registry ordinal 5: ibex:target-profile-mismatch.
    IbexTargetProfileMismatch,
    /// Registry ordinal 6: composition-unknown-role.
    CompositionUnknownRole,
    /// Registry ordinal 7: composition-duplicate-role.
    CompositionDuplicateRole,
    /// Registry ordinal 8: composition-package-extra.
    CompositionPackageExtra,
    /// Registry ordinal 9: composition-package-missing.
    CompositionPackageMissing,
    /// Registry ordinal 10: composition-mismatch.
    CompositionMismatch,
    /// Registry ordinal 11: package-root-mismatch.
    PackageRootMismatch,
    /// Registry ordinal 12: ibex:prepared-commitment-schema.
    IbexPreparedCommitmentSchema,
    /// Registry ordinal 13: ibex:package-inventory.
    IbexPackageInventory,
    /// Registry ordinal 14: ibex:prepared-commitment-corrupt.
    IbexPreparedCommitmentCorrupt,
    /// Registry ordinal 15: carrier-integrity.
    CarrierIntegrity,
    /// Registry ordinal 16: ibex:principal-grouping.
    IbexPrincipalGrouping,
    /// Registry ordinal 17: ibex:encoding-incompatible.
    IbexEncodingIncompatible,
    /// Registry ordinal 18: ibex:engine-unavailable.
    IbexEngineUnavailable,
    /// Registry ordinal 19: ibex:engine-binding-mismatch.
    IbexEngineBindingMismatch,
    /// Registry ordinal 20: ibex:bytecode-preflight.
    IbexBytecodePreflight,
    /// Registry ordinal 21: ibex:package-graph-binding.
    IbexPackageGraphBinding,
    /// Registry ordinal 22: generation-splice.
    GenerationSplice,
    /// Registry ordinal 23: alias-conflict.
    AliasConflict,
    /// Registry ordinal 24: partition-mismatch.
    PartitionMismatch,
    /// Registry ordinal 25: ibex:duplicate-source-id.
    IbexDuplicateSourceId,
    /// Registry ordinal 26: package-overlap.
    PackageOverlap,
    /// Registry ordinal 27: app-references-agent.
    AppReferencesAgent,
    /// Registry ordinal 28: local-agreement-disagreement.
    LocalAgreementDisagreement,
    /// Registry ordinal 29: union-table-mismatch.
    UnionTableMismatch,
    /// Registry ordinal 30: boundary-inventory-mismatch.
    BoundaryInventoryMismatch,
    /// Registry ordinal 31: external-target-absent.
    ExternalTargetAbsent,
    /// Registry ordinal 32: external-owner-mismatch.
    ExternalOwnerMismatch,
    /// Registry ordinal 33: export-disagreement.
    ExportDisagreement,
    /// Registry ordinal 34: cross-principal-denied.
    CrossPrincipalDenied,
    /// Registry ordinal 35: entry-plan-mismatch.
    EntryPlanMismatch,
    /// Registry ordinal 36: entry-descriptor-invalid.
    EntryDescriptorInvalid,
    /// Registry ordinal 37: composition-root-unlinked.
    CompositionRootUnlinked,
    /// Registry ordinal 38: link-failure.
    LinkFailure,
}

impl CompositionRefusalCode {
    /// All 38 admission refusal codes in normative ordinal order.
    pub const ALL: [CompositionRefusalCode; 38] = [
        Self::EnvelopeMalformed,
        Self::CompositionCommitmentMismatch,
        Self::CompositionReplayed,
        Self::CompositionPolicyStale,
        Self::IbexTargetProfileMismatch,
        Self::CompositionUnknownRole,
        Self::CompositionDuplicateRole,
        Self::CompositionPackageExtra,
        Self::CompositionPackageMissing,
        Self::CompositionMismatch,
        Self::PackageRootMismatch,
        Self::IbexPreparedCommitmentSchema,
        Self::IbexPackageInventory,
        Self::IbexPreparedCommitmentCorrupt,
        Self::CarrierIntegrity,
        Self::IbexPrincipalGrouping,
        Self::IbexEncodingIncompatible,
        Self::IbexEngineUnavailable,
        Self::IbexEngineBindingMismatch,
        Self::IbexBytecodePreflight,
        Self::IbexPackageGraphBinding,
        Self::GenerationSplice,
        Self::AliasConflict,
        Self::PartitionMismatch,
        Self::IbexDuplicateSourceId,
        Self::PackageOverlap,
        Self::AppReferencesAgent,
        Self::LocalAgreementDisagreement,
        Self::UnionTableMismatch,
        Self::BoundaryInventoryMismatch,
        Self::ExternalTargetAbsent,
        Self::ExternalOwnerMismatch,
        Self::ExportDisagreement,
        Self::CrossPrincipalDenied,
        Self::EntryPlanMismatch,
        Self::EntryDescriptorInvalid,
        Self::CompositionRootUnlinked,
        Self::LinkFailure,
    ];

    /// Return the exact lockstep registry code.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EnvelopeMalformed => "envelope-malformed",
            Self::CompositionCommitmentMismatch => "composition-commitment-mismatch",
            Self::CompositionReplayed => "composition-replayed",
            Self::CompositionPolicyStale => "composition-policy-stale",
            Self::IbexTargetProfileMismatch => "ibex:target-profile-mismatch",
            Self::CompositionUnknownRole => "composition-unknown-role",
            Self::CompositionDuplicateRole => "composition-duplicate-role",
            Self::CompositionPackageExtra => "composition-package-extra",
            Self::CompositionPackageMissing => "composition-package-missing",
            Self::CompositionMismatch => "composition-mismatch",
            Self::PackageRootMismatch => "package-root-mismatch",
            Self::IbexPreparedCommitmentSchema => "ibex:prepared-commitment-schema",
            Self::IbexPackageInventory => "ibex:package-inventory",
            Self::IbexPreparedCommitmentCorrupt => "ibex:prepared-commitment-corrupt",
            Self::CarrierIntegrity => "carrier-integrity",
            Self::IbexPrincipalGrouping => "ibex:principal-grouping",
            Self::IbexEncodingIncompatible => "ibex:encoding-incompatible",
            Self::IbexEngineUnavailable => "ibex:engine-unavailable",
            Self::IbexEngineBindingMismatch => "ibex:engine-binding-mismatch",
            Self::IbexBytecodePreflight => "ibex:bytecode-preflight",
            Self::IbexPackageGraphBinding => "ibex:package-graph-binding",
            Self::GenerationSplice => "generation-splice",
            Self::AliasConflict => "alias-conflict",
            Self::PartitionMismatch => "partition-mismatch",
            Self::IbexDuplicateSourceId => "ibex:duplicate-source-id",
            Self::PackageOverlap => "package-overlap",
            Self::AppReferencesAgent => "app-references-agent",
            Self::LocalAgreementDisagreement => "local-agreement-disagreement",
            Self::UnionTableMismatch => "union-table-mismatch",
            Self::BoundaryInventoryMismatch => "boundary-inventory-mismatch",
            Self::ExternalTargetAbsent => "external-target-absent",
            Self::ExternalOwnerMismatch => "external-owner-mismatch",
            Self::ExportDisagreement => "export-disagreement",
            Self::CrossPrincipalDenied => "cross-principal-denied",
            Self::EntryPlanMismatch => "entry-plan-mismatch",
            Self::EntryDescriptorInvalid => "entry-descriptor-invalid",
            Self::CompositionRootUnlinked => "composition-root-unlinked",
            Self::LinkFailure => "link-failure",
        }
    }

    /// Return the normative one-based registry ordinal.
    pub fn ordinal(&self) -> u32 {
        match self {
            Self::EnvelopeMalformed => 1,
            Self::CompositionCommitmentMismatch => 2,
            Self::CompositionReplayed => 3,
            Self::CompositionPolicyStale => 4,
            Self::IbexTargetProfileMismatch => 5,
            Self::CompositionUnknownRole => 6,
            Self::CompositionDuplicateRole => 7,
            Self::CompositionPackageExtra => 8,
            Self::CompositionPackageMissing => 9,
            Self::CompositionMismatch => 10,
            Self::PackageRootMismatch => 11,
            Self::IbexPreparedCommitmentSchema => 12,
            Self::IbexPackageInventory => 13,
            Self::IbexPreparedCommitmentCorrupt => 14,
            Self::CarrierIntegrity => 15,
            Self::IbexPrincipalGrouping => 16,
            Self::IbexEncodingIncompatible => 17,
            Self::IbexEngineUnavailable => 18,
            Self::IbexEngineBindingMismatch => 19,
            Self::IbexBytecodePreflight => 20,
            Self::IbexPackageGraphBinding => 21,
            Self::GenerationSplice => 22,
            Self::AliasConflict => 23,
            Self::PartitionMismatch => 24,
            Self::IbexDuplicateSourceId => 25,
            Self::PackageOverlap => 26,
            Self::AppReferencesAgent => 27,
            Self::LocalAgreementDisagreement => 28,
            Self::UnionTableMismatch => 29,
            Self::BoundaryInventoryMismatch => 30,
            Self::ExternalTargetAbsent => 31,
            Self::ExternalOwnerMismatch => 32,
            Self::ExportDisagreement => 33,
            Self::CrossPrincipalDenied => 34,
            Self::EntryPlanMismatch => 35,
            Self::EntryDescriptorInvalid => 36,
            Self::CompositionRootUnlinked => 37,
            Self::LinkFailure => 38,
        }
    }

    /// Return the admission step that owns this refusal.
    pub fn step(&self) -> u8 {
        match self {
            Self::EnvelopeMalformed => 1,
            Self::CompositionCommitmentMismatch => 2,
            Self::CompositionReplayed => 2,
            Self::CompositionPolicyStale => 2,
            Self::IbexTargetProfileMismatch => 2,
            Self::CompositionUnknownRole => 2,
            Self::CompositionDuplicateRole => 2,
            Self::CompositionPackageExtra => 2,
            Self::CompositionPackageMissing => 2,
            Self::CompositionMismatch => 2,
            Self::PackageRootMismatch => 3,
            Self::IbexPreparedCommitmentSchema => 3,
            Self::IbexPackageInventory => 3,
            Self::IbexPreparedCommitmentCorrupt => 3,
            Self::CarrierIntegrity => 3,
            Self::IbexPrincipalGrouping => 3,
            Self::IbexEncodingIncompatible => 3,
            Self::IbexEngineUnavailable => 3,
            Self::IbexEngineBindingMismatch => 3,
            Self::IbexBytecodePreflight => 3,
            Self::IbexPackageGraphBinding => 3,
            Self::GenerationSplice => 3,
            Self::AliasConflict => 3,
            Self::PartitionMismatch => 4,
            Self::IbexDuplicateSourceId => 4,
            Self::PackageOverlap => 4,
            Self::AppReferencesAgent => 5,
            Self::LocalAgreementDisagreement => 5,
            Self::UnionTableMismatch => 6,
            Self::BoundaryInventoryMismatch => 6,
            Self::ExternalTargetAbsent => 6,
            Self::ExternalOwnerMismatch => 6,
            Self::ExportDisagreement => 6,
            Self::CrossPrincipalDenied => 6,
            Self::EntryPlanMismatch => 7,
            Self::EntryDescriptorInvalid => 7,
            Self::CompositionRootUnlinked => 7,
            Self::LinkFailure => 8,
        }
    }

    /// Return the registry's attacker/producer/environment class.
    pub fn class(&self) -> CompositionRefusalClass {
        match self {
            Self::EnvelopeMalformed => CompositionRefusalClass::Attacker,
            Self::CompositionCommitmentMismatch => CompositionRefusalClass::Attacker,
            Self::CompositionReplayed => CompositionRefusalClass::Attacker,
            Self::CompositionPolicyStale => CompositionRefusalClass::Environment,
            Self::IbexTargetProfileMismatch => CompositionRefusalClass::Environment,
            Self::CompositionUnknownRole => CompositionRefusalClass::Attacker,
            Self::CompositionDuplicateRole => CompositionRefusalClass::Attacker,
            Self::CompositionPackageExtra => CompositionRefusalClass::ProducerDefect,
            Self::CompositionPackageMissing => CompositionRefusalClass::ProducerDefect,
            Self::CompositionMismatch => CompositionRefusalClass::ProducerDefect,
            Self::PackageRootMismatch => CompositionRefusalClass::Attacker,
            Self::IbexPreparedCommitmentSchema => CompositionRefusalClass::ProducerDefect,
            Self::IbexPackageInventory => CompositionRefusalClass::Attacker,
            Self::IbexPreparedCommitmentCorrupt => CompositionRefusalClass::Attacker,
            Self::CarrierIntegrity => CompositionRefusalClass::Attacker,
            Self::IbexPrincipalGrouping => CompositionRefusalClass::ProducerDefect,
            Self::IbexEncodingIncompatible => CompositionRefusalClass::ProducerDefect,
            Self::IbexEngineUnavailable => CompositionRefusalClass::Environment,
            Self::IbexEngineBindingMismatch => CompositionRefusalClass::Environment,
            Self::IbexBytecodePreflight => CompositionRefusalClass::Environment,
            Self::IbexPackageGraphBinding => CompositionRefusalClass::Attacker,
            Self::GenerationSplice => CompositionRefusalClass::ProducerDefect,
            Self::AliasConflict => CompositionRefusalClass::ProducerDefect,
            Self::PartitionMismatch => CompositionRefusalClass::ProducerDefect,
            Self::IbexDuplicateSourceId => CompositionRefusalClass::ProducerDefect,
            Self::PackageOverlap => CompositionRefusalClass::ProducerDefect,
            Self::AppReferencesAgent => CompositionRefusalClass::ProducerDefect,
            Self::LocalAgreementDisagreement => CompositionRefusalClass::ProducerDefect,
            Self::UnionTableMismatch => CompositionRefusalClass::ProducerDefect,
            Self::BoundaryInventoryMismatch => CompositionRefusalClass::Attacker,
            Self::ExternalTargetAbsent => CompositionRefusalClass::ProducerDefect,
            Self::ExternalOwnerMismatch => CompositionRefusalClass::ProducerDefect,
            Self::ExportDisagreement => CompositionRefusalClass::ProducerDefect,
            Self::CrossPrincipalDenied => CompositionRefusalClass::Attacker,
            Self::EntryPlanMismatch => CompositionRefusalClass::ProducerDefect,
            Self::EntryDescriptorInvalid => CompositionRefusalClass::ProducerDefect,
            Self::CompositionRootUnlinked => CompositionRefusalClass::ProducerDefect,
            Self::LinkFailure => CompositionRefusalClass::Environment,
        }
    }

    /// Resolve an exact registry code to its typed refusal variant.
    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "envelope-malformed" => Some(Self::EnvelopeMalformed),
            "composition-commitment-mismatch" => Some(Self::CompositionCommitmentMismatch),
            "composition-replayed" => Some(Self::CompositionReplayed),
            "composition-policy-stale" => Some(Self::CompositionPolicyStale),
            "ibex:target-profile-mismatch" => Some(Self::IbexTargetProfileMismatch),
            "composition-unknown-role" => Some(Self::CompositionUnknownRole),
            "composition-duplicate-role" => Some(Self::CompositionDuplicateRole),
            "composition-package-extra" => Some(Self::CompositionPackageExtra),
            "composition-package-missing" => Some(Self::CompositionPackageMissing),
            "composition-mismatch" => Some(Self::CompositionMismatch),
            "package-root-mismatch" => Some(Self::PackageRootMismatch),
            "ibex:prepared-commitment-schema" => Some(Self::IbexPreparedCommitmentSchema),
            "ibex:package-inventory" => Some(Self::IbexPackageInventory),
            "ibex:prepared-commitment-corrupt" => Some(Self::IbexPreparedCommitmentCorrupt),
            "carrier-integrity" => Some(Self::CarrierIntegrity),
            "ibex:principal-grouping" => Some(Self::IbexPrincipalGrouping),
            "ibex:encoding-incompatible" => Some(Self::IbexEncodingIncompatible),
            "ibex:engine-unavailable" => Some(Self::IbexEngineUnavailable),
            "ibex:engine-binding-mismatch" => Some(Self::IbexEngineBindingMismatch),
            "ibex:bytecode-preflight" => Some(Self::IbexBytecodePreflight),
            "ibex:package-graph-binding" => Some(Self::IbexPackageGraphBinding),
            "generation-splice" => Some(Self::GenerationSplice),
            "alias-conflict" => Some(Self::AliasConflict),
            "partition-mismatch" => Some(Self::PartitionMismatch),
            "ibex:duplicate-source-id" => Some(Self::IbexDuplicateSourceId),
            "package-overlap" => Some(Self::PackageOverlap),
            "app-references-agent" => Some(Self::AppReferencesAgent),
            "local-agreement-disagreement" => Some(Self::LocalAgreementDisagreement),
            "union-table-mismatch" => Some(Self::UnionTableMismatch),
            "boundary-inventory-mismatch" => Some(Self::BoundaryInventoryMismatch),
            "external-target-absent" => Some(Self::ExternalTargetAbsent),
            "external-owner-mismatch" => Some(Self::ExternalOwnerMismatch),
            "export-disagreement" => Some(Self::ExportDisagreement),
            "cross-principal-denied" => Some(Self::CrossPrincipalDenied),
            "entry-plan-mismatch" => Some(Self::EntryPlanMismatch),
            "entry-descriptor-invalid" => Some(Self::EntryDescriptorInvalid),
            "composition-root-unlinked" => Some(Self::CompositionRootUnlinked),
            "link-failure" => Some(Self::LinkFailure),
            _ => None,
        }
    }
}

/// Security/operational classification assigned by the lockstep registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CompositionRefusalClass {
    /// Attacker-controlled or tamper-shaped failure.
    Attacker,
    /// Invalid state emitted by a producer.
    ProducerDefect,
    /// Runtime or verifier environment mismatch.
    Environment,
}

impl CompositionRefusalClass {
    /// Return the exact one-letter registry class.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Attacker => "A",
            Self::ProducerDefect => "P",
            Self::Environment => "E",
        }
    }
}

/// Return the registry's single default refusal for an admission step label.
pub fn composition_step_default(step: &str) -> Option<CompositionRefusalCode> {
    match step {
        "1" => Some(CompositionRefusalCode::EnvelopeMalformed),
        "2a" => Some(CompositionRefusalCode::CompositionCommitmentMismatch),
        "2b" => Some(CompositionRefusalCode::CompositionMismatch),
        "3" => Some(CompositionRefusalCode::PackageRootMismatch),
        "4" => Some(CompositionRefusalCode::PartitionMismatch),
        "5" => Some(CompositionRefusalCode::LocalAgreementDisagreement),
        "6" => Some(CompositionRefusalCode::UnionTableMismatch),
        "7" => Some(CompositionRefusalCode::EntryPlanMismatch),
        "8" => Some(CompositionRefusalCode::LinkFailure),
        _ => None,
    }
}

/// Exact-side environment outcomes that are intentionally outside admission.
pub const COMPOSITION_ENVIRONMENT_CODES_V1: [&str; 4] = [
    "composition-unproducible",
    "producer-refused-composition",
    "agent-composition-unavailable",
    "composition-admission-unimplemented",
];
