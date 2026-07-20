//! Informational retained-descriptor authorization benchmark for ENG-24253.
//!
//! Compares raw I/O, the former full typed decision per use, and a
//! descriptor-local lease that performs one full repeat decision while
//! checking immutable generation tuples for subsequent uses. It exercises both
//! a 64 MiB sequential read and many distinct operations on one retained fd.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use capsec_semantics::cache::GenerationSet;
use capsec_semantics::decision::{
    evaluate_decision_set, ArmInputs, AuthorityCeiling, BoundAuthority, DecisionAuthorityState,
    EffectGate, PrincipalPolicy, SemanticIdentity, TargetArmState, TargetCellDisposition,
    VerifiedDecisionContext, Workflow,
};
use capsec_semantics::model::{
    AuthoritySelector, DecisionSet, Digest, LogicalPath, LogicalRoot, NonEmptyString,
    ObjectPlatform, PathComponent, Principal, SafeUint, StableId,
};
use capsec_semantics::path_alias::{
    BoundVolumePathCanonicalizer, PathAliasCanonicalizerIdentity, PathAliasCanonicalizers,
    PathCanonicalizerRootBinding,
};
use capsec_semantics::registry::{ValidatedProfile, PROFILE, SEMANTIC_CORE};

const ZERO_DIGEST: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const FILE_BYTES: usize = 64 * 1024 * 1024;
const REPEATED_FD_OPERATIONS: usize = 25_000;

fn context_and_decision() -> (VerifiedDecisionContext, DecisionSet, EffectGate) {
    let definitions = ValidatedProfile::from_json(
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/capability-definitions.json"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/capsec/registry/policy-rules.json"
        )),
    )
    .unwrap()
    .definitions;
    let principal: Principal = serde_json::from_value(serde_json::json!({
        "kind":"package", "name":"reader-lib", "integrity":ZERO_DIGEST,
        "locator":"reader-lib@1.0.0"
    }))
    .unwrap();
    let selector: AuthoritySelector = serde_json::from_value(serde_json::json!({
        "cap":"fs:read",
        "resource":{"kind":"path-tree","path":{"root":"project","components":[]}}
    }))
    .unwrap();
    let digest = Digest::new(ZERO_DIGEST).unwrap();
    let identity = SemanticIdentity {
        profile: PROFILE.into(),
        semantic_core: SEMANTIC_CORE.into(),
        vocab_digest: digest.clone(),
        registry_digest: digest.clone(),
        policy_digest: digest.clone(),
        armed_snapshot_digest: digest.clone(),
    };
    let generations = GenerationSet {
        negative: SafeUint::ZERO,
        dynamic: SafeUint::ZERO,
        handle: SafeUint::ZERO,
    };
    let mut principal_policies = BTreeMap::new();
    principal_policies.insert(
        principal.clone(),
        PrincipalPolicy {
            static_floor: vec![BoundAuthority {
                source_id: NonEmptyString::new("bench.static-floor").unwrap(),
                selector,
                armed_snapshot_digest: digest,
                package_root_owner: None,
            }],
            escalation_ceiling: AuthorityCeiling::Bounded(Vec::new()),
            ..PrincipalPolicy::default()
        },
    );
    let authority = DecisionAuthorityState {
        generations,
        process_ceiling: AuthorityCeiling::Unbounded.into(),
        protected_objects: Vec::new().into(),
        protected_resources: Vec::new().into(),
        principal_policies: principal_policies.into(),
        revocations: Vec::new(),
        handles: Vec::new(),
        dynamic_grants: Vec::new(),
    };
    // Path-capable fixtures bind the same per-volume canonicalizer used for
    // both authority selectors and occurrences; a neutral arm is deliberately
    // valid only for profiles with no path decisions.
    // @ref LLP 0023#3-path-grammar-normalization-aliasing-and-containment
    let volume = NonEmptyString::new("dev-bench").unwrap();
    let path_canonicalizers = PathAliasCanonicalizers::bind(
        vec![BoundVolumePathCanonicalizer {
            platform: ObjectPlatform::Unix,
            volume: volume.clone(),
            identity: PathAliasCanonicalizerIdentity::ByteIdentityV1,
        }],
        [PathCanonicalizerRootBinding {
            logical_root: LogicalRoot::Project,
            owner: None,
            logical_path: None,
            host_path: LogicalPath {
                root: LogicalRoot::Absolute,
                components: vec![PathComponent::utf8("project").unwrap()],
                host_bound: Some(true),
            },
            platform: ObjectPlatform::Unix,
            volume,
        }],
    )
    .unwrap();
    let context = VerifiedDecisionContext::arm_with_path_canonicalizers(
        ArmInputs {
            expected_identity: identity.clone(),
            loaded_identity: identity,
            target: TargetArmState::CompleteAdvertised,
            structure_valid: true,
        },
        definitions,
        authority,
        path_canonicalizers,
    )
    .unwrap();
    let decision: DecisionSet = serde_json::from_value(serde_json::json!({
        "decisionSetSchema":"ibex/capsec-decision-set/1",
        "operationId":"bench-large-read",
        "atomicityGroup":"bench.fs.large-read",
        "combination":"conjunction",
        "context":{
            "stage":"repeat", "actor":principal,
            "constrainedPrincipals":[principal]
        },
        "effects":[{
            "cap":"fs:read", "effectOwner":principal,
            "resource":{
                "kind":"path-occurrence",
                "requested":{"root":"project","components":[{"encoding":"utf8","value":"large.bin"}]},
                "followMode":"follow-final", "objectState":"existing",
                "parentObject":{"platform":"unix","volume":"dev-bench","file":"parent"},
                "finalObject":{"platform":"unix","volume":"dev-bench","file":"large"},
                "retainedHandle":"fd:bench"
            }
        }]
    }))
    .unwrap();
    let gate = EffectGate {
        coverage_edge_id: StableId::new("bench.fs.large-read").unwrap(),
        target_cell: TargetCellDisposition::Complete,
        definition_and_edge_predicates_satisfied: true,
    };
    (context, decision, gate)
}

#[derive(Clone, Copy)]
enum Arm {
    Baseline,
    FullPerChunk,
    DescriptorLease,
}

fn run(
    file: &mut std::fs::File,
    arm: Arm,
    context: &VerifiedDecisionContext,
    decision: &DecisionSet,
    gate: &EffectGate,
) -> Duration {
    file.seek(SeekFrom::Start(0)).unwrap();
    let start = Instant::now();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0usize;
    let leased_generations = context.authority().generations;
    let mut lease_active = false;
    loop {
        match arm {
            Arm::Baseline => {}
            Arm::FullPerChunk => {
                black_box(evaluate_decision_set(
                    context,
                    decision,
                    std::slice::from_ref(gate),
                    Workflow::ProductionEnforce,
                    &|_| None,
                ))
                .unwrap();
            }
            Arm::DescriptorLease => {
                if !lease_active || context.authority().generations != leased_generations {
                    black_box(evaluate_decision_set(
                        context,
                        decision,
                        std::slice::from_ref(gate),
                        Workflow::ProductionEnforce,
                        &|_| None,
                    ))
                    .unwrap();
                    lease_active = true;
                }
                black_box(context.authority().generations);
            }
        }
        let amount = file.read(&mut buffer).unwrap();
        if amount == 0 {
            break;
        }
        total += amount;
        black_box(&buffer[..amount]);
    }
    assert_eq!(total, FILE_BYTES);
    start.elapsed()
}

fn run_repeated_fd_operations(
    file: &mut std::fs::File,
    arm: Arm,
    context: &VerifiedDecisionContext,
    decision: &DecisionSet,
    gate: &EffectGate,
) -> Duration {
    let start = Instant::now();
    let mut byte = [0_u8; 1];
    let leased_generations = context.authority().generations;
    let mut lease_active = false;
    for index in 0..REPEATED_FD_OPERATIONS {
        match arm {
            Arm::Baseline => {}
            Arm::FullPerChunk => {
                black_box(evaluate_decision_set(
                    context,
                    decision,
                    std::slice::from_ref(gate),
                    Workflow::ProductionEnforce,
                    &|_| None,
                ))
                .unwrap();
            }
            Arm::DescriptorLease => {
                if !lease_active || context.authority().generations != leased_generations {
                    black_box(evaluate_decision_set(
                        context,
                        decision,
                        std::slice::from_ref(gate),
                        Workflow::ProductionEnforce,
                        &|_| None,
                    ))
                    .unwrap();
                    lease_active = true;
                }
                black_box(context.authority().generations);
            }
        }
        file.seek(SeekFrom::Start((index % FILE_BYTES) as u64))
            .unwrap();
        file.read_exact(&mut byte).unwrap();
        black_box(byte[0]);
    }
    start.elapsed()
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort();
    values[values.len() / 2]
}

fn main() {
    let (context, decision, gate) = context_and_decision();
    let mut file = tempfile::tempfile().unwrap();
    let block = vec![0x5a; 1024 * 1024];
    for _ in 0..(FILE_BYTES / block.len()) {
        file.write_all(&block).unwrap();
    }
    let mut samples = |arm| {
        median(
            (0..5)
                .map(|_| run(&mut file, arm, &context, &decision, &gate))
                .collect(),
        )
    };
    let baseline = samples(Arm::Baseline);
    let former = samples(Arm::FullPerChunk);
    let lease = samples(Arm::DescriptorLease);
    println!(
        "capsec descriptor authorization (64 MiB): baseline={baseline:?} full-per-chunk={former:?} generation-lease={lease:?}"
    );

    let mut repeated_samples = |arm| {
        median(
            (0..5)
                .map(|_| run_repeated_fd_operations(&mut file, arm, &context, &decision, &gate))
                .collect(),
        )
    };
    let repeated_baseline = repeated_samples(Arm::Baseline);
    let repeated_former = repeated_samples(Arm::FullPerChunk);
    let repeated_lease = repeated_samples(Arm::DescriptorLease);
    println!(
        "capsec retained descriptor ({REPEATED_FD_OPERATIONS} operations): baseline={repeated_baseline:?} full-per-operation={repeated_former:?} generation-lease={repeated_lease:?}"
    );
}
