//! Generation-safe decision cache identities.
//!
//! A generation is advanced before an authority mutation is published. Cache
//! keys bind all frozen semantic identities plus the exact available positive
//! sources, so possession of one handle cannot authorize a lookup performed
//! without it. @ref LLP 0021#handles-dynamic-authority-and-generations

use std::collections::HashMap;

use serde_json::to_value;

use crate::canonical::to_jcs_bytes;
use crate::containment::validate_occurrence_stage_facts;
use crate::model::{
    ActionId, Digest, EffectOccurrence, Generation, NonEmptyString, StableId, Stage,
};
use crate::{Error, Result};

/// Exact positive-authority inputs that are not represented by the three
/// global generations alone.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PositiveAuthorityContext {
    pub coverage_edge_id: StableId,
    pub handle_ids: Vec<NonEmptyString>,
    pub dynamic_grant_ids: Vec<NonEmptyString>,
    pub operation_lease_ids: Vec<NonEmptyString>,
}

impl PositiveAuthorityContext {
    pub fn validate(&self) -> Result<()> {
        require_sorted_unique(&self.handle_ids, "handle ids")?;
        require_sorted_unique(&self.dynamic_grant_ids, "dynamic grant ids")?;
        require_sorted_unique(&self.operation_lease_ids, "operation lease ids")?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GenerationSet {
    pub negative: Generation,
    pub dynamic: Generation,
    pub handle: Generation,
}

/// The complete minimum cache identity frozen by LLP 0021, plus exact
/// positive-source identity to close handle-possession collisions.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DecisionCacheKey {
    pub action: ActionId,
    pub resource_canonical_bytes: Vec<u8>,
    pub principal_set_canonical_bytes: Vec<u8>,
    pub effect_owner_canonical_bytes: Vec<u8>,
    pub stage: Stage,
    pub vocab_digest: Digest,
    pub registry_digest: Digest,
    pub policy_digest: Digest,
    pub armed_snapshot_digest: Digest,
    pub generations: GenerationSet,
    pub positive_authority: PositiveAuthorityContext,
}

impl DecisionCacheKey {
    pub fn new(
        occurrence: &EffectOccurrence,
        vocab_digest: Digest,
        registry_digest: Digest,
        policy_digest: Digest,
        armed_snapshot_digest: Digest,
        generations: GenerationSet,
        positive_authority: PositiveAuthorityContext,
    ) -> Result<Self> {
        if !occurrence.principal_context_is_valid() {
            return invalid("decision cache occurrence has invalid principal context");
        }
        validate_occurrence_stage_facts(occurrence)?;
        positive_authority.validate()?;
        Ok(Self {
            action: occurrence.action.clone(),
            resource_canonical_bytes: to_jcs_bytes(&to_value(&occurrence.resource).map_err(
                |error| Error::InvalidCanonicalData {
                    path: "resource".into(),
                    message: error.to_string(),
                },
            )?)?,
            principal_set_canonical_bytes: to_jcs_bytes(
                &to_value(&occurrence.constrained_principals).map_err(|error| {
                    Error::InvalidCanonicalData {
                        path: "constrainedPrincipals".into(),
                        message: error.to_string(),
                    }
                })?,
            )?,
            effect_owner_canonical_bytes: to_jcs_bytes(
                &to_value(&occurrence.effect_owner).map_err(|error| {
                    Error::InvalidCanonicalData {
                        path: "effectOwner".into(),
                        message: error.to_string(),
                    }
                })?,
            )?,
            stage: occurrence.stage,
            vocab_digest,
            registry_digest,
            policy_digest,
            armed_snapshot_digest,
            generations,
            positive_authority,
        })
    }

    /// Repeat and cleanup stages require a live gate and must never be served
    /// from a prior decision, even when every generation is unchanged.
    pub fn is_cacheable(&self) -> bool {
        !matches!(self.stage, Stage::Repeat | Stage::Cleanup)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationKind {
    Negative,
    Dynamic,
    Handle,
}

/// Checked monotonic generation clock. `advance_before` commits the next value
/// before invoking the publisher closure.
#[derive(Debug, Eq, PartialEq)]
pub struct GenerationClock {
    current: Generation,
}

impl GenerationClock {
    pub const fn new(current: Generation) -> Self {
        Self { current }
    }

    pub const fn current(&self) -> Generation {
        self.current
    }

    pub fn advance_before<T>(&mut self, publish: impl FnOnce(Generation) -> T) -> Result<T> {
        let next = self.current.checked_increment().ok_or_else(|| {
            Error::InvalidModel("generation exhausted the I-JSON safe integer range".into())
        })?;
        self.current = next;
        Ok(publish(next))
    }
}

/// Small exact-key cache. Generation changes naturally miss; repeat/cleanup
/// requests are refused at both insertion and lookup.
#[derive(Debug)]
pub struct DecisionCache<V> {
    entries: HashMap<DecisionCacheKey, V>,
}

impl<V> Default for DecisionCache<V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<V> DecisionCache<V> {
    pub fn get(&self, key: &DecisionCacheKey) -> Option<&V> {
        key.is_cacheable().then(|| self.entries.get(key)).flatten()
    }

    pub fn insert(&mut self, key: DecisionCacheKey, value: V) -> bool {
        if !key.is_cacheable() {
            return false;
        }
        self.entries.insert(key, value);
        true
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn require_sorted_unique<T: Ord>(values: &[T], label: &str) -> Result<()> {
    if values.windows(2).any(|window| window[0] >= window[1]) {
        return invalid(format!("{label} must be strictly sorted and unique"));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::InvalidModel(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Principal, SafeUint};
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Occurrences {
        occurrences: Vec<EffectOccurrence>,
    }

    fn digest(byte: u8) -> Digest {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        Digest::new(format!("sha256-{}", URL_SAFE_NO_PAD.encode([byte; 32]))).unwrap()
    }

    fn root(name: &str) -> Principal {
        serde_json::from_value(json!({ "kind": "root", "identity": name })).unwrap()
    }

    fn occurrence(stage: Stage) -> EffectOccurrence {
        let examples: Occurrences = serde_json::from_slice(include_bytes!(
            "../../../capsec/examples/effect-occurrences.canonical.json"
        ))
        .unwrap();
        let mut occurrence = examples
            .occurrences
            .into_iter()
            .find(|row| row.action.as_str() == "env:read")
            .unwrap();
        occurrence.stage = stage;
        occurrence
    }

    fn key(stage: Stage, generations: GenerationSet) -> DecisionCacheKey {
        DecisionCacheKey::new(
            &occurrence(stage),
            digest(1),
            digest(2),
            digest(3),
            digest(4),
            generations,
            PositiveAuthorityContext {
                coverage_edge_id: StableId::new("edge.fs-read").unwrap(),
                handle_ids: vec![],
                dynamic_grant_ids: vec![],
                operation_lease_ids: vec![],
            },
        )
        .unwrap()
    }

    #[test]
    fn generation_advances_before_publication() {
        let mut clock = GenerationClock::new(SafeUint::ZERO);
        let observed = clock
            .advance_before(|generation| generation)
            .expect("generation advances");
        assert_eq!(observed.get(), 1);
        assert_eq!(clock.current().get(), 1);
    }

    #[test]
    fn repeat_and_cleanup_are_refused_by_insert_and_lookup() {
        let generations = GenerationSet {
            negative: SafeUint::ZERO,
            dynamic: SafeUint::ZERO,
            handle: SafeUint::ZERO,
        };
        let mut cache = DecisionCache::default();
        for stage in [Stage::Repeat, Stage::Cleanup] {
            let key = key(stage, generations);
            assert!(!cache.insert(key.clone(), "allow"));
            assert_eq!(cache.get(&key), None);
        }
        assert!(cache.is_empty());
    }

    #[test]
    fn generation_change_misses_an_existing_decision() {
        let zero = GenerationSet {
            negative: SafeUint::ZERO,
            dynamic: SafeUint::ZERO,
            handle: SafeUint::ZERO,
        };
        let mut advanced = zero;
        advanced.negative = SafeUint::new(1).unwrap();
        let original = key(Stage::Requested, zero);
        let after_revocation = key(Stage::Requested, advanced);
        let mut cache = DecisionCache::default();
        assert!(cache.insert(original.clone(), "allow"));
        assert_eq!(cache.get(&original), Some(&"allow"));
        assert_eq!(cache.get(&after_revocation), None);
    }

    #[test]
    fn positive_authority_ids_are_part_of_the_exact_key() {
        let generations = GenerationSet {
            negative: SafeUint::ZERO,
            dynamic: SafeUint::ZERO,
            handle: SafeUint::ZERO,
        };
        let original = key(Stage::Requested, generations);
        let mut with_handle = original.clone();
        with_handle.positive_authority.handle_ids = vec![NonEmptyString::new("handle-1").unwrap()];
        let mut cache = DecisionCache::default();
        assert!(cache.insert(original, "deny"));
        assert_eq!(cache.get(&with_handle), None);
    }

    #[test]
    fn cache_key_rejects_unsorted_principals_and_authority_ids() {
        let generations = GenerationSet {
            negative: SafeUint::ZERO,
            dynamic: SafeUint::ZERO,
            handle: SafeUint::ZERO,
        };
        let result = DecisionCacheKey::new(
            &{
                let mut occurrence = occurrence(Stage::Requested);
                occurrence.actor = root("a");
                occurrence.effect_owner = root("a");
                occurrence.constrained_principals = vec![root("z"), root("a")];
                occurrence
            },
            digest(1),
            digest(2),
            digest(3),
            digest(4),
            generations,
            PositiveAuthorityContext {
                coverage_edge_id: StableId::new("edge.fs-read").unwrap(),
                handle_ids: vec![
                    NonEmptyString::new("z").unwrap(),
                    NonEmptyString::new("a").unwrap(),
                ],
                dynamic_grant_ids: vec![],
                operation_lease_ids: vec![],
            },
        );
        assert!(result.is_err());
    }
}
