//! Digest-bound path alias canonicalization.
//!
//! Authorization coordinates are canonicalized independently of display and
//! module identity. A caller's spelling therefore remains available for
//! diagnostics while selectors, occurrences, and decision-cache inputs share
//! one bound-volume identity.
//!
//! @ref LLP 0023#3-path-grammar-normalization-aliasing-and-containment — one
//! versioned per-volume function is applied to authored selectors and runtime
//! occurrences alike, and its identity is part of the armed snapshot

use std::collections::{BTreeMap, BTreeSet};

use caseless::Caseless;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::model::{
    LogicalPath, LogicalRoot, NonEmptyString, ObjectPlatform, OccurrenceResource, PathComponent,
    Principal, SelectorResource, UnixAddress,
};
use crate::{Error, Result};

/// Exact implementation identity selected by the trusted bound-volume
/// adapter. The Apple variants deliberately pin Unicode 9.0, the comparison
/// version implemented by APFS, instead of inheriting the toolchain's current
/// Unicode tables.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PathAliasCanonicalizerIdentity {
    ByteIdentityV1,
    AppleApfsUnicode9NfdV1,
    AppleApfsUnicode9SafeCasefoldNfdV1,
}

/// Digest-bound canonicalizer selection for one platform volume.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundVolumePathCanonicalizer {
    pub platform: ObjectPlatform,
    pub volume: NonEmptyString,
    pub identity: PathAliasCanonicalizerIdentity,
}

impl BoundVolumePathCanonicalizer {
    fn validate(&self) -> Result<()> {
        let apple_algorithm = matches!(
            self.identity,
            PathAliasCanonicalizerIdentity::AppleApfsUnicode9NfdV1
                | PathAliasCanonicalizerIdentity::AppleApfsUnicode9SafeCasefoldNfdV1
        );
        if apple_algorithm != (self.platform == ObjectPlatform::Apple) {
            return Err(Error::AliasCanonicalizationRefused(
                "an Apple APFS canonicalizer must bind an Apple volume, and non-Apple volumes must use byte identity"
                    .into(),
            ));
        }
        Ok(())
    }

    fn canonicalize(&self, path: &LogicalPath) -> Result<LogicalPath> {
        let components = path
            .components
            .iter()
            .map(|component| self.canonicalize_component(component))
            .collect::<Result<Vec<_>>>()?;
        Ok(LogicalPath {
            root: path.root,
            components,
            host_bound: path.host_bound,
        })
    }

    fn canonicalize_component(&self, component: &PathComponent) -> Result<PathComponent> {
        match self.identity {
            PathAliasCanonicalizerIdentity::ByteIdentityV1 => Ok(component.clone()),
            PathAliasCanonicalizerIdentity::AppleApfsUnicode9NfdV1 => {
                let value = utf8_component(component)?;
                PathComponent::utf8(value.chars().nfd().collect::<String>())
                    .map_err(Error::AliasCanonicalizationRefused)
            }
            PathAliasCanonicalizerIdentity::AppleApfsUnicode9SafeCasefoldNfdV1 => {
                let value = utf8_component(component)?;
                // APFS uses Unicode 9 canonical folding. The vendored caseless
                // table is Unicode 10, whose mappings are stable for characters
                // assigned in Unicode 9, but it cannot prove that an arbitrary
                // later character was assigned in APFS's table. Decompose with
                // the pinned Unicode-9 table, fold ASCII directly, and refuse
                // any remaining non-ASCII code point whose full fold changes.
                // This covers ordinary Latin case and normalization aliases
                // while failing closed for the unsupported remainder.
                let mut folded = String::new();
                for character in value.chars().nfd() {
                    if character.is_ascii() {
                        folded.push(character.to_ascii_lowercase());
                        continue;
                    }
                    let full_fold = std::iter::once(character)
                        .default_case_fold()
                        .collect::<String>();
                    if full_fold != character.to_string() {
                        return Err(Error::AliasCanonicalizationRefused(format!(
                            "Apple Unicode-9 safe casefold does not admit non-ASCII folding character U+{:04X}",
                            character as u32
                        )));
                    }
                    folded.push(character);
                }
                PathComponent::utf8(folded.chars().nfd().collect::<String>())
                    .map_err(Error::AliasCanonicalizationRefused)
            }
        }
    }
}

fn utf8_component(component: &PathComponent) -> Result<&str> {
    match component {
        PathComponent::Utf8(value) => Ok(value),
        PathComponent::Base64Url(_) => Err(Error::AliasCanonicalizationRefused(
            "Apple bound-volume paths must be valid UTF-8".into(),
        )),
    }
}

/// The root-binding coordinate associated with a volume canonicalizer. Package
/// roots remain owner-relative, so two packages on one physical volume never
/// share an alias namespace merely because their volume IDs are equal.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PathCanonicalizerRootBinding {
    pub logical_root: LogicalRoot,
    pub owner: Option<Principal>,
    pub logical_path: Option<LogicalPath>,
    pub host_path: LogicalPath,
    pub platform: ObjectPlatform,
    pub volume: NonEmptyString,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct BoundRootCanonicalizer {
    logical_root: LogicalRoot,
    owner: Option<Principal>,
    logical_path: Option<LogicalPath>,
    canonical_logical_path: Option<LogicalPath>,
    canonical_host_path: LogicalPath,
    canonicalizer: BoundVolumePathCanonicalizer,
}

/// Immutable lookup table retained by the armed decision context.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PathAliasCanonicalizers {
    rows: Vec<BoundVolumePathCanonicalizer>,
    bindings: Vec<BoundRootCanonicalizer>,
}

impl PathAliasCanonicalizers {
    pub fn bind(
        rows: Vec<BoundVolumePathCanonicalizer>,
        root_bindings: impl IntoIterator<Item = PathCanonicalizerRootBinding>,
    ) -> Result<Self> {
        let row_bytes = rows
            .iter()
            .map(|row| {
                let value = serde_json::to_value(row).map_err(|error| {
                    Error::InvalidModel(format!(
                        "cannot encode bound-volume canonicalizer: {error}"
                    ))
                })?;
                crate::canonical::to_jcs_bytes(&value)
            })
            .collect::<Result<Vec<_>>>()?;
        if row_bytes.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(Error::AliasCanonicalizationRefused(
                "bound-volume canonicalizers must be sorted and unique".into(),
            ));
        }
        for row in &rows {
            row.validate()?;
        }
        let root_bindings = root_bindings.into_iter().collect::<Vec<_>>();
        let required = root_bindings
            .iter()
            .map(|binding| (binding.platform, binding.volume.clone()))
            .collect::<BTreeSet<_>>();
        let supplied = rows
            .iter()
            .map(|row| (row.platform, row.volume.clone()))
            .collect::<BTreeSet<_>>();
        if required != supplied || supplied.len() != rows.len() {
            return Err(Error::AliasCanonicalizationRefused(
                "bound-volume canonicalizers must exactly cover armed root-binding volumes".into(),
            ));
        }
        let by_volume = rows
            .iter()
            .cloned()
            .map(|row| ((row.platform, row.volume.clone()), row))
            .collect::<BTreeMap<_, _>>();
        let mut bindings = root_bindings
            .into_iter()
            .map(|binding| {
                let canonicalizer = by_volume
                    .get(&(binding.platform, binding.volume.clone()))
                    .expect("exact coverage checked above")
                    .clone();
                let canonical_logical_path = binding
                    .logical_path
                    .as_ref()
                    .map(|path| canonicalizer.canonicalize(path))
                    .transpose()?;
                let canonical_host_path = canonicalizer.canonicalize(&binding.host_path)?;
                Ok(BoundRootCanonicalizer {
                    logical_root: binding.logical_root,
                    owner: binding.owner,
                    logical_path: binding.logical_path,
                    canonical_logical_path,
                    canonical_host_path,
                    canonicalizer,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        bindings.sort();
        let mut binding_coordinates = BTreeSet::new();
        if bindings.iter().any(|binding| {
            !binding_coordinates.insert((
                binding.logical_root,
                binding.owner.clone(),
                binding.canonical_logical_path.clone(),
            ))
        }) {
            return Err(Error::AliasCanonicalizationRefused(
                "canonicalizer root bindings are ambiguous".into(),
            ));
        }
        let mut host_coordinates = BTreeSet::new();
        if bindings.iter().any(|binding| {
            !host_coordinates.insert((
                binding.canonicalizer.platform,
                binding.canonicalizer.volume.clone(),
                binding.canonical_host_path.clone(),
            ))
        }) {
            return Err(Error::AliasCanonicalizationRefused(
                "root bindings alias to one host coordinate".into(),
            ));
        }
        Ok(Self { rows, bindings })
    }

    pub fn rows(&self) -> &[BoundVolumePathCanonicalizer] {
        &self.rows
    }

    /// Canonicalize an absolute host coordinate using the independently bound
    /// algorithm for its exact platform volume. Root-binding selection uses
    /// this before comparing prefixes, so an aliased package prefix cannot
    /// fall through to a less-specific Project binding.
    pub fn canonicalize_volume_path(
        &self,
        platform: ObjectPlatform,
        volume: &NonEmptyString,
        path: &LogicalPath,
    ) -> Result<LogicalPath> {
        let matching = self
            .rows
            .iter()
            .filter(|row| row.platform == platform && &row.volume == volume)
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(Error::AliasCanonicalizationRefused(format!(
                "bound volume has {} canonicalizer rows",
                matching.len()
            )));
        }
        matching[0].canonicalize(path)
    }

    pub fn canonicalize_path(
        &self,
        path: &LogicalPath,
        package_owner: Option<&Principal>,
    ) -> Result<LogicalPath> {
        self.binding_for_path(path, package_owner)?
            .canonicalizer
            .canonicalize(path)
    }

    fn binding_for_path(
        &self,
        path: &LogicalPath,
        package_owner: Option<&Principal>,
    ) -> Result<&BoundRootCanonicalizer> {
        if self.bindings.is_empty() {
            return Err(Error::AliasCanonicalizationRefused(
                "path-capable decision context has no bound-volume canonicalizer".into(),
            ));
        }
        let matching = self
            .bindings
            .iter()
            .filter(|binding| {
                binding.logical_root == path.root
                    && match path.root {
                        LogicalRoot::Package => binding.owner.as_ref() == package_owner,
                        LogicalRoot::Absolute => {
                            binding.owner.is_none()
                                && (binding.logical_path.as_ref() == Some(path)
                                    || binding.canonical_logical_path.as_ref() == Some(path))
                        }
                        _ => binding.owner.is_none(),
                    }
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(Error::AliasCanonicalizationRefused(format!(
                "logical path has {} bound-volume canonicalizer matches",
                matching.len()
            )));
        }
        Ok(matching[0])
    }

    pub fn canonicalize_selector(
        &self,
        selector: &SelectorResource,
        package_owner: Option<&Principal>,
    ) -> Result<SelectorResource> {
        let mut canonical = selector.clone();
        match &mut canonical {
            SelectorResource::PathExact { path } | SelectorResource::PathTree { path } => {
                *path = self.canonicalize_path(path, package_owner)?;
            }
            SelectorResource::ConnectUnix { address, .. }
            | SelectorResource::ListenUnix { address, .. } => {
                if let UnixAddress::Path { path } = address {
                    *path = self.canonicalize_path(path, package_owner)?;
                }
            }
            SelectorResource::Executable {
                path, interpreter, ..
            } => {
                *path = self.canonicalize_path(path, package_owner)?;
                if let Some(interpreter) = interpreter {
                    interpreter.path = self.canonicalize_path(&interpreter.path, package_owner)?;
                }
            }
            _ => {}
        }
        Ok(canonical)
    }

    pub fn canonicalize_occurrence(
        &self,
        occurrence: &OccurrenceResource,
        principal: &Principal,
    ) -> Result<OccurrenceResource> {
        let package_owner = principal.is_package().then_some(principal);
        let mut canonical = occurrence.clone();
        match &mut canonical {
            OccurrenceResource::PathOccurrence {
                requested,
                parent_object,
                final_object,
                ..
            } => {
                let binding = self.binding_for_path(requested, package_owner)?;
                for object in parent_object.iter().chain(final_object.iter()) {
                    if object.platform != binding.canonicalizer.platform
                        || object.volume != binding.canonicalizer.volume
                    {
                        return Err(Error::AliasCanonicalizationRefused(
                            "path occurrence crosses its bound canonicalizer volume".into(),
                        ));
                    }
                }
                *requested = binding.canonicalizer.canonicalize(requested)?;
            }
            OccurrenceResource::UnixConnectOccurrence { requested, .. }
            | OccurrenceResource::ListenOccurrence { requested, .. }
            | OccurrenceResource::DnsOccurrence { requested, .. }
            | OccurrenceResource::EnvironmentOccurrence { requested, .. }
            | OccurrenceResource::ExecutableOccurrence { requested, .. }
            | OccurrenceResource::StdioOccurrence { requested }
            | OccurrenceResource::SystemInfoOccurrence { requested }
            | OccurrenceResource::DeviceOccurrence { requested, .. }
            | OccurrenceResource::StorageOccurrence { requested, .. }
            | OccurrenceResource::LifecycleOccurrence { requested }
            | OccurrenceResource::SessionStateOccurrence { requested }
            | OccurrenceResource::ClosedOccurrence { requested, .. } => {
                **requested = self.canonicalize_selector(requested, package_owner)?;
            }
            OccurrenceResource::NetworkOccurrence { .. } => {}
        }
        Ok(canonical)
    }
}

/// Rebuild the deterministic volume table used by non-executable contract
/// fixtures after they substitute root-binding object identities. Production
/// launchers must use their bound-volume adapter instead.
#[doc(hidden)]
pub fn contract_fixture_canonicalizer_rows(
    volumes: impl IntoIterator<Item = (ObjectPlatform, NonEmptyString)>,
) -> Result<Vec<BoundVolumePathCanonicalizer>> {
    let mut rows = volumes
        .into_iter()
        .map(|(platform, volume)| BoundVolumePathCanonicalizer {
            platform,
            volume,
            identity: if platform == ObjectPlatform::Apple {
                PathAliasCanonicalizerIdentity::AppleApfsUnicode9SafeCasefoldNfdV1
            } else {
                PathAliasCanonicalizerIdentity::ByteIdentityV1
            },
        })
        .collect::<Vec<_>>();
    rows.sort_by_cached_key(|row| {
        let value = serde_json::to_value(row).expect("fixture canonicalizer serializes");
        crate::canonical::to_jcs_bytes(&value).expect("fixture canonicalizer is valid JCS")
    });
    rows.dedup_by(|left, right| left.platform == right.platform && left.volume == right.volume);
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> LogicalPath {
        LogicalPath {
            root: LogicalRoot::Project,
            components: vec![PathComponent::utf8(value).unwrap()],
            host_bound: None,
        }
    }

    fn canonicalizers(identity: PathAliasCanonicalizerIdentity) -> PathAliasCanonicalizers {
        let row = BoundVolumePathCanonicalizer {
            platform: ObjectPlatform::Apple,
            volume: NonEmptyString::new("volume-1").unwrap(),
            identity,
        };
        PathAliasCanonicalizers::bind(
            vec![row],
            [PathCanonicalizerRootBinding {
                logical_root: LogicalRoot::Project,
                owner: None,
                logical_path: None,
                host_path: LogicalPath {
                    root: LogicalRoot::Absolute,
                    components: vec![PathComponent::utf8("project").unwrap()],
                    host_bound: Some(true),
                },
                platform: ObjectPlatform::Apple,
                volume: NonEmptyString::new("volume-1").unwrap(),
            }],
        )
        .unwrap()
    }

    #[test]
    fn apple_case_and_nfd_aliases_have_one_authorization_coordinate() {
        let table =
            canonicalizers(PathAliasCanonicalizerIdentity::AppleApfsUnicode9SafeCasefoldNfdV1);
        let display = path("Secrets");
        let authorization = table.canonicalize_path(&display, None).unwrap();
        assert_eq!(display.components[0].bytes(), b"Secrets");
        assert_eq!(authorization.components[0].bytes(), b"secrets");
        assert_eq!(
            authorization,
            table.canonicalize_path(&path("secrets"), None).unwrap()
        );
        assert_eq!(
            table.canonicalize_path(&path("caf\u{e9}"), None).unwrap(),
            table.canonicalize_path(&path("cafe\u{301}"), None).unwrap()
        );
    }

    #[test]
    fn unsupported_non_ascii_casefold_refuses_instead_of_falling_back() {
        let table =
            canonicalizers(PathAliasCanonicalizerIdentity::AppleApfsUnicode9SafeCasefoldNfdV1);
        assert!(matches!(
            table.canonicalize_path(&path("\u{3a3}"), None),
            Err(Error::AliasCanonicalizationRefused(_))
        ));
    }

    #[test]
    fn exact_absolute_binding_remains_canonicalizer_idempotent() {
        let lexical = LogicalPath {
            root: LogicalRoot::Absolute,
            components: vec![
                PathComponent::utf8("Applications").unwrap(),
                PathComponent::utf8("Ibex").unwrap(),
            ],
            host_bound: Some(true),
        };
        let row = BoundVolumePathCanonicalizer {
            platform: ObjectPlatform::Apple,
            volume: NonEmptyString::new("volume-1").unwrap(),
            identity: PathAliasCanonicalizerIdentity::AppleApfsUnicode9SafeCasefoldNfdV1,
        };
        let table = PathAliasCanonicalizers::bind(
            vec![row],
            [PathCanonicalizerRootBinding {
                logical_root: LogicalRoot::Absolute,
                owner: None,
                logical_path: Some(lexical.clone()),
                host_path: lexical.clone(),
                platform: ObjectPlatform::Apple,
                volume: NonEmptyString::new("volume-1").unwrap(),
            }],
        )
        .unwrap();

        let canonical = table.canonicalize_path(&lexical, None).unwrap();
        assert_eq!(canonical.components[0].bytes(), b"applications");
        assert_eq!(
            table.canonicalize_path(&canonical, None).unwrap(),
            canonical
        );
    }

    #[test]
    fn occurrence_crossing_a_nested_volume_refuses() {
        let table =
            canonicalizers(PathAliasCanonicalizerIdentity::AppleApfsUnicode9SafeCasefoldNfdV1);
        let principal: Principal = serde_json::from_value(serde_json::json!({
            "kind": "root",
            "identity": "project-root"
        }))
        .unwrap();
        let occurrence = OccurrenceResource::PathOccurrence {
            requested: path("Secret"),
            follow_mode: crate::model::FollowMode::FollowFinal,
            object_state: crate::model::ObjectState::Existing,
            parent_object: None,
            final_object: Some(
                serde_json::from_value(serde_json::json!({
                    "platform": "apple",
                    "volume": "nested-volume",
                    "file": "file-1"
                }))
                .unwrap(),
            ),
            final_object_generation: None,
            retained_handle: None,
        };
        assert!(matches!(
            table.canonicalize_occurrence(&occurrence, &principal),
            Err(Error::AliasCanonicalizationRefused(message))
                if message.contains("crosses its bound canonicalizer volume")
        ));
    }
}
