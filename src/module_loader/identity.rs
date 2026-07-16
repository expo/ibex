//! Authenticated source identity and typed module-resolution requests.
//!
//! @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
//! — module records key on `(runtime, SourceId)`, never host-path display text.
//! @ref LLP 0026#1-source-admission-and-resolution — resolution kind,
//! conditions, attributes, and the authenticated referrer all participate in
//! cache identity.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use capsec_semantics::model::{NonEmptyString, PathComponent, Principal};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const SOURCE_ID_PREFIX: &str = "ibex-source-id-v1:";

/// Carrier-independent identity of one original source module.
///
/// Generated/chunked/HBC forms intentionally have no separate variant: they
/// retain the file/builtin/synthetic SourceId of the source they carry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SourceId {
    File {
        principal: Principal,
        path: Vec<PathComponent>,
    },
    Builtin {
        domain: NonEmptyString,
        source_key: NonEmptyString,
    },
    Synthetic {
        session_identity: NonEmptyString,
        source_identity: NonEmptyString,
    },
}

impl SourceId {
    pub fn file(principal: Principal, path: Vec<PathComponent>) -> Result<Self> {
        if !matches!(
            principal,
            Principal::Root { .. } | Principal::Package { .. }
        ) {
            return Err(anyhow!(
                "file-backed SourceId requires a root or package defining principal"
            ));
        }
        if path.is_empty() || path.iter().any(|component| !component.is_canonical()) {
            return Err(anyhow!(
                "file-backed SourceId requires a non-empty canonical component vector"
            ));
        }
        Ok(Self::File { principal, path })
    }

    pub fn builtin(domain: impl Into<String>, source_key: impl Into<String>) -> Result<Self> {
        Ok(Self::Builtin {
            domain: NonEmptyString::new(domain.into()).map_err(anyhow::Error::msg)?,
            source_key: NonEmptyString::new(source_key.into()).map_err(anyhow::Error::msg)?,
        })
    }

    pub fn synthetic(
        session_identity: impl Into<String>,
        source_identity: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self::Synthetic {
            session_identity: NonEmptyString::new(session_identity.into())
                .map_err(anyhow::Error::msg)?,
            source_identity: NonEmptyString::new(source_identity.into())
                .map_err(anyhow::Error::msg)?,
        })
    }

    /// Canonical portable wire form: version tag + base64url(JCS(value)).
    pub fn encode(&self) -> Result<String> {
        validate_source_id(self)?;
        let value = serde_json::to_value(self).context("cannot serialize SourceId")?;
        let bytes = capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| anyhow!("cannot canonicalize SourceId: {error}"))?;
        Ok(format!(
            "{SOURCE_ID_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(bytes)
        ))
    }

    pub fn decode(encoded: &str) -> Result<Self> {
        let payload = encoded
            .strip_prefix(SOURCE_ID_PREFIX)
            .ok_or_else(|| anyhow!("unsupported SourceId wire version"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| anyhow!("SourceId payload is not canonical base64url"))?;
        if URL_SAFE_NO_PAD.encode(&bytes) != payload {
            return Err(anyhow!("SourceId payload is not canonical base64url"));
        }
        let text = std::str::from_utf8(&bytes).context("SourceId payload is not UTF-8")?;
        let value = capsec_semantics::strict_json::parse_strict(text)
            .map_err(|error| anyhow!("SourceId payload is not strict JSON: {error}"))?;
        let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| anyhow!("cannot canonicalize SourceId payload: {error}"))?;
        if canonical != bytes {
            return Err(anyhow!("SourceId payload is not canonical JCS"));
        }
        let source_id: Self =
            serde_json::from_value(value).context("SourceId payload has an invalid shape")?;
        validate_source_id(&source_id)?;
        Ok(source_id)
    }

    pub fn defining_principal(&self) -> Option<&Principal> {
        match self {
            Self::File { principal, .. } => Some(principal),
            Self::Builtin { .. } | Self::Synthetic { .. } => None,
        }
    }
}

fn validate_source_id(source_id: &SourceId) -> Result<()> {
    match source_id {
        SourceId::File { principal, path } => {
            SourceId::file(principal.clone(), path.clone()).map(|_| ())
        }
        SourceId::Builtin { domain, source_key } => {
            SourceId::builtin(domain.as_str(), source_key.as_str()).map(|_| ())
        }
        SourceId::Synthetic {
            session_identity,
            source_identity,
        } => SourceId::synthetic(session_identity.as_str(), source_identity.as_str()).map(|_| ()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionKind {
    EsmStatic,
    DynamicImport,
    CommonJsRequire,
    Entry,
}

impl ResolutionKind {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::EsmStatic => "esm-static",
            Self::DynamicImport => "dynamic-import",
            Self::CommonJsRequire => "common-js-require",
            Self::Entry => "entry",
        }
    }

    pub const fn abi_code(self) -> u32 {
        match self {
            Self::CommonJsRequire => 0,
            Self::EsmStatic => 1,
            Self::DynamicImport => 2,
            Self::Entry => 3,
        }
    }

    pub fn from_abi_code(code: u32) -> Result<Self> {
        match code {
            0 => Ok(Self::CommonJsRequire),
            1 => Ok(Self::EsmStatic),
            2 => Ok(Self::DynamicImport),
            3 => Ok(Self::Entry),
            _ => Err(anyhow!("unknown module resolution kind code {code}")),
        }
    }
}

/// Canonical membership set used for conditional exports. Object-key order in
/// the package remains the selection order; this set only answers membership.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConditionSet(Vec<NonEmptyString>);

impl ConditionSet {
    pub fn for_kind(kind: ResolutionKind) -> Self {
        let names = match kind {
            ResolutionKind::CommonJsRequire => ["node", "require"],
            ResolutionKind::EsmStatic | ResolutionKind::DynamicImport | ResolutionKind::Entry => {
                ["import", "node"]
            }
        };
        Self(
            names
                .into_iter()
                .map(|name| NonEmptyString::new(name).expect("static condition is non-empty"))
                .collect(),
        )
    }

    pub fn with_user_conditions(
        kind: ResolutionKind,
        conditions: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        let mut names = Self::for_kind(kind)
            .0
            .into_iter()
            .map(|name| name.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        for condition in conditions {
            if condition.is_empty() || condition == "default" {
                return Err(anyhow!(
                    "resolution conditions must be non-empty and must not include unconditional default"
                ));
            }
            names.insert(condition);
        }
        Ok(Self(
            names
                .into_iter()
                .map(|name| NonEmptyString::new(name).expect("validated non-empty condition"))
                .collect(),
        ))
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(NonEmptyString::as_str)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ImportAttributes(BTreeMap<String, String>);

impl ImportAttributes {
    pub fn new(entries: impl IntoIterator<Item = (String, String)>) -> Result<Self> {
        let mut attributes = BTreeMap::new();
        for (key, value) in entries {
            if key != "type" || value != "json" {
                return Err(anyhow!(
                    "unsupported runtime import attribute {key}={value:?}"
                ));
            }
            if attributes.insert(key.clone(), value).is_some() {
                return Err(anyhow!("duplicate runtime import attribute {key}"));
            }
        }
        Ok(Self(attributes))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn entries(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    pub fn asserts_json(&self) -> bool {
        self.0.get("type").is_some_and(|value| value == "json")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolutionCacheKey {
    pub requester: SourceId,
    pub specifier: String,
    pub kind: ResolutionKind,
    pub conditions: ConditionSet,
    pub attributes: ImportAttributes,
}

impl ResolutionCacheKey {
    pub fn new(
        requester: SourceId,
        specifier: impl Into<String>,
        kind: ResolutionKind,
        conditions: ConditionSet,
        attributes: ImportAttributes,
    ) -> Result<Self> {
        let specifier = specifier.into();
        if specifier.trim().is_empty() {
            return Err(anyhow!("module specifier must not be empty"));
        }
        Ok(Self {
            requester,
            specifier,
            kind,
            conditions,
            attributes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsec_semantics::model::{Digest, PackageLocator};

    fn package_principal() -> Principal {
        Principal::Package {
            name: NonEmptyString::new("pkg").unwrap(),
            locator: PackageLocator::new("pkg@1.0.0").unwrap(),
            integrity: Digest::new("sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        }
    }

    fn source_id() -> SourceId {
        SourceId::file(
            package_principal(),
            vec![
                PathComponent::utf8("src").unwrap(),
                PathComponent::utf8("x.js").unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn source_id_round_trips_canonical_wire_and_keeps_principal_once() {
        let source = source_id();
        let encoded = source.encode().unwrap();
        assert_eq!(SourceId::decode(&encoded).unwrap(), source);
        assert_eq!(source.defining_principal(), Some(&package_principal()));
        assert!(!encoded.contains("/host/"));
    }

    #[test]
    fn source_id_rejects_noncanonical_wire_and_non_source_principals() {
        let encoded = source_id().encode().unwrap();
        assert!(SourceId::decode(&format!("{encoded}=")).is_err());
        assert!(SourceId::file(
            Principal::Runtime {
                identity: NonEmptyString::new("runtime").unwrap(),
            },
            vec![PathComponent::utf8("x.js").unwrap()],
        )
        .is_err());
    }

    #[test]
    fn resolution_cache_separates_import_require_conditions_and_attributes() {
        let requester = source_id();
        let import = ResolutionCacheKey::new(
            requester.clone(),
            "conditional-pkg",
            ResolutionKind::EsmStatic,
            ConditionSet::for_kind(ResolutionKind::EsmStatic),
            ImportAttributes::default(),
        )
        .unwrap();
        let require = ResolutionCacheKey::new(
            requester.clone(),
            "conditional-pkg",
            ResolutionKind::CommonJsRequire,
            ConditionSet::for_kind(ResolutionKind::CommonJsRequire),
            ImportAttributes::default(),
        )
        .unwrap();
        let json = ResolutionCacheKey::new(
            requester,
            "conditional-pkg",
            ResolutionKind::EsmStatic,
            ConditionSet::for_kind(ResolutionKind::EsmStatic),
            ImportAttributes::new([("type".into(), "json".into())]).unwrap(),
        )
        .unwrap();
        assert_ne!(import, require);
        assert_ne!(import, json);
        assert_eq!(
            import.conditions.names().collect::<Vec<_>>(),
            ["import", "node"]
        );
        assert_eq!(
            require.conditions.names().collect::<Vec<_>>(),
            ["node", "require"]
        );
    }
}
