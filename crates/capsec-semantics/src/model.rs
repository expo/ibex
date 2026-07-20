//! Typed, product-neutral values consumed by the CapSec semantic core.
//!
//! Action identifiers remain data: this module validates their closed wire
//! grammar, but the product registry decides which identifiers exist and which
//! resource kinds they accept.
//! @ref LLP 0021#typed-resources-and-initial-vocabulary — typed selectors and
//! occurrences replace colon-delimited authority strings.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;

use crate::{Error, Result as CapsecResult};

const MAX_IJSON_UINT: u64 = 9_007_199_254_740_991;

fn deserialize_checked_string<'de, D>(
    deserializer: D,
    label: &str,
    valid: impl FnOnce(&str) -> bool,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if valid(&value) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(format!(
            "invalid {label}: {value:?}"
        )))
    }
}

fn valid_action_id(value: &str) -> bool {
    let mut parts = value.split(':');
    let Some(family) = parts.next() else {
        return false;
    };
    let Some(action) = parts.next() else {
        return false;
    };
    parts.next().is_none() && valid_action_part(family) && valid_action_part(action)
}

fn valid_action_part(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
}

/// A syntactically canonical action identity. Whether it is known is decided by
/// the loaded product vocabulary, never by this type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ActionId(String);

impl ActionId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        valid_action_id(&value)
            .then_some(Self(value.clone()))
            .ok_or_else(|| format!("invalid action id {value:?}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ActionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_checked_string(deserializer, "action id", valid_action_id).map(Self)
    }
}

impl fmt::Display for ActionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for ActionId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Canonical textual SHA-256 identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let encoded = value
            .strip_prefix("sha256-")
            .ok_or_else(|| format!("invalid digest {value:?}"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| format!("invalid digest {value:?}"))?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
            return Err(format!("invalid digest {value:?}"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A non-empty wire string used for opaque identities whose interpretation is
/// owned by a runtime adapter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct NonEmptyString(String);

impl NonEmptyString {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        (!value.is_empty())
            .then_some(Self(value.clone()))
            .ok_or_else(|| "value must not be empty".to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NonEmptyString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_checked_string(deserializer, "non-empty string", |value| !value.is_empty())
            .map(Self)
    }
}

impl fmt::Display for NonEmptyString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An I-JSON-safe unsigned integer, used for generations and counters that are
/// serialized through JavaScript consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SafeUint(u64);

impl SafeUint {
    pub const ZERO: Self = Self(0);

    pub fn new(value: u64) -> Result<Self, String> {
        (value <= MAX_IJSON_UINT)
            .then_some(Self(value))
            .ok_or_else(|| format!("integer {value} exceeds the I-JSON safe range"))
    }

    pub fn get(self) -> u64 {
        self.0
    }

    pub fn checked_increment(self) -> Option<Self> {
        self.0
            .checked_add(1)
            .and_then(|value| Self::new(value).ok())
    }
}

impl<'de> Deserialize<'de> for SafeUint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

pub type Generation = SafeUint;

/// A stable registry/operation identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct StableId(String);

impl StableId {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let mut previous_separator = true;
        let valid = !value.is_empty()
            && value.bytes().all(|byte| {
                let separator = matches!(byte, b'.' | b'_' | b'/' | b'-');
                let accepted =
                    matches!(byte, b'a'..=b'z' | b'0'..=b'9') || (separator && !previous_separator);
                previous_separator = separator;
                accepted
            })
            && !previous_separator;
        valid
            .then_some(Self(value.clone()))
            .ok_or_else(|| format!("invalid stable id {value:?}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for StableId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// An integrity-bound package graph locator (`name@locator`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PackageLocator(String);

impl PackageLocator {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let separator = if value.starts_with('@') {
            value
                .find('/')
                .and_then(|slash| value[slash + 1..].find('@').map(|at| slash + 1 + at))
        } else {
            value.find('@')
        };
        let valid_name_part = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
        };
        let valid = separator.is_some_and(|at| {
            let (name, locator) = value.split_at(at);
            let locator = &locator[1..];
            let name_valid = if let Some(scoped) = name.strip_prefix('@') {
                let mut parts = scoped.split('/');
                parts.next().is_some_and(valid_name_part)
                    && parts.next().is_some_and(valid_name_part)
                    && parts.next().is_none()
            } else {
                valid_name_part(name)
            };
            name_valid
                && !locator.is_empty()
                && !locator.chars().any(|character| {
                    character == '@' || character.is_whitespace() || character.is_control()
                })
        });
        valid
            .then_some(Self(value.clone()))
            .ok_or_else(|| format!("invalid package locator {value:?}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for PackageLocator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Principal {
    Package {
        name: NonEmptyString,
        integrity: Digest,
        locator: PackageLocator,
    },
    Root {
        identity: NonEmptyString,
    },
    Runtime {
        identity: NonEmptyString,
    },
    ModuleLoader {
        identity: NonEmptyString,
    },
    Quarantine {
        identity: NonEmptyString,
    },
}

impl Principal {
    pub fn is_package(&self) -> bool {
        matches!(self, Self::Package { .. })
    }

    pub fn is_root(&self) -> bool {
        matches!(self, Self::Root { .. })
    }

    pub fn is_quarantine(&self) -> bool {
        matches!(self, Self::Quarantine { .. })
    }

    pub fn is_transparent_runtime_frame(&self) -> bool {
        matches!(
            self,
            Self::Runtime { identity } if identity.as_str() == "ibex-runtime-internal"
        )
    }

    /// RFC 8785 key used for every constrained-principal set. Rust enum/field
    /// order is not the semantic wire order, so adapters must never sort the
    /// ordinary serde encoding instead.
    /// @ref LLP 0021#decision-staging-and-principal-semantics
    pub fn canonical_order_key(&self) -> crate::Result<Vec<u8>> {
        let value = serde_json::to_value(self)
            .map_err(|error| crate::Error::InvalidModel(error.to_string()))?;
        crate::canonical::to_jcs_bytes(&value)
    }
}

pub fn principals_are_canonical(principals: &[Principal]) -> bool {
    let keys = principals
        .iter()
        .map(Principal::canonical_order_key)
        .collect::<crate::Result<Vec<_>>>();
    keys.is_ok_and(|keys| keys.windows(2).all(|pair| pair[0] < pair[1]))
}

pub fn sort_and_dedup_principals(principals: &mut Vec<Principal>) -> crate::Result<()> {
    let mut keyed = principals
        .iter()
        .cloned()
        .map(|principal| Ok((principal.canonical_order_key()?, principal)))
        .collect::<crate::Result<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    *principals = keyed.into_iter().map(|(_, principal)| principal).collect();
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Requested,
    Discovery,
    Candidate,
    Commit,
    Delivery,
    Repeat,
    Cleanup,
}

impl Stage {
    pub fn is_at_least_discovery(self) -> bool {
        !matches!(self, Self::Requested)
    }

    pub fn is_commit_or_later(self) -> bool {
        matches!(
            self,
            Self::Commit | Self::Delivery | Self::Repeat | Self::Cleanup
        )
    }

    pub fn is_delivery_or_repeat(self) -> bool {
        matches!(self, Self::Delivery | Self::Repeat)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Port(NonZeroU16);

impl Port {
    pub fn new(value: u16) -> Option<Self> {
        NonZeroU16::new(value).map(Self)
    }

    pub fn get(self) -> u16 {
        self.0.get()
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        NonZeroU16::deserialize(deserializer).map(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct IpAddress(IpAddr);

impl IpAddress {
    pub fn new(address: IpAddr) -> Self {
        Self(canonical_ip(address))
    }

    pub fn get(self) -> IpAddr {
        self.0
    }
}

impl<'de> Deserialize<'de> for IpAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let address: IpAddr = text.parse().map_err(serde::de::Error::custom)?;
        let address = canonical_ip(address);
        if address.to_string() != text {
            return Err(serde::de::Error::custom(format!(
                "non-canonical IP address {text:?}; expected {:?}",
                address.to_string()
            )));
        }
        Ok(Self(address))
    }
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

impl fmt::Display for IpAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DnsName(String);

impl DnsName {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let numeric_alias = value.split('.').all(|label| {
            !label.is_empty()
                && (label.bytes().all(|byte| byte.is_ascii_digit())
                    || label.strip_prefix("0x").is_some_and(|hex| {
                        !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                    }))
        });
        let valid = value.len() <= 253
            && value.parse::<IpAddr>().is_err()
            && !numeric_alias
            && value.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
                    && !label.starts_with('-')
                    && !label.ends_with('-')
            });
        valid
            .then_some(Self(value.clone()))
            .ok_or_else(|| format!("invalid canonical DNS name {value:?}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DnsName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathComponent {
    Utf8(String),
    Base64Url(Vec<u8>),
}

impl PathComponent {
    pub fn utf8(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        validate_path_component_bytes(value.as_bytes())?;
        Ok(Self::Utf8(value))
    }

    pub fn binary(bytes: Vec<u8>) -> Result<Self, String> {
        validate_path_component_bytes(&bytes)?;
        if std::str::from_utf8(&bytes).is_ok() {
            return Err("valid UTF-8 path components must use utf8 encoding".to_string());
        }
        Ok(Self::Base64Url(bytes))
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Utf8(value) => value.as_bytes(),
            Self::Base64Url(value) => value,
        }
    }

    pub fn is_canonical(&self) -> bool {
        validate_path_component_bytes(self.bytes()).is_ok()
            && match self {
                Self::Utf8(_) => true,
                Self::Base64Url(bytes) => std::str::from_utf8(bytes).is_err(),
            }
    }
}

fn validate_path_component_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&0)
        || bytes.contains(&b'/')
    {
        return Err("forbidden path component bytes".to_string());
    }
    Ok(())
}

impl Serialize for PathComponent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        #[serde(tag = "encoding", content = "value")]
        enum Wire<'a> {
            #[serde(rename = "utf8")]
            Utf8(&'a str),
            #[serde(rename = "base64url")]
            Base64Url(String),
        }
        match self {
            Self::Utf8(value) => Wire::Utf8(value).serialize(serializer),
            Self::Base64Url(bytes) => {
                Wire::Base64Url(URL_SAFE_NO_PAD.encode(bytes)).serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for PathComponent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "encoding", content = "value", deny_unknown_fields)]
        enum Wire {
            #[serde(rename = "utf8")]
            Utf8(String),
            #[serde(rename = "base64url")]
            Base64Url(String),
        }
        match Wire::deserialize(deserializer)? {
            Wire::Utf8(value) => Self::utf8(value).map_err(serde::de::Error::custom),
            Wire::Base64Url(value) => {
                let bytes = URL_SAFE_NO_PAD
                    .decode(&value)
                    .map_err(serde::de::Error::custom)?;
                if URL_SAFE_NO_PAD.encode(&bytes) != value {
                    return Err(serde::de::Error::custom(
                        "non-canonical base64url path component",
                    ));
                }
                Self::binary(bytes).map_err(serde::de::Error::custom)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogicalRoot {
    Project,
    Package,
    Home,
    Tmp,
    Absolute,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogicalPath {
    pub root: LogicalRoot,
    pub components: Vec<PathComponent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_bound: Option<bool>,
}

impl LogicalPath {
    pub fn is_canonical(&self) -> bool {
        self.components.iter().all(PathComponent::is_canonical)
            && match self.root {
                LogicalRoot::Absolute => self.host_bound == Some(true),
                _ => self.host_bound.is_none(),
            }
    }

    pub fn contains_package_root(&self) -> bool {
        self.root == LogicalRoot::Package
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectPlatform {
    Unix,
    Windows,
    Apple,
    Android,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObjectIdentity {
    pub platform: ObjectPlatform,
    pub volume: NonEmptyString,
    pub file: NonEmptyString,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Host {
    DnsName {
        name: DnsName,
    },
    DnsSubtree {
        apex: DnsName,
        #[serde(rename = "includeApex")]
        include_apex: bool,
    },
    Ip {
        address: IpAddress,
    },
    Cidr {
        network: IpAddress,
        prefix: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ConcreteHost {
    DnsName { name: DnsName },
    Ip { address: IpAddress },
}

impl From<&ConcreteHost> for Host {
    fn from(value: &ConcreteHost) -> Self {
        match value {
            ConcreteHost::DnsName { name } => Self::DnsName { name: name.clone() },
            ConcreteHost::Ip { address } => Self::Ip { address: *address },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RemotePort {
    Exact { value: Port },
    Range { start: Port, end: Port },
}

impl RemotePort {
    pub fn is_canonical(self) -> bool {
        match self {
            Self::Exact { .. } => true,
            Self::Range { start, end } => start <= end,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ListenPort {
    Exact { value: Port },
    Range { start: Port, end: Port },
    Ephemeral,
}

impl ListenPort {
    pub fn is_canonical(self) -> bool {
        match self {
            Self::Exact { .. } | Self::Ephemeral => true,
            Self::Range { start, end } => start <= end,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Route {
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerClass {
    Public,
    Private,
    Loopback,
    LinkLocal,
    CarrierGradeNat,
    UniqueLocal,
    Unspecified,
    Multicast,
    Metadata,
    Reserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FetchScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectTransport {
    Tcp,
    Tls,
    Udp,
    Ws,
    Wss,
    Webtransport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SocketType {
    Datagram,
    Seqpacket,
    Stream,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum UnixAddress {
    Path { path: LogicalPath },
    Abstract { name: NonEmptyString },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ListenBind {
    Loopback,
    AllInterfaces,
    Address { address: IpAddress },
    Interface { name: NonEmptyString },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DnsRecordType {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
    #[serde(rename = "CAA")]
    Caa,
    #[serde(rename = "CNAME")]
    Cname,
    #[serde(rename = "MX")]
    Mx,
    #[serde(rename = "NAPTR")]
    Naptr,
    #[serde(rename = "NS")]
    Ns,
    #[serde(rename = "PTR")]
    Ptr,
    #[serde(rename = "SOA")]
    Soa,
    #[serde(rename = "SRV")]
    Srv,
    #[serde(rename = "TXT")]
    Txt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentTarget {
    BrokerBase,
    PrincipalOverlay,
    ChildLaunch,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EnvironmentName(String);

impl EnvironmentName {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid = matches!(bytes.next(), Some(b'A'..=b'Z' | b'_'))
            && bytes.all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_'));
        valid
            .then_some(Self(value.clone()))
            .ok_or_else(|| format!("invalid environment name {value:?}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for EnvironmentName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterpreterIdentity {
    pub path: LogicalPath,
    pub content_digest: Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StdioStream {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StdioSourceKind {
    Pipe,
    Broker,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StdioSource {
    pub kind: StdioSourceKind,
    pub identity: NonEmptyString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemInfoName {
    Architecture,
    CameraMetadata,
    Cpus,
    Cwd,
    Hostname,
    Language,
    LoadAverage,
    Locale,
    Memory,
    NetworkInterfaces,
    OsRelease,
    Platform,
    Screen,
    StoragePaths,
    Uptime,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LocationUsage {
    Foreground,
    Background,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LocationPrecision {
    Coarse,
    Precise,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CameraFacing {
    Front,
    Back,
    External,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CameraMedia {
    Photo,
    Video,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MicrophoneMedia {
    Audio,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClipboardSelection {
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClipboardFormat {
    Html,
    Image,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageStore {
    Local,
    Session,
    Persistent,
}

/// The three lifecycle operations deliberately share one capability action
/// while retaining distinct, exact resource identities. An exit request is
/// never interchangeable with observing or changing the orderly-exit code.
// @ref LLP 0025#10-registry-obligations — lifecycle:exit carries separate
// request, exitCode getter, and exitCode setter dispositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LifecycleDisposition {
    ExitRequest,
    ExitCodeGet,
    ExitCodeSet,
}

/// Runtime-generation-local state whose identity is authenticated by the
/// native session handle rather than supplied by JavaScript.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionStateName {
    Cwd,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StorageNamespace {
    Principal,
    Shared { name: NonEmptyString },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClosedSurfaceClass {
    Ffi,
    Inspector,
    Ipc,
    ProcessCwd,
    ProcessEnvironment,
    ProcessIdentity,
    ProcessLimit,
    ProcessPriority,
    ProcessSignal,
    ProcessUmask,
    RuntimeInspection,
    Storage,
    Vm,
    Wasi,
    Worker,
}

/// All authorable and deny-only resource selector wire shapes in the frozen
/// semantic profile. The enum contains no wildcard variant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SelectorResource {
    PathExact {
        path: LogicalPath,
    },
    PathTree {
        path: LogicalPath,
    },
    FetchEndpoint {
        schemes: Vec<FetchScheme>,
        host: Host,
        port: RemotePort,
        peer_classes: Vec<PeerClass>,
        route: Route,
    },
    ConnectEndpoint {
        transport: ConnectTransport,
        host: Host,
        port: RemotePort,
        peer_classes: Vec<PeerClass>,
        route: Route,
    },
    ConnectUnix {
        socket_type: SocketType,
        address: UnixAddress,
    },
    ListenInet {
        transport: ListenTransport,
        bind: ListenBind,
        port: ListenPort,
        dual_stack: bool,
        peer_classes: Vec<PeerClass>,
    },
    ListenUnix {
        socket_type: SocketType,
        address: UnixAddress,
    },
    DnsQuery {
        name: DnsName,
        absolute: bool,
        record_types: Vec<DnsRecordType>,
        resolver: DnsResolver,
    },
    EnvironmentName {
        target: EnvironmentTarget,
        name: EnvironmentName,
    },
    Executable {
        logical_name: NonEmptyString,
        path: LogicalPath,
        content_digest: Digest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interpreter: Option<InterpreterIdentity>,
    },
    Stdio {
        stream: StdioStream,
        source: StdioSource,
    },
    SystemInfo {
        name: SystemInfoName,
    },
    DeviceLocation {
        usage: LocationUsage,
        precision: LocationPrecision,
    },
    Camera {
        facing: CameraFacing,
        media: Vec<CameraMedia>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<NonEmptyString>,
    },
    Microphone {
        media: MicrophoneMedia,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<NonEmptyString>,
    },
    Clipboard {
        selection: ClipboardSelection,
        formats: Vec<ClipboardFormat>,
    },
    StorageNamespace {
        store: StorageStore,
        namespace: StorageNamespace,
    },
    SessionLifecycle {
        disposition: LifecycleDisposition,
    },
    SessionState {
        name: SessionStateName,
    },
    /// One exact operation from an authenticated WebGPU profile. Every digest
    /// is part of the selector so authority for one generated routing program
    /// cannot be replayed after a profile or codec-plan change.
    GpuOperation {
        profile_id: NonEmptyString,
        profile_digest: Digest,
        webgpu_c_vocabulary_digest: Digest,
        operation_set_digest: Digest,
        semantic_program_digest: Digest,
        runtime_routing_digest: Digest,
        operation_id: NonEmptyString,
    },
    ClosedSurface {
        surface_class: ClosedSurfaceClass,
    },
}

impl SelectorResource {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::PathExact { .. } => "path-exact",
            Self::PathTree { .. } => "path-tree",
            Self::FetchEndpoint { .. } => "fetch-endpoint",
            Self::ConnectEndpoint { .. } => "connect-endpoint",
            Self::ConnectUnix { .. } => "connect-unix",
            Self::ListenInet { .. } => "listen-inet",
            Self::ListenUnix { .. } => "listen-unix",
            Self::DnsQuery { .. } => "dns-query",
            Self::EnvironmentName { .. } => "environment-name",
            Self::Executable { .. } => "executable",
            Self::Stdio { .. } => "stdio",
            Self::SystemInfo { .. } => "system-info",
            Self::DeviceLocation { .. } => "device-location",
            Self::Camera { .. } => "camera",
            Self::Microphone { .. } => "microphone",
            Self::Clipboard { .. } => "clipboard",
            Self::StorageNamespace { .. } => "storage-namespace",
            Self::SessionLifecycle { .. } => "session-lifecycle",
            Self::SessionState { .. } => "session-state",
            Self::GpuOperation { .. } => "gpu-operation",
            Self::ClosedSurface { .. } => "closed-surface",
        }
    }

    pub fn contains_package_logical_root(&self) -> bool {
        fn path_has_package(path: &LogicalPath) -> bool {
            path.root == LogicalRoot::Package
        }
        fn unix_has_package(address: &UnixAddress) -> bool {
            matches!(address, UnixAddress::Path { path } if path_has_package(path))
        }
        match self {
            Self::PathExact { path } | Self::PathTree { path } => path_has_package(path),
            Self::ConnectUnix { address, .. } | Self::ListenUnix { address, .. } => {
                unix_has_package(address)
            }
            Self::Executable {
                path, interpreter, ..
            } => {
                path_has_package(path)
                    || interpreter
                        .as_ref()
                        .is_some_and(|value| path_has_package(&value.path))
            }
            _ => false,
        }
    }

    pub fn is_closed_surface(&self) -> bool {
        matches!(self, Self::ClosedSurface { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsResolver {
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySelector {
    #[serde(rename = "cap")]
    pub action: ActionId,
    pub resource: SelectorResource,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NetworkRequest {
    FetchEndpoint {
        scheme: FetchScheme,
        host: ConcreteHost,
        port: Port,
    },
    ConnectEndpoint {
        transport: ConnectTransport,
        host: ConcreteHost,
        port: Port,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedPeer {
    pub address: IpAddress,
    pub port: Port,
}

pub type AcceptedPeer = VerifiedPeer;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundEndpoint {
    pub address: IpAddress,
    pub port: Port,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<NonEmptyString>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnixPeerCredentials {
    pub uid: DecimalId,
    pub gid: DecimalId,
    pub pid: DecimalId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DecimalId(String);

impl<'de> Deserialize<'de> for DecimalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = deserialize_checked_string(deserializer, "decimal id", |value| {
            value == "0"
                || (value.starts_with(|character: char| matches!(character, '1'..='9'))
                    && value.bytes().all(|byte| byte.is_ascii_digit()))
        })?;
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "recordType", deny_unknown_fields)]
pub enum DnsAnswer {
    #[serde(rename = "A")]
    A { address: IpAddress },
    #[serde(rename = "AAAA")]
    Aaaa { address: IpAddress },
    #[serde(rename = "CNAME")]
    Cname { name: DnsName },
    #[serde(rename = "NS")]
    Ns { name: DnsName },
    #[serde(rename = "PTR")]
    Ptr { name: DnsName },
    #[serde(rename = "CAA")]
    Caa {
        critical: bool,
        tag: NonEmptyString,
        value: String,
    },
    #[serde(rename = "MX")]
    Mx { priority: u16, exchange: DnsName },
    #[serde(rename = "NAPTR")]
    Naptr {
        order: u16,
        preference: u16,
        flags: String,
        service: String,
        regexp: String,
        replacement: NonEmptyString,
    },
    #[serde(rename = "SOA")]
    Soa {
        name: DnsName,
        admin: DnsName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        #[serde(rename = "minimumTtl")]
        minimum_ttl: u32,
    },
    #[serde(rename = "SRV")]
    Srv {
        priority: u16,
        weight: u16,
        port: Port,
        target: NonEmptyString,
    },
    #[serde(rename = "TXT")]
    Txt { chunks: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FollowMode {
    FollowFinal,
    NoFollowFinal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObjectState {
    Unknown,
    Existing,
    AbsentCreate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentValueOrigin {
    BrokerBase,
    PrincipalOverlay,
    Literal,
}

/// Runtime facts for one normalized effect. Nested requested resources reuse
/// `SelectorResource`; semantic validation rejects variants outside the subset
/// allowed by each occurrence kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OccurrenceResource {
    PathOccurrence {
        requested: LogicalPath,
        follow_mode: FollowMode,
        object_state: ObjectState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_object: Option<ObjectIdentity>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        final_object: Option<ObjectIdentity>,
        /// Object-reuse discriminator observed from the retained final handle.
        /// Apple adapters carry `st_gen`; platforms without a reliable
        /// generation use the armed host's lifetime-retained descriptor token.
        /// It is intentionally separate from `ObjectIdentity`: existing
        /// snapshot/root identities remain platform+volume+file coordinates,
        /// while commit guards can require the stronger pair.
        /// @ref LLP 0023#42-authenticated-package-source-is-immutable
        #[serde(default, skip_serializing_if = "Option::is_none")]
        final_object_generation: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retained_handle: Option<NonEmptyString>,
    },
    NetworkOccurrence {
        requested: NetworkRequest,
        route: Route,
        candidates: Vec<IpAddress>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selected_candidate: Option<IpAddress>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verified_peer: Option<VerifiedPeer>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        redirect_index: Option<SafeUint>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        connection_id: Option<NonEmptyString>,
    },
    UnixConnectOccurrence {
        requested: Box<SelectorResource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        socket_object: Option<ObjectIdentity>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        connection_id: Option<NonEmptyString>,
    },
    ListenOccurrence {
        requested: Box<SelectorResource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bound_endpoints: Option<Vec<BoundEndpoint>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bound_unix_object: Option<ObjectIdentity>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        listener_id: Option<NonEmptyString>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        accepted_peer: Option<AcceptedPeer>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        accepted_unix_peer: Option<UnixPeerCredentials>,
    },
    DnsOccurrence {
        requested: Box<SelectorResource>,
        answers: Vec<DnsAnswer>,
    },
    EnvironmentOccurrence {
        requested: Box<SelectorResource>,
        value_origin: EnvironmentValueOrigin,
    },
    ExecutableOccurrence {
        requested: Box<SelectorResource>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        executable_object: Option<ObjectIdentity>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interpreter_object: Option<ObjectIdentity>,
    },
    StdioOccurrence {
        requested: Box<SelectorResource>,
    },
    SystemInfoOccurrence {
        requested: Box<SelectorResource>,
    },
    DeviceOccurrence {
        requested: Box<SelectorResource>,
        broker_generation: SafeUint,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_identity: Option<NonEmptyString>,
    },
    StorageOccurrence {
        requested: Box<SelectorResource>,
        namespace_owner: Principal,
    },
    LifecycleOccurrence {
        requested: Box<SelectorResource>,
    },
    SessionStateOccurrence {
        requested: Box<SelectorResource>,
    },
    /// Native-only identities for one GPU authority session. The host adapter
    /// derives each digest from the exact C carrier; JavaScript never supplies
    /// these facts or chooses the operation effect.
    GpuOperationOccurrence {
        requested: Box<SelectorResource>,
        realm_identity: Digest,
        account_identity: Digest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_identity: Option<Digest>,
        receiver_identity: Digest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_identity: Option<Digest>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        presented_handle_identities: Vec<Digest>,
    },
    ClosedOccurrence {
        requested: Box<SelectorResource>,
        surface: NonEmptyString,
    },
}

impl OccurrenceResource {
    pub fn requested_selector_resource(&self) -> Option<SelectorResource> {
        match self {
            Self::PathOccurrence { requested, .. } => Some(SelectorResource::PathExact {
                path: requested.clone(),
            }),
            Self::NetworkOccurrence {
                requested, route, ..
            } => match requested {
                NetworkRequest::FetchEndpoint { scheme, host, port } => {
                    Some(SelectorResource::FetchEndpoint {
                        schemes: vec![*scheme],
                        host: host.into(),
                        port: RemotePort::Exact { value: *port },
                        peer_classes: Vec::new(),
                        route: *route,
                    })
                }
                NetworkRequest::ConnectEndpoint {
                    transport,
                    host,
                    port,
                } => Some(SelectorResource::ConnectEndpoint {
                    transport: *transport,
                    host: host.into(),
                    port: RemotePort::Exact { value: *port },
                    peer_classes: Vec::new(),
                    route: *route,
                }),
            },
            Self::UnixConnectOccurrence { requested, .. }
            | Self::ListenOccurrence { requested, .. }
            | Self::DnsOccurrence { requested, .. }
            | Self::EnvironmentOccurrence { requested, .. }
            | Self::ExecutableOccurrence { requested, .. }
            | Self::StdioOccurrence { requested }
            | Self::SystemInfoOccurrence { requested }
            | Self::DeviceOccurrence { requested, .. }
            | Self::StorageOccurrence { requested, .. }
            | Self::LifecycleOccurrence { requested }
            | Self::SessionStateOccurrence { requested }
            | Self::GpuOperationOccurrence { requested, .. }
            | Self::ClosedOccurrence { requested, .. } => Some((**requested).clone()),
        }
    }

    /// Product registries use this exact resource-kind identity to enforce the
    /// action-to-occurrence join without compiling action names into this crate.
    pub fn requested_kind_name(&self) -> Option<&'static str> {
        match self {
            Self::PathOccurrence { .. } => Some("path-exact"),
            Self::NetworkOccurrence { requested, .. } => Some(match requested {
                NetworkRequest::FetchEndpoint { .. } => "fetch-endpoint",
                NetworkRequest::ConnectEndpoint { .. } => "connect-endpoint",
            }),
            Self::UnixConnectOccurrence { requested, .. }
            | Self::ListenOccurrence { requested, .. }
            | Self::DnsOccurrence { requested, .. }
            | Self::EnvironmentOccurrence { requested, .. }
            | Self::ExecutableOccurrence { requested, .. }
            | Self::StdioOccurrence { requested }
            | Self::SystemInfoOccurrence { requested }
            | Self::DeviceOccurrence { requested, .. }
            | Self::StorageOccurrence { requested, .. }
            | Self::LifecycleOccurrence { requested }
            | Self::SessionStateOccurrence { requested }
            | Self::GpuOperationOccurrence { requested, .. }
            | Self::ClosedOccurrence { requested, .. } => Some(requested.kind_name()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectOccurrence {
    #[serde(rename = "cap")]
    pub action: ActionId,
    pub stage: Stage,
    pub actor: Principal,
    pub effect_owner: Principal,
    pub constrained_principals: Vec<Principal>,
    pub resource: OccurrenceResource,
}

impl EffectOccurrence {
    pub fn principal_context_is_valid(&self) -> bool {
        if !principal_set_is_canonical(&self.constrained_principals) {
            return false;
        }
        [&self.actor, &self.effect_owner]
            .into_iter()
            .all(|principal| {
                principal.is_transparent_runtime_frame()
                    || self.constrained_principals.contains(principal)
            })
    }
}

impl Principal {
    /// Canonical semantic-set key shared by every runtime and decision ingress.
    /// This must be JCS rather than serde's struct-field order because package
    /// principals carry additional keys that change the relative ordering.
    pub fn canonical_sort_key(&self) -> crate::Result<Vec<u8>> {
        let value = serde_json::to_value(self)
            .map_err(|error| crate::Error::InvalidModel(error.to_string()))?;
        crate::canonical::to_jcs_bytes(&value)
    }
}

/// Return the one canonical representation of an authenticated principal set.
///
/// Principal-set order is RFC 8785 JCS byte order, not Rust's derived `Ord`
/// and not serde_json's insertion order.  Keeping this helper in the neutral
/// semantic crate prevents ABI adapters from subtly disagreeing with the
/// evaluator about mixed root/package sets.
/// @ref LLP 0021#decision-staging-and-principal-semantics
pub fn canonicalize_principal_set(
    principals: impl IntoIterator<Item = Principal>,
) -> CapsecResult<Vec<Principal>> {
    let mut keyed = principals
        .into_iter()
        .map(|principal| {
            if principal.is_transparent_runtime_frame() {
                return Err(Error::InvalidModel(
                    "transparent runtime principal cannot constrain a decision".into(),
                ));
            }
            let value = serde_json::to_value(&principal)
                .map_err(|error| Error::InvalidModel(error.to_string()))?;
            let key = crate::canonical::to_jcs_bytes(&value)?;
            Ok((key, principal))
        })
        .collect::<CapsecResult<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    keyed.dedup_by(|left, right| left.0 == right.0);
    if keyed.is_empty() {
        return Err(Error::InvalidModel(
            "constrained principal set cannot be empty".into(),
        ));
    }
    Ok(keyed.into_iter().map(|(_, principal)| principal).collect())
}

/// Validate that a principal set already uses the canonical wire order.
pub fn principal_set_is_canonical(principals: &[Principal]) -> bool {
    canonicalize_principal_set(principals.iter().cloned())
        .is_ok_and(|canonical| canonical == principals)
}

#[cfg(test)]
mod principal_set_tests {
    use super::*;

    #[test]
    fn package_locator_rejects_control_characters() {
        assert!(PackageLocator::new("pkg@1.0.0\0shadow").is_err());
        assert!(PackageLocator::new("pkg@1.0.0\nshadow").is_err());
        assert!(PackageLocator::new("pkg@1.0.0").is_ok());
    }

    #[test]
    fn canonical_principal_set_uses_jcs_and_deduplicates() {
        let root: Principal = serde_json::from_value(serde_json::json!({
            "kind": "root", "identity": "project-root"
        }))
        .unwrap();
        let package: Principal = serde_json::from_value(serde_json::json!({
            "kind": "package",
            "name": "pkg",
            "integrity": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "locator": "pkg@1.0.0"
        }))
        .unwrap();
        let canonical =
            canonicalize_principal_set([root.clone(), package.clone(), root.clone()]).unwrap();
        assert_eq!(canonical.len(), 2);
        assert!(principal_set_is_canonical(&canonical));
        let mut reversed = canonical;
        reversed.reverse();
        assert!(!principal_set_is_canonical(&reversed));
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Effect {
    #[serde(rename = "cap")]
    pub action: ActionId,
    pub effect_owner: Principal,
    pub resource: OccurrenceResource,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionContext {
    pub stage: Stage,
    pub actor: Principal,
    pub constrained_principals: Vec<Principal>,
    #[serde(default)]
    pub presented_handle_ids: Vec<NonEmptyString>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionSetSchema {
    #[serde(rename = "ibex/capsec-decision-set/1")]
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EffectCombination {
    Conjunction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionSet {
    pub decision_set_schema: DecisionSetSchema,
    pub operation_id: NonEmptyString,
    pub atomicity_group: StableId,
    pub combination: EffectCombination,
    pub context: DecisionContext,
    pub effects: Vec<Effect>,
}

impl DecisionSet {
    pub fn occurrences(&self) -> Vec<EffectOccurrence> {
        self.effects
            .iter()
            .map(|effect| EffectOccurrence {
                action: effect.action.clone(),
                stage: self.context.stage,
                actor: self.context.actor.clone(),
                effect_owner: effect.effect_owner.clone(),
                constrained_principals: self.context.constrained_principals.clone(),
                resource: effect.resource.clone(),
            })
            .collect()
    }
}
