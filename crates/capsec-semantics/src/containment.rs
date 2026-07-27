//! Typed resource containment and selector-to-occurrence matching.
//!
//! Containment is deliberately exact across action identities. Runtime facts
//! may narrow an occurrence but can never be promoted into reusable authority.
//! @ref LLP 0021#handles-dynamic-authority-and-generations — attenuation is
//! same-action, same-snapshot, and same package-root owner.
//! @ref LLP 0021#decision-staging-and-principal-semantics — late facts are
//! authorized at the stage where they become known, never speculated early.

use crate::canonical::to_jcs_bytes;
use crate::error::{Error, Result};
use crate::model::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Containment {
    Equal,
    StrictSubset,
    Incomparable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainmentContext {
    pub same_snapshot: bool,
    pub same_package_root_owner: bool,
}

impl ContainmentContext {
    pub const SAME_AUTHORITY_DOMAIN: Self = Self {
        same_snapshot: true,
        same_package_root_owner: true,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityPolarity {
    Positive,
    Denial,
}

/// Runtime-neutral hook for the product's digest-bound address classifier.
/// Returning `None` fails closed whenever a concrete peer class is required.
pub trait PeerClassifier {
    fn classify(&self, address: IpAddress) -> Option<PeerClass>;
}

impl<F> PeerClassifier for F
where
    F: Fn(IpAddress) -> Option<PeerClass>,
{
    fn classify(&self, address: IpAddress) -> Option<PeerClass> {
        self(address)
    }
}

pub fn compare_authority_containment(
    parent: &AuthoritySelector,
    child: &AuthoritySelector,
    context: &ContainmentContext,
) -> Containment {
    try_compare_authority_containment(parent, child, context).unwrap_or(Containment::Incomparable)
}

/// Checked form used by decision and arming paths. Malformed authority is an
/// error, not merely an incomparable selector.
pub fn try_compare_authority_containment(
    parent: &AuthoritySelector,
    child: &AuthoritySelector,
    context: &ContainmentContext,
) -> Result<Containment> {
    validate_authority_selector(parent)?;
    validate_authority_selector(child)?;
    if !context.same_snapshot || parent.action != child.action {
        return Ok(Containment::Incomparable);
    }
    if (parent.resource.contains_package_logical_root()
        || child.resource.contains_package_logical_root())
        && !context.same_package_root_owner
    {
        return Ok(Containment::Incomparable);
    }
    if parent.resource == child.resource {
        return Ok(Containment::Equal);
    }
    Ok(if resource_contains(&parent.resource, &child.resource) {
        Containment::StrictSubset
    } else {
        Containment::Incomparable
    })
}

pub fn validate_authority_selector(selector: &AuthoritySelector) -> Result<()> {
    validate_selector_resource(&selector.resource)
}

/// Validate schema-adjacent canonical invariants that Rust's tagged enums do
/// not encode by themselves.
pub fn validate_selector_resource(resource: &SelectorResource) -> Result<()> {
    match resource {
        SelectorResource::PathExact { path } | SelectorResource::PathTree { path } => {
            validate_logical_path(path)?
        }
        SelectorResource::FetchEndpoint {
            schemes,
            host,
            port,
            peer_classes,
            ..
        } => {
            validate_set(schemes, "schemes", true)?;
            validate_host(host)?;
            validate_remote_port(*port)?;
            validate_set(peer_classes, "peerClasses", true)?;
        }
        SelectorResource::ConnectEndpoint {
            host,
            port,
            peer_classes,
            ..
        } => {
            validate_host(host)?;
            validate_remote_port(*port)?;
            validate_set(peer_classes, "peerClasses", true)?;
        }
        SelectorResource::ConnectUnix { address, .. }
        | SelectorResource::ListenUnix { address, .. } => validate_unix_address(address)?,
        SelectorResource::ListenInet {
            port, peer_classes, ..
        } => {
            validate_listen_port(*port)?;
            validate_set(peer_classes, "peerClasses", true)?;
        }
        SelectorResource::DnsQuery {
            absolute,
            record_types,
            ..
        } => {
            if !absolute {
                return invalid("DNS selector must be absolute");
            }
            validate_set(record_types, "recordTypes", true)?;
        }
        SelectorResource::EnvironmentName { .. }
        | SelectorResource::Stdio { .. }
        | SelectorResource::SystemInfo { .. }
        | SelectorResource::DeviceLocation { .. }
        | SelectorResource::Microphone { .. }
        | SelectorResource::StorageNamespace { .. }
        | SelectorResource::SessionLifecycle { .. }
        | SelectorResource::SessionState { .. }
        | SelectorResource::RuntimeExtension { .. }
        | SelectorResource::ClosedSurface { .. } => {}
        SelectorResource::Executable {
            path, interpreter, ..
        } => {
            validate_logical_path(path)?;
            if let Some(interpreter) = interpreter {
                validate_logical_path(&interpreter.path)?;
            }
        }
        SelectorResource::Camera { media, .. } => validate_set(media, "media", true)?,
        SelectorResource::Clipboard { formats, .. } => validate_set(formats, "formats", true)?,
    }
    Ok(())
}

fn validate_logical_path(path: &LogicalPath) -> Result<()> {
    if path.is_canonical() {
        Ok(())
    } else {
        invalid("logical path has invalid absolute hostBound disposition")
    }
}

fn validate_host(host: &Host) -> Result<()> {
    if let Host::Cidr { network, prefix } = host {
        if !cidr_is_canonical(*network, *prefix) {
            return invalid("CIDR is not a canonical network with zero host bits");
        }
    }
    Ok(())
}

fn validate_remote_port(port: RemotePort) -> Result<()> {
    if port.is_canonical() {
        Ok(())
    } else {
        invalid("remote port range is reversed")
    }
}

fn validate_listen_port(port: ListenPort) -> Result<()> {
    if port.is_canonical() {
        Ok(())
    } else {
        invalid("listen port range is reversed")
    }
}

fn validate_unix_address(address: &UnixAddress) -> Result<()> {
    match address {
        UnixAddress::Path { path } => validate_logical_path(path),
        UnixAddress::Abstract { name } if name.as_str().contains('\0') => {
            invalid("abstract Unix socket name contains NUL")
        }
        UnixAddress::Abstract { .. } => Ok(()),
    }
}

// @ref LLP 0021#decision-staging-and-principal-semantics — semantic-set order
// is RFC 8785/JCS order at every adapter and validation layer.
fn canonical_wire<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|error| {
        Error::InvalidModel(format!("cannot encode semantic set item: {error}"))
    })?;
    to_jcs_bytes(&value)
}

fn validate_set<T: Serialize>(values: &[T], label: &str, nonempty: bool) -> Result<()> {
    if nonempty && values.is_empty() {
        return invalid(&format!("{label} must not be empty"));
    }
    let encodings = values
        .iter()
        .map(canonical_wire)
        .collect::<Result<Vec<_>>>()?;
    if encodings.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid(&format!("{label} must be canonically sorted and unique"));
    }
    Ok(())
}

fn resource_contains(parent: &SelectorResource, child: &SelectorResource) -> bool {
    if parent == child {
        return true;
    }
    match (parent, child) {
        (
            SelectorResource::PathExact { path: parent },
            SelectorResource::PathExact { path: child },
        ) => path_equal(parent, child),
        (
            SelectorResource::PathTree { path: parent },
            SelectorResource::PathExact { path: child }
            | SelectorResource::PathTree { path: child },
        ) => path_prefix(parent, child),
        (
            SelectorResource::FetchEndpoint {
                schemes: parent_schemes,
                host: parent_host,
                port: parent_port,
                peer_classes: parent_peers,
                route: parent_route,
            },
            SelectorResource::FetchEndpoint {
                schemes: child_schemes,
                host: child_host,
                port: child_port,
                peer_classes: child_peers,
                route: child_route,
            },
        ) => {
            set_contains(parent_schemes, child_schemes)
                && host_contains(parent_host, child_host)
                && remote_port_contains(*parent_port, *child_port)
                && set_contains(parent_peers, child_peers)
                && parent_route == child_route
        }
        (
            SelectorResource::ConnectEndpoint {
                transport: parent_transport,
                host: parent_host,
                port: parent_port,
                peer_classes: parent_peers,
                route: parent_route,
            },
            SelectorResource::ConnectEndpoint {
                transport: child_transport,
                host: child_host,
                port: child_port,
                peer_classes: child_peers,
                route: child_route,
            },
        ) => {
            parent_transport == child_transport
                && host_contains(parent_host, child_host)
                && remote_port_contains(*parent_port, *child_port)
                && set_contains(parent_peers, child_peers)
                && parent_route == child_route
        }
        (
            SelectorResource::ListenInet {
                transport: parent_transport,
                bind: parent_bind,
                port: parent_port,
                dual_stack: parent_dual_stack,
                peer_classes: parent_peers,
            },
            SelectorResource::ListenInet {
                transport: child_transport,
                bind: child_bind,
                port: child_port,
                dual_stack: child_dual_stack,
                peer_classes: child_peers,
            },
        ) => {
            parent_transport == child_transport
                && bind_contains(parent_bind, child_bind)
                && listen_port_contains(*parent_port, *child_port)
                && (*parent_dual_stack || !*child_dual_stack)
                && set_contains(parent_peers, child_peers)
        }
        (
            SelectorResource::DnsQuery {
                name: parent_name,
                absolute: parent_absolute,
                record_types: parent_types,
                resolver: parent_resolver,
            },
            SelectorResource::DnsQuery {
                name: child_name,
                absolute: child_absolute,
                record_types: child_types,
                resolver: child_resolver,
            },
        ) => {
            parent_name == child_name
                && parent_absolute == child_absolute
                && parent_resolver == child_resolver
                && set_contains(parent_types, child_types)
        }
        (
            SelectorResource::Camera {
                facing: parent_facing,
                media: parent_media,
                device_id: parent_device,
            },
            SelectorResource::Camera {
                facing: child_facing,
                media: child_media,
                device_id: child_device,
            },
        ) => {
            (*parent_facing == CameraFacing::Any || parent_facing == child_facing)
                && set_contains(parent_media, child_media)
                && (parent_device.is_none() || parent_device == child_device)
        }
        (
            SelectorResource::DeviceLocation {
                usage: parent_usage,
                precision: parent_precision,
            },
            SelectorResource::DeviceLocation {
                usage: child_usage,
                precision: child_precision,
            },
        ) => {
            (*parent_usage == LocationUsage::Background || parent_usage == child_usage)
                && (*parent_precision == LocationPrecision::Precise
                    || parent_precision == child_precision)
        }
        (
            SelectorResource::Microphone {
                media: parent_media,
                device_id: parent_device,
            },
            SelectorResource::Microphone {
                media: child_media,
                device_id: child_device,
            },
        ) => {
            parent_media == child_media
                && (parent_device.is_none() || parent_device == child_device)
        }
        (
            SelectorResource::Clipboard {
                selection: parent_selection,
                formats: parent_formats,
            },
            SelectorResource::Clipboard {
                selection: child_selection,
                formats: child_formats,
            },
        ) => parent_selection == child_selection && set_contains(parent_formats, child_formats),
        _ => false,
    }
}

fn set_contains<T: Ord>(parent: &[T], child: &[T]) -> bool {
    let parent: BTreeSet<_> = parent.iter().collect();
    child.iter().all(|value| parent.contains(value))
}

fn path_equal(parent: &LogicalPath, child: &LogicalPath) -> bool {
    parent.is_canonical()
        && child.is_canonical()
        && parent.root == child.root
        && parent.components.len() == child.components.len()
        && parent
            .components
            .iter()
            .zip(&child.components)
            .all(|(left, right)| left.bytes() == right.bytes())
}

fn path_prefix(parent: &LogicalPath, child: &LogicalPath) -> bool {
    parent.is_canonical()
        && child.is_canonical()
        && parent.root == child.root
        && parent.components.len() <= child.components.len()
        && parent
            .components
            .iter()
            .zip(&child.components)
            .all(|(left, right)| left.bytes() == right.bytes())
}

fn host_contains(parent: &Host, child: &Host) -> bool {
    if parent == child {
        return true;
    }
    match (parent, child) {
        (Host::DnsSubtree { apex, include_apex }, Host::DnsName { name }) => {
            dns_subtree_contains(apex, *include_apex, name.as_str(), true)
        }
        (
            Host::DnsSubtree { apex, include_apex },
            Host::DnsSubtree {
                apex: child_apex,
                include_apex: child_include_apex,
            },
        ) => dns_subtree_contains(
            apex,
            *include_apex,
            child_apex.as_str(),
            *child_include_apex,
        ),
        (Host::Cidr { network, prefix }, Host::Ip { address }) => {
            cidr_contains(*network, *prefix, *address)
        }
        (
            Host::Cidr { network, prefix },
            Host::Cidr {
                network: child_network,
                prefix: child_prefix,
            },
        ) => {
            child_prefix >= prefix
                && cidr_is_canonical(*network, *prefix)
                && cidr_is_canonical(*child_network, *child_prefix)
                && cidr_contains(*network, *prefix, *child_network)
        }
        _ => false,
    }
}

fn dns_subtree_contains(
    parent: &DnsName,
    include_apex: bool,
    child: &str,
    child_includes_apex: bool,
) -> bool {
    if child == parent.as_str() {
        include_apex || !child_includes_apex
    } else {
        child
            .strip_suffix(parent.as_str())
            .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

fn ip_parts(address: IpAddress) -> (u128, u8) {
    match address.get() {
        IpAddr::V4(value) => (u32::from(value) as u128, 32),
        IpAddr::V6(value) => (u128::from(value), 128),
    }
}

fn cidr_is_canonical(network: IpAddress, prefix: u8) -> bool {
    let (value, bits) = ip_parts(network);
    if prefix > bits {
        return false;
    }
    let host_bits = bits - prefix;
    let host_mask = if host_bits == 128 {
        u128::MAX
    } else if host_bits == 0 {
        0
    } else {
        (1_u128 << host_bits) - 1
    };
    value & host_mask == 0
}

fn cidr_contains(network: IpAddress, prefix: u8, candidate: IpAddress) -> bool {
    let (network_value, network_bits) = ip_parts(network);
    let (candidate_value, candidate_bits) = ip_parts(candidate);
    if network_bits != candidate_bits
        || prefix > network_bits
        || !cidr_is_canonical(network, prefix)
    {
        return false;
    }
    let shift = network_bits - prefix;
    if shift == 128 {
        true
    } else {
        network_value >> shift == candidate_value >> shift
    }
}

fn remote_port_contains(parent: RemotePort, child: RemotePort) -> bool {
    if !parent.is_canonical() || !child.is_canonical() {
        return false;
    }
    match (parent, child) {
        (RemotePort::Exact { value: parent }, RemotePort::Exact { value: child }) => {
            parent == child
        }
        (RemotePort::Range { start, end }, RemotePort::Exact { value }) => {
            start <= value && value <= end
        }
        (
            RemotePort::Range {
                start: parent_start,
                end: parent_end,
            },
            RemotePort::Range {
                start: child_start,
                end: child_end,
            },
        ) => parent_start <= child_start && child_end <= parent_end,
        _ => false,
    }
}

fn listen_port_contains(parent: ListenPort, child: ListenPort) -> bool {
    if !parent.is_canonical() || !child.is_canonical() {
        return false;
    }
    match (parent, child) {
        (ListenPort::Exact { value: parent }, ListenPort::Exact { value: child }) => {
            parent == child
        }
        (ListenPort::Range { start, end }, ListenPort::Exact { value }) => {
            start <= value && value <= end
        }
        (
            ListenPort::Range {
                start: parent_start,
                end: parent_end,
            },
            ListenPort::Range {
                start: child_start,
                end: child_end,
            },
        ) => parent_start <= child_start && child_end <= parent_end,
        (ListenPort::Ephemeral, ListenPort::Ephemeral) => true,
        _ => false,
    }
}

fn bind_contains(parent: &ListenBind, child: &ListenBind) -> bool {
    if parent == child || matches!(parent, ListenBind::AllInterfaces) {
        return true;
    }
    matches!(
        (parent, child),
        (ListenBind::Loopback, ListenBind::Address { address }) if address.get().is_loopback()
    )
}

/// Validate all facts whose presence or absence is stage-sensitive. An error is
/// a hard refusal condition in every workflow.
pub fn validate_occurrence_stage_facts(occurrence: &EffectOccurrence) -> Result<()> {
    if !occurrence.principal_context_is_valid() {
        return invalid("actor/effect owner escaped the canonical constrained principal set");
    }
    validate_set(
        &occurrence.constrained_principals,
        "constrainedPrincipals",
        true,
    )?;
    let stage = occurrence.stage;
    match &occurrence.resource {
        OccurrenceResource::PathOccurrence {
            requested,
            object_state,
            parent_object,
            final_object,
            final_object_generation,
            retained_handle,
            ..
        } => {
            validate_logical_path(requested)?;
            if (stage == Stage::Requested) != (*object_state == ObjectState::Unknown) {
                return invalid("path object state must be unknown exactly at requested stage");
            }
            fact(
                "parentObject",
                parent_object.is_some(),
                stage.is_at_least_discovery(),
                *object_state == ObjectState::AbsentCreate && stage.is_at_least_discovery(),
            )?;
            fact(
                "finalObject",
                final_object.is_some(),
                stage.is_at_least_discovery(),
                *object_state == ObjectState::Existing && stage.is_at_least_discovery(),
            )?;
            if final_object_generation.is_some()
                && (final_object.is_none() || !stage.is_at_least_discovery())
            {
                return invalid(
                    "finalObjectGeneration requires a discovered retained final object",
                );
            }
            fact(
                "retainedHandle",
                retained_handle.is_some(),
                stage.is_commit_or_later(),
                stage.is_commit_or_later(),
            )?;
            if *object_state == ObjectState::AbsentCreate
                && !matches!(occurrence.action.as_str(), "fs:list" | "fs:write")
            {
                return invalid("only fs:list/fs:write may target an absent-create path");
            }
        }
        OccurrenceResource::NetworkOccurrence {
            requested,
            candidates,
            selected_candidate,
            verified_peer,
            connection_id,
            ..
        } => {
            validate_set(candidates, "candidates", false)?;
            fact(
                "selectedCandidate",
                selected_candidate.is_some(),
                matches!(
                    stage,
                    Stage::Candidate
                        | Stage::Commit
                        | Stage::Delivery
                        | Stage::Repeat
                        | Stage::Cleanup
                ),
                matches!(
                    stage,
                    Stage::Candidate
                        | Stage::Commit
                        | Stage::Delivery
                        | Stage::Repeat
                        | Stage::Cleanup
                ),
            )?;
            for (name, present) in [
                ("verifiedPeer", verified_peer.is_some()),
                ("connectionId", connection_id.is_some()),
            ] {
                fact(
                    name,
                    present,
                    stage.is_commit_or_later(),
                    stage.is_commit_or_later(),
                )?;
            }
            let requested_host = match requested {
                NetworkRequest::FetchEndpoint { host, .. }
                | NetworkRequest::ConnectEndpoint { host, .. } => host,
            };
            if stage == Stage::Requested
                && matches!(requested_host, ConcreteHost::DnsName { .. })
                && !candidates.is_empty()
            {
                return invalid("requested DNS network effect contains speculative candidates");
            }
            if let ConcreteHost::Ip { address } = requested_host {
                if candidates.as_slice() != [*address] {
                    return invalid("literal-IP network request has a different candidate set");
                }
            }
            if let Some(selected) = selected_candidate {
                if !candidates.contains(selected) {
                    return invalid("selected network candidate is not in candidates");
                }
            }
            if let Some(peer) = verified_peer {
                let requested_port = match requested {
                    NetworkRequest::FetchEndpoint { port, .. }
                    | NetworkRequest::ConnectEndpoint { port, .. } => port,
                };
                if Some(peer.address) != *selected_candidate || peer.port != *requested_port {
                    return invalid(
                        "verified peer differs from the selected candidate/requested port",
                    );
                }
            }
        }
        OccurrenceResource::UnixConnectOccurrence {
            requested,
            socket_object,
            connection_id,
        } => {
            let SelectorResource::ConnectUnix { address, .. } = requested.as_ref() else {
                return invalid("unix-connect occurrence requested a non-connect-unix resource");
            };
            validate_selector_resource(requested)?;
            let pathname = matches!(address, UnixAddress::Path { .. });
            fact(
                "socketObject",
                socket_object.is_some(),
                stage.is_at_least_discovery(),
                pathname && stage.is_at_least_discovery(),
            )?;
            if !pathname && socket_object.is_some() {
                return invalid("abstract Unix connection has a pathname object identity");
            }
            fact(
                "connectionId",
                connection_id.is_some(),
                stage.is_commit_or_later(),
                stage.is_commit_or_later(),
            )?;
        }
        OccurrenceResource::ListenOccurrence {
            requested,
            bound_endpoints,
            bound_unix_object,
            listener_id,
            accepted_peer,
            accepted_unix_peer,
        } => {
            let inet = matches!(requested.as_ref(), SelectorResource::ListenInet { .. });
            let unix = matches!(requested.as_ref(), SelectorResource::ListenUnix { .. });
            if !inet && !unix {
                return invalid("listen occurrence requested a non-listen resource");
            }
            validate_selector_resource(requested)?;
            if bound_endpoints.as_ref().is_some_and(Vec::is_empty) {
                return invalid("boundEndpoints must not be empty when present");
            }
            if let Some(endpoints) = bound_endpoints {
                validate_set(endpoints, "boundEndpoints", true)?;
            }
            fact(
                "boundEndpoints",
                bound_endpoints.is_some(),
                inet && stage.is_commit_or_later(),
                inet && stage.is_commit_or_later(),
            )?;
            let pathname_unix = matches!(
                requested.as_ref(),
                SelectorResource::ListenUnix {
                    address: UnixAddress::Path { .. },
                    ..
                }
            );
            fact(
                "boundUnixObject",
                bound_unix_object.is_some(),
                pathname_unix && stage.is_commit_or_later(),
                pathname_unix && stage.is_commit_or_later(),
            )?;
            fact(
                "listenerId",
                listener_id.is_some(),
                stage.is_commit_or_later(),
                stage.is_commit_or_later(),
            )?;
            fact(
                "acceptedPeer",
                accepted_peer.is_some(),
                inet && stage.is_delivery_or_repeat(),
                inet && stage.is_delivery_or_repeat(),
            )?;
            fact(
                "acceptedUnixPeer",
                accepted_unix_peer.is_some(),
                unix && stage.is_delivery_or_repeat(),
                unix && stage.is_delivery_or_repeat(),
            )?;
            validate_bound_endpoints(requested, bound_endpoints.as_deref())?;
        }
        OccurrenceResource::DnsOccurrence { requested, answers } => {
            let SelectorResource::DnsQuery { record_types, .. } = requested.as_ref() else {
                return invalid("DNS occurrence requested a non-DNS resource");
            };
            validate_selector_resource(requested)?;
            if stage == Stage::Requested && !answers.is_empty() {
                return invalid("requested DNS effect contains speculative answers");
            }
            validate_set(answers, "answers", false)?;
            for answer in answers {
                if !record_types.contains(&dns_answer_type(answer)) {
                    return invalid("DNS answer type was not requested");
                }
                validate_dns_answer(answer)?;
                if matches!(answer, DnsAnswer::A { address } if !matches!(address.get(), IpAddr::V4(_)))
                    || matches!(answer, DnsAnswer::Aaaa { address } if !matches!(address.get(), IpAddr::V6(_)))
                {
                    return invalid("DNS answer address family disagrees with record type");
                }
            }
        }
        OccurrenceResource::EnvironmentOccurrence { requested, .. } => {
            if !matches!(requested.as_ref(), SelectorResource::EnvironmentName { .. }) {
                return invalid("environment occurrence requested a non-environment resource");
            }
            validate_selector_resource(requested)?;
        }
        OccurrenceResource::ExecutableOccurrence {
            requested,
            executable_object,
            interpreter_object,
        } => {
            let SelectorResource::Executable { interpreter, .. } = requested.as_ref() else {
                return invalid("executable occurrence requested a non-executable resource");
            };
            validate_selector_resource(requested)?;
            fact(
                "executableObject",
                executable_object.is_some(),
                stage.is_at_least_discovery(),
                stage.is_at_least_discovery(),
            )?;
            fact(
                "interpreterObject",
                interpreter_object.is_some(),
                stage.is_at_least_discovery(),
                interpreter.is_some() && stage.is_at_least_discovery(),
            )?;
            if interpreter.is_none() && interpreter_object.is_some() {
                return invalid("executable without interpreter has interpreter object fact");
            }
        }
        OccurrenceResource::StdioOccurrence { requested } => {
            if !matches!(requested.as_ref(), SelectorResource::Stdio { .. }) {
                return invalid("stdio occurrence requested a non-stdio resource");
            }
            validate_selector_resource(requested)?;
        }
        OccurrenceResource::SystemInfoOccurrence { requested } => {
            if !matches!(requested.as_ref(), SelectorResource::SystemInfo { .. }) {
                return invalid("system-info occurrence requested a non-system-info resource");
            }
            validate_selector_resource(requested)?;
        }
        OccurrenceResource::DeviceOccurrence {
            requested,
            device_identity,
            ..
        } => {
            if !matches!(
                requested.as_ref(),
                SelectorResource::DeviceLocation { .. }
                    | SelectorResource::Camera { .. }
                    | SelectorResource::Microphone { .. }
                    | SelectorResource::Clipboard { .. }
            ) {
                return invalid("device occurrence requested a non-device resource");
            }
            validate_selector_resource(requested)?;
            fact(
                "deviceIdentity",
                device_identity.is_some(),
                stage.is_commit_or_later(),
                stage.is_commit_or_later(),
            )?;
            let requested_device = match requested.as_ref() {
                SelectorResource::Camera { device_id, .. }
                | SelectorResource::Microphone { device_id, .. } => device_id.as_ref(),
                _ => None,
            };
            if stage.is_commit_or_later()
                && requested_device.is_some()
                && requested_device != device_identity.as_ref()
            {
                return invalid("broker-resolved device differs from requested deviceId");
            }
        }
        OccurrenceResource::StorageOccurrence { requested, .. } => {
            if !matches!(
                requested.as_ref(),
                SelectorResource::StorageNamespace { .. }
            ) {
                return invalid("storage occurrence requested a non-storage resource");
            }
            validate_selector_resource(requested)?;
        }
        OccurrenceResource::LifecycleOccurrence { requested } => {
            if !matches!(
                requested.as_ref(),
                SelectorResource::SessionLifecycle { .. }
            ) {
                return invalid("lifecycle occurrence requested a non-lifecycle resource");
            }
            if !matches!(stage, Stage::Requested | Stage::Commit) {
                return invalid("lifecycle occurrence supports only requested and commit stages");
            }
            validate_selector_resource(requested)?;
        }
        OccurrenceResource::SessionStateOccurrence { requested } => {
            if !matches!(requested.as_ref(), SelectorResource::SessionState { .. }) {
                return invalid("session-state occurrence requested a non-session-state resource");
            }
            if !matches!(stage, Stage::Requested | Stage::Commit) {
                return invalid(
                    "session-state occurrence supports only requested and commit stages",
                );
            }
            validate_selector_resource(requested)?;
        }
        OccurrenceResource::RuntimeExtensionOccurrence { requested, .. } => {
            if !matches!(
                requested.as_ref(),
                SelectorResource::RuntimeExtension { .. }
            ) {
                return invalid("runtime-extension occurrence requested a non-extension resource");
            }
            if !matches!(stage, Stage::Requested | Stage::Commit | Stage::Repeat) {
                return invalid(
                    "runtime-extension occurrence supports only requested, commit, and repeat stages",
                );
            }
            validate_selector_resource(requested)?;
        }
        OccurrenceResource::ClosedOccurrence { requested, .. } => {
            if !matches!(requested.as_ref(), SelectorResource::ClosedSurface { .. }) {
                return invalid("closed occurrence requested a non-closed resource");
            }
            validate_selector_resource(requested)?;
        }
    }
    Ok(())
}

fn fact(name: &str, present: bool, allowed: bool, required: bool) -> Result<()> {
    if present && !allowed {
        return invalid(&format!("speculative {name} fact at this stage"));
    }
    if required && !present {
        return invalid(&format!("stage lacks required {name} fact"));
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(Error::InvalidModel(message.to_string()))
}

fn dns_answer_type(answer: &DnsAnswer) -> DnsRecordType {
    match answer {
        DnsAnswer::A { .. } => DnsRecordType::A,
        DnsAnswer::Aaaa { .. } => DnsRecordType::Aaaa,
        DnsAnswer::Cname { .. } => DnsRecordType::Cname,
        DnsAnswer::Ns { .. } => DnsRecordType::Ns,
        DnsAnswer::Ptr { .. } => DnsRecordType::Ptr,
        DnsAnswer::Caa { .. } => DnsRecordType::Caa,
        DnsAnswer::Mx { .. } => DnsRecordType::Mx,
        DnsAnswer::Naptr { .. } => DnsRecordType::Naptr,
        DnsAnswer::Soa { .. } => DnsRecordType::Soa,
        DnsAnswer::Srv { .. } => DnsRecordType::Srv,
        DnsAnswer::Txt { .. } => DnsRecordType::Txt,
    }
}

fn validate_dns_answer(answer: &DnsAnswer) -> Result<()> {
    match answer {
        DnsAnswer::Caa { tag, .. } => {
            if !tag
                .as_str()
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
            {
                return invalid("CAA tag is not canonical lowercase ASCII");
            }
        }
        DnsAnswer::Naptr { replacement, .. } => {
            if replacement.as_str() != "." && DnsName::new(replacement.as_str().to_owned()).is_err()
            {
                return invalid("NAPTR replacement is not a canonical DNS name or root");
            }
        }
        DnsAnswer::Srv { target, .. } => {
            if target.as_str() != "." && DnsName::new(target.as_str().to_owned()).is_err() {
                return invalid("SRV target is not a canonical DNS name or root");
            }
        }
        DnsAnswer::Txt { chunks } if chunks.is_empty() => {
            return invalid("TXT answer chunks must not be empty");
        }
        _ => {}
    }
    Ok(())
}

fn validate_bound_endpoints(
    requested: &SelectorResource,
    endpoints: Option<&[BoundEndpoint]>,
) -> Result<()> {
    let SelectorResource::ListenInet {
        bind,
        port,
        dual_stack,
        ..
    } = requested
    else {
        return Ok(());
    };
    let Some(endpoints) = endpoints else {
        // Bound endpoint families are materialized by commit. Pre-commit
        // stages cannot prove or disprove a requested dual-stack bind.
        return Ok(());
    };
    let mut saw_v4 = false;
    let mut saw_v6 = false;
    for endpoint in endpoints {
        let endpoint_port = ListenPort::Exact {
            value: endpoint.port,
        };
        // `ephemeral` is not reusable authority over any exact port, but an
        // occurrence must materialize the OS-selected concrete port after bind.
        if !matches!(port, ListenPort::Ephemeral) && !listen_port_contains(*port, endpoint_port) {
            return invalid("bound port is outside requested listener authority");
        }
        match endpoint.address.get() {
            IpAddr::V4(_) => saw_v4 = true,
            IpAddr::V6(_) => saw_v6 = true,
        }
        match bind {
            ListenBind::Address { address } if *address != endpoint.address => {
                return invalid("bound address differs from requested address")
            }
            ListenBind::Loopback if !endpoint.address.get().is_loopback() => {
                return invalid("non-loopback address used for loopback bind")
            }
            ListenBind::Interface { name } if endpoint.interface.as_ref() != Some(name) => {
                return invalid("bound interface differs from requested interface")
            }
            _ => {}
        }
    }
    if (*dual_stack && !(saw_v4 && saw_v6)) || (!*dual_stack && saw_v4 && saw_v6) {
        return invalid("bound endpoint families disagree with dualStack");
    }
    Ok(())
}

/// Match one policy selector against one normalized effect occurrence. The
/// product supplies peer classification from its digest-bound registry.
pub fn selector_matches_occurrence<C: PeerClassifier>(
    selector: &AuthoritySelector,
    occurrence: &EffectOccurrence,
    context: &ContainmentContext,
    polarity: AuthorityPolarity,
    classifier: &C,
) -> Result<bool> {
    validate_occurrence_stage_facts(occurrence)?;
    selector_matches_occurrence_after_stage_validation(
        selector, occurrence, context, polarity, classifier,
    )
}

/// Decision evaluation validates malformed stage facts at their own precedence
/// stratum. Earlier hard-deny strata use this form so the decisive evidence is
/// not accidentally attributed to the first optional policy matcher.
pub(crate) fn selector_matches_occurrence_after_stage_validation<C: PeerClassifier>(
    selector: &AuthoritySelector,
    occurrence: &EffectOccurrence,
    context: &ContainmentContext,
    polarity: AuthorityPolarity,
    classifier: &C,
) -> Result<bool> {
    validate_authority_selector(selector)?;
    if selector.action != occurrence.action || !context.same_snapshot {
        return Ok(false);
    }
    let requested = occurrence
        .resource
        .requested_selector_resource()
        .ok_or_else(|| Error::InvalidModel("occurrence has no requested resource".to_string()))?;
    if (selector.resource.contains_package_logical_root()
        || requested.contains_package_logical_root())
        && !context.same_package_root_owner
    {
        return Ok(false);
    }
    if selector.resource.is_closed_surface() && polarity == AuthorityPolarity::Positive {
        return Ok(false);
    }

    let structurally_contained = match (&selector.resource, &occurrence.resource) {
        (
            SelectorResource::FetchEndpoint {
                schemes,
                host,
                port,
                peer_classes,
                route,
            },
            OccurrenceResource::NetworkOccurrence {
                requested:
                    NetworkRequest::FetchEndpoint {
                        scheme,
                        host: requested_host,
                        port: requested_port,
                    },
                route: requested_route,
                selected_candidate,
                ..
            },
        ) => {
            schemes.contains(scheme)
                && host_contains(host, &Host::from(requested_host))
                && remote_port_contains(
                    *port,
                    RemotePort::Exact {
                        value: *requested_port,
                    },
                )
                && route == requested_route
                && peer_fact_allowed(
                    requested_host,
                    *selected_candidate,
                    peer_classes,
                    occurrence.stage,
                    classifier,
                )
        }
        (
            SelectorResource::ConnectEndpoint {
                transport,
                host,
                port,
                peer_classes,
                route,
            },
            OccurrenceResource::NetworkOccurrence {
                requested:
                    NetworkRequest::ConnectEndpoint {
                        transport: requested_transport,
                        host: requested_host,
                        port: requested_port,
                    },
                route: requested_route,
                selected_candidate,
                ..
            },
        ) => {
            transport == requested_transport
                && host_contains(host, &Host::from(requested_host))
                && remote_port_contains(
                    *port,
                    RemotePort::Exact {
                        value: *requested_port,
                    },
                )
                && route == requested_route
                && peer_fact_allowed(
                    requested_host,
                    *selected_candidate,
                    peer_classes,
                    occurrence.stage,
                    classifier,
                )
        }
        (
            SelectorResource::ListenInet { peer_classes, .. },
            OccurrenceResource::ListenOccurrence { accepted_peer, .. },
        ) => {
            resource_contains(&selector.resource, &requested)
                && accepted_peer.as_ref().is_none_or(|peer| {
                    classifier
                        .classify(peer.address)
                        .is_some_and(|class| peer_classes.contains(&class))
                })
        }
        _ => resource_contains(&selector.resource, &requested),
    };
    Ok(structurally_contained)
}

fn peer_fact_allowed<C: PeerClassifier>(
    requested_host: &ConcreteHost,
    selected: Option<IpAddress>,
    allowed: &[PeerClass],
    stage: Stage,
    classifier: &C,
) -> bool {
    let address = selected.or(match requested_host {
        ConcreteHost::Ip { address } => Some(*address),
        ConcreteHost::DnsName { .. } => None,
    });
    match address {
        Some(address) => classifier
            .classify(address)
            .is_some_and(|class| allowed.contains(&class)),
        None => !matches!(
            stage,
            Stage::Candidate | Stage::Commit | Stage::Delivery | Stage::Repeat | Stage::Cleanup
        ),
    }
}

#[allow(dead_code)]
fn _ip_type_markers(_: Ipv4Addr, _: Ipv6Addr) {}
