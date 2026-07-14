//! Authority retained with the object or peer that was actually selected.
//!
//! Adapters create these records only after opening/connecting and verifying
//! the committed object identity. Repeated operations validate owner, snapshot,
//! and generations without reopening a path or resolving a hostname again.
//! @ref LLP 0021#wp5--convert-filesystem-effects-and-checked-object-execution
//! @ref LLP 0021#wp6--convert-network-effects-and-protected-peers

use crate::cache::GenerationSet;
use crate::model::{Digest, NonEmptyString, ObjectIdentity, PeerClass, Principal, VerifiedPeer};
use crate::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedObjectAuthority {
    pub owner: Principal,
    pub authority_source: NonEmptyString,
    pub armed_snapshot_digest: Digest,
    pub generations: GenerationSet,
    pub object: ObjectIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedPeerAuthority {
    pub owner: Principal,
    pub authority_source: NonEmptyString,
    pub armed_snapshot_digest: Digest,
    pub generations: GenerationSet,
    pub peer: VerifiedPeer,
    pub peer_class: PeerClass,
    pub connection_id: NonEmptyString,
}

impl ProtectedPeerAuthority {
    pub fn verify_use(
        &self,
        actor: &Principal,
        armed_snapshot_digest: &Digest,
        generations: GenerationSet,
        actual_peer: &VerifiedPeer,
    ) -> Result<()> {
        if matches!(
            self.peer_class,
            PeerClass::Metadata | PeerClass::Unspecified
        ) {
            return refused("protected peer class is always denied");
        }
        if actor != &self.owner
            || armed_snapshot_digest != &self.armed_snapshot_digest
            || generations.negative != self.generations.negative
            || generations.handle != self.generations.handle
            || actual_peer != &self.peer
        {
            return refused("connection use differs from the checked protected peer");
        }
        Ok(())
    }
}

impl RetainedObjectAuthority {
    pub fn verify_use(
        &self,
        actor: &Principal,
        armed_snapshot_digest: &Digest,
        generations: GenerationSet,
        actual_object: &ObjectIdentity,
    ) -> Result<()> {
        if actor != &self.owner {
            return refused("retained object used by a different principal");
        }
        if armed_snapshot_digest != &self.armed_snapshot_digest {
            return refused("retained object belongs to a different armed snapshot");
        }
        if generations.negative != self.generations.negative
            || generations.handle != self.generations.handle
        {
            return refused("retained object authority has stale generations");
        }
        if actual_object != &self.object {
            return refused("operation object differs from the checked object");
        }
        Ok(())
    }
}

fn refused<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::ArmRefused(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{NonEmptyString, SafeUint};

    fn digest(byte: char) -> Digest {
        Digest::new(format!("sha256-{}", byte.to_string().repeat(43))).unwrap()
    }

    fn principal(name: &str) -> Principal {
        Principal::Root {
            identity: NonEmptyString::new(name).unwrap(),
        }
    }

    fn object(file: &str) -> ObjectIdentity {
        ObjectIdentity {
            platform: crate::model::ObjectPlatform::Unix,
            volume: NonEmptyString::new("dev:1").unwrap(),
            file: NonEmptyString::new(file).unwrap(),
        }
    }

    fn generations() -> GenerationSet {
        GenerationSet {
            negative: SafeUint::ZERO,
            dynamic: SafeUint::ZERO,
            handle: SafeUint::ZERO,
        }
    }

    #[test]
    fn repeated_use_is_bound_to_owner_snapshot_generation_and_actual_object() {
        let record = RetainedObjectAuthority {
            owner: principal("package-a"),
            authority_source: NonEmptyString::new("policy.floor.0").unwrap(),
            armed_snapshot_digest: digest('A'),
            generations: generations(),
            object: object("ino:7"),
        };
        assert!(record
            .verify_use(
                &principal("package-a"),
                &digest('A'),
                generations(),
                &object("ino:7"),
            )
            .is_ok());
        assert!(record
            .verify_use(
                &principal("package-b"),
                &digest('A'),
                generations(),
                &object("ino:7"),
            )
            .is_err());
        assert!(record
            .verify_use(
                &principal("package-a"),
                &digest('A'),
                generations(),
                &object("ino:8"),
            )
            .is_err());
    }

    #[test]
    fn verified_peer_is_retained_and_metadata_is_always_denied() {
        use crate::model::{IpAddress, Port, VerifiedPeer};
        use std::net::{IpAddr, Ipv4Addr};
        let peer = VerifiedPeer {
            address: IpAddress::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            port: Port::new(443).unwrap(),
        };
        let mut record = ProtectedPeerAuthority {
            owner: principal("package-a"),
            authority_source: NonEmptyString::new("policy.floor.1").unwrap(),
            armed_snapshot_digest: digest('A'),
            generations: generations(),
            peer: peer.clone(),
            peer_class: PeerClass::Public,
            connection_id: NonEmptyString::new("connection-1").unwrap(),
        };
        assert!(record
            .verify_use(&principal("package-a"), &digest('A'), generations(), &peer)
            .is_ok());
        record.peer_class = PeerClass::Metadata;
        assert!(record
            .verify_use(&principal("package-a"), &digest('A'), generations(), &peer)
            .is_err());
    }
}
