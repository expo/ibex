//! Authenticated hot-update envelopes and session-lifetime replay admission.
//!
//! LLP 0055 §6 defines the signature and replay law, while §5.2 fixes the
//! admission order around the hot-revision state machine. LLP 0042's
//! update-payload-signature section owns key custody and verifier delivery.
//! Signature verification is unconditional wherever hot updates exist: a
//! consumer session structurally requires a verifier, so a consumer that was
//! never delivered one has no hot-update admission path. Postures differ only
//! in verifier delivery (the v1 loopback startup envelope versus Exact H2 boot
//! enrollment), never in whether verification runs. Production mode cannot
//! reach this surface because `generation.rs` structurally refuses `begin`.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::rc::Rc;

use anyhow::{anyhow, bail, Result};
use capsec_semantics::model::Digest;
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair as _};
use serde::{Deserialize, Serialize};

use super::artifact::digest_bytes;
use super::generation::{HmrOrigin, HotRevisionCommitV1};
use super::hot_revision::{HotRevisionBegunV1, HotRevisionReadyToPublishV1, HotRevisionSurfaceV1};
use super::identity::SourceId;
use super::security::GraphImportPolicy;

/// Signature domain and signed-body schema identifier.
pub const HOT_UPDATE_SIGNATURE_DOMAIN_V1: &str = "ibex/hot-update-signature/1";
pub(crate) const HOT_UPDATE_ENVELOPE_DIGEST_DOMAIN_V1: &str = "ibex:hot-update:envelope:1";
pub const HOT_UPDATE_SIGNED_BODY_LIMIT: usize = 64 * 1024;
pub const HOT_UPDATE_BODY_LIMIT: usize = 16 * 1024 * 1024;
pub const HOT_UPDATE_MAX_REPLACED_MODULES: usize = 512;
pub const HOT_UPDATE_REPLAY_CAPACITY: usize = 4096;

const I_JSON_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const ROTATION_REQUIRED_DIAGNOSTIC: &str = "hot update session requires producer runId rotation";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HotUpdateAuthorityStampV1 {
    pub snapshot_digest: Digest,
    pub policy: u64,
    pub negative: u64,
    pub dynamic: u64,
    pub handle: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HotUpdateSignedBodyV1 {
    pub schema: String,
    pub run_id: String,
    pub authority_stamp: HotUpdateAuthorityStampV1,
    pub execution_generation: u64,
    pub base_hot_revision: u64,
    pub target_hot_revision: u64,
    pub update_id: String,
    pub target_descriptor: String,
    pub entry: String,
    pub profile: String,
    pub consumer_identity: String,
    pub base_graph_digest: Digest,
    pub payload_digest: Digest,
    pub issued_at_ms: u64,
}

impl HotUpdateSignedBodyV1 {
    fn validate_shape(&self) -> Result<()> {
        if self.update_id.is_empty() {
            bail!("hot update updateId must be nonempty");
        }
        for (field, value) in [
            ("authorityStamp.policy", self.authority_stamp.policy),
            ("authorityStamp.negative", self.authority_stamp.negative),
            ("authorityStamp.dynamic", self.authority_stamp.dynamic),
            ("authorityStamp.handle", self.authority_stamp.handle),
            ("executionGeneration", self.execution_generation),
            ("baseHotRevision", self.base_hot_revision),
            ("targetHotRevision", self.target_hot_revision),
            ("issuedAtMs", self.issued_at_ms),
        ] {
            if value > I_JSON_MAX_SAFE_INTEGER {
                bail!("hot update signed body field {field} exceeds the I-JSON safe range");
            }
        }
        Ok(())
    }
}

/// Producer-held ephemeral signing session. Rotation means minting a new
/// session; no private material is serializable, printable, or exposed.
// @ref LLP 0055#6-update-payload-authentication-obligation-3-amends-llp-0042 —
// the private key lives only in the producing runId session's process memory.
// @ref LLP 0042#update-payload-signature-llp-0055-6 — verifier delivery never
// transfers or persists the producer's signing key.
pub struct HotUpdateSigningSessionV1 {
    key_pair: Ed25519KeyPair,
    run_id: String,
}

impl fmt::Debug for HotUpdateSigningSessionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HotUpdateSigningSessionV1 {{ run_id: {:?}, key: <redacted> }}",
            self.run_id
        )
    }
}

impl HotUpdateSigningSessionV1 {
    pub fn mint(run_id: &str) -> Result<Self> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow!("cannot generate the hot-update Ed25519 keypair"))?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| anyhow!("cannot parse the generated hot-update Ed25519 keypair"))?;
        Ok(Self {
            key_pair,
            run_id: run_id.to_owned(),
        })
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn verifier(&self) -> HotUpdateVerifierV1 {
        HotUpdateVerifierV1 {
            public_key: self.key_pair.public_key().as_ref().to_vec(),
        }
    }

    pub fn sign(&self, body: &HotUpdateSignedBodyV1) -> Result<HotUpdateEnvelopeV1> {
        if body.run_id != self.run_id {
            bail!("hot update signed body runId does not match the signing session");
        }
        if body.schema != HOT_UPDATE_SIGNATURE_DOMAIN_V1 {
            bail!("hot update signed body schema is unsupported");
        }
        body.validate_shape()?;
        if body.base_hot_revision.checked_add(1) != Some(body.target_hot_revision) {
            bail!("hot update target revision must be exactly base+1");
        }
        let value = serde_json::to_value(body)?;
        let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|error| anyhow!("cannot canonicalize hot update signed body: {error}"))?;
        if canonical.len() > HOT_UPDATE_SIGNED_BODY_LIMIT {
            bail!("hot update signed body exceeds the limit");
        }
        let signature = self.key_pair.sign(&signing_message(&canonical));
        let mut signature_bytes = [0; 64];
        signature_bytes.copy_from_slice(signature.as_ref());
        Ok(HotUpdateEnvelopeV1 {
            body: canonical,
            signature: signature_bytes,
        })
    }
}

#[derive(Clone, Debug)]
pub struct HotUpdateVerifierV1 {
    public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HotUpdateEnvelopeV1 {
    pub body: Vec<u8>,
    pub signature: [u8; 64],
}

impl HotUpdateEnvelopeV1 {
    pub fn envelope_digest(&self) -> Result<Digest> {
        let mut bytes = Vec::with_capacity(self.body.len() + self.signature.len());
        bytes.extend_from_slice(&self.body);
        bytes.extend_from_slice(&self.signature);
        digest_bytes(HOT_UPDATE_ENVELOPE_DIGEST_DOMAIN_V1, &bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HotUpdateRefusalClassV1 {
    KeepLastGood,
    FullReloadCurrentAuthority,
    RegeneratePolicyAndRestartRuntime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HotUpdateOutcomeReceiptV1 {
    Committed {
        generation: u64,
        revision: u64,
    },
    CommittedDegraded {
        generation: u64,
        revision: u64,
        detail: String,
    },
    Refused {
        class: HotUpdateRefusalClassV1,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HotUpdateSessionExpectationsV1 {
    pub run_id: String,
    pub authority_stamp: HotUpdateAuthorityStampV1,
    pub target_descriptor: String,
    pub entry: String,
    pub profile: String,
    pub consumer_identity: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ReplayEntry {
    Pending {
        envelope_digest: Option<Digest>,
    },
    Terminal {
        envelope_digest: Digest,
        receipt: HotUpdateOutcomeReceiptV1,
    },
}

/// Host-held replay owner for one producer `runId` session.
// @ref LLP 0055#6-update-payload-authentication-obligation-3-amends-llp-0042 —
// the table survives runtime recreation and is retired only by runId rotation.
pub struct HotUpdateConsumerSessionV1 {
    verifier: signature::UnparsedPublicKey<Vec<u8>>,
    expectations: HotUpdateSessionExpectationsV1,
    replay: BTreeMap<String, ReplayEntry>,
    pending_update: Option<String>,
    terminal_count: usize,
    capacity: usize,
    rotation_required: Rc<Cell<bool>>,
}

impl HotUpdateConsumerSessionV1 {
    pub fn new(
        verifier: HotUpdateVerifierV1,
        expectations: HotUpdateSessionExpectationsV1,
    ) -> Self {
        Self::with_replay_capacity(verifier, expectations, HOT_UPDATE_REPLAY_CAPACITY)
    }

    #[cfg(test)]
    fn with_capacity(
        verifier: HotUpdateVerifierV1,
        expectations: HotUpdateSessionExpectationsV1,
        capacity: usize,
    ) -> Self {
        Self::with_replay_capacity(verifier, expectations, capacity)
    }

    fn with_replay_capacity(
        verifier: HotUpdateVerifierV1,
        expectations: HotUpdateSessionExpectationsV1,
        capacity: usize,
    ) -> Self {
        Self {
            verifier: signature::UnparsedPublicKey::new(&signature::ED25519, verifier.public_key),
            expectations,
            replay: BTreeMap::new(),
            pending_update: None,
            terminal_count: 0,
            capacity,
            rotation_required: Rc::new(Cell::new(false)),
        }
    }

    pub fn rotation_required(&self) -> bool {
        self.rotation_required.get()
    }

    /// Runs checks 1 and 2 plus the normative rotation, busy, and capacity
    /// gates, reserving a pending row only for an accepted check-3 attempt.
    // @ref LLP 0055#52-hotrevisionsurfacev1--single-flight-typed-states-no-fallible-check-after-an-effect
    pub fn admit(
        &mut self,
        surface: &HotRevisionSurfaceV1,
        envelope: &HotUpdateEnvelopeV1,
        payload: &[u8],
    ) -> HotUpdateAdmissionV1 {
        let body = match self.authenticate(envelope, payload) {
            Ok(body) => body,
            Err(reason) => return HotUpdateAdmissionV1::Unauthenticated { reason },
        };

        // A poisoned session cannot consult even a known row: quarantine has
        // no receipt and its stranded reservation must never degrade to busy.
        if self.rotation_required.get() {
            return HotUpdateAdmissionV1::RotationRequired {
                class: HotUpdateRefusalClassV1::KeepLastGood,
                diagnostic: ROTATION_REQUIRED_DIAGNOSTIC.to_owned(),
            };
        }

        let envelope_digest = match envelope.envelope_digest() {
            Ok(digest) => digest,
            Err(error) => {
                return HotUpdateAdmissionV1::Unauthenticated {
                    reason: format!("hot update envelope digest failed: {error}"),
                };
            }
        };
        if let Some(entry) = self.replay.get(&body.update_id) {
            return match entry {
                ReplayEntry::Pending {
                    envelope_digest: Some(bound_digest),
                } if bound_digest == &envelope_digest => HotUpdateAdmissionV1::Busy {
                    diagnostic: format!("hot update {} is in flight", body.update_id),
                },
                ReplayEntry::Pending { .. } => HotUpdateAdmissionV1::IdentityConflict {
                    class: HotUpdateRefusalClassV1::KeepLastGood,
                    diagnostic: format!(
                        "hot update identity conflict: updateId {} was already bound to different bytes",
                        body.update_id
                    ),
                },
                ReplayEntry::Terminal {
                    envelope_digest: bound_digest,
                    receipt,
                } if bound_digest == &envelope_digest => HotUpdateAdmissionV1::Duplicate {
                    receipt: receipt.clone(),
                },
                ReplayEntry::Terminal { .. } => HotUpdateAdmissionV1::IdentityConflict {
                    class: HotUpdateRefusalClassV1::KeepLastGood,
                    diagnostic: format!(
                        "hot update identity conflict: updateId {} was already bound to different bytes",
                        body.update_id
                    ),
                },
            };
        }

        // Busy is an occupancy answer, not an update outcome. Sealing it would
        // prevent the producer from retrying after the owner-thread flight ends.
        if self.pending_update.is_some() || surface.is_in_flight() {
            return HotUpdateAdmissionV1::Busy {
                diagnostic:
                    "hot revision surface is busy; retry after the in-flight update settles"
                        .to_owned(),
            };
        }

        // Session-lifetime idempotence forbids eviction. A same-runId reload
        // creates a generation but cannot retire this table, so capacity names
        // producer rotation and performs no generation transition.
        if self.terminal_count >= self.capacity {
            return HotUpdateAdmissionV1::CapacityRotationRequired {
                class: HotUpdateRefusalClassV1::KeepLastGood,
                diagnostic:
                    "hot update replay table is at capacity; only producer runId rotation retires it"
                        .to_owned(),
            };
        }

        let payload = payload.to_vec();
        let previous = self.replay.insert(
            body.update_id.clone(),
            ReplayEntry::Pending {
                envelope_digest: Some(envelope_digest.clone()),
            },
        );
        debug_assert!(previous.is_none(), "check-2 miss must reserve a fresh row");
        self.pending_update = Some(body.update_id.clone());
        HotUpdateAdmissionV1::Admitted(Box::new(HotUpdateAdmittedV1 {
            update_id: body.update_id.clone(),
            envelope_digest,
            body,
            payload,
            rotation_required: Rc::clone(&self.rotation_required),
            consumed: false,
        }))
    }

    fn authenticate(
        &self,
        envelope: &HotUpdateEnvelopeV1,
        payload: &[u8],
    ) -> std::result::Result<HotUpdateSignedBodyV1, String> {
        if envelope.body.len() > HOT_UPDATE_SIGNED_BODY_LIMIT {
            return Err("hot update signed body exceeds the limit".to_owned());
        }
        if payload.len() > HOT_UPDATE_BODY_LIMIT {
            return Err("hot update body exceeds the limit".to_owned());
        }
        if self
            .verifier
            .verify(&signing_message(&envelope.body), &envelope.signature)
            .is_err()
        {
            return Err("hot update signature verification failed".to_owned());
        }

        let text = std::str::from_utf8(&envelope.body)
            .map_err(|_| "hot update signed body is not canonical JCS".to_owned())?;
        let value = capsec_semantics::strict_json::parse_strict(text)
            .map_err(|_| "hot update signed body is not canonical JCS".to_owned())?;
        let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
            .map_err(|_| "hot update signed body is not canonical JCS".to_owned())?;
        if canonical.as_slice() != envelope.body.as_slice() {
            return Err("hot update signed body is not canonical JCS".to_owned());
        }
        let body: HotUpdateSignedBodyV1 = serde_json::from_value(value)
            .map_err(|error| format!("hot update signed body shape is invalid: {error}"))?;
        body.validate_shape().map_err(|error| error.to_string())?;
        if body.schema != HOT_UPDATE_SIGNATURE_DOMAIN_V1 {
            return Err("hot update signed body schema mismatch".to_owned());
        }

        self.require_address(&body.run_id, &self.expectations.run_id, "runId")?;
        self.require_address(
            &body.authority_stamp.snapshot_digest,
            &self.expectations.authority_stamp.snapshot_digest,
            "authorityStamp.snapshotDigest",
        )?;
        self.require_address(
            &body.authority_stamp.policy,
            &self.expectations.authority_stamp.policy,
            "authorityStamp.policy",
        )?;
        self.require_address(
            &body.authority_stamp.negative,
            &self.expectations.authority_stamp.negative,
            "authorityStamp.negative",
        )?;
        self.require_address(
            &body.authority_stamp.dynamic,
            &self.expectations.authority_stamp.dynamic,
            "authorityStamp.dynamic",
        )?;
        self.require_address(
            &body.authority_stamp.handle,
            &self.expectations.authority_stamp.handle,
            "authorityStamp.handle",
        )?;
        self.require_address(
            &body.target_descriptor,
            &self.expectations.target_descriptor,
            "targetDescriptor",
        )?;
        self.require_address(&body.entry, &self.expectations.entry, "entry")?;
        self.require_address(&body.profile, &self.expectations.profile, "profile")?;
        self.require_address(
            &body.consumer_identity,
            &self.expectations.consumer_identity,
            "consumerIdentity",
        )?;

        // Currency deliberately remains unchecked until after replay lookup;
        // otherwise a post-commit retransmit would miss its terminal receipt.
        let payload_digest = hot_update_payload_digest(payload)
            .map_err(|error| format!("hot update payload digest failed: {error}"))?;
        if payload_digest != body.payload_digest {
            return Err("hot update payload digest mismatch".to_owned());
        }
        Ok(body)
    }

    fn require_address<T: PartialEq>(
        &self,
        actual: &T,
        expected: &T,
        field: &str,
    ) -> std::result::Result<(), String> {
        if actual != expected {
            return Err(format!("hot update session addressing mismatch: {field}"));
        }
        Ok(())
    }

    /// Performs check 3 under the pending reservation and delegates all graph
    /// and authority checks to the landed revision algebra. Under LLP 0055
    /// §6 and §13.1, `invalidated` and every record later staged must be
    /// derived by the H2 decode seam from [`HotUpdateAdmittedV1::payload`]: the
    /// library binds the authenticated bytes, while that decoder owns their
    /// typed derivation.
    pub fn begin_admitted<P: GraphImportPolicy>(
        &mut self,
        mut admitted: HotUpdateAdmittedV1,
        surface: &mut HotRevisionSurfaceV1,
        policy: &P,
        origin: HmrOrigin,
        invalidated: Vec<SourceId>,
    ) -> std::result::Result<(HotRevisionBegunV1, HotUpdateSettlementV1), HotUpdateRefusalV1> {
        if !Rc::ptr_eq(&admitted.rotation_required, &self.rotation_required) {
            return Err(HotUpdateRefusalV1 {
                class: HotUpdateRefusalClassV1::KeepLastGood,
                message: "hot update admitted handle belongs to another consumer session"
                    .to_owned(),
            });
        }
        debug_assert!(
            Rc::ptr_eq(&admitted.rotation_required, &self.rotation_required),
            "admitted update belongs to this consumer session"
        );

        if admitted.body.base_hot_revision.checked_add(1) != Some(admitted.body.target_hot_revision)
        {
            return Err(self.refuse_admitted(
                &mut admitted,
                HotUpdateRefusalClassV1::KeepLastGood,
                "hot update target revision must be exactly base+1",
            ));
        }
        if invalidated.len() > HOT_UPDATE_MAX_REPLACED_MODULES {
            return Err(self.refuse_admitted(
                &mut admitted,
                HotUpdateRefusalClassV1::KeepLastGood,
                "hot update exceeds the replaced-module limit",
            ));
        }

        let live = surface.current_coordinates();
        if admitted.body.execution_generation != live.0.get()
            || admitted.body.base_hot_revision != live.1.get()
        {
            let message = format!(
                "hot update base is stale; committed coordinates are generation {} revision {}",
                live.0.get(),
                live.1.get()
            );
            // @ref LLP 0055#12-obligation-ledger-exact-0417-6-h1-entry-obligations —
            // owner ask 2 is TAKEN: a revision race keeps last-good and restages.
            return Err(self.refuse_admitted(
                &mut admitted,
                HotUpdateRefusalClassV1::KeepLastGood,
                &message,
            ));
        }

        // The equality check above proved the envelope's claimed base IS the
        // live coordinate, so passing `live` here passes the update's claimed
        // base by value; the algebra's begin-time CAS remains the §5.2-item-8
        // style backstop behind this consumer-layer check-3 comparison.
        let begun = match surface.begin(policy, origin, live, invalidated) {
            Ok(begun) => begun,
            Err(error) => {
                let message = error.to_string();
                if message.contains("quarantined") {
                    // Quarantine has no member in the closed receipt union. Its
                    // pending row therefore stays stranded while the shared
                    // session poison forces every later answer to rotation.
                    admitted.rotation_required.set(true);
                    admitted.consumed = true;
                    return Err(HotUpdateRefusalV1 {
                        class: HotUpdateRefusalClassV1::KeepLastGood,
                        message: ROTATION_REQUIRED_DIAGNOSTIC.to_owned(),
                    });
                }
                if message.contains("surface is busy") {
                    // An owner-side busy race is not a terminal update outcome;
                    // unreserve it so a later retry can pass check 2.
                    let removed = self.remove_pending(&admitted);
                    debug_assert!(removed, "busy unreserve must remove the pending row");
                    if removed {
                        admitted.consumed = true;
                    }
                    return Err(HotUpdateRefusalV1 {
                        class: HotUpdateRefusalClassV1::KeepLastGood,
                        message,
                    });
                }
                let class = if message.contains("must invalidate at least one module")
                    || message.contains("hot update base is stale")
                {
                    HotUpdateRefusalClassV1::KeepLastGood
                } else if message.contains("regenerate policy and restart")
                    || message.contains("restart required")
                    || message.contains("changed a module defining principal")
                {
                    HotUpdateRefusalClassV1::RegeneratePolicyAndRestartRuntime
                } else if message.contains("widened the authenticated source graph") {
                    HotUpdateRefusalClassV1::FullReloadCurrentAuthority
                } else {
                    // Unmapped algebra refusals require re-derivation under
                    // the current authority.
                    HotUpdateRefusalClassV1::FullReloadCurrentAuthority
                };
                return Err(self.refuse_admitted(&mut admitted, class, &message));
            }
        };

        if &admitted.body.base_graph_digest != surface.graph_digest() {
            drop(begun);
            return Err(self.refuse_admitted(
                &mut admitted,
                HotUpdateRefusalClassV1::FullReloadCurrentAuthority,
                "hot update base graph digest is stale; pull live coordinates and restage",
            ));
        }

        let settlement = HotUpdateSettlementV1 {
            update_id: admitted.update_id.clone(),
            rotation_required: Rc::clone(&admitted.rotation_required),
            settled: false,
        };
        admitted.consumed = true;
        Ok((begun, settlement))
    }

    /// Commits and finalizes the replay receipt in one owner-thread call frame.
    /// Under the LLP 0002/0003 drive contract, this call frame is LLP 0055
    /// §5.3's post-fence finalization point: no interleaved admission can
    /// observe `Pending` after the surface commit succeeds.
    // @ref LLP 0055#53-the-commit-bundle-atomic-owner-thread-no-fail — success
    // finalizes the pre-reserved outcome before the owner thread can yield.
    pub fn commit_admitted<P: GraphImportPolicy>(
        &mut self,
        mut settlement: HotUpdateSettlementV1,
        surface: &mut HotRevisionSurfaceV1,
        policy: &P,
        ready: HotRevisionReadyToPublishV1,
    ) -> Result<HotRevisionCommitV1> {
        if !Rc::ptr_eq(&settlement.rotation_required, &self.rotation_required) {
            return Err(anyhow!(
                "hot update settlement handle belongs to another consumer session"
            ));
        }
        debug_assert!(
            Rc::ptr_eq(&settlement.rotation_required, &self.rotation_required),
            "commit settlement belongs to this consumer session"
        );

        let commit = match surface.commit(policy, ready) {
            Ok(commit) => commit,
            Err(error) => {
                // Commit-time backstops have no receipt in the closed union.
                // Poison the handle's origin session and strand its reservation.
                settlement.rotation_required.set(true);
                settlement.settled = true;
                return Err(error);
            }
        };
        let receipt = HotUpdateOutcomeReceiptV1::Committed {
            generation: commit.generation.get(),
            revision: commit.revision.get(),
        };
        let settled = self.terminalize_pending(&settlement.update_id, receipt);
        debug_assert!(settled, "commit settlement must replace a pending row");
        if settled {
            settlement.settled = true;
        }
        Ok(commit)
    }

    /// Finalizes every ordinary post-begin refusal before it is yielded.
    pub fn settle_refused(
        &mut self,
        mut settlement: HotUpdateSettlementV1,
        class: HotUpdateRefusalClassV1,
        message: &str,
    ) {
        if !Rc::ptr_eq(&settlement.rotation_required, &self.rotation_required) {
            return;
        }
        debug_assert!(
            Rc::ptr_eq(&settlement.rotation_required, &self.rotation_required),
            "refusal settlement belongs to this consumer session"
        );
        let receipt = HotUpdateOutcomeReceiptV1::Refused {
            class,
            message: message.to_owned(),
        };
        let settled = self.terminalize_pending(&settlement.update_id, receipt);
        debug_assert!(settled, "refusal settlement must replace a pending row");
        if settled {
            settlement.settled = true;
        }
    }

    /// Poisons the session without minting an outcome that the closed receipt
    /// union cannot represent. The pending row is deliberately stranded.
    pub fn settle_quarantined(&mut self, mut settlement: HotUpdateSettlementV1) {
        if !Rc::ptr_eq(&settlement.rotation_required, &self.rotation_required) {
            return;
        }
        debug_assert!(
            Rc::ptr_eq(&settlement.rotation_required, &self.rotation_required),
            "quarantine settlement belongs to this consumer session"
        );
        settlement.rotation_required.set(true);
        settlement.settled = true;
    }

    fn refuse_admitted(
        &mut self,
        admitted: &mut HotUpdateAdmittedV1,
        class: HotUpdateRefusalClassV1,
        message: &str,
    ) -> HotUpdateRefusalV1 {
        let refusal = HotUpdateRefusalV1 {
            class: class.clone(),
            message: message.to_owned(),
        };
        let settled = self.terminalize_matching_pending(
            &admitted.update_id,
            &admitted.envelope_digest,
            HotUpdateOutcomeReceiptV1::Refused {
                class,
                message: message.to_owned(),
            },
        );
        debug_assert!(settled, "check-3 refusal must replace its pending row");
        if settled {
            admitted.consumed = true;
        }
        refusal
    }

    fn remove_pending(&mut self, admitted: &HotUpdateAdmittedV1) -> bool {
        if matches!(
            self.replay.get(&admitted.update_id),
            Some(ReplayEntry::Pending {
                envelope_digest: Some(envelope_digest),
            }) if envelope_digest == &admitted.envelope_digest
        ) {
            self.replay.remove(&admitted.update_id);
            self.pending_update = None;
            true
        } else {
            false
        }
    }

    fn terminalize_pending(&mut self, update_id: &str, receipt: HotUpdateOutcomeReceiptV1) -> bool {
        let Some(entry) = self.replay.get_mut(update_id) else {
            return false;
        };
        let envelope_digest = match entry {
            ReplayEntry::Pending { envelope_digest } => match envelope_digest.take() {
                Some(envelope_digest) => envelope_digest,
                None => return false,
            },
            _ => return false,
        };
        *entry = ReplayEntry::Terminal {
            envelope_digest,
            receipt,
        };
        self.pending_update = None;
        self.terminal_count += 1;
        true
    }

    fn terminalize_matching_pending(
        &mut self,
        update_id: &str,
        expected_digest: &Digest,
        receipt: HotUpdateOutcomeReceiptV1,
    ) -> bool {
        let Some(entry) = self.replay.get_mut(update_id) else {
            return false;
        };
        let envelope_digest = match entry {
            ReplayEntry::Pending { envelope_digest }
                if envelope_digest.as_ref() == Some(expected_digest) =>
            {
                match envelope_digest.take() {
                    Some(envelope_digest) => envelope_digest,
                    None => return false,
                }
            }
            _ => return false,
        };
        *entry = ReplayEntry::Terminal {
            envelope_digest,
            receipt,
        };
        self.pending_update = None;
        self.terminal_count += 1;
        true
    }
}

#[derive(Debug)]
pub enum HotUpdateAdmissionV1 {
    Unauthenticated {
        reason: String,
    },
    RotationRequired {
        class: HotUpdateRefusalClassV1,
        diagnostic: String,
    },
    Busy {
        diagnostic: String,
    },
    Duplicate {
        receipt: HotUpdateOutcomeReceiptV1,
    },
    IdentityConflict {
        class: HotUpdateRefusalClassV1,
        diagnostic: String,
    },
    CapacityRotationRequired {
        class: HotUpdateRefusalClassV1,
        diagnostic: String,
    },
    Admitted(Box<HotUpdateAdmittedV1>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HotUpdateRefusalV1 {
    pub class: HotUpdateRefusalClassV1,
    pub message: String,
}

pub struct HotUpdateAdmittedV1 {
    update_id: String,
    envelope_digest: Digest,
    body: HotUpdateSignedBodyV1,
    payload: Vec<u8>,
    rotation_required: Rc<Cell<bool>>,
    consumed: bool,
}

impl fmt::Debug for HotUpdateAdmittedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HotUpdateAdmittedV1")
            .field("update_id", &self.update_id)
            .field("envelope_digest", &self.envelope_digest)
            .field("body", &self.body)
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl HotUpdateAdmittedV1 {
    /// Returns the exact digest-verified update bytes bound to this token.
    /// The invalidated set passed to `begin_admitted` and every record later
    /// staged must be derived from these bytes by the H2 decode seam: LLP 0055
    /// §6 binds the bytes, and §13.1 leaves their record-form decoding to H2.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl Drop for HotUpdateAdmittedV1 {
    fn drop(&mut self) {
        if !self.consumed {
            self.rotation_required.set(true);
        }
    }
}

pub struct HotUpdateSettlementV1 {
    update_id: String,
    rotation_required: Rc<Cell<bool>>,
    settled: bool,
}

impl fmt::Debug for HotUpdateSettlementV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HotUpdateSettlementV1")
            .field("update_id", &self.update_id)
            .field("settled", &self.settled)
            .finish()
    }
}

impl Drop for HotUpdateSettlementV1 {
    fn drop(&mut self) {
        if !self.settled {
            self.rotation_required.set(true);
        }
    }
}

/// The shared payload-digest construction: producer minting `payloadDigest`
/// and consumer verification MUST use this exact domain-separated form (the
/// Exact H2 transport producer consumes this helper's definition).
pub fn hot_update_payload_digest(payload: &[u8]) -> Result<Digest> {
    digest_bytes(HOT_UPDATE_SIGNATURE_DOMAIN_V1, payload)
}

fn signing_message(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(HOT_UPDATE_SIGNATURE_DOMAIN_V1.len() + 1 + body.len());
    message.extend_from_slice(HOT_UPDATE_SIGNATURE_DOMAIN_V1.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(body);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_loader::generation::GenerationPublicationKind;
    use crate::module_loader::hot_revision::test_support::{
        artifact, artifact_with_top_level_await, digest, policy, policy_with_digest, preflighted,
        record, source, surface, Policy,
    };
    use crate::module_loader::hot_revision::ActivationTokenV1;

    const PAYLOAD: &[u8] = br#"{"invalidated":["entry.mjs"],"replacements":["entry.mjs@2"]}"#;

    struct Rig {
        signing: HotUpdateSigningSessionV1,
        consumer: HotUpdateConsumerSessionV1,
        surface: HotRevisionSurfaceV1,
        policy: Policy,
        source_id: SourceId,
        payload: Vec<u8>,
    }

    impl Rig {
        fn new(run_id: &str) -> Self {
            let policy = policy();
            let source_id = source("entry.mjs");
            let surface = surface(&[artifact(source_id.clone(), 1)], &policy);
            let signing = HotUpdateSigningSessionV1::mint(run_id).unwrap();
            let expectations = expectations(run_id, &policy);
            let consumer = HotUpdateConsumerSessionV1::new(signing.verifier(), expectations);
            Self {
                signing,
                consumer,
                surface,
                policy,
                source_id,
                payload: PAYLOAD.to_vec(),
            }
        }

        fn body(&self, update_id: &str) -> HotUpdateSignedBodyV1 {
            let coordinates = self.surface.current_coordinates();
            HotUpdateSignedBodyV1 {
                schema: HOT_UPDATE_SIGNATURE_DOMAIN_V1.to_owned(),
                run_id: self.signing.run_id().to_owned(),
                authority_stamp: authority_stamp(&self.policy),
                execution_generation: coordinates.0.get(),
                base_hot_revision: coordinates.1.get(),
                target_hot_revision: coordinates.1.get() + 1,
                update_id: update_id.to_owned(),
                target_descriptor: "ios-simulator-arm64".to_owned(),
                entry: "src/index.ts".to_owned(),
                profile: "development".to_owned(),
                consumer_identity: "boot-consumer-1".to_owned(),
                base_graph_digest: self.surface.graph_digest().clone(),
                payload_digest: hot_update_payload_digest(&self.payload).unwrap(),
                issued_at_ms: 1_777_777_777_777,
            }
        }
    }

    fn authority_stamp(policy: &impl GraphImportPolicy) -> HotUpdateAuthorityStampV1 {
        let generations = policy.snapshot_generations();
        HotUpdateAuthorityStampV1 {
            snapshot_digest: policy.snapshot_digest().clone(),
            policy: generations.policy.get(),
            negative: generations.negative.get(),
            dynamic: generations.dynamic.get(),
            handle: generations.handle.get(),
        }
    }

    fn expectations(
        run_id: &str,
        policy: &impl GraphImportPolicy,
    ) -> HotUpdateSessionExpectationsV1 {
        HotUpdateSessionExpectationsV1 {
            run_id: run_id.to_owned(),
            authority_stamp: authority_stamp(policy),
            target_descriptor: "ios-simulator-arm64".to_owned(),
            entry: "src/index.ts".to_owned(),
            profile: "development".to_owned(),
            consumer_identity: "boot-consumer-1".to_owned(),
        }
    }

    fn canonical_body(body: &HotUpdateSignedBodyV1) -> Vec<u8> {
        capsec_semantics::canonical::to_jcs_bytes(&serde_json::to_value(body).unwrap()).unwrap()
    }

    fn envelope_for_bytes(
        signing: &HotUpdateSigningSessionV1,
        body: Vec<u8>,
        domain: &str,
    ) -> HotUpdateEnvelopeV1 {
        let mut message = Vec::with_capacity(domain.len() + 1 + body.len());
        message.extend_from_slice(domain.as_bytes());
        message.push(b'\n');
        message.extend_from_slice(&body);
        let signature = signing.key_pair.sign(&message);
        let mut signature_bytes = [0; 64];
        signature_bytes.copy_from_slice(signature.as_ref());
        HotUpdateEnvelopeV1 {
            body,
            signature: signature_bytes,
        }
    }

    fn raw_envelope(
        signing: &HotUpdateSigningSessionV1,
        body: &HotUpdateSignedBodyV1,
    ) -> HotUpdateEnvelopeV1 {
        envelope_for_bytes(
            signing,
            canonical_body(body),
            HOT_UPDATE_SIGNATURE_DOMAIN_V1,
        )
    }

    fn take_admitted(admission: HotUpdateAdmissionV1) -> HotUpdateAdmittedV1 {
        match admission {
            HotUpdateAdmissionV1::Admitted(admitted) => *admitted,
            other => panic!("expected admitted update, got {other:?}"),
        }
    }

    fn assert_unauthenticated_no_poison(
        mut rig: Rig,
        envelope: HotUpdateEnvelopeV1,
        payload: Vec<u8>,
        expected_reason: &str,
        update_id: &str,
    ) {
        match rig.consumer.admit(&rig.surface, &envelope, &payload) {
            HotUpdateAdmissionV1::Unauthenticated { reason } => {
                assert_eq!(reason, expected_reason);
            }
            other => panic!("expected unauthenticated refusal, got {other:?}"),
        }
        assert!(rig.consumer.replay.is_empty());

        let legitimate_body = rig.body(update_id);
        let legitimate = rig.signing.sign(&legitimate_body).unwrap();
        let mut admitted =
            take_admitted(rig.consumer.admit(&rig.surface, &legitimate, &rig.payload));
        assert!(matches!(
            rig.consumer.replay.get(update_id),
            Some(ReplayEntry::Pending { .. })
        ));
        admitted.consumed = true;
    }

    fn assert_check1_body_mutation(
        update_id: &str,
        expected_reason: &str,
        mutate: impl FnOnce(&mut HotUpdateSignedBodyV1),
    ) {
        let rig = Rig::new("run-check-1");
        let mut body = rig.body(update_id);
        mutate(&mut body);
        let envelope = raw_envelope(&rig.signing, &body);
        let payload = rig.payload.clone();
        assert_unauthenticated_no_poison(rig, envelope, payload, expected_reason, update_id);
    }

    fn assert_refused_receipt(
        admission: HotUpdateAdmissionV1,
        expected: &HotUpdateOutcomeReceiptV1,
    ) {
        match admission {
            HotUpdateAdmissionV1::Duplicate { receipt } => assert_eq!(&receipt, expected),
            other => panic!("expected duplicate refusal receipt, got {other:?}"),
        }
    }

    fn assert_check3_terminalized(
        rig: &mut Rig,
        body: HotUpdateSignedBodyV1,
        envelope: HotUpdateEnvelopeV1,
        invalidated: Vec<SourceId>,
        expected_class: HotUpdateRefusalClassV1,
        expected_message: &str,
    ) {
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        assert!(matches!(
            rig.consumer.replay.get(&body.update_id),
            Some(ReplayEntry::Pending { .. })
        ));
        let refusal = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                invalidated,
            )
            .err()
            .expect("check 3 must refuse");
        assert_eq!(refusal.class, expected_class);
        assert_eq!(refusal.message, expected_message);
        let receipt = HotUpdateOutcomeReceiptV1::Refused {
            class: refusal.class.clone(),
            message: refusal.message.clone(),
        };
        assert_refused_receipt(
            rig.consumer.admit(&rig.surface, &envelope, &rig.payload),
            &receipt,
        );

        let mut different_body = body;
        different_body.issued_at_ms += 1;
        let different = raw_envelope(&rig.signing, &different_body);
        match rig.consumer.admit(&rig.surface, &different, &rig.payload) {
            HotUpdateAdmissionV1::IdentityConflict { class, diagnostic } => {
                assert_eq!(class, HotUpdateRefusalClassV1::KeepLastGood);
                assert!(diagnostic.contains(&different_body.update_id));
            }
            other => panic!("expected identity conflict, got {other:?}"),
        }
        assert_refused_receipt(
            rig.consumer.admit(&rig.surface, &envelope, &rig.payload),
            &receipt,
        );
    }

    fn commit_update(
        rig: &mut Rig,
        update_id: &str,
        replacement_value: u32,
    ) -> (HotUpdateSignedBodyV1, HotUpdateEnvelopeV1) {
        let body = rig.body(update_id);
        let envelope = rig.signing.sign(&body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        assert_eq!(admitted.payload(), rig.payload.as_slice());
        let (begun, settlement) = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .unwrap();
        let replacement = artifact(rig.source_id.clone(), replacement_value);
        let mut preflighted = begun
            .stage([record(&replacement)])
            .unwrap()
            .preflight(&rig.surface)
            .unwrap();
        let token = preflighted
            .shadow_publication_token(&rig.source_id)
            .unwrap();
        preflighted
            .shadow_publish(&token, GenerationPublicationKind::Evaluation)
            .unwrap();
        let ready = preflighted
            .evaluated()
            .unwrap()
            .prepare_activation(ActivationTokenV1::trivial())
            .ready();
        rig.consumer
            .commit_admitted(settlement, &mut rig.surface, &rig.policy, ready)
            .unwrap();
        (body, envelope)
    }

    #[test]
    fn f9_happy_path_commits_and_post_commit_duplicate_replays_old_currency_receipt() {
        let mut rig = Rig::new("run-happy");
        let (_body, envelope) = commit_update(&mut rig, "update-happy", 2);
        let coordinates = rig.surface.current_coordinates();
        assert_eq!(coordinates.0.get(), 41);
        assert_eq!(coordinates.1.get(), 1);
        match rig.consumer.admit(&rig.surface, &envelope, &rig.payload) {
            HotUpdateAdmissionV1::Duplicate { receipt } => assert_eq!(
                receipt,
                HotUpdateOutcomeReceiptV1::Committed {
                    generation: 41,
                    revision: 1,
                }
            ),
            other => panic!("expected committed duplicate, got {other:?}"),
        }
    }

    #[test]
    fn f9_check1_signature_attacks_never_enter_replay() {
        let rig = Rig::new("run-signature-tamper");
        let body = rig.body("tampered");
        let mut envelope = rig.signing.sign(&body).unwrap();
        envelope.body[0] ^= 1;
        let payload = rig.payload.clone();
        assert_unauthenticated_no_poison(
            rig,
            envelope,
            payload,
            "hot update signature verification failed",
            "tampered",
        );

        let rig = Rig::new("run-wrong-domain");
        let body = rig.body("wrong-domain");
        let envelope = envelope_for_bytes(
            &rig.signing,
            canonical_body(&body),
            "ibex/hot-update-signature/wrong",
        );
        let payload = rig.payload.clone();
        assert_unauthenticated_no_poison(
            rig,
            envelope,
            payload,
            "hot update signature verification failed",
            "wrong-domain",
        );

        let rig = Rig::new("run-wrong-key");
        let body = rig.body("wrong-key");
        let second = HotUpdateSigningSessionV1::mint("run-wrong-key").unwrap();
        let envelope = second.sign(&body).unwrap();
        let payload = rig.payload.clone();
        assert_unauthenticated_no_poison(
            rig,
            envelope,
            payload,
            "hot update signature verification failed",
            "wrong-key",
        );

        let rig = Rig::new("run-zero-signature");
        let body = rig.body("zero-signature");
        let mut envelope = rig.signing.sign(&body).unwrap();
        envelope.signature = [0; 64];
        let payload = rig.payload.clone();
        assert_unauthenticated_no_poison(
            rig,
            envelope,
            payload,
            "hot update signature verification failed",
            "zero-signature",
        );
    }

    #[test]
    fn f9_check1_session_addressing_mismatches_never_enter_replay() {
        assert_check1_body_mutation(
            "run-id",
            "hot update session addressing mismatch: runId",
            |body| body.run_id = "other-run".to_owned(),
        );
        assert_check1_body_mutation(
            "snapshot",
            "hot update session addressing mismatch: authorityStamp.snapshotDigest",
            |body| body.authority_stamp.snapshot_digest = digest("other-authority"),
        );
        assert_check1_body_mutation(
            "authority-generation",
            "hot update session addressing mismatch: authorityStamp.policy",
            |body| body.authority_stamp.policy += 1,
        );
        assert_check1_body_mutation(
            "target",
            "hot update session addressing mismatch: targetDescriptor",
            |body| body.target_descriptor = "android-emulator-arm64".to_owned(),
        );
        assert_check1_body_mutation(
            "entry",
            "hot update session addressing mismatch: entry",
            |body| body.entry = "src/other.ts".to_owned(),
        );
        assert_check1_body_mutation(
            "profile",
            "hot update session addressing mismatch: profile",
            |body| body.profile = "release".to_owned(),
        );
        assert_check1_body_mutation(
            "consumer",
            "hot update session addressing mismatch: consumerIdentity",
            |body| body.consumer_identity = "boot-consumer-2".to_owned(),
        );
    }

    #[test]
    fn f9_check1_schema_canonical_shape_and_payload_failures_never_enter_replay() {
        assert_check1_body_mutation(
            "wrong-schema",
            "hot update signed body schema mismatch",
            |body| body.schema = "ibex/hot-update-signature/2".to_owned(),
        );

        let rig = Rig::new("run-noncanonical");
        let body = rig.body("noncanonical");
        let mut bytes = canonical_body(&body);
        bytes.push(b' ');
        let envelope = envelope_for_bytes(&rig.signing, bytes, HOT_UPDATE_SIGNATURE_DOMAIN_V1);
        let payload = rig.payload.clone();
        assert_unauthenticated_no_poison(
            rig,
            envelope,
            payload,
            "hot update signed body is not canonical JCS",
            "noncanonical",
        );

        let mut rig = Rig::new("run-unknown-field");
        let body = rig.body("unknown-field");
        let mut value = serde_json::to_value(&body).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::json!(true));
        let bytes = capsec_semantics::canonical::to_jcs_bytes(&value).unwrap();
        let envelope = envelope_for_bytes(&rig.signing, bytes, HOT_UPDATE_SIGNATURE_DOMAIN_V1);
        let payload = rig.payload.clone();
        match rig.consumer.admit(&rig.surface, &envelope, &payload) {
            HotUpdateAdmissionV1::Unauthenticated { reason } => {
                assert!(reason.starts_with("hot update signed body shape is invalid:"));
            }
            other => panic!("expected shape refusal, got {other:?}"),
        }
        assert!(rig.consumer.replay.is_empty());
        let legitimate = rig.signing.sign(&body).unwrap();
        assert!(matches!(
            rig.consumer.admit(&rig.surface, &legitimate, &payload),
            HotUpdateAdmissionV1::Admitted(_)
        ));

        let rig = Rig::new("run-payload-mismatch");
        let body = rig.body("payload-mismatch");
        let envelope = rig.signing.sign(&body).unwrap();
        assert_unauthenticated_no_poison(
            rig,
            envelope,
            b"tampered payload".to_vec(),
            "hot update payload digest mismatch",
            "payload-mismatch",
        );
    }

    #[test]
    fn f9_check1_oversize_inputs_refuse_before_decode_or_digest() {
        let rig = Rig::new("run-oversize-signed");
        let mut body = rig.body("oversize-signed");
        body.target_descriptor = "x".repeat(HOT_UPDATE_SIGNED_BODY_LIMIT);
        let envelope = raw_envelope(&rig.signing, &body);
        assert!(envelope.body.len() > HOT_UPDATE_SIGNED_BODY_LIMIT);
        let payload = rig.payload.clone();
        assert_unauthenticated_no_poison(
            rig,
            envelope,
            payload,
            "hot update signed body exceeds the limit",
            "oversize-signed",
        );

        let rig = Rig::new("run-oversize-payload");
        let body = rig.body("oversize-payload");
        let envelope = rig.signing.sign(&body).unwrap();
        assert_unauthenticated_no_poison(
            rig,
            envelope,
            vec![0; HOT_UPDATE_BODY_LIMIT + 1],
            "hot update body exceeds the limit",
            "oversize-payload",
        );
    }

    #[test]
    fn f9_check3_stale_generation_terminalizes_keep_last_good() {
        let mut rig = Rig::new("run-stale-generation");
        let mut body = rig.body("stale-generation");
        body.execution_generation += 1;
        let envelope = rig.signing.sign(&body).unwrap();
        let invalidated = vec![rig.source_id.clone()];
        assert_check3_terminalized(
            &mut rig,
            body,
            envelope,
            invalidated,
            HotUpdateRefusalClassV1::KeepLastGood,
            "hot update base is stale; committed coordinates are generation 41 revision 0",
        );
    }

    #[test]
    fn f9_check3_target_not_successor_terminalizes_keep_last_good() {
        let mut rig = Rig::new("run-target-not-successor");
        let mut body = rig.body("target-not-successor");
        body.target_hot_revision += 1;
        let envelope = raw_envelope(&rig.signing, &body);
        let invalidated = vec![rig.source_id.clone()];
        assert_check3_terminalized(
            &mut rig,
            body,
            envelope,
            invalidated,
            HotUpdateRefusalClassV1::KeepLastGood,
            "hot update target revision must be exactly base+1",
        );
    }

    #[test]
    fn f9_check3_empty_and_oversize_invalidations_terminalize_keep_last_good() {
        let mut rig = Rig::new("run-empty-invalidation");
        let body = rig.body("empty-invalidation");
        let envelope = rig.signing.sign(&body).unwrap();
        assert_check3_terminalized(
            &mut rig,
            body,
            envelope,
            Vec::new(),
            HotUpdateRefusalClassV1::KeepLastGood,
            "HMR update must invalidate at least one module",
        );

        let mut rig = Rig::new("run-oversize-invalidation");
        let body = rig.body("oversize-invalidation");
        let envelope = rig.signing.sign(&body).unwrap();
        let invalidated = (0..=HOT_UPDATE_MAX_REPLACED_MODULES)
            .map(|index| source(&format!("module-{index}.mjs")))
            .collect();
        assert_check3_terminalized(
            &mut rig,
            body,
            envelope,
            invalidated,
            HotUpdateRefusalClassV1::KeepLastGood,
            "hot update exceeds the replaced-module limit",
        );
    }

    #[test]
    fn f9_check3_authority_drift_terminalizes_restart_family_refusal() {
        let mut rig = Rig::new("run-authority-drift");
        let body = rig.body("authority-drift");
        let envelope = rig.signing.sign(&body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        let different_policy = policy_with_digest("different-authority");
        let refusal = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &different_policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .err()
            .expect("authority drift must refuse");
        assert_eq!(
            refusal.class,
            HotUpdateRefusalClassV1::RegeneratePolicyAndRestartRuntime
        );
        assert_eq!(
            refusal.message,
            "HMR authority changed; regenerate policy and restart the runtime"
        );
        assert_refused_receipt(
            rig.consumer.admit(&rig.surface, &envelope, &rig.payload),
            &HotUpdateOutcomeReceiptV1::Refused {
                class: HotUpdateRefusalClassV1::RegeneratePolicyAndRestartRuntime,
                message: refusal.message,
            },
        );
    }

    #[test]
    fn f9_stale_revision_and_graph_digest_after_commit_have_distinct_replay_outcomes() {
        let mut rig = Rig::new("run-post-commit-stale");
        let (_committed_body, committed_envelope) = commit_update(&mut rig, "committed", 2);
        assert!(matches!(
            rig.consumer
                .admit(&rig.surface, &committed_envelope, &rig.payload),
            HotUpdateAdmissionV1::Duplicate {
                receipt: HotUpdateOutcomeReceiptV1::Committed { .. }
            }
        ));

        let mut stale = rig.body("fresh-stale-revision");
        stale.base_hot_revision = 0;
        stale.target_hot_revision = 1;
        let stale_envelope = rig.signing.sign(&stale).unwrap();
        let invalidated = vec![rig.source_id.clone()];
        assert_check3_terminalized(
            &mut rig,
            stale,
            stale_envelope,
            invalidated,
            HotUpdateRefusalClassV1::KeepLastGood,
            "hot update base is stale; committed coordinates are generation 41 revision 1",
        );

        let mut wrong_graph = rig.body("wrong-base-graph");
        wrong_graph.base_graph_digest = digest("wrong-live-graph");
        let wrong_graph_envelope = rig.signing.sign(&wrong_graph).unwrap();
        let invalidated = vec![rig.source_id.clone()];
        assert_check3_terminalized(
            &mut rig,
            wrong_graph,
            wrong_graph_envelope,
            invalidated,
            HotUpdateRefusalClassV1::FullReloadCurrentAuthority,
            "hot update base graph digest is stale; pull live coordinates and restage",
        );
    }

    #[test]
    fn f9_pending_duplicate_is_busy_then_replays_terminal_refusal() {
        let mut rig = Rig::new("run-pending-duplicate");
        let body = rig.body("pending");
        let envelope = rig.signing.sign(&body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        match rig.consumer.admit(&rig.surface, &envelope, &rig.payload) {
            HotUpdateAdmissionV1::Busy { diagnostic } => {
                assert_eq!(diagnostic, "hot update pending is in flight");
            }
            other => panic!("expected pending busy, got {other:?}"),
        }
        let (begun, settlement) = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .unwrap();
        drop(begun);
        rig.consumer.settle_refused(
            settlement,
            HotUpdateRefusalClassV1::KeepLastGood,
            "staged evaluation threw",
        );
        assert_refused_receipt(
            rig.consumer.admit(&rig.surface, &envelope, &rig.payload),
            &HotUpdateOutcomeReceiptV1::Refused {
                class: HotUpdateRefusalClassV1::KeepLastGood,
                message: "staged evaluation threw".to_owned(),
            },
        );
    }

    #[test]
    fn f9_pending_reservation_occupies_admission_before_surface_begin() {
        let mut rig = Rig::new("run-pending-occupancy");
        let first_body = rig.body("pending-a");
        let first_envelope = rig.signing.sign(&first_body).unwrap();
        let first = take_admitted(
            rig.consumer
                .admit(&rig.surface, &first_envelope, &rig.payload),
        );
        assert_eq!(rig.consumer.pending_update.as_deref(), Some("pending-a"));

        let second_body = rig.body("pending-b");
        let second_envelope = rig.signing.sign(&second_body).unwrap();
        match rig
            .consumer
            .admit(&rig.surface, &second_envelope, &rig.payload)
        {
            HotUpdateAdmissionV1::Busy { diagnostic } => assert_eq!(
                diagnostic,
                "hot revision surface is busy; retry after the in-flight update settles"
            ),
            other => panic!("expected pending reservation to answer busy, got {other:?}"),
        }
        assert!(!rig.consumer.replay.contains_key("pending-b"));

        let (begun, settlement) = rig
            .consumer
            .begin_admitted(
                first,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .unwrap();
        drop(begun);
        rig.consumer.settle_refused(
            settlement,
            HotUpdateRefusalClassV1::KeepLastGood,
            "test refusal",
        );
        assert!(rig.consumer.pending_update.is_none());

        let second = take_admitted(rig.consumer.admit(
            &rig.surface,
            &second_envelope,
            &rig.payload,
        ));
        let (begun, settlement) = rig
            .consumer
            .begin_admitted(
                second,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .unwrap();
        drop(begun);
        rig.consumer.settle_refused(
            settlement,
            HotUpdateRefusalClassV1::KeepLastGood,
            "test cleanup",
        );
    }

    #[test]
    fn f9_pending_update_id_is_content_bound_before_settlement() {
        let mut rig = Rig::new("run-pending-content-binding");
        let body = rig.body("pending-identity");
        let envelope = rig.signing.sign(&body).unwrap();
        let original_digest = envelope.envelope_digest().unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));

        let mut different_body = body;
        different_body.issued_at_ms += 1;
        let different_envelope = rig.signing.sign(&different_body).unwrap();
        match rig
            .consumer
            .admit(&rig.surface, &different_envelope, &rig.payload)
        {
            HotUpdateAdmissionV1::IdentityConflict { class, diagnostic } => {
                assert_eq!(class, HotUpdateRefusalClassV1::KeepLastGood);
                assert!(diagnostic.contains("pending-identity"));
            }
            other => panic!("expected pending identity conflict, got {other:?}"),
        }
        assert!(matches!(
            rig.consumer.replay.get("pending-identity"),
            Some(ReplayEntry::Pending {
                envelope_digest: Some(bound_digest),
            }) if bound_digest == &original_digest
        ));
        assert!(matches!(
            rig.consumer.admit(&rig.surface, &envelope, &rig.payload),
            HotUpdateAdmissionV1::Busy { .. }
        ));

        let (begun, settlement) = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .unwrap();
        drop(begun);
        rig.consumer.settle_refused(
            settlement,
            HotUpdateRefusalClassV1::KeepLastGood,
            "staged evaluation threw",
        );
        let receipt = HotUpdateOutcomeReceiptV1::Refused {
            class: HotUpdateRefusalClassV1::KeepLastGood,
            message: "staged evaluation threw".to_owned(),
        };
        assert_refused_receipt(
            rig.consumer.admit(&rig.surface, &envelope, &rig.payload),
            &receipt,
        );
        match rig
            .consumer
            .admit(&rig.surface, &different_envelope, &rig.payload)
        {
            HotUpdateAdmissionV1::IdentityConflict { class, .. } => {
                assert_eq!(class, HotUpdateRefusalClassV1::KeepLastGood);
            }
            other => panic!("expected terminal identity conflict, got {other:?}"),
        }
    }

    #[test]
    fn f9_different_id_and_host_driven_flights_are_unrecorded_busy_answers() {
        let mut rig = Rig::new("run-different-id-busy");
        let first_body = rig.body("first");
        let first_envelope = rig.signing.sign(&first_body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(
            &rig.surface,
            &first_envelope,
            &rig.payload,
        ));
        let (begun, settlement) = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .unwrap();
        let second_body = rig.body("second");
        let second_envelope = rig.signing.sign(&second_body).unwrap();
        assert!(matches!(
            rig.consumer
                .admit(&rig.surface, &second_envelope, &rig.payload),
            HotUpdateAdmissionV1::Busy { .. }
        ));
        assert!(!rig.consumer.replay.contains_key("second"));
        drop(begun);
        rig.consumer.settle_refused(
            settlement,
            HotUpdateRefusalClassV1::KeepLastGood,
            "test refusal",
        );
        let mut admitted = take_admitted(rig.consumer.admit(
            &rig.surface,
            &second_envelope,
            &rig.payload,
        ));
        admitted.consumed = true;

        let mut rig = Rig::new("run-host-busy");
        let coordinates = rig.surface.current_coordinates();
        let host_begun = rig
            .surface
            .begin(
                &rig.policy,
                HmrOrigin::Vite,
                coordinates,
                [rig.source_id.clone()],
            )
            .unwrap();
        let body = rig.body("host-busy");
        let envelope = rig.signing.sign(&body).unwrap();
        assert!(matches!(
            rig.consumer.admit(&rig.surface, &envelope, &rig.payload),
            HotUpdateAdmissionV1::Busy { .. }
        ));
        assert!(rig.consumer.replay.is_empty());
        drop(host_begun);
        let mut admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        admitted.consumed = true;
    }

    #[test]
    fn f9_identity_conflict_preserves_the_original_terminal_receipt() {
        let mut rig = Rig::new("run-identity-conflict");
        let body = rig.body("identity");
        let envelope = rig.signing.sign(&body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        let refusal = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                Vec::new(),
            )
            .err()
            .expect("empty invalidation must refuse");
        let original = HotUpdateOutcomeReceiptV1::Refused {
            class: refusal.class,
            message: refusal.message,
        };
        let mut different = body;
        different.issued_at_ms += 1;
        let different_envelope = rig.signing.sign(&different).unwrap();
        assert!(matches!(
            rig.consumer
                .admit(&rig.surface, &different_envelope, &rig.payload),
            HotUpdateAdmissionV1::IdentityConflict {
                class: HotUpdateRefusalClassV1::KeepLastGood,
                ..
            }
        ));
        assert_refused_receipt(
            rig.consumer.admit(&rig.surface, &envelope, &rig.payload),
            &original,
        );
    }

    #[test]
    fn f9_capacity_never_evicts_and_duplicates_still_replay() {
        assert_eq!(HOT_UPDATE_REPLAY_CAPACITY, 4096);
        let mut rig = Rig::new("run-capacity");
        rig.consumer = HotUpdateConsumerSessionV1::with_capacity(
            rig.signing.verifier(),
            expectations(rig.signing.run_id(), &rig.policy),
            2,
        );
        let before = rig.surface.current_coordinates();
        let mut first_envelope = None;
        for update_id in ["capacity-1", "capacity-2"] {
            let body = rig.body(update_id);
            let envelope = rig.signing.sign(&body).unwrap();
            let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
            rig.consumer
                .begin_admitted(
                    admitted,
                    &mut rig.surface,
                    &rig.policy,
                    HmrOrigin::Exact,
                    Vec::new(),
                )
                .err()
                .expect("empty invalidation must refuse");
            if first_envelope.is_none() {
                first_envelope = Some(envelope);
            }
        }
        assert_eq!(rig.consumer.terminal_count, 2);
        let new_body = rig.body("capacity-3");
        let new_envelope = rig.signing.sign(&new_body).unwrap();
        match rig
            .consumer
            .admit(&rig.surface, &new_envelope, &rig.payload)
        {
            HotUpdateAdmissionV1::CapacityRotationRequired { class, diagnostic } => {
                assert_eq!(class, HotUpdateRefusalClassV1::KeepLastGood);
                assert_eq!(
                    diagnostic,
                    "hot update replay table is at capacity; only producer runId rotation retires it"
                );
            }
            other => panic!("expected capacity answer, got {other:?}"),
        }
        assert!(!rig.consumer.replay.contains_key("capacity-3"));
        assert_eq!(rig.surface.current_coordinates(), before);
        assert!(matches!(
            rig.consumer
                .admit(&rig.surface, &first_envelope.unwrap(), &rig.payload),
            HotUpdateAdmissionV1::Duplicate { .. }
        ));
    }

    #[test]
    fn f9_quarantine_poison_precedes_pending_duplicate_and_rotation_retires_table() {
        let mut rig = Rig::new("run-before-rotation");
        let body = rig.body("stranded");
        let envelope = rig.signing.sign(&body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        let (begun, settlement) = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .unwrap();
        drop(begun);
        rig.consumer.settle_quarantined(settlement);
        assert!(rig.consumer.rotation_required());
        let later = rig.signing.sign(&rig.body("later")).unwrap();
        for candidate in [&envelope, &later] {
            match rig.consumer.admit(&rig.surface, candidate, &rig.payload) {
                HotUpdateAdmissionV1::RotationRequired { class, diagnostic } => {
                    assert_eq!(class, HotUpdateRefusalClassV1::KeepLastGood);
                    assert_eq!(diagnostic, ROTATION_REQUIRED_DIAGNOSTIC);
                }
                other => panic!("expected rotation gate, got {other:?}"),
            }
        }

        let mut rotated = Rig::new("run-after-rotation");
        assert!(matches!(
            rotated
                .consumer
                .admit(&rotated.surface, &envelope, &rotated.payload),
            HotUpdateAdmissionV1::Unauthenticated { .. }
        ));
        assert!(rotated.consumer.replay.is_empty());
        let fresh_body = rotated.body("stranded");
        let fresh_envelope = rotated.signing.sign(&fresh_body).unwrap();
        let mut admitted = take_admitted(rotated.consumer.admit(
            &rotated.surface,
            &fresh_envelope,
            &rotated.payload,
        ));
        admitted.consumed = true;
    }

    #[test]
    fn f9_dropped_linear_handles_fail_closed_into_rotation() {
        let mut rig = Rig::new("run-drop-admitted");
        let body = rig.body("drop-admitted");
        let envelope = rig.signing.sign(&body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        drop(admitted);
        assert!(rig.consumer.rotation_required());
        assert!(matches!(
            rig.consumer.admit(&rig.surface, &envelope, &rig.payload),
            HotUpdateAdmissionV1::RotationRequired {
                class: HotUpdateRefusalClassV1::KeepLastGood,
                ..
            }
        ));

        let mut rig = Rig::new("run-drop-settlement");
        let body = rig.body("drop-settlement");
        let envelope = rig.signing.sign(&body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        let (begun, settlement) = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .unwrap();
        drop(settlement);
        drop(begun);
        assert!(rig.consumer.rotation_required());
    }

    #[test]
    fn f9_foreign_session_handles_mutate_only_their_origin_via_drop() {
        let mut rig = Rig::new("run-foreign-admitted");
        let mut foreign_consumer = HotUpdateConsumerSessionV1::new(
            rig.signing.verifier(),
            expectations(rig.signing.run_id(), &rig.policy),
        );
        let body = rig.body("foreign-admitted");
        let envelope = rig.signing.sign(&body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        let refusal = foreign_consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .err()
            .expect("a foreign admitted handle must refuse");
        assert_eq!(refusal.class, HotUpdateRefusalClassV1::KeepLastGood);
        assert_eq!(
            refusal.message,
            "hot update admitted handle belongs to another consumer session"
        );
        assert!(foreign_consumer.replay.is_empty());
        assert!(foreign_consumer.pending_update.is_none());
        assert!(!foreign_consumer.rotation_required());
        assert!(matches!(
            rig.consumer.replay.get("foreign-admitted"),
            Some(ReplayEntry::Pending { .. })
        ));
        assert!(rig.consumer.rotation_required());
        assert!(!rig.surface.is_in_flight());

        let mut rig = Rig::new("run-foreign-settlement");
        let mut foreign_consumer = HotUpdateConsumerSessionV1::new(
            rig.signing.verifier(),
            expectations(rig.signing.run_id(), &rig.policy),
        );
        let body = rig.body("foreign-settlement");
        let envelope = rig.signing.sign(&body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        let (begun, settlement) = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .unwrap();
        foreign_consumer.settle_refused(
            settlement,
            HotUpdateRefusalClassV1::KeepLastGood,
            "foreign refusal",
        );
        assert!(foreign_consumer.replay.is_empty());
        assert!(foreign_consumer.pending_update.is_none());
        assert!(!foreign_consumer.rotation_required());
        assert!(matches!(
            rig.consumer.replay.get("foreign-settlement"),
            Some(ReplayEntry::Pending { .. })
        ));
        assert!(rig.consumer.rotation_required());
        drop(begun);
    }

    #[test]
    fn f9_quarantined_commit_mints_no_receipt_and_rotation_gate_governs() {
        let mut rig = Rig::new("run-quarantined-commit");
        let body = rig.body("quarantined-commit");
        let envelope = rig.signing.sign(&body).unwrap();
        let admitted = take_admitted(rig.consumer.admit(&rig.surface, &envelope, &rig.payload));
        let (begun, settlement) = rig
            .consumer
            .begin_admitted(
                admitted,
                &mut rig.surface,
                &rig.policy,
                HmrOrigin::Exact,
                vec![rig.source_id.clone()],
            )
            .unwrap();
        let replacement = artifact(rig.source_id.clone(), 2);
        let mut preflighted = begun
            .stage([record(&replacement)])
            .unwrap()
            .preflight(&rig.surface)
            .unwrap();
        let token = preflighted
            .shadow_publication_token(&rig.source_id)
            .unwrap();
        preflighted
            .shadow_publish(&token, GenerationPublicationKind::Evaluation)
            .unwrap();
        let ready = preflighted
            .evaluated()
            .unwrap()
            .prepare_activation(ActivationTokenV1::flip(|| {
                panic!("test activation quarantine")
            }))
            .ready();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = rig
                .consumer
                .commit_admitted(settlement, &mut rig.surface, &rig.policy, ready);
        }));
        assert!(panic.is_err());
        assert!(rig.consumer.rotation_required());
        assert!(matches!(
            rig.consumer.admit(&rig.surface, &envelope, &rig.payload),
            HotUpdateAdmissionV1::RotationRequired {
                class: HotUpdateRefusalClassV1::KeepLastGood,
                ..
            }
        ));
        assert!(matches!(
            rig.consumer.replay.get("quarantined-commit"),
            Some(ReplayEntry::Pending { .. })
        ));
    }

    #[test]
    fn signing_session_refuses_dishonest_or_oversize_bodies() {
        let rig = Rig::new("run-sign-refusal");
        let mut wrong_run = rig.body("wrong-run");
        wrong_run.run_id = "different-run".to_owned();
        assert!(rig.signing.sign(&wrong_run).is_err());

        let mut wrong_target = rig.body("wrong-target");
        wrong_target.target_hot_revision += 1;
        assert!(rig.signing.sign(&wrong_target).is_err());

        let mut oversize = rig.body("oversize");
        oversize.target_descriptor = "x".repeat(HOT_UPDATE_SIGNED_BODY_LIMIT);
        assert!(rig.signing.sign(&oversize).is_err());
        assert!(format!("{:?}", rig.signing).contains("key: <redacted>"));
    }

    #[test]
    fn tla_staged_replacement_requires_evaluation_and_top_level_await_receipts() {
        let source_id = source("tla-entry.mjs");
        let current_policy = policy();
        let boot = artifact(source_id.clone(), 1);
        let replacement = artifact_with_top_level_await(source_id.clone(), 2, true);
        let mut revision_surface = surface(&[boot], &current_policy);

        let mut missing_tla = preflighted(
            &mut revision_surface,
            &current_policy,
            &source_id,
            &replacement,
        );
        let token = missing_tla.shadow_publication_token(&source_id).unwrap();
        missing_tla
            .shadow_publish(&token, GenerationPublicationKind::Evaluation)
            .unwrap();
        assert_eq!(
            missing_tla
                .evaluated()
                .err()
                .expect("missing TLA receipt must refuse")
                .to_string(),
            "staged evaluation has not settled"
        );

        let mut settled = preflighted(
            &mut revision_surface,
            &current_policy,
            &source_id,
            &replacement,
        );
        let token = settled.shadow_publication_token(&source_id).unwrap();
        settled
            .shadow_publish(&token, GenerationPublicationKind::Evaluation)
            .unwrap();
        settled
            .shadow_publish(&token, GenerationPublicationKind::TopLevelAwait)
            .unwrap();
        drop(settled.evaluated().unwrap());
    }
}
