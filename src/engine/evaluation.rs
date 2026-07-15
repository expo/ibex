//! Typed values shared by the authenticated source-ingress and engine worker.
//!
//! This module deliberately contains no public constructor for a source
//! request or value handle. Operator source reaches the engine only after the
//! session ingress has consumed a linear submission credential, and engine
//! references are minted only by the owning runtime adapter.
//! @ref LLP 0024#1-the-in-memory-source-api — source is a closed sum whose
//! security-relevant fields are derived from an authenticated credential.

use std::fmt;
use std::num::NonZeroU64;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use capsec_semantics::model::{Digest, LogicalPath, Principal};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Version of the Rust/native structured-evaluation contract.
pub const STRUCTURED_EVALUATION_VERSION: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    Interactive,
    Transcript,
    Program,
    OneShot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainPolicy {
    ReadyWorkOnly,
    ToQuiescence,
}

impl ExecutionMode {
    pub const fn drain_policy(self) -> DrainPolicy {
        match self {
            Self::Interactive | Self::Transcript => DrainPolicy::ReadyWorkOnly,
            Self::Program | Self::OneShot => DrainPolicy::ToQuiescence,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File,
    Stdin,
    Repl,
    Eval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceGoal {
    ScriptWithExtensions,
    Module,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParserDialect {
    JavaScript,
    JavaScriptJsx,
    TypeScript,
    TypeScriptJsx,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceRole {
    Entry,
    Dependency,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleKind {
    Esm,
    CommonJs,
}

/// A strict UTF-8 source payload. Empty input is intentionally valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceText(Arc<str>);

impl SourceText {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SourceRefusal> {
        String::from_utf8(bytes)
            .map(|text| Self(Arc::from(text)))
            .map_err(|error| SourceRefusal::InvalidUtf8 {
                valid_up_to: error.utf8_error().valid_up_to(),
            })
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Synthetic display name used in errors and stack frames. It is never a
/// cache key or retained platform identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLabel(Arc<str>);

impl SourceLabel {
    /// Reconstitute a label from the checked native result ABI. Native may
    /// return only the authenticated label or a label from the generated
    /// source-map chain; the same empty/NUL invariant still applies here.
    /// @ref LLP 0024#2-source-identity-and-reserved-schemes
    pub(crate) fn from_native(label: Arc<str>) -> Result<Self, SourceRefusal> {
        if label.is_empty() || label.contains('\0') {
            return Err(SourceRefusal::InvalidSourceLabel);
        }
        Ok(Self(label))
    }

    pub fn repl(ordinal: NonZeroU64) -> Self {
        Self(Arc::from(format!("repl:{ordinal}")))
    }

    pub fn loaded(ordinal: NonZeroU64, virtual_path: &str) -> Result<Self, SourceRefusal> {
        if virtual_path.is_empty() || virtual_path.contains('\0') {
            return Err(SourceRefusal::InvalidSourceLabel);
        }
        Ok(Self(Arc::from(format!("repl:{ordinal}:{virtual_path}"))))
    }

    pub fn stdin() -> Self {
        Self(Arc::from("ibex:stdin"))
    }

    pub fn eval() -> Self {
        Self(Arc::from("ibex:eval"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SourceRefusal {
    #[error("source is not valid UTF-8 (valid prefix ends at byte {valid_up_to})")]
    InvalidUtf8 { valid_up_to: usize },
    #[error("source exceeds the authenticated input limit of {max_bytes} bytes")]
    InputTooLarge { max_bytes: usize },
    #[error("source label is empty or contains an embedded NUL")]
    InvalidSourceLabel,
    #[error("submission credential belongs to a different armed session")]
    WrongSession,
    #[error("submission form does not match the armed entry kind and execution mode")]
    WrongEntryRoute,
    #[error("submission ordinal is not the session's next ordinal")]
    WrongOrdinal,
    #[error("the session already has an unsettled evaluation")]
    EvaluationInFlight,
    #[error("the armed session already has an active submission sequencer")]
    SequenceAlreadyClaimed,
    #[error("the submission was not the session's pending native request")]
    SubmissionNotPending,
    #[error("the session exhausted its submission ordinal space")]
    OrdinalExhausted,
    #[error("loaded source must be minted through the generated .load classifier")]
    LoadedOriginRequiresClassifier,
    #[error("file source must be minted through the authenticated file-entry constructor")]
    FileOriginRequiresConstructor,
    #[error("the authenticated file entry has already been submitted")]
    FileEntryAlreadySubmitted,
    #[error(".load refuses module-kind-asserting extensions")]
    LoadModuleKindRefused,
    #[error(".load refuses type-only declaration files")]
    LoadTypesOnlyRefused,
    #[error(".load refuses unknown or extensionless source paths")]
    LoadUnsupportedPath,
    #[error("authenticated file entry identity is not a canonical virtual project file URL")]
    InvalidFileIdentity,
    #[error("the authenticated .js file kind was not resolved by the Host")]
    FileModuleKindUnauthenticated,
    #[error("direct CommonJS TypeScript execution is unavailable for .cts entries")]
    FileCommonJsUnsupported,
    #[error("direct bytecode execution requires authenticated original-source provenance")]
    FileBytecodeUnsupported,
    #[error("direct file execution refuses unsupported or extensionless source paths")]
    FileUnsupportedPath,
    #[error("program bytes were supplied for a JSON-data submission")]
    ExpectedJsonData,
    #[error("JSON bytes were supplied for a program submission")]
    ExpectedProgram,
}

/// Opaque authenticated session reference. It can be cloned for transfer to a
/// worker, but its fields and constructor remain crate-private.
#[derive(Clone)]
pub struct ArmedSessionToken(Arc<ArmedSessionIdentity>);

impl fmt::Debug for ArmedSessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArmedSessionToken(<opaque>)")
    }
}

#[derive(Debug)]
struct ArmedSessionIdentity {
    snapshot_digest: Digest,
    run_nonce: Arc<str>,
    root_principal: Principal,
    entry_kind: EntryKind,
    entry_identity: Arc<str>,
    mode: ExecutionMode,
    endowment_projection_digest: Digest,
    unforgeable_nonce: [u8; 32],
    submissions: Mutex<SubmissionState>,
}

#[derive(Debug)]
struct SubmissionState {
    next_ordinal: Option<NonZeroU64>,
    in_flight: Option<NonZeroU64>,
    active_sequence: Option<u64>,
    next_sequence_id: u64,
}

impl Default for SubmissionState {
    fn default() -> Self {
        Self {
            next_ordinal: Some(NonZeroU64::MIN),
            in_flight: None,
            active_sequence: None,
            next_sequence_id: 1,
        }
    }
}

impl Drop for ArmedSessionIdentity {
    fn drop(&mut self) {
        volatile_wipe(&mut self.unforgeable_nonce);
    }
}

impl ArmedSessionToken {
    /// Called only after the launcher has authenticated the immutable armed
    /// snapshot and derived (rather than accepted) the root/session fields.
    pub(crate) fn from_authenticated_snapshot(
        snapshot_digest: Digest,
        run_nonce: Arc<str>,
        root_principal: Principal,
        entry_kind: EntryKind,
        entry_identity: Arc<str>,
        mode: ExecutionMode,
        endowment_projection_digest: Digest,
    ) -> Result<Self, getrandom::Error> {
        let mut unforgeable_nonce = [0_u8; 32];
        loop {
            getrandom::getrandom(&mut unforgeable_nonce)?;
            if unforgeable_nonce.iter().any(|byte| *byte != 0) {
                break;
            }
        }
        Ok(Self(Arc::new(ArmedSessionIdentity {
            snapshot_digest,
            run_nonce,
            root_principal,
            entry_kind,
            entry_identity,
            mode,
            endowment_projection_digest,
            unforgeable_nonce,
            submissions: Mutex::new(SubmissionState::default()),
        })))
    }

    pub(crate) fn same_session(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Derive the module-cache identity for a session-owned synthetic module.
    /// The digest names this authenticated token instance, not merely the
    /// snapshot shared by multiple runtimes; the public source label remains a
    /// separate display value.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    fn synthetic_module_source_id(&self, source_identity: &str) -> crate::vfs::SourceId {
        let mut hash = Sha256::new();
        hash.update(b"ibex/synthetic-module-session/1\0");
        hash_field(&mut hash, self.0.snapshot_digest.as_str().as_bytes());
        hash_field(&mut hash, self.0.run_nonce.as_bytes());
        hash_field(&mut hash, &self.0.unforgeable_nonce);
        crate::vfs::SourceId::synthetic_module(digest_from_hash(hash), source_identity)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SourceShape {
    Program {
        goal: SourceGoal,
        dialect: ParserDialect,
        role: SourceRole,
        module_kind: Option<ModuleKind>,
        is_main: bool,
    },
    JsonData,
}

/// Fields fixed by the authenticated ingress before any source bytes are
/// accepted. This value has no public constructor.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedSubmission {
    session: ArmedSessionToken,
    label: SourceLabel,
    referrer: LogicalPath,
    shape: SourceShape,
    file_arguments: Option<Arc<[Arc<str>]>>,
    ordinal: NonZeroU64,
}

impl AuthenticatedSubmission {
    fn new(
        session: ArmedSessionToken,
        label: SourceLabel,
        referrer: LogicalPath,
        shape: SourceShape,
        file_arguments: Option<Arc<[Arc<str>]>>,
        ordinal: NonZeroU64,
    ) -> Self {
        Self {
            session,
            label,
            referrer,
            shape,
            file_arguments,
            ordinal,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum SubmissionOrigin {
    File { user_arguments: Arc<[Arc<str>]> },
    Repl,
    Loaded { virtual_path: Arc<str> },
    Stdin,
    Eval,
}

/// Serializes source submission for one session and assigns the source
/// ordinal. Minting is refused until the preceding request is settled.
#[derive(Debug)]
pub struct SubmissionSequence {
    session: ArmedSessionToken,
    sequence_id: u64,
}

impl SubmissionSequence {
    pub fn new(session: ArmedSessionToken) -> Result<Self, SourceRefusal> {
        let sequence_id = {
            let mut state = lock_submission_state(&session);
            if state.active_sequence.is_some() {
                return Err(SourceRefusal::SequenceAlreadyClaimed);
            }
            if state.in_flight.is_some() {
                return Err(SourceRefusal::EvaluationInFlight);
            }
            let sequence_id = state.next_sequence_id;
            state.next_sequence_id = state
                .next_sequence_id
                .checked_add(1)
                .ok_or(SourceRefusal::OrdinalExhausted)?;
            state.active_sequence = Some(sequence_id);
            sequence_id
        };
        Ok(Self {
            session,
            sequence_id,
        })
    }

    #[cfg(test)]
    pub(crate) fn mint(
        &mut self,
        origin: SubmissionOrigin,
        referrer: LogicalPath,
        shape: SourceShape,
    ) -> Result<MintedSubmission, SourceRefusal> {
        match &origin {
            SubmissionOrigin::Loaded { .. } => {
                return Err(SourceRefusal::LoadedOriginRequiresClassifier)
            }
            SubmissionOrigin::File { .. } => {
                return Err(SourceRefusal::FileOriginRequiresConstructor)
            }
            SubmissionOrigin::Repl | SubmissionOrigin::Stdin | SubmissionOrigin::Eval => {}
        }
        self.mint_derived(origin, referrer, shape)
    }

    /// Mint one prompt submission with the fixed Script+extensions contract.
    /// The binary ingress supplies only the authenticated referrer; it cannot
    /// choose a parser goal, dialect, role, or module shape.
    pub fn mint_repl(&mut self, referrer: LogicalPath) -> Result<MintedSubmission, SourceRefusal> {
        self.require_route(
            EntryKind::Repl,
            &[ExecutionMode::Interactive, ExecutionMode::Transcript],
        )?;
        self.mint_derived(
            SubmissionOrigin::Repl,
            referrer,
            SourceShape::Program {
                goal: SourceGoal::ScriptWithExtensions,
                dialect: ParserDialect::TypeScript,
                role: SourceRole::Entry,
                module_kind: None,
                is_main: false,
            },
        )
    }

    /// Mint one authenticated one-shot (`-e`, `-p`, or `ibex eval`) source.
    /// The launcher supplies only the already-authenticated project referrer;
    /// the Script+extensions goal and every other execution-shape field are
    /// fixed here so a CLI spelling cannot reopen the bare evaluator.
    /// @ref LLP 0024#3-source-goal
    pub fn mint_eval(&mut self, referrer: LogicalPath) -> Result<MintedSubmission, SourceRefusal> {
        self.require_route(EntryKind::Eval, &[ExecutionMode::OneShot])?;
        self.mint_derived(
            SubmissionOrigin::Eval,
            referrer,
            SourceShape::Program {
                goal: SourceGoal::ScriptWithExtensions,
                dialect: ParserDialect::TypeScript,
                role: SourceRole::Entry,
                module_kind: None,
                is_main: false,
            },
        )
    }

    /// Mint the single program-stdin main module. Unlike REPL and one-shot
    /// source, `ibex:stdin` is an ESM-shaped module entry and owns the main
    /// module facts. The closed constructor prevents piped bytes from choosing
    /// their source identity or shaping authority-bearing request metadata.
    /// @ref LLP 0024#3-source-goal
    pub fn mint_stdin(&mut self, referrer: LogicalPath) -> Result<MintedSubmission, SourceRefusal> {
        self.require_route(EntryKind::Stdin, &[ExecutionMode::Program])?;
        self.mint_derived(
            SubmissionOrigin::Stdin,
            referrer,
            SourceShape::Program {
                goal: SourceGoal::Module,
                dialect: ParserDialect::TypeScript,
                role: SourceRole::Entry,
                module_kind: Some(ModuleKind::Esm),
                is_main: true,
            },
        )
    }

    /// Mint `.load` source only after the generated runtime-surface authority
    /// derives its closed source shape from the virtual path. Callers cannot
    /// select a dialect or relabel JSON as executable source.
    pub fn mint_load(
        &mut self,
        virtual_path: Arc<str>,
        referrer: LogicalPath,
    ) -> Result<MintedSubmission, SourceRefusal> {
        self.require_route(
            EntryKind::Repl,
            &[ExecutionMode::Interactive, ExecutionMode::Transcript],
        )?;
        let shape = canonical_load_shape(&virtual_path)?;
        self.mint_derived(SubmissionOrigin::Loaded { virtual_path }, referrer, shape)
    }

    /// Mint the one authenticated direct-file main module. Its source label,
    /// dialect, goal, module kind, main flag, and virtual argv entry are all
    /// derived from the digest-bound armed entry identity. Only the trailing
    /// user arguments remain operator data.
    ///
    /// A `.js` entry remains kind-pending until the Host resolves its
    /// authenticated package/module metadata after the typed read. CommonJS
    /// and JSON otherwise retain distinct closed shapes; neither can fall back
    /// to a bare evaluator or a mutable `require` wrapper.
    /// @ref LLP 0022#1-session-execution-ingress-and-the-capability-registry
    /// @ref LLP 0023#6-path-bearing-observables
    /// @ref LLP 0024#1-the-in-memory-source-api
    pub fn mint_file(
        &mut self,
        referrer: LogicalPath,
        user_arguments: &[String],
    ) -> Result<MintedSubmission, SourceRefusal> {
        self.require_route(EntryKind::File, &[ExecutionMode::Program])?;
        // A direct file entry is the session's one main program, not a prompt
        // sequence. Abandoning a request before native admission leaves the
        // ordinal pending and is retryable; once admission consumes ordinal 1,
        // no fresh ingress or sequencer may execute the main a second time.
        if lock_submission_state(&self.session).next_ordinal != Some(NonZeroU64::MIN) {
            return Err(SourceRefusal::FileEntryAlreadySubmitted);
        }
        let virtual_path = virtual_path_from_file_identity(&self.session.0.entry_identity)?;
        let shape = canonical_file_shape(&virtual_path)?;
        let user_arguments = user_arguments
            .iter()
            .map(|argument| Arc::<str>::from(argument.as_str()))
            .collect::<Vec<_>>();
        if user_arguments
            .iter()
            .any(|argument| argument.as_bytes().contains(&0))
        {
            return Err(SourceRefusal::InvalidFileIdentity);
        }
        self.mint_derived(
            SubmissionOrigin::File {
                user_arguments: user_arguments.into(),
            },
            referrer,
            shape,
        )
    }

    fn require_route(
        &self,
        entry_kind: EntryKind,
        modes: &[ExecutionMode],
    ) -> Result<(), SourceRefusal> {
        if self.session.0.entry_kind != entry_kind || !modes.contains(&self.session.0.mode) {
            return Err(SourceRefusal::WrongEntryRoute);
        }
        Ok(())
    }

    fn mint_derived(
        &mut self,
        origin: SubmissionOrigin,
        referrer: LogicalPath,
        shape: SourceShape,
    ) -> Result<MintedSubmission, SourceRefusal> {
        let mut state = lock_submission_state(&self.session);
        if state.active_sequence != Some(self.sequence_id) {
            return Err(SourceRefusal::SequenceAlreadyClaimed);
        }
        if state.in_flight.is_some() {
            return Err(SourceRefusal::EvaluationInFlight);
        }
        let ordinal = state.next_ordinal.ok_or(SourceRefusal::OrdinalExhausted)?;
        let (label, file_arguments) = match origin {
            SubmissionOrigin::File { user_arguments } => {
                let virtual_path = virtual_path_from_file_identity(&self.session.0.entry_identity)?;
                let mut arguments = Vec::with_capacity(user_arguments.len() + 2);
                arguments.push(Arc::<str>::from("ibex:runtime"));
                arguments.push(virtual_path);
                arguments.extend(user_arguments.iter().cloned());
                (
                    SourceLabel(self.session.0.entry_identity.clone()),
                    Some(arguments.into()),
                )
            }
            SubmissionOrigin::Repl => (SourceLabel::repl(ordinal), None),
            SubmissionOrigin::Loaded { virtual_path } => {
                (SourceLabel::loaded(ordinal, &virtual_path)?, None)
            }
            SubmissionOrigin::Stdin => (SourceLabel::stdin(), None),
            SubmissionOrigin::Eval => (SourceLabel::eval(), None),
        };
        state.in_flight = Some(ordinal);
        drop(state);
        Ok(MintedSubmission::new(
            AuthenticatedSubmission::new(
                self.session.clone(),
                label,
                referrer,
                shape,
                file_arguments,
                ordinal,
            ),
            SubmissionPermit::new(self.session.clone(), ordinal),
        ))
    }
}

fn virtual_path_from_file_identity(identity: &str) -> Result<Arc<str>, SourceRefusal> {
    let encoded = identity
        .strip_prefix("file://")
        .filter(|path| path.starts_with("/project/"))
        .ok_or(SourceRefusal::InvalidFileIdentity)?;
    if encoded.contains(['\0', '\\', '?', '#']) || encoded.ends_with('/') {
        return Err(SourceRefusal::InvalidFileIdentity);
    }
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let high = bytes
            .get(index + 1)
            .and_then(|byte| hex_value(*byte))
            .ok_or(SourceRefusal::InvalidFileIdentity)?;
        let low = bytes
            .get(index + 2)
            .and_then(|byte| hex_value(*byte))
            .ok_or(SourceRefusal::InvalidFileIdentity)?;
        let value = (high << 4) | low;
        if matches!(value, 0 | b'/') {
            return Err(SourceRefusal::InvalidFileIdentity);
        }
        decoded.push(value);
        index += 3;
    }
    let decoded = String::from_utf8(decoded).map_err(|_| SourceRefusal::InvalidFileIdentity)?;
    if decoded
        .split('/')
        .skip(1)
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(SourceRefusal::InvalidFileIdentity);
    }
    Ok(Arc::from(decoded))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn canonical_file_shape(virtual_path: &str) -> Result<SourceShape, SourceRefusal> {
    let name = virtual_path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or(SourceRefusal::FileUnsupportedPath)?;
    if name.to_ascii_lowercase().ends_with(".d.ts") {
        return Err(SourceRefusal::FileUnsupportedPath);
    }
    let extension = name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .ok_or(SourceRefusal::FileUnsupportedPath)?;
    if extension == "json" {
        return Ok(SourceShape::JsonData);
    }
    if extension == "cjs" {
        return Ok(SourceShape::Program {
            goal: SourceGoal::ScriptWithExtensions,
            dialect: ParserDialect::JavaScript,
            role: SourceRole::Entry,
            module_kind: Some(ModuleKind::CommonJs),
            is_main: true,
        });
    }
    // `.js` dialect is fixed by its extension, while its module kind is fixed
    // only by authenticated resolver/package metadata. `None` is an internal
    // pending marker: `ImmutableByteCapsule::into_request` refuses it unless
    // the Host replaces it after the typed read.
    if extension == "js" {
        return Ok(SourceShape::Program {
            goal: SourceGoal::Module,
            dialect: ParserDialect::JavaScript,
            role: SourceRole::Entry,
            module_kind: None,
            is_main: true,
        });
    }
    let dialect = match extension.as_str() {
        "mjs" => ParserDialect::JavaScript,
        "mts" | "ts" => ParserDialect::TypeScript,
        "tsx" => ParserDialect::TypeScriptJsx,
        "jsx" => ParserDialect::JavaScriptJsx,
        "cts" => return Err(SourceRefusal::FileCommonJsUnsupported),
        "hbc" => return Err(SourceRefusal::FileBytecodeUnsupported),
        _ => return Err(SourceRefusal::FileUnsupportedPath),
    };
    Ok(SourceShape::Program {
        goal: SourceGoal::Module,
        dialect,
        role: SourceRole::Entry,
        module_kind: Some(ModuleKind::Esm),
        is_main: true,
    })
}

fn authenticated_javascript_file_shape(
    virtual_path: &str,
    module_kind: ModuleKind,
) -> Result<SourceShape, SourceRefusal> {
    let pending = canonical_file_shape(virtual_path)?;
    if !matches!(
        pending,
        SourceShape::Program {
            goal: SourceGoal::Module,
            dialect: ParserDialect::JavaScript,
            role: SourceRole::Entry,
            module_kind: None,
            is_main: true,
        }
    ) {
        return Err(SourceRefusal::FileModuleKindUnauthenticated);
    }
    Ok(SourceShape::Program {
        goal: match module_kind {
            ModuleKind::Esm => SourceGoal::Module,
            ModuleKind::CommonJs => SourceGoal::ScriptWithExtensions,
        },
        dialect: ParserDialect::JavaScript,
        role: SourceRole::Entry,
        module_kind: Some(module_kind),
        is_main: true,
    })
}

fn canonical_load_shape(virtual_path: &str) -> Result<SourceShape, SourceRefusal> {
    use crate::repl_surface::{LoadDisposition, ParserDialect as GeneratedDialect};

    match crate::repl_surface::classify_load_path(virtual_path) {
        LoadDisposition::Script(dialect) => Ok(SourceShape::Program {
            goal: SourceGoal::ScriptWithExtensions,
            dialect: match dialect {
                GeneratedDialect::JavaScript => ParserDialect::JavaScript,
                GeneratedDialect::JavaScriptJsx => ParserDialect::JavaScriptJsx,
                GeneratedDialect::TypeScript => ParserDialect::TypeScript,
                GeneratedDialect::TypeScriptJsx => ParserDialect::TypeScriptJsx,
                GeneratedDialect::Json => return Err(SourceRefusal::ExpectedJsonData),
            },
            role: SourceRole::Entry,
            module_kind: None,
            is_main: false,
        }),
        LoadDisposition::JsonData => Ok(SourceShape::JsonData),
        LoadDisposition::RefuseModuleKind => Err(SourceRefusal::LoadModuleKindRefused),
        LoadDisposition::RefuseTypesOnly => Err(SourceRefusal::LoadTypesOnlyRefused),
        LoadDisposition::RefuseUnknownOrExtensionless => Err(SourceRefusal::LoadUnsupportedPath),
    }
}

impl Drop for SubmissionSequence {
    fn drop(&mut self) {
        let mut state = lock_submission_state(&self.session);
        if state.active_sequence == Some(self.sequence_id) {
            state.active_sequence = None;
        }
    }
}

fn lock_submission_state(
    session: &ArmedSessionToken,
) -> std::sync::MutexGuard<'_, SubmissionState> {
    match session.0.submissions.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct SubmissionPermit {
    session: ArmedSessionToken,
    ordinal: NonZeroU64,
    accepted: bool,
}

impl fmt::Debug for SubmissionPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubmissionPermit")
            .field("ordinal", &self.ordinal)
            .field("accepted", &self.accepted)
            .finish_non_exhaustive()
    }
}

impl SubmissionPermit {
    fn new(session: ArmedSessionToken, ordinal: NonZeroU64) -> Self {
        Self {
            session,
            ordinal,
            accepted: false,
        }
    }

    fn accept(&mut self) -> Result<(), SourceRefusal> {
        if self.accepted {
            return Err(SourceRefusal::SubmissionNotPending);
        }
        let mut state = lock_submission_state(&self.session);
        if state.in_flight != Some(self.ordinal) || state.next_ordinal != Some(self.ordinal) {
            return Err(SourceRefusal::SubmissionNotPending);
        }
        state.in_flight = None;
        state.next_ordinal = self.ordinal.get().checked_add(1).and_then(NonZeroU64::new);
        self.accepted = true;
        Ok(())
    }
}

impl Drop for SubmissionPermit {
    fn drop(&mut self) {
        if self.accepted {
            return;
        }
        let mut state = lock_submission_state(&self.session);
        if state.in_flight == Some(self.ordinal) && state.next_ordinal == Some(self.ordinal) {
            state.in_flight = None;
        }
    }
}

/// A linear credential can move only forward through these concrete states.
/// None implements `Clone` or serialization.
#[derive(Debug)]
pub struct MintedSubmission {
    submission: AuthenticatedSubmission,
    permit: SubmissionPermit,
}

#[derive(Debug)]
pub struct ReadAuthorizedSubmission {
    submission: AuthenticatedSubmission,
    permit: SubmissionPermit,
    read_evidence: ReadEvidence,
}

#[derive(Debug)]
enum ReadEvidence {
    Inline,
    TypedRead(Digest),
}

#[derive(Debug)]
pub struct ImmutableByteCapsule {
    submission: AuthenticatedSubmission,
    permit: SubmissionPermit,
    read_evidence: ReadEvidence,
    source_id: Option<crate::vfs::SourceId>,
    bytes_digest: Digest,
    bytes: Vec<u8>,
}

impl MintedSubmission {
    fn new(submission: AuthenticatedSubmission, permit: SubmissionPermit) -> Self {
        Self { submission, permit }
    }

    /// Captured logical base which the typed-read adapter must match before it
    /// authorizes bytes for this submission.
    pub(crate) fn logical_referrer(&self) -> &LogicalPath {
        &self.submission.referrer
    }

    /// Authenticate the still-linear submission against the exact cached Host
    /// session identity before any typed read decision or object lookup.
    pub(crate) fn authenticates_for(&self, session: &ArmedSessionToken) -> bool {
        self.submission.session.same_session(session)
    }

    /// Defense-in-depth for the Host trust boundary: verify both the generated
    /// shape and the exact loaded label before any typed decision or lookup.
    pub(crate) fn is_canonical_load_for(&self, virtual_path: &str) -> bool {
        let Ok(shape) = canonical_load_shape(virtual_path) else {
            return false;
        };
        let Ok(label) = SourceLabel::loaded(self.submission.ordinal, virtual_path) else {
            return false;
        };
        self.submission.shape == shape && self.submission.label == label
    }

    /// Defense-in-depth for a direct file read: the VFS's canonical virtual
    /// spelling must be exactly the file identity authenticated into the armed
    /// snapshot, and the submission must carry the one closed file shape and
    /// argv projection derived from that identity.
    pub(crate) fn is_canonical_file_for(&self, virtual_path: &str, source_label: &str) -> bool {
        if self.submission.session.0.entry_kind != EntryKind::File
            || self.submission.session.0.mode != ExecutionMode::Program
            || self.submission.session.0.entry_identity.as_ref() != source_label
            || self.submission.label.as_str() != source_label
        {
            return false;
        }
        let Ok(expected_virtual_path) =
            virtual_path_from_file_identity(&self.submission.session.0.entry_identity)
        else {
            return false;
        };
        if expected_virtual_path.as_ref() != virtual_path {
            return false;
        }
        let Ok(shape) = canonical_file_shape(virtual_path) else {
            return false;
        };
        let Some(arguments) = self.submission.file_arguments.as_deref() else {
            return false;
        };
        self.submission.shape == shape
            && arguments.len() >= 2
            && arguments[0].as_ref() == "ibex:runtime"
            && arguments[1].as_ref() == virtual_path
    }

    pub(crate) fn awaits_authenticated_file_module_kind(&self) -> bool {
        matches!(
            self.submission.shape,
            SourceShape::Program {
                goal: SourceGoal::Module,
                dialect: ParserDialect::JavaScript,
                role: SourceRole::Entry,
                module_kind: None,
                is_main: true,
            }
        ) && self.submission.session.0.entry_kind == EntryKind::File
            && self.submission.session.0.mode == ExecutionMode::Program
    }

    /// Replace the requested base with the authenticated final-object base
    /// returned by the typed VFS read. This is deliberately crate-private and
    /// consuming: only the Host's post-read seam can advance the still-linear
    /// submission, and the credential binding is computed later from this
    /// retained identity when the immutable byte capsule is closed.
    /// @ref LLP 0023#73-referrer-capture — a contained
    /// symlink resolves relative imports from its authenticated final object,
    /// not from the requested directory entry.
    pub(crate) fn with_authenticated_referrer(mut self, referrer: LogicalPath) -> Self {
        self.submission.referrer = referrer;
        self
    }

    /// Replace the requested file spelling with the authenticated final-entry
    /// source identity returned by the VFS read. This is the only route by
    /// which a symlinked direct entry can acquire its physical target's
    /// `SourceLabel`; argv keeps the operator's virtual entry spelling.
    ///
    /// The consuming, crate-private seam also re-derives dialect/kind-pending
    /// shape from the authenticated final filename so an alias cannot select a
    /// grammar independently of the source it ultimately executes.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    pub(crate) fn with_authenticated_file_source(
        mut self,
        virtual_path: &str,
        source_label: &str,
    ) -> Result<Self, SourceRefusal> {
        if self.submission.session.0.entry_kind != EntryKind::File
            || self.submission.session.0.mode != ExecutionMode::Program
            || !source_label.starts_with("file:///project/")
            || source_label
                .chars()
                .any(|character| matches!(character, '\0' | '?' | '#'))
        {
            return Err(SourceRefusal::WrongEntryRoute);
        }
        self.submission.shape = canonical_file_shape(virtual_path)?;
        self.submission.label = SourceLabel::from_native(Arc::from(source_label))?;
        Ok(self)
    }

    /// Close the one pending `.js` file shape with the module kind returned by
    /// the Host's authenticated resolver. The consuming, crate-private method
    /// keeps operator code from selecting ESM versus CommonJS and ensures the
    /// final kind participates in the request credential binding.
    /// @ref LLP 0024#4-grammar-selection
    pub(crate) fn with_authenticated_file_module_kind(
        mut self,
        module_kind: ModuleKind,
    ) -> Result<Self, SourceRefusal> {
        if self.submission.session.0.entry_kind != EntryKind::File
            || self.submission.session.0.mode != ExecutionMode::Program
        {
            return Err(SourceRefusal::WrongEntryRoute);
        }
        let virtual_path =
            virtual_path_from_file_identity(&self.submission.session.0.entry_identity)?;
        let pending = canonical_file_shape(&virtual_path)?;
        if self.submission.shape != pending {
            return Err(SourceRefusal::FileModuleKindUnauthenticated);
        }
        self.submission.shape = authenticated_javascript_file_shape(&virtual_path, module_kind)?;
        Ok(self)
    }

    pub fn authorize_inline(self) -> ReadAuthorizedSubmission {
        ReadAuthorizedSubmission {
            submission: self.submission,
            permit: self.permit,
            read_evidence: ReadEvidence::Inline,
        }
    }

    pub fn authorize_typed_read(self, evidence: Digest) -> ReadAuthorizedSubmission {
        ReadAuthorizedSubmission {
            submission: self.submission,
            permit: self.permit,
            read_evidence: ReadEvidence::TypedRead(evidence),
        }
    }
}

impl ReadAuthorizedSubmission {
    pub fn bind_bytes(self, bytes: Vec<u8>) -> ImmutableByteCapsule {
        self.bind_bytes_with_source_id(bytes, None)
    }

    /// Bind a typed module identity to the exact authenticated read. This is
    /// crate-private so inline callers cannot label arbitrary bytes as a VFS
    /// module; only the Host's post-read file seam can supply the `SourceId`.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    pub(crate) fn bind_module_bytes(
        self,
        bytes: Vec<u8>,
        source_id: crate::vfs::SourceId,
    ) -> ImmutableByteCapsule {
        self.bind_bytes_with_source_id(bytes, Some(source_id))
    }

    fn bind_bytes_with_source_id(
        self,
        bytes: Vec<u8>,
        source_id: Option<crate::vfs::SourceId>,
    ) -> ImmutableByteCapsule {
        // Program stdin is the sole synthetic module in the structured source
        // surface. Prompt, `.load`, and one-shot sources are scripts and must
        // continue to have no module-cache identity.
        let source_id = source_id.or_else(|| {
            (self.submission.session.0.entry_kind == EntryKind::Stdin
                && self.submission.label.as_str() == "ibex:stdin"
                && matches!(
                    &self.submission.shape,
                    SourceShape::Program {
                        goal: SourceGoal::Module,
                        role: SourceRole::Entry,
                        module_kind: Some(ModuleKind::Esm),
                        is_main: true,
                        ..
                    }
                ))
            .then(|| {
                self.submission
                    .session
                    .synthetic_module_source_id("ibex:stdin")
            })
        });
        ImmutableByteCapsule {
            submission: self.submission,
            permit: self.permit,
            read_evidence: self.read_evidence,
            source_id,
            bytes_digest: sha256_digest(&bytes),
            bytes,
        }
    }
}

/// Engine-ready request. Constructing one consumes the immutable byte capsule;
/// evaluating it consumes the request, completing the credential lifecycle.
#[derive(Debug)]
pub enum SourceRequest {
    Program(ProgramSourceRequest),
    JsonData(JsonDataRequest),
}

#[derive(Debug)]
pub struct ProgramSourceRequest {
    common: RequestCommon,
    text: SourceText,
    goal: SourceGoal,
    dialect: ParserDialect,
    role: SourceRole,
    module_kind: Option<ModuleKind>,
    is_main: bool,
}

#[derive(Debug)]
pub struct JsonDataRequest {
    common: RequestCommon,
    text: SourceText,
}

#[derive(Debug)]
struct RequestCommon {
    session: ArmedSessionToken,
    label: SourceLabel,
    referrer: LogicalPath,
    file_arguments: Option<Arc<[Arc<str>]>>,
    ordinal: NonZeroU64,
    bytes_digest: Digest,
    read_evidence: ReadEvidence,
    source_id: Option<crate::vfs::SourceId>,
    credential_binding: RequestBinding,
    permit: SubmissionPermit,
}

/// Raw credential material retained for the authenticated native call. This
/// type is intentionally private, non-serializable, and opaque under `Debug`.
#[derive(Eq, PartialEq)]
struct RequestBinding([u8; 32]);

impl Drop for RequestBinding {
    fn drop(&mut self) {
        volatile_wipe(&mut self.0);
    }
}

impl fmt::Debug for RequestBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestBinding(<opaque>)")
    }
}

/// Borrowed credential fields for the native evaluator. The only constructor
/// is [`SourceRequest::native_credential_for`], which authenticates the closed
/// request before exposing any bytes.
/// @ref LLP 0024#1-the-in-memory-source-api — native evaluation receives the
/// opaque session/submission credential only after the closed request verifies.
pub(crate) struct NativeCredentialView<'a> {
    session_nonce: &'a [u8; 32],
    request_binding: &'a [u8; 32],
    ordinal: NonZeroU64,
}

impl fmt::Debug for NativeCredentialView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeCredentialView(<opaque>)")
    }
}

impl NativeCredentialView<'_> {
    pub(crate) fn session_nonce(&self) -> &[u8; 32] {
        self.session_nonce
    }

    pub(crate) fn request_binding(&self) -> &[u8; 32] {
        self.request_binding
    }

    pub(crate) fn ordinal(&self) -> NonZeroU64 {
        self.ordinal
    }
}

impl ImmutableByteCapsule {
    pub fn into_request(self) -> Result<SourceRequest, SourceRefusal> {
        let text = SourceText::from_bytes(self.bytes)?;
        if self.submission.session.0.entry_kind == EntryKind::File && self.source_id.is_none() {
            return Err(SourceRefusal::FileOriginRequiresConstructor);
        }
        if self.submission.session.0.entry_kind == EntryKind::File
            && matches!(
                self.submission.shape,
                SourceShape::Program {
                    module_kind: None,
                    ..
                }
            )
        {
            return Err(SourceRefusal::FileModuleKindUnauthenticated);
        }
        let credential_binding = credential_binding(
            &self.submission,
            &self.read_evidence,
            self.source_id.as_ref(),
            &self.bytes_digest,
        );
        let common = RequestCommon {
            session: self.submission.session,
            label: self.submission.label,
            referrer: self.submission.referrer,
            file_arguments: self.submission.file_arguments,
            ordinal: self.submission.ordinal,
            bytes_digest: self.bytes_digest,
            read_evidence: self.read_evidence,
            source_id: self.source_id,
            credential_binding,
            permit: self.permit,
        };
        Ok(match self.submission.shape {
            SourceShape::Program {
                goal,
                dialect,
                role,
                module_kind,
                is_main,
            } => SourceRequest::Program(ProgramSourceRequest {
                common,
                text,
                goal,
                dialect,
                role,
                module_kind,
                is_main,
            }),
            SourceShape::JsonData => SourceRequest::JsonData(JsonDataRequest { common, text }),
        })
    }
}

impl SourceRequest {
    pub fn source_label(&self) -> &SourceLabel {
        &self.common().label
    }

    pub fn virtual_referrer(&self) -> &LogicalPath {
        &self.common().referrer
    }

    pub fn submission_ordinal(&self) -> NonZeroU64 {
        self.common().ordinal
    }

    pub fn source_digest(&self) -> &Digest {
        &self.common().bytes_digest
    }

    /// Authenticated module-cache identity, when this request is a typed VFS
    /// module entry. Script inputs deliberately return `None`.
    pub fn source_id(&self) -> Option<&crate::vfs::SourceId> {
        self.common().source_id.as_ref()
    }

    pub fn execution_mode(&self) -> ExecutionMode {
        self.common().session.0.mode
    }

    pub fn entry_kind(&self) -> EntryKind {
        self.common().session.0.entry_kind
    }

    pub fn authenticated_principal(&self) -> &Principal {
        &self.common().session.0.root_principal
    }

    /// Virtualized file-mode argv bound into the authenticated request. The
    /// first two elements are fixed (`ibex:runtime`, virtual entry spelling);
    /// only trailing elements originate as operator data. Other entry kinds
    /// have no file argv projection.
    pub(crate) fn file_arguments(&self) -> Option<&[Arc<str>]> {
        self.common().file_arguments.as_deref()
    }

    /// Canonical virtual spelling selected for the authenticated file entry.
    /// This is an observable (`process.argv[1]`, `__filename`), not a backing
    /// path or cache identity, and is exposed without the remaining argv data.
    pub fn authenticated_file_virtual_path(&self) -> Option<&str> {
        self.common()
            .file_arguments
            .as_deref()
            .and_then(|arguments| arguments.get(1))
            .map(AsRef::as_ref)
    }

    pub fn text(&self) -> &SourceText {
        match self {
            Self::Program(request) => &request.text,
            Self::JsonData(request) => &request.text,
        }
    }

    pub(crate) fn authenticates_for(&self, session: &ArmedSessionToken) -> bool {
        let common = self.common();
        let actual_bytes_digest = sha256_digest(self.text().as_bytes());
        common.session.same_session(session)
            && common.bytes_digest == actual_bytes_digest
            && common.credential_binding
                == credential_binding_from_request(self, &actual_bytes_digest)
    }

    pub(crate) fn native_credential_for<'a>(
        &'a self,
        session: &ArmedSessionToken,
    ) -> Option<NativeCredentialView<'a>> {
        if !self.authenticates_for(session) {
            return None;
        }
        let common = self.common();
        Some(NativeCredentialView {
            session_nonce: &common.session.0.unforgeable_nonce,
            request_binding: &common.credential_binding.0,
            ordinal: common.ordinal,
        })
    }

    /// Mark the exact pending ordinal consumed after native admission publishes
    /// a work target. Typed read, UTF-8, shape, and authentication refusals occur
    /// before this boundary; syntax/lowering and JSON parsing occur after it, so
    /// their recoverable failures still advance the submitted source ordinal.
    pub(crate) fn mark_native_accepted(&mut self) -> Result<(), SourceRefusal> {
        self.common_mut().permit.accept()
    }

    fn common(&self) -> &RequestCommon {
        match self {
            Self::Program(request) => &request.common,
            Self::JsonData(request) => &request.common,
        }
    }

    fn common_mut(&mut self) -> &mut RequestCommon {
        match self {
            Self::Program(request) => &mut request.common,
            Self::JsonData(request) => &mut request.common,
        }
    }
}

impl ProgramSourceRequest {
    pub fn goal(&self) -> SourceGoal {
        self.goal
    }

    pub fn dialect(&self) -> ParserDialect {
        self.dialect
    }

    pub fn role(&self) -> SourceRole {
        self.role
    }

    pub fn module_kind(&self) -> Option<ModuleKind> {
        self.module_kind
    }

    pub fn is_main(&self) -> bool {
        self.is_main
    }

    pub(crate) fn authenticated_file_virtual_path(&self) -> Option<&str> {
        self.common
            .file_arguments
            .as_deref()
            .and_then(|arguments| arguments.get(1))
            .map(AsRef::as_ref)
    }
}

fn credential_binding_from_request(
    request: &SourceRequest,
    bytes_digest: &Digest,
) -> RequestBinding {
    let common = request.common();
    let shape = match request {
        SourceRequest::Program(program) => SourceShape::Program {
            goal: program.goal,
            dialect: program.dialect,
            role: program.role,
            module_kind: program.module_kind,
            is_main: program.is_main,
        },
        SourceRequest::JsonData(_) => SourceShape::JsonData,
    };
    let submission = AuthenticatedSubmission {
        session: common.session.clone(),
        label: common.label.clone(),
        referrer: common.referrer.clone(),
        shape,
        file_arguments: common.file_arguments.clone(),
        ordinal: common.ordinal,
    };
    credential_binding(
        &submission,
        &common.read_evidence,
        common.source_id.as_ref(),
        bytes_digest,
    )
}

fn credential_binding(
    submission: &AuthenticatedSubmission,
    read_evidence: &ReadEvidence,
    source_id: Option<&crate::vfs::SourceId>,
    bytes_digest: &Digest,
) -> RequestBinding {
    let mut hash = Sha256::new();
    hash.update(b"ibex/structured-submission/1\0");
    hash_field(&mut hash, &submission.session.0.unforgeable_nonce);
    hash_field(
        &mut hash,
        submission.session.0.snapshot_digest.as_str().as_bytes(),
    );
    hash_field(&mut hash, submission.session.0.run_nonce.as_bytes());
    hash_field(
        &mut hash,
        submission
            .session
            .0
            .endowment_projection_digest
            .as_str()
            .as_bytes(),
    );
    hash_field(
        &mut hash,
        &serde_json::to_vec(&submission.session.0.root_principal)
            .expect("authenticated principal is serializable"),
    );
    hash_field(
        &mut hash,
        match submission.session.0.entry_kind {
            EntryKind::File => b"file",
            EntryKind::Stdin => b"stdin",
            EntryKind::Repl => b"repl",
            EntryKind::Eval => b"eval",
        },
    );
    hash_field(&mut hash, submission.session.0.entry_identity.as_bytes());
    hash_field(
        &mut hash,
        match submission.session.0.mode {
            ExecutionMode::Interactive => b"interactive",
            ExecutionMode::Transcript => b"transcript",
            ExecutionMode::Program => b"program",
            ExecutionMode::OneShot => b"one-shot",
        },
    );
    hash_field(&mut hash, submission.label.as_str().as_bytes());
    hash_field(
        &mut hash,
        &serde_json::to_vec(&submission.referrer)
            .expect("authenticated logical path is serializable"),
    );
    match &submission.shape {
        SourceShape::JsonData => hash_field(&mut hash, b"json-data"),
        SourceShape::Program {
            goal,
            dialect,
            role,
            module_kind,
            is_main,
        } => {
            hash_field(&mut hash, b"program");
            hash_field(
                &mut hash,
                match goal {
                    SourceGoal::ScriptWithExtensions => b"script-with-extensions",
                    SourceGoal::Module => b"module",
                },
            );
            hash_field(
                &mut hash,
                match dialect {
                    ParserDialect::JavaScript => b"javascript",
                    ParserDialect::JavaScriptJsx => b"javascript-jsx",
                    ParserDialect::TypeScript => b"typescript",
                    ParserDialect::TypeScriptJsx => b"typescript-jsx",
                },
            );
            hash_field(
                &mut hash,
                match role {
                    SourceRole::Entry => b"entry",
                    SourceRole::Dependency => b"dependency",
                },
            );
            hash_field(
                &mut hash,
                match module_kind {
                    None => b"none",
                    Some(ModuleKind::Esm) => b"esm",
                    Some(ModuleKind::CommonJs) => b"commonjs",
                },
            );
            hash_field(&mut hash, if *is_main { b"main" } else { b"not-main" });
        }
    }
    match &submission.file_arguments {
        None => hash_field(&mut hash, b"no-file-arguments"),
        Some(arguments) => {
            hash_field(&mut hash, b"file-arguments");
            hash_field(&mut hash, &(arguments.len() as u64).to_be_bytes());
            for argument in arguments.iter() {
                hash_field(&mut hash, argument.as_bytes());
            }
        }
    }
    match source_id {
        None => hash_field(&mut hash, b"no-source-id"),
        Some(source_id) => {
            hash_field(&mut hash, b"source-id");
            hash_field(&mut hash, source_id.cache_key().as_bytes());
        }
    }
    hash_field(&mut hash, &submission.ordinal.get().to_be_bytes());
    hash_field(&mut hash, bytes_digest.as_str().as_bytes());
    match read_evidence {
        ReadEvidence::Inline => hash_field(&mut hash, b"inline"),
        ReadEvidence::TypedRead(evidence) => {
            hash_field(&mut hash, b"typed-read");
            hash_field(&mut hash, evidence.as_str().as_bytes());
        }
    }
    RequestBinding(hash.finalize().into())
}

fn hash_field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn volatile_wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn sha256_digest(bytes: &[u8]) -> Digest {
    let mut hash = Sha256::new();
    hash.update(bytes);
    digest_from_hash(hash)
}

fn digest_from_hash(hash: Sha256) -> Digest {
    Digest::new(format!(
        "sha256-{}",
        URL_SAFE_NO_PAD.encode(hash.finalize())
    ))
    .expect("SHA-256 always produces a canonical digest")
}

/// Runtime-owned JavaScript reference. `Rc` makes the handle neither `Send`
/// nor `Sync`; inspection and release must happen on its owner thread.
/// @ref LLP 0024#6-evaluation-outcomes-and-the-abi — handles are rooted,
/// runtime-scoped, explicitly released, and never cross a process boundary.
#[derive(Debug)]
pub struct ValueHandle {
    runtime_nonce: NonZeroU64,
    handle_id: NonZeroU64,
    owner_thread: ThreadId,
    _thread_affinity: std::marker::PhantomData<Rc<()>>,
}

impl ValueHandle {
    pub(crate) fn from_runtime(
        runtime_nonce: NonZeroU64,
        handle_id: NonZeroU64,
        owner_thread: ThreadId,
    ) -> Self {
        Self {
            runtime_nonce,
            handle_id,
            owner_thread,
            _thread_affinity: std::marker::PhantomData,
        }
    }

    pub fn belongs_to_current_thread(&self) -> bool {
        self.owner_thread == std::thread::current().id()
    }

    /// Opaque runtime namespace used by the native release/inspection calls.
    /// It is identity, not authority; callers still cannot mint a handle.
    pub fn runtime_nonce(&self) -> NonZeroU64 {
        self.runtime_nonce
    }

    /// Opaque handle id used by the native release/inspection calls.
    pub fn handle_id(&self) -> NonZeroU64 {
        self.handle_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThrowMetadata {
    Unavailable {
        required_stratum: CapabilityStratum,
    },
    Captured {
        message: Option<Arc<str>>,
        stack: Option<Arc<str>>,
        positions: Vec<SourcePosition>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePosition {
    pub source_label: SourceLabel,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug)]
pub enum EvaluationOutcome {
    Empty,
    Value(ValueHandle),
    Throw {
        value: ValueHandle,
        metadata: ThrowMetadata,
    },
    Cancelled,
    Lifecycle {
        exit_code: i32,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CapabilityStratum {
    Base,
    SafeThrow,
    SourcePositions,
    RichInspection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorCapabilities {
    pub protocol_version: u16,
    pub base: bool,
    pub safe_throw: bool,
    pub source_positions: bool,
    pub rich_inspection: bool,
}

impl EvaluatorCapabilities {
    pub fn validate(&self) -> Result<(), CapabilityAdvertisementError> {
        if self.protocol_version != STRUCTURED_EVALUATION_VERSION {
            return Err(CapabilityAdvertisementError::UnsupportedVersion(
                self.protocol_version,
            ));
        }
        if !self.base && (self.safe_throw || self.source_positions || self.rich_inspection) {
            return Err(CapabilityAdvertisementError::MissingBase);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CapabilityAdvertisementError {
    #[error("unsupported structured-evaluation protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("an evaluator cannot advertise an optional stratum without base support")]
    MissingBase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkKind {
    Evaluation,
    BackgroundCallback,
    Timer,
    MicrotaskDrain,
    CompletionQuery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkTarget {
    pub id: NonZeroU64,
    pub kind: WorkKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationResolution {
    Accepted,
    Unavailable,
    Failed,
    Defeated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationState {
    Pending {
        target: WorkTarget,
    },
    Resolved {
        target: WorkTarget,
        resolution: CancellationResolution,
    },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum EngineFault {
    #[error("engine rejected the source request: {0}")]
    Rejected(Arc<str>),
    #[error("engine ran out of memory")]
    OutOfMemory,
    #[error("engine runtime is poisoned")]
    Poisoned,
    #[error("value handle is stale, belongs to another runtime, or is used on the wrong thread")]
    InvalidHandle,
    #[error("structured Hermes evaluation refused the operation: {0}")]
    Structured(StructuredEngineFault),
    #[error("engine protocol violation: {0}")]
    Protocol(Arc<str>),
}

/// Exact native refusal codes from the versioned structured Hermes ABI.
///
/// Keeping these as a closed typed enum prevents adapters from flattening a
/// session-authentication or lifecycle failure into a generic string error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[repr(u32)]
pub enum StructuredEngineFault {
    #[error("invalid input")]
    InvalidInput = 1,
    #[error("invalid UTF-8")]
    InvalidUtf8 = 2,
    #[error("out of memory")]
    OutOfMemory = 3,
    #[error("engine failure")]
    Engine = 4,
    #[error("authenticated armed ingress is required")]
    ArmedIngressRequired = 5,
    #[error("operation was attempted from the wrong thread")]
    WrongThread = 6,
    #[error("value handle is stale or belongs to another runtime")]
    StaleHandle = 7,
    #[error("raw thrown-value capture is unavailable")]
    RawThrowUnavailable = 8,
    #[error("completion-record discrimination is unavailable")]
    CompletionRecordUnavailable = 9,
    #[error("the authenticated session is not bound")]
    SessionNotBound = 10,
    #[error("the credential belongs to another session")]
    WrongSession = 11,
    #[error("the submission credential was already consumed")]
    SubmissionReplay = 12,
    #[error("the submission ordinal is not next")]
    WrongOrdinal = 13,
    #[error("another structured evaluation is in flight")]
    EvaluationInFlight = 14,
    #[error("the submission ordinal space is exhausted")]
    OrdinalExhausted = 15,
    #[error("an armed runtime is required")]
    ArmedRuntimeRequired = 16,
    #[error("armed runtime bootstrap is not sealed")]
    BootstrapNotSealed = 17,
}

pub type EvaluationResult = Result<EvaluationOutcome, EngineFault>;

#[cfg(test)]
mod tests {
    use super::*;
    use capsec_semantics::model::{LogicalRoot, NonEmptyString};

    fn digest(byte: u8) -> Digest {
        let encoded = URL_SAFE_NO_PAD.encode([byte; 32]);
        Digest::new(format!("sha256-{encoded}")).unwrap()
    }

    fn session() -> ArmedSessionToken {
        session_for(EntryKind::Repl, "ibex:repl", ExecutionMode::Interactive)
    }

    fn session_for(
        entry_kind: EntryKind,
        entry_identity: &str,
        mode: ExecutionMode,
    ) -> ArmedSessionToken {
        ArmedSessionToken::from_authenticated_snapshot(
            digest(1),
            Arc::from("AQIDBAUGBwgJCgsMDQ4PEA"),
            Principal::Root {
                identity: NonEmptyString::new("project-root").unwrap(),
            },
            entry_kind,
            Arc::from(entry_identity),
            mode,
            digest(2),
        )
        .unwrap()
    }

    fn session_with_nonce(unforgeable_nonce: [u8; 32]) -> ArmedSessionToken {
        session_with_nonce_and_entry_identity(unforgeable_nonce, "ibex:repl")
    }

    fn session_with_nonce_and_entry_identity(
        unforgeable_nonce: [u8; 32],
        entry_identity: &str,
    ) -> ArmedSessionToken {
        ArmedSessionToken(Arc::new(ArmedSessionIdentity {
            snapshot_digest: digest(1),
            run_nonce: Arc::from("AQIDBAUGBwgJCgsMDQ4PEA"),
            root_principal: Principal::Root {
                identity: NonEmptyString::new("project-root").unwrap(),
            },
            entry_kind: EntryKind::Repl,
            entry_identity: Arc::from(entry_identity),
            mode: ExecutionMode::Interactive,
            endowment_projection_digest: digest(2),
            unforgeable_nonce,
            submissions: Mutex::new(SubmissionState::default()),
        }))
    }

    fn referrer() -> LogicalPath {
        LogicalPath {
            root: LogicalRoot::Project,
            components: Vec::new(),
            host_bound: None,
        }
    }

    fn test_file_source_id(identity: &str) -> crate::vfs::SourceId {
        // Production file requests receive a file SourceId from the Host's
        // authenticated VFS read. These constructor-focused unit tests use a
        // test-only opaque identity so they cannot bypass the same capsule
        // requirement by calling bind_bytes.
        crate::vfs::SourceId::synthetic_module(digest(7), identity)
    }

    fn program_request_for(session: ArmedSessionToken, bytes: Vec<u8>) -> SourceRequest {
        let mut sequence = SubmissionSequence::new(session).unwrap();
        let mut request = sequence
            .mint(
                SubmissionOrigin::Repl,
                referrer(),
                SourceShape::Program {
                    goal: SourceGoal::ScriptWithExtensions,
                    dialect: ParserDialect::TypeScript,
                    role: SourceRole::Entry,
                    module_kind: None,
                    is_main: true,
                },
            )
            .unwrap()
            .authorize_inline()
            .bind_bytes(bytes)
            .into_request()
            .unwrap();
        request.mark_native_accepted().unwrap();
        request
    }

    fn program_request(bytes: Vec<u8>) -> SourceRequest {
        program_request_for(session(), bytes)
    }

    #[test]
    fn strict_utf8_rejects_invalid_bytes_but_accepts_empty_source() {
        assert_eq!(program_request(Vec::new()).text().as_str(), "");
        assert_eq!(
            SourceText::from_bytes(vec![0xff]).unwrap_err(),
            SourceRefusal::InvalidUtf8 { valid_up_to: 0 }
        );
    }

    #[test]
    fn request_security_fields_come_from_the_session_credential() {
        let session = session();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let submission = sequence
            .mint(SubmissionOrigin::Eval, referrer(), SourceShape::JsonData)
            .unwrap();
        let request = submission
            .authorize_typed_read(digest(9))
            .bind_bytes(br#"{"ok":true}"#.to_vec())
            .into_request()
            .unwrap();

        assert!(request.authenticates_for(&session));
        assert_eq!(request.execution_mode(), ExecutionMode::Interactive);
        assert_eq!(request.entry_kind(), EntryKind::Repl);
        assert!(request.authenticated_principal().is_root());
        assert_eq!(request.submission_ordinal().get(), 1);
    }

    #[test]
    fn a_request_does_not_authenticate_for_an_equal_looking_other_session() {
        let request = program_request(b"1 + 1".to_vec());
        assert!(!request.authenticates_for(&session()));
    }

    #[test]
    fn native_credential_view_returns_the_exact_retained_raw_bytes() {
        let nonce = [0xa5; 32];
        let session = session_with_nonce(nonce);
        let request = program_request_for(session.clone(), b"const answer = 42".to_vec());
        let expected_binding = request.common().credential_binding.0;

        let credential = request.native_credential_for(&session).unwrap();
        assert_eq!(credential.session_nonce(), &nonce);
        assert_eq!(credential.request_binding(), &expected_binding);
        assert_eq!(credential.ordinal(), NonZeroU64::MIN);
        assert_eq!(
            URL_SAFE_NO_PAD.encode(credential.request_binding()),
            "7-KQkRE0W_qas61Nexd39KLHYEjTqsLqit57Lj0JiTQ"
        );
    }

    #[test]
    fn native_credential_view_refuses_tampered_requests_after_recomputation() {
        let session = session_with_nonce([0x5a; 32]);
        let mut bytes_tampered =
            program_request_for(session.clone(), b"const answer = 42".to_vec());
        let SourceRequest::Program(program) = &mut bytes_tampered else {
            panic!("program helper returned JSON")
        };
        program.text = SourceText::from_bytes(b"const answer = 43".to_vec()).unwrap();
        assert!(!bytes_tampered.authenticates_for(&session));
        assert!(bytes_tampered.native_credential_for(&session).is_none());

        let mut shape_tampered =
            program_request_for(session.clone(), b"const answer = 42".to_vec());
        let SourceRequest::Program(program) = &mut shape_tampered else {
            panic!("program helper returned JSON")
        };
        program.goal = SourceGoal::Module;
        assert!(!shape_tampered.authenticates_for(&session));
        assert!(shape_tampered.native_credential_for(&session).is_none());
    }

    #[test]
    fn native_credential_view_refuses_an_equal_looking_wrong_session() {
        let nonce = [0x33; 32];
        let owning_session = session_with_nonce(nonce);
        let equal_looking_other_session = session_with_nonce(nonce);
        let request = program_request_for(owning_session.clone(), b"const answer = 42".to_vec());

        assert!(request.native_credential_for(&owning_session).is_some());
        assert!(request
            .native_credential_for(&equal_looking_other_session)
            .is_none());
    }

    #[test]
    fn request_binding_authenticates_the_snapshot_entry_identity() {
        let nonce = [0x35; 32];
        let first_session = session_with_nonce_and_entry_identity(nonce, "ibex:repl");
        let second_session = session_with_nonce_and_entry_identity(nonce, "ibex:eval");
        let first = program_request_for(first_session.clone(), b"1 + 1".to_vec());
        let second = program_request_for(second_session.clone(), b"1 + 1".to_vec());

        assert_ne!(
            first
                .native_credential_for(&first_session)
                .unwrap()
                .request_binding(),
            second
                .native_credential_for(&second_session)
                .unwrap()
                .request_binding()
        );
    }

    #[test]
    fn native_credentials_and_request_debug_output_are_opaque() {
        let nonce = [0x44; 32];
        let session = session_with_nonce(nonce);
        let request = program_request_for(session.clone(), b"const answer = 42".to_vec());
        let credential = request.native_credential_for(&session).unwrap();
        let nonce_debug = format!("{nonce:?}");
        let nonce_base64 = URL_SAFE_NO_PAD.encode(nonce);
        let binding_debug = format!("{:?}", credential.request_binding());
        let binding_base64 = URL_SAFE_NO_PAD.encode(credential.request_binding());
        let request_debug = format!("{request:?}");
        let credential_debug = format!("{credential:?}");

        assert_eq!(credential_debug, "NativeCredentialView(<opaque>)");
        assert!(request_debug.contains("RequestBinding(<opaque>)"));
        for secret in [
            nonce_debug.as_str(),
            nonce_base64.as_str(),
            binding_debug.as_str(),
            binding_base64.as_str(),
            "AQIDBAUGBwgJCgsMDQ4PEA",
        ] {
            assert!(
                !request_debug.contains(secret),
                "request Debug leaked {secret}"
            );
            assert!(
                !credential_debug.contains(secret),
                "credential Debug leaked {secret}"
            );
        }
    }

    #[test]
    fn interactive_and_batch_modes_have_distinct_drain_boundaries() {
        assert_eq!(
            ExecutionMode::Interactive.drain_policy(),
            DrainPolicy::ReadyWorkOnly
        );
        assert_eq!(
            ExecutionMode::Transcript.drain_policy(),
            DrainPolicy::ReadyWorkOnly
        );
        assert_eq!(
            ExecutionMode::Program.drain_policy(),
            DrainPolicy::ToQuiescence
        );
        assert_eq!(
            ExecutionMode::OneShot.drain_policy(),
            DrainPolicy::ToQuiescence
        );
    }

    #[test]
    fn optional_strata_cannot_be_advertised_without_base() {
        let capabilities = EvaluatorCapabilities {
            protocol_version: STRUCTURED_EVALUATION_VERSION,
            base: false,
            safe_throw: true,
            source_positions: false,
            rich_inspection: false,
        };
        assert_eq!(
            capabilities.validate(),
            Err(CapabilityAdvertisementError::MissingBase)
        );
    }

    #[test]
    fn empty_completion_and_undefined_value_are_different_variants() {
        let value = ValueHandle::from_runtime(
            NonZeroU64::new(10).unwrap(),
            NonZeroU64::new(20).unwrap(),
            std::thread::current().id(),
        );
        assert!(matches!(EvaluationOutcome::Empty, EvaluationOutcome::Empty));
        assert!(matches!(
            EvaluationOutcome::Value(value),
            EvaluationOutcome::Value(_)
        ));
    }

    #[test]
    fn work_and_cancellation_keep_the_exact_target() {
        let target = WorkTarget {
            id: NonZeroU64::new(42).unwrap(),
            kind: WorkKind::CompletionQuery,
        };
        let pending = CancellationState::Pending { target };
        let resolved = CancellationState::Resolved {
            target,
            resolution: CancellationResolution::Defeated,
        };
        assert!(matches!(pending, CancellationState::Pending { target: t } if t == target));
        assert!(matches!(resolved, CancellationState::Resolved { target: t, .. } if t == target));
    }

    #[test]
    fn session_sequence_allows_only_one_in_flight_submission() {
        let session = session();
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let shape = SourceShape::Program {
            goal: SourceGoal::ScriptWithExtensions,
            dialect: ParserDialect::TypeScript,
            role: SourceRole::Entry,
            module_kind: None,
            is_main: true,
        };
        let first = sequence
            .mint(SubmissionOrigin::Repl, referrer(), shape.clone())
            .unwrap();
        assert_eq!(
            sequence
                .mint(SubmissionOrigin::Repl, referrer(), shape.clone())
                .unwrap_err(),
            SourceRefusal::EvaluationInFlight
        );
        let mut first = first
            .authorize_inline()
            .bind_bytes(b"let x = 1".to_vec())
            .into_request()
            .unwrap();
        first.mark_native_accepted().unwrap();
        let second = sequence
            .mint(SubmissionOrigin::Repl, referrer(), shape)
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"x".to_vec())
            .into_request()
            .unwrap();
        assert_eq!(second.source_label().as_str(), "repl:2");
    }

    #[test]
    fn cloned_tokens_share_one_exclusive_submission_sequence() {
        let session = session();
        let sequence = SubmissionSequence::new(session.clone()).unwrap();
        assert_eq!(
            SubmissionSequence::new(session.clone()).unwrap_err(),
            SourceRefusal::SequenceAlreadyClaimed
        );

        let cloned = session.clone();
        let cross_thread = std::thread::spawn(move || SubmissionSequence::new(cloned).unwrap_err())
            .join()
            .unwrap();
        assert_eq!(cross_thread, SourceRefusal::SequenceAlreadyClaimed);

        drop(sequence);
        assert!(SubmissionSequence::new(session).is_ok());
    }

    #[test]
    fn preaccept_refusals_abort_without_consuming_the_ordinal() {
        let session = session();
        let mut sequence = SubmissionSequence::new(session).unwrap();
        let shape = SourceShape::Program {
            goal: SourceGoal::ScriptWithExtensions,
            dialect: ParserDialect::JavaScript,
            role: SourceRole::Entry,
            module_kind: None,
            is_main: true,
        };

        let invalid = sequence
            .mint(SubmissionOrigin::Repl, referrer(), shape.clone())
            .unwrap()
            .authorize_inline()
            .bind_bytes(vec![0xff])
            .into_request();
        assert_eq!(
            invalid.unwrap_err(),
            SourceRefusal::InvalidUtf8 { valid_up_to: 0 }
        );

        let request = sequence
            .mint(SubmissionOrigin::Repl, referrer(), shape)
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"1 + 1".to_vec())
            .into_request()
            .unwrap();
        assert_eq!(request.submission_ordinal(), NonZeroU64::MIN);
        assert_eq!(request.source_label().as_str(), "repl:1");
    }

    #[test]
    fn admitted_syntax_and_json_failures_consume_their_ordinals() {
        let session = session();
        let mut sequence = SubmissionSequence::new(session).unwrap();
        let program_shape = SourceShape::Program {
            goal: SourceGoal::ScriptWithExtensions,
            dialect: ParserDialect::JavaScript,
            role: SourceRole::Entry,
            module_kind: None,
            is_main: false,
        };

        // Admission is deliberately before either parser. These texts are
        // invalid in their respective grammars, but each was still submitted.
        let mut invalid_program = sequence
            .mint(SubmissionOrigin::Repl, referrer(), program_shape.clone())
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"let =".to_vec())
            .into_request()
            .unwrap();
        invalid_program.mark_native_accepted().unwrap();
        drop(invalid_program);

        let mut invalid_json = sequence
            .mint(SubmissionOrigin::Repl, referrer(), SourceShape::JsonData)
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"{".to_vec())
            .into_request()
            .unwrap();
        assert_eq!(invalid_json.source_label().as_str(), "repl:2");
        invalid_json.mark_native_accepted().unwrap();
        drop(invalid_json);

        let next = sequence
            .mint(SubmissionOrigin::Repl, referrer(), program_shape)
            .unwrap();
        assert_eq!(next.submission.label.as_str(), "repl:3");
    }

    #[test]
    fn native_acceptance_advances_once_even_while_the_request_is_retained() {
        let session = session();
        let mut sequence = SubmissionSequence::new(session).unwrap();
        let shape = SourceShape::Program {
            goal: SourceGoal::ScriptWithExtensions,
            dialect: ParserDialect::JavaScript,
            role: SourceRole::Entry,
            module_kind: None,
            is_main: true,
        };
        let mut first = sequence
            .mint(SubmissionOrigin::Repl, referrer(), shape.clone())
            .unwrap()
            .authorize_inline()
            .bind_bytes(b"throw 1".to_vec())
            .into_request()
            .unwrap();

        first.mark_native_accepted().unwrap();
        assert_eq!(
            first.mark_native_accepted().unwrap_err(),
            SourceRefusal::SubmissionNotPending
        );
        let second = sequence
            .mint(SubmissionOrigin::Repl, referrer(), shape)
            .unwrap();
        assert_eq!(second.submission.label.as_str(), "repl:2");
    }

    #[test]
    fn repl_shape_is_fixed_before_the_submission_becomes_pending() {
        let mut sequence = SubmissionSequence::new(session()).unwrap();
        let repl = sequence.mint_repl(referrer()).unwrap();
        assert_eq!(repl.submission.label.as_str(), "repl:1");
        assert!(matches!(
            repl.submission.shape,
            SourceShape::Program {
                goal: SourceGoal::ScriptWithExtensions,
                dialect: ParserDialect::TypeScript,
                role: SourceRole::Entry,
                module_kind: None,
                is_main: false,
            }
        ));
    }

    #[test]
    fn eval_and_stdin_shapes_are_fixed_and_route_bound() {
        let mut eval = SubmissionSequence::new(session_for(
            EntryKind::Eval,
            "ibex:eval",
            ExecutionMode::OneShot,
        ))
        .unwrap();
        let eval_submission = eval.mint_eval(referrer()).unwrap();
        assert_eq!(eval_submission.submission.label.as_str(), "ibex:eval");
        assert!(matches!(
            eval_submission.submission.shape,
            SourceShape::Program {
                goal: SourceGoal::ScriptWithExtensions,
                dialect: ParserDialect::TypeScript,
                role: SourceRole::Entry,
                module_kind: None,
                is_main: false,
            }
        ));

        let mut stdin = SubmissionSequence::new(session_for(
            EntryKind::Stdin,
            "ibex:stdin",
            ExecutionMode::Program,
        ))
        .unwrap();
        let stdin_submission = stdin.mint_stdin(referrer()).unwrap();
        assert_eq!(stdin_submission.submission.label.as_str(), "ibex:stdin");
        assert!(matches!(
            stdin_submission.submission.shape,
            SourceShape::Program {
                goal: SourceGoal::Module,
                dialect: ParserDialect::TypeScript,
                role: SourceRole::Entry,
                module_kind: Some(ModuleKind::Esm),
                is_main: true,
            }
        ));
        let stdin_request = stdin_submission
            .authorize_inline()
            .bind_bytes(b"export default 1".to_vec())
            .into_request()
            .unwrap();
        assert!(stdin_request.source_id().is_some());

        let same_session = stdin_request.common().session.clone();
        let same_id = same_session.synthetic_module_source_id("ibex:stdin");
        assert_eq!(stdin_request.source_id(), Some(&same_id));
        let other_session = session_for(EntryKind::Stdin, "ibex:stdin", ExecutionMode::Program);
        assert_ne!(
            same_id.cache_key(),
            other_session
                .synthetic_module_source_id("ibex:stdin")
                .cache_key()
        );

        assert_eq!(
            SubmissionSequence::new(session())
                .unwrap()
                .mint_eval(referrer())
                .unwrap_err(),
            SourceRefusal::WrongEntryRoute
        );
        assert_eq!(
            SubmissionSequence::new(session())
                .unwrap()
                .mint_stdin(referrer())
                .unwrap_err(),
            SourceRefusal::WrongEntryRoute
        );
    }

    #[test]
    fn load_shape_is_derived_from_the_generated_surface() {
        let mut sequence = SubmissionSequence::new(session()).unwrap();
        let javascript = sequence
            .mint_load(Arc::from("/project/tool.js"), referrer())
            .unwrap();
        assert!(javascript.is_canonical_load_for("/project/tool.js"));
        assert!(matches!(
            &javascript.submission.shape,
            SourceShape::Program {
                dialect: ParserDialect::JavaScript,
                role: SourceRole::Entry,
                is_main: false,
                ..
            }
        ));
        drop(javascript);

        let json = sequence
            .mint_load(Arc::from("/project/data.json"), referrer())
            .unwrap();
        assert!(json.is_canonical_load_for("/project/data.json"));
        assert_eq!(json.submission.shape, SourceShape::JsonData);
    }

    #[test]
    fn refused_or_caller_shaped_loads_do_not_consume_an_ordinal() {
        let mut sequence = SubmissionSequence::new(session()).unwrap();
        for (path, expected) in [
            ("/project/module.mjs", SourceRefusal::LoadModuleKindRefused),
            ("/project/types.d.ts", SourceRefusal::LoadTypesOnlyRefused),
            ("/project/no-extension", SourceRefusal::LoadUnsupportedPath),
        ] {
            assert_eq!(
                sequence.mint_load(Arc::from(path), referrer()).unwrap_err(),
                expected
            );
        }
        assert_eq!(
            sequence
                .mint(
                    SubmissionOrigin::Loaded {
                        virtual_path: Arc::from("/project/forged.js"),
                    },
                    referrer(),
                    SourceShape::JsonData,
                )
                .unwrap_err(),
            SourceRefusal::LoadedOriginRequiresClassifier
        );

        let valid = sequence
            .mint_load(Arc::from("/project/valid.ts"), referrer())
            .unwrap();
        assert_eq!(valid.submission.label.as_str(), "repl:1:/project/valid.ts");
    }

    #[test]
    fn file_submission_derives_module_shape_identity_and_virtual_argv() {
        let session = session_for(
            EntryKind::File,
            "file:///project/src/hello%20world.mts",
            ExecutionMode::Program,
        );
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();
        let user_arguments = vec![
            "--mode=test".to_owned(),
            String::new(),
            "snowman-☃".to_owned(),
        ];
        let submission = sequence.mint_file(referrer(), &user_arguments).unwrap();

        assert_eq!(
            submission.submission.label.as_str(),
            "file:///project/src/hello%20world.mts"
        );
        assert!(submission.is_canonical_file_for(
            "/project/src/hello world.mts",
            "file:///project/src/hello%20world.mts"
        ));
        assert!(matches!(
            submission.submission.shape,
            SourceShape::Program {
                goal: SourceGoal::Module,
                dialect: ParserDialect::TypeScript,
                role: SourceRole::Entry,
                module_kind: Some(ModuleKind::Esm),
                is_main: true,
            }
        ));

        let request = submission
            .authorize_typed_read(digest(9))
            .bind_module_bytes(
                b"export const answer: number = 42;".to_vec(),
                test_file_source_id("file:///project/src/hello%20world.mts"),
            )
            .into_request()
            .unwrap();
        assert!(request.authenticates_for(&session));
        assert_eq!(
            request.source_label().as_str(),
            session.0.entry_identity.as_ref()
        );
        assert_eq!(request.virtual_referrer(), &referrer());
        assert_eq!(request.execution_mode(), ExecutionMode::Program);
        assert_eq!(request.entry_kind(), EntryKind::File);
        assert_eq!(
            request
                .file_arguments()
                .unwrap()
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<&str>>(),
            vec![
                "ibex:runtime",
                "/project/src/hello world.mts",
                "--mode=test",
                "",
                "snowman-☃",
            ]
        );
    }

    #[test]
    fn file_argv_is_part_of_the_opaque_request_binding() {
        let session = session_for(
            EntryKind::File,
            "file:///project/main.mjs",
            ExecutionMode::Program,
        );
        let mut request = SubmissionSequence::new(session.clone())
            .unwrap()
            .mint_file(referrer(), &["original".to_owned()])
            .unwrap()
            .authorize_typed_read(digest(9))
            .bind_module_bytes(
                b"export {};".to_vec(),
                test_file_source_id("file:///project/main.mjs"),
            )
            .into_request()
            .unwrap();
        assert!(request.authenticates_for(&session));

        request.common_mut().file_arguments = Some(
            vec![
                Arc::from("ibex:runtime"),
                Arc::from("/project/main.mjs"),
                Arc::from("tampered"),
            ]
            .into(),
        );
        assert!(!request.authenticates_for(&session));
        assert!(request.native_credential_for(&session).is_none());
    }

    #[test]
    fn file_entry_can_retry_before_admission_but_cannot_run_twice() {
        let session = session_for(
            EntryKind::File,
            "file:///project/main.mjs",
            ExecutionMode::Program,
        );
        let mut sequence = SubmissionSequence::new(session.clone()).unwrap();

        // Dropping a request which never reached native admission restores the
        // pending first ordinal, so an operational preparation retry is safe.
        drop(sequence.mint_file(referrer(), &[]).unwrap());
        let mut request = sequence
            .mint_file(referrer(), &[])
            .unwrap()
            .authorize_typed_read(digest(9))
            .bind_module_bytes(
                b"export {};".to_vec(),
                test_file_source_id("file:///project/main.mjs"),
            )
            .into_request()
            .unwrap();
        request.mark_native_accepted().unwrap();
        drop(request);
        drop(sequence);

        let mut repeat = SubmissionSequence::new(session).unwrap();
        assert_eq!(
            repeat.mint_file(referrer(), &[]).unwrap_err(),
            SourceRefusal::FileEntryAlreadySubmitted
        );
    }

    #[test]
    fn file_entry_preserves_percent_encoded_posix_backslash() {
        let session = session_for(
            EntryKind::File,
            "file:///project/odd%5Cname.mjs",
            ExecutionMode::Program,
        );
        let submission = SubmissionSequence::new(session)
            .unwrap()
            .mint_file(referrer(), &[])
            .unwrap();
        assert!(submission
            .is_canonical_file_for("/project/odd\\name.mjs", "file:///project/odd%5Cname.mjs"));
        assert_eq!(
            submission.submission.file_arguments.as_deref().unwrap()[1].as_ref(),
            "/project/odd\\name.mjs"
        );
    }

    #[test]
    fn file_constructor_is_route_bound_and_generic_mint_cannot_shape_it() {
        let mut repl = SubmissionSequence::new(session()).unwrap();
        assert_eq!(
            repl.mint_file(referrer(), &[]).unwrap_err(),
            SourceRefusal::WrongEntryRoute
        );

        let mut file = SubmissionSequence::new(session_for(
            EntryKind::File,
            "file:///project/main.mjs",
            ExecutionMode::Program,
        ))
        .unwrap();
        assert_eq!(
            file.mint(
                SubmissionOrigin::File {
                    user_arguments: Arc::from([]),
                },
                referrer(),
                SourceShape::JsonData,
            )
            .unwrap_err(),
            SourceRefusal::FileOriginRequiresConstructor
        );
    }

    #[test]
    fn file_constructor_refuses_unsupported_module_routes_without_consuming() {
        for (identity, expected) in [
            (
                "file:///project/main.cts",
                SourceRefusal::FileCommonJsUnsupported,
            ),
            (
                "file:///project/main.hbc",
                SourceRefusal::FileBytecodeUnsupported,
            ),
            ("file:///project/main", SourceRefusal::FileUnsupportedPath),
            (
                "file:///project/types.d.ts",
                SourceRefusal::FileUnsupportedPath,
            ),
        ] {
            let mut sequence = SubmissionSequence::new(session_for(
                EntryKind::File,
                identity,
                ExecutionMode::Program,
            ))
            .unwrap();
            assert_eq!(sequence.mint_file(referrer(), &[]).unwrap_err(), expected);
        }
    }

    #[test]
    fn file_constructor_keeps_dialect_separate_from_authenticated_module_kind() {
        let mut cjs = SubmissionSequence::new(session_for(
            EntryKind::File,
            "file:///project/main.cjs",
            ExecutionMode::Program,
        ))
        .unwrap();
        assert!(matches!(
            cjs.mint_file(referrer(), &[]).unwrap().submission.shape,
            SourceShape::Program {
                goal: SourceGoal::ScriptWithExtensions,
                dialect: ParserDialect::JavaScript,
                role: SourceRole::Entry,
                module_kind: Some(ModuleKind::CommonJs),
                is_main: true,
            }
        ));

        let mut json = SubmissionSequence::new(session_for(
            EntryKind::File,
            "file:///project/main.json",
            ExecutionMode::Program,
        ))
        .unwrap();
        assert_eq!(
            json.mint_file(referrer(), &[]).unwrap().submission.shape,
            SourceShape::JsonData
        );

        for (kind, goal) in [
            (ModuleKind::Esm, SourceGoal::Module),
            (ModuleKind::CommonJs, SourceGoal::ScriptWithExtensions),
        ] {
            let mut javascript = SubmissionSequence::new(session_for(
                EntryKind::File,
                "file:///project/main.js",
                ExecutionMode::Program,
            ))
            .unwrap();
            let pending = javascript.mint_file(referrer(), &[]).unwrap();
            assert!(pending.awaits_authenticated_file_module_kind());
            let finalized = pending.with_authenticated_file_module_kind(kind).unwrap();
            assert!(matches!(
                finalized.submission.shape,
                SourceShape::Program {
                    goal: actual_goal,
                    dialect: ParserDialect::JavaScript,
                    role: SourceRole::Entry,
                    module_kind: Some(actual_kind),
                    is_main: true,
                } if actual_goal == goal && actual_kind == kind
            ));
        }
    }

    #[test]
    fn file_constructor_derives_each_supported_parser_dialect() {
        for (identity, expected) in [
            ("file:///project/main.mjs", ParserDialect::JavaScript),
            ("file:///project/main.mts", ParserDialect::TypeScript),
            ("file:///project/main.ts", ParserDialect::TypeScript),
            ("file:///project/main.tsx", ParserDialect::TypeScriptJsx),
            ("file:///project/main.jsx", ParserDialect::JavaScriptJsx),
        ] {
            let mut sequence = SubmissionSequence::new(session_for(
                EntryKind::File,
                identity,
                ExecutionMode::Program,
            ))
            .unwrap();
            let submission = sequence.mint_file(referrer(), &[]).unwrap();
            assert!(matches!(
                submission.submission.shape,
                SourceShape::Program {
                    goal: SourceGoal::Module,
                    dialect,
                    role: SourceRole::Entry,
                    module_kind: Some(ModuleKind::Esm),
                    is_main: true,
                } if dialect == expected
            ));
        }
    }

    #[test]
    fn file_constructor_rejects_noncanonical_snapshot_identity() {
        for identity in [
            "/project/main.mjs",
            "file:///project/../private/main.mjs",
            "file:///project/a%2fb.mjs",
            "file:///project/main.mjs?query",
            "file:///project/main.mjs#fragment",
            "file:///project/directory/",
        ] {
            let mut sequence = SubmissionSequence::new(session_for(
                EntryKind::File,
                identity,
                ExecutionMode::Program,
            ))
            .unwrap();
            assert_eq!(
                sequence.mint_file(referrer(), &[]).unwrap_err(),
                SourceRefusal::InvalidFileIdentity,
                "{identity}"
            );
        }
    }
}
