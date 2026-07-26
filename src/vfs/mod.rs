//! Session-local virtual filesystem identities and authenticated whole-file reads.
//!
//! This module deliberately keeps host spellings behind the mount translation.
//! Callers resolve untrusted UTF-8 syntax into a [`NamespacePath`], authorize that
//! typed value, and only then may the VFS perform descriptor-relative discovery.
//! @ref LLP 0023#2-identity-versus-spelling — authorization identity is staged;
//! display spellings are neither authorization nor module-cache keys.

use std::fmt;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use capsec_semantics::arming::{ArmedRootBinding, ArmedSnapshot};
use capsec_semantics::model::{
    Digest, LogicalPath, LogicalRoot, ObjectIdentity, PathComponent, Principal,
};
use sha2::{Digest as _, Sha256};

use crate::host::object_identity_for_host_path;
#[cfg(any(test, windows))]
use crate::host::object_identity_for_open_file;

const PROJECT_MOUNT: &str = "project";
const READ_EVIDENCE_DOMAIN: &[u8] = b"ibex/vfs-authenticated-read/1\0";

static NEXT_VFS_ID: AtomicU64 = AtomicU64::new(1);

fn next_vfs_identity(operation: &str, virtual_path: Option<Arc<str>>) -> Result<u64, VfsError> {
    NEXT_VFS_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| VfsError::stale_session(operation, virtual_path))
}

/// Stable VFS refusal classes. The JS projection is supplied by [`VfsError::code`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VfsReason {
    ClosedOperation,
    StaleSession,
    MalformedInput,
    EncodedSeparator,
    OutsideMount,
    SyntheticNode,
    PolicyDenied,
    Absent,
    SymlinkDepthExceeded,
    UnmappableLink,
    StaleIdentity,
    InputTooLarge,
    HostError,
}

impl VfsReason {
    /// Global error-union order. Lower ranks win when two independently
    /// detected failures compete; each path stage additionally preserves the
    /// containment -> authorization -> existence order.
    /// @ref LLP 0023#72-the-structured-result-and-its-error-classes
    pub const fn precedence_rank(self) -> u8 {
        match self {
            VfsReason::StaleSession => 0,
            VfsReason::ClosedOperation => 1,
            VfsReason::MalformedInput => 2,
            VfsReason::EncodedSeparator => 3,
            VfsReason::OutsideMount => 4,
            VfsReason::SyntheticNode => 5,
            VfsReason::PolicyDenied => 6,
            VfsReason::Absent => 7,
            VfsReason::SymlinkDepthExceeded => 8,
            VfsReason::UnmappableLink => 9,
            VfsReason::StaleIdentity => 10,
            VfsReason::InputTooLarge => 11,
            VfsReason::HostError => 12,
        }
    }

    pub const fn stable_code(self) -> &'static str {
        match self {
            VfsReason::ClosedOperation => "EPERM",
            VfsReason::StaleSession => "ERR_IBEX_STALE_SESSION",
            VfsReason::MalformedInput => "ERR_INVALID_ARG_VALUE",
            VfsReason::EncodedSeparator => "ERR_INVALID_FILE_URL_PATH",
            VfsReason::OutsideMount => "ERR_IBEX_OUTSIDE_MOUNT",
            VfsReason::SyntheticNode => "ERR_IBEX_SYNTHETIC_NODE",
            VfsReason::PolicyDenied => "EACCES",
            VfsReason::Absent => "ENOENT",
            VfsReason::SymlinkDepthExceeded => "ELOOP",
            VfsReason::UnmappableLink => "ERR_IBEX_UNMAPPABLE_LINK",
            VfsReason::StaleIdentity => "ERR_IBEX_STALE_IDENTITY",
            VfsReason::InputTooLarge => "ERR_IBEX_INPUT_TOO_LARGE",
            VfsReason::HostError => "ERR_IBEX_HOST_IO",
        }
    }

    pub const fn dominant(self, other: Self) -> Self {
        if self.precedence_rank() <= other.precedence_rank() {
            self
        } else {
            other
        }
    }
}

/// A path error whose observables are confined to the virtual namespace.
///
/// It intentionally does not retain an `io::Error` or backing `PathBuf`: either
/// could accidentally reintroduce a host spelling through `Display` or a source
/// chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsError {
    reason: VfsReason,
    code: Arc<str>,
    operation: Arc<str>,
    virtual_path: Option<Arc<str>>,
    safe_decision_id: Option<Arc<str>>,
    host_errno: Option<i32>,
}

impl VfsError {
    pub fn reason(&self) -> VfsReason {
        self.reason
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn virtual_path(&self) -> Option<&str> {
        self.virtual_path.as_deref()
    }

    pub fn safe_decision_id(&self) -> Option<&str> {
        self.safe_decision_id.as_deref()
    }

    pub fn host_errno(&self) -> Option<i32> {
        self.host_errno
    }

    fn new(
        reason: VfsReason,
        code: impl Into<Arc<str>>,
        operation: impl Into<Arc<str>>,
        virtual_path: Option<Arc<str>>,
    ) -> Self {
        Self {
            reason,
            code: code.into(),
            operation: operation.into(),
            virtual_path,
            safe_decision_id: None,
            host_errno: None,
        }
    }

    pub(crate) fn malformed(operation: &str) -> Self {
        Self::new(
            VfsReason::MalformedInput,
            "ERR_INVALID_ARG_VALUE",
            operation,
            None,
        )
    }

    fn encoded_separator(operation: &str) -> Self {
        Self::new(
            VfsReason::EncodedSeparator,
            "ERR_INVALID_FILE_URL_PATH",
            operation,
            None,
        )
    }

    fn outside_mount(operation: &str, path: Arc<str>) -> Self {
        Self::new(
            VfsReason::OutsideMount,
            "ERR_IBEX_OUTSIDE_MOUNT",
            operation,
            Some(path),
        )
    }

    pub(crate) fn stale_session(operation: &str, path: Option<Arc<str>>) -> Self {
        Self::new(
            VfsReason::StaleSession,
            "ERR_IBEX_STALE_SESSION",
            operation,
            path,
        )
    }

    fn synthetic_node(operation: &str, path: Arc<str>) -> Self {
        Self::new(
            VfsReason::SyntheticNode,
            "ERR_IBEX_SYNTHETIC_NODE",
            operation,
            Some(path),
        )
    }

    pub(crate) fn policy_denied(
        operation: &str,
        path: Arc<str>,
        safe_decision_id: impl Into<Arc<str>>,
    ) -> Self {
        let mut error = Self::new(VfsReason::PolicyDenied, "EACCES", operation, Some(path));
        error.safe_decision_id = Some(safe_decision_id.into());
        error
    }

    fn absent(operation: &str, path: Arc<str>) -> Self {
        Self::new(VfsReason::Absent, "ENOENT", operation, Some(path))
    }

    fn stale_identity(operation: &str, path: Arc<str>) -> Self {
        Self::new(
            VfsReason::StaleIdentity,
            "ERR_IBEX_STALE_IDENTITY",
            operation,
            Some(path),
        )
    }

    fn input_too_large(operation: &str, path: Arc<str>) -> Self {
        Self::new(
            VfsReason::InputTooLarge,
            "ERR_IBEX_INPUT_TOO_LARGE",
            operation,
            Some(path),
        )
    }

    fn symlink_depth(operation: &str, path: Arc<str>) -> Self {
        Self::new(
            VfsReason::SymlinkDepthExceeded,
            "ELOOP",
            operation,
            Some(path),
        )
    }

    fn host(operation: &str, path: Arc<str>, error: &std::io::Error) -> Self {
        let errno = error.raw_os_error();
        let code = errno_name(errno).unwrap_or("ERR_IBEX_HOST_IO");
        let mut result = Self::new(VfsReason::HostError, code, operation, Some(path));
        result.host_errno = errno;
        result
    }

    fn host_code(operation: &str, path: Arc<str>, code: &'static str) -> Self {
        let mut result = Self::new(VfsReason::HostError, code, operation, Some(path));
        result.host_errno = errno_for_code(code);
        result
    }
}

impl fmt::Display for VfsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.operation)?;
        if let Some(path) = &self.virtual_path {
            write!(formatter, " '{path}'")?;
        }
        if let Some(decision) = &self.safe_decision_id {
            write!(formatter, " (decision {decision})")?;
        }
        Ok(())
    }
}

impl std::error::Error for VfsError {}

fn errno_name(errno: Option<i32>) -> Option<&'static str> {
    #[cfg(unix)]
    match errno? {
        libc::EACCES => Some("EACCES"),
        libc::EEXIST => Some("EEXIST"),
        libc::EISDIR => Some("EISDIR"),
        libc::ELOOP => Some("ELOOP"),
        libc::EMFILE => Some("EMFILE"),
        libc::ENFILE => Some("ENFILE"),
        libc::ENAMETOOLONG => Some("ENAMETOOLONG"),
        libc::ENOSPC => Some("ENOSPC"),
        libc::ENOTDIR => Some("ENOTDIR"),
        libc::EPERM => Some("EPERM"),
        libc::EROFS => Some("EROFS"),
        _ => None,
    }
    #[cfg(not(unix))]
    {
        let _ = errno;
        None
    }
}

fn errno_for_code(code: &str) -> Option<i32> {
    #[cfg(unix)]
    match code {
        "EACCES" => Some(libc::EACCES),
        "EEXIST" => Some(libc::EEXIST),
        "EISDIR" => Some(libc::EISDIR),
        "ELOOP" => Some(libc::ELOOP),
        "EMFILE" => Some(libc::EMFILE),
        "ENFILE" => Some(libc::ENFILE),
        "ENAMETOOLONG" => Some(libc::ENAMETOOLONG),
        "ENOENT" => Some(libc::ENOENT),
        "ENOSPC" => Some(libc::ENOSPC),
        "ENOTDIR" => Some(libc::ENOTDIR),
        "EPERM" => Some(libc::EPERM),
        "EROFS" => Some(libc::EROFS),
        _ => None,
    }
    #[cfg(not(unix))]
    {
        let _ = code;
        None
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountWritePolicy {
    TypedProjectPolicy,
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountSymlinkPolicy {
    ContainedFollow,
    NoFollow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountLifecycle {
    Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MountAttributes {
    pub write_policy: MountWritePolicy,
    pub symlink_policy: MountSymlinkPolicy,
    pub lifecycle: MountLifecycle,
    pub metadata_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountDescriptor {
    virtual_path: Arc<str>,
    logical_root: LogicalRoot,
    attributes: MountAttributes,
}

impl MountDescriptor {
    pub fn virtual_path(&self) -> &str {
        &self.virtual_path
    }

    pub fn logical_root(&self) -> LogicalRoot {
        self.logical_root
    }

    pub fn attributes(&self) -> MountAttributes {
        self.attributes
    }
}

/// Version tag for the resolver path record which crosses the native/loader
/// boundary. The record contains only authenticated logical identity and its
/// virtual display spelling; backing paths remain native-only.
/// @ref LLP 0023#6-path-bearing-observables — resolver `path`/`pkgRoot`
/// fields are typed logical values, never host strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ResolverLogicalPathSchema {
    #[serde(rename = "ibex/logical-path/1")]
    V1,
}

/// A host-independent resolver path. `binding_owner` identifies which
/// authenticated package binding gives a package-relative logical path its
/// meaning. `session_handle` prevents cross-Host replay. Both are identity, not
/// authority, and must be revalidated against native state whenever the record
/// returns from the loader.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolverLogicalPath {
    schema: ResolverLogicalPathSchema,
    session_handle: String,
    virtual_path: String,
    logical_path: LogicalPath,
    binding_owner: Option<Principal>,
}

impl ResolverLogicalPath {
    fn new(
        session_handle: impl Into<String>,
        virtual_path: impl Into<String>,
        logical_path: LogicalPath,
        binding_owner: Option<Principal>,
    ) -> Result<Self, VfsError> {
        let record = Self {
            schema: ResolverLogicalPathSchema::V1,
            session_handle: session_handle.into(),
            virtual_path: virtual_path.into(),
            logical_path,
            binding_owner,
        };
        record
            .validate()
            .map_err(|_| VfsError::malformed("module-resolver-path"))?;
        Ok(record)
    }

    pub fn schema(&self) -> ResolverLogicalPathSchema {
        self.schema
    }

    pub fn virtual_path(&self) -> &str {
        &self.virtual_path
    }

    pub fn session_handle(&self) -> &str {
        &self.session_handle
    }

    pub fn logical_path(&self) -> &LogicalPath {
        &self.logical_path
    }

    pub fn binding_owner(&self) -> Option<&Principal> {
        self.binding_owner.as_ref()
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != ResolverLogicalPathSchema::V1 {
            return Err("unsupported resolver logical-path schema");
        }
        if self.session_handle.len() != 19
            || !self.session_handle.starts_with("mrs")
            || !self.session_handle[3..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("resolver session handle is not canonical");
        }
        if self.virtual_path.contains('\0')
            || !(self.virtual_path == "/project" || self.virtual_path.starts_with("/project/"))
        {
            return Err("resolver virtual path is outside /project");
        }
        if !self.logical_path.is_canonical() || self.logical_path.host_bound.is_some() {
            return Err("resolver logical path is not canonical and host-independent");
        }
        match self.logical_path.root {
            LogicalRoot::Project if self.binding_owner.is_none() => Ok(()),
            LogicalRoot::Package
                if self
                    .binding_owner
                    .as_ref()
                    .is_some_and(|owner| matches!(owner, Principal::Package { .. })) =>
            {
                Ok(())
            }
            _ => Err("resolver logical root and binding owner disagree"),
        }
    }
}

#[derive(Debug)]
struct SessionIdentity {
    generation: u64,
    alive: AtomicBool,
}

#[derive(Clone)]
pub struct VfsSessionHandle(Arc<SessionIdentity>);

impl PartialEq for VfsSessionHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for VfsSessionHandle {}

impl fmt::Debug for VfsSessionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VfsSessionHandle(<opaque>)")
    }
}

impl VfsSessionHandle {
    pub fn generation(&self) -> u64 {
        self.0.generation
    }
}

#[derive(Clone)]
struct BackingMount {
    host_root: PathBuf,
    root_object: ObjectIdentity,
}

#[derive(Clone, Debug)]
struct PackageBinding {
    owner: Principal,
    virtual_prefix: Arc<[Arc<str>]>,
    root_object: ObjectIdentity,
}

/// A session-local VFS. Construction consumes only authenticated snapshot
/// facts and performs no host lookup.
#[derive(Clone)]
pub struct VirtualFileSystem {
    session: VfsSessionHandle,
    snapshot_digest: Option<Digest>,
    mount: Arc<BackingMount>,
    mounts: Arc<[MountDescriptor]>,
    root_principal: Principal,
    package_bindings: Arc<[PackageBinding]>,
}

impl fmt::Debug for VirtualFileSystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VirtualFileSystem")
            .field("session", &self.session)
            .field("mounts", &self.mounts)
            .finish_non_exhaustive()
    }
}

struct RetainedDirectory {
    namespace: NamespacePath,
    object: ObjectIdentity,
    #[cfg(any(unix, windows))]
    retained: std::fs::File,
}

/// Private translation result used only by native filesystem adapters.
///
/// `backing_path` is never serialized or exposed to JavaScript. The separate
/// virtual spelling is the only value suitable for diagnostics and public
/// path-bearing fields.
#[derive(Debug)]
pub(crate) struct ResolvedPrivatePath {
    backing_path: Vec<u8>,
    virtual_path: Vec<u8>,
}

impl ResolvedPrivatePath {
    #[cfg(test)]
    pub(crate) fn backing_path(&self) -> &[u8] {
        &self.backing_path
    }

    #[cfg(test)]
    pub(crate) fn virtual_path(&self) -> &[u8] {
        &self.virtual_path
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.backing_path, self.virtual_path)
    }
}

/// Runtime-local namespace state bound to one native runtime generation.
///
/// The runtime nonce is engine-authenticated provenance, not a JavaScript
/// assertion. Initial construction opens `/project` through the authenticated
/// root binding and retains that exact directory object. Later relative
/// resolutions re-verify both its handle and canonical namespace before forming
/// the requested child path.
/// @ref LLP 0023#5-the-virtual-resolution-base-working-directory
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
pub(crate) struct RuntimeVfsSession {
    runtime_nonce: NonZeroU64,
    vfs: VirtualFileSystem,
    cwd: Mutex<RetainedDirectory>,
    alive: AtomicBool,
}

/// Opaque Rust-side lease over one authenticated native runtime's VFS state.
///
/// Callers cannot construct this from a nonce or a virtual spelling. The Host
/// registry mints it only after matching an engine-supplied runtime generation
/// to the exact cloned Host identity that was claimed at native construction.
/// A retained lease does not extend the generation: native teardown closes the
/// underlying session, after which every operation fails stale.
/// @ref LLP 0023#5-the-virtual-resolution-base-working-directory
/// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
#[derive(Clone)]
pub struct AuthenticatedRuntimeVfs(Arc<RuntimeVfsSession>);

impl fmt::Debug for AuthenticatedRuntimeVfs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatedRuntimeVfs(<opaque>)")
    }
}

impl AuthenticatedRuntimeVfs {
    pub(crate) fn new(session: Arc<RuntimeVfsSession>) -> Self {
        Self(session)
    }

    /// Capture the exact retained cwd namespace for this runtime generation.
    /// Capture re-verifies the retained object before returning its logical
    /// identity, so a replaced or moved base fails instead of being reduced to
    /// a trusted-looking string.
    pub fn capture_cwd(&self) -> Result<NamespacePath, VfsError> {
        self.0.current_namespace()
    }

    /// Resolve untrusted path syntax against this runtime's retained cwd.
    pub fn resolve(&self, input: &[u8]) -> Result<NamespacePath, VfsError> {
        self.0.resolve_namespace(input)
    }

    /// Immutable mount descriptors for this live runtime generation.
    pub fn mounts(&self) -> Result<&[MountDescriptor], VfsError> {
        self.0.ensure_live("mounts", None)?;
        Ok(self.0.vfs.mounts())
    }

    /// The exact VFS whose session identity appears on namespaces minted by
    /// this lease. This is intentionally an immutable borrow: callers can use
    /// it for typed Host reads but cannot replace the runtime's cwd.
    #[doc(hidden)]
    pub fn virtual_file_system(&self) -> Result<&VirtualFileSystem, VfsError> {
        self.0.ensure_live("resolve", None)?;
        Ok(&self.0.vfs)
    }
}

impl fmt::Debug for RuntimeVfsSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeVfsSession")
            .field("runtime_nonce", &"<opaque>")
            .field("vfs", &self.vfs)
            .finish_non_exhaustive()
    }
}

impl RuntimeVfsSession {
    pub(crate) fn new(runtime_nonce: NonZeroU64, vfs: VirtualFileSystem) -> Result<Self, VfsError> {
        let namespace = vfs.default_base()?;
        let cwd = vfs.retain_directory(namespace, "mount", |_| Ok(()))?;
        Ok(Self {
            runtime_nonce,
            vfs,
            cwd: Mutex::new(cwd),
            alive: AtomicBool::new(true),
        })
    }

    pub(crate) fn runtime_nonce(&self) -> NonZeroU64 {
        self.runtime_nonce
    }

    pub(crate) fn close(&self) {
        self.alive.store(false, Ordering::Release);
        self.vfs.close();
    }

    fn current_namespace(&self) -> Result<NamespacePath, VfsError> {
        self.ensure_live("cwd", None)?;
        let mut cwd = lock_recover(&self.cwd);
        self.vfs.verify_retained_directory(&mut cwd, "cwd")?;
        let result = cwd.namespace.clone();
        self.ensure_live("cwd", Some(result.virtual_path.clone()))?;
        Ok(result)
    }

    pub(crate) fn current_cwd(&self) -> Result<Vec<u8>, VfsError> {
        Ok(self.current_namespace()?.virtual_path().as_bytes().to_vec())
    }

    fn resolve_namespace(&self, input: &[u8]) -> Result<NamespacePath, VfsError> {
        self.ensure_live("resolve", None)?;
        let is_absolute = input.first() == Some(&b'/');
        let namespace = if is_absolute {
            self.vfs.resolve_root_bytes(input, None)?
        } else {
            let mut cwd = lock_recover(&self.cwd);
            self.vfs.verify_retained_directory(&mut cwd, "resolve")?;
            self.vfs.resolve_root_bytes(input, Some(&cwd.namespace))?
        };
        self.ensure_live("resolve", Some(namespace.virtual_path.clone()))?;
        Ok(namespace)
    }

    /// Resolve untrusted lexical syntax against this runtime's authenticated
    /// cwd and return separate private/public spellings. This performs no
    /// target lookup. A relative input first re-verifies the retained cwd,
    /// because a stale base must fail before the requested child is formed.
    pub(crate) fn resolve_private_path(
        &self,
        input: &[u8],
    ) -> Result<ResolvedPrivatePath, VfsError> {
        let namespace = self.resolve_namespace(input)?;
        let backing_path = self.vfs.private_backing_path_bytes(&namespace, "resolve")?;
        self.ensure_live("resolve", Some(namespace.virtual_path.clone()))?;
        Ok(ResolvedPrivatePath {
            virtual_path: namespace.virtual_path().as_bytes().to_vec(),
            backing_path,
        })
    }

    /// Project a canonical backing identity produced by an already-retained
    /// native target into this runtime generation's logical namespace. The
    /// backing bytes are input-only and the returned bytes are always a
    /// canonical virtual spelling.
    ///
    /// This is deliberately narrower than general path resolution: native
    /// filesystem code must first authenticate/retain the target and supply
    /// its canonical OS identity. The session binding then supplies the only
    /// admissible host-to-logical mapping.
    /// @ref LLP 0023#6-path-bearing-observables
    /// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
    pub(crate) fn project_realpath_identity(
        &self,
        requested_virtual: &[u8],
        canonical_backing: &[u8],
    ) -> Result<Vec<u8>, VfsError> {
        self.ensure_live("realpath", None)?;
        let requested = self.vfs.resolve_root_bytes(requested_virtual, None)?;
        if requested.is_synthetic_root() {
            return Err(VfsError::synthetic_node(
                "realpath",
                requested.virtual_path.clone(),
            ));
        }
        let safe_path = requested.virtual_path.clone();
        let canonical_root = self
            .vfs
            .verified_canonical_root("realpath", safe_path.clone())?;
        #[cfg(unix)]
        let canonical_target = {
            use std::os::unix::ffi::OsStrExt as _;
            PathBuf::from(std::ffi::OsStr::from_bytes(canonical_backing))
        };
        #[cfg(not(unix))]
        let canonical_target = PathBuf::from(
            std::str::from_utf8(canonical_backing).map_err(|_| VfsError::malformed("realpath"))?,
        );
        if !canonical_target.is_absolute() {
            return Err(VfsError::malformed("realpath"));
        }
        let virtual_path = virtual_path_for_authenticated_project_path(
            &canonical_root,
            &canonical_target,
            "realpath",
        )?;
        let projected = self.vfs.resolve_root_bytes(virtual_path.as_bytes(), None)?;
        self.ensure_live("realpath", Some(projected.virtual_path.clone()))?;
        Ok(projected.virtual_path().as_bytes().to_vec())
    }

    /// Atomically replace this runtime's cwd after the target has been resolved,
    /// contained, observed to be a directory, and retained. The caller must
    /// take the typed cwd-mutation and directory-metadata decisions before
    /// invoking this private native operation.
    #[cfg(test)]
    pub(crate) fn chdir(&self, input: &[u8]) -> Result<Vec<u8>, VfsError> {
        self.chdir_authorized(input, |_, _, _, _| Ok(()))
    }

    /// Stage cwd authorization around the exact retained-directory lookup and
    /// commit. The requested callback runs before target lookup; the commit
    /// callback sees the verified replacement identity while the cwd mutex is
    /// still held, so a denial leaves the prior cwd intact.
    pub(crate) fn chdir_authorized<F>(
        &self,
        input: &[u8],
        mut authorize: F,
    ) -> Result<Vec<u8>, VfsError>
    where
        F: FnMut(
            capsec_semantics::model::Stage,
            &std::path::Path,
            &NamespacePath,
            Option<&ObjectIdentity>,
        ) -> Result<(), VfsError>,
    {
        self.ensure_live("chdir", None)?;
        let mut cwd = lock_recover(&self.cwd);
        let is_absolute = input.first() == Some(&b'/');
        let namespace = if is_absolute {
            self.vfs.resolve_root_bytes(input, None)?
        } else {
            self.vfs.verify_retained_directory(&mut cwd, "chdir")?;
            self.vfs.resolve_root_bytes(input, Some(&cwd.namespace))?
        };
        let requested_backing = self.vfs.private_backing_path(&namespace, "chdir")?;
        authorize(
            capsec_semantics::model::Stage::Requested,
            &requested_backing,
            &namespace,
            None,
        )?;
        let mut replacement =
            self.vfs
                .retain_directory(namespace, "chdir", |target_namespace| {
                    let target_backing =
                        self.vfs.private_backing_path(target_namespace, "chdir")?;
                    authorize(
                        capsec_semantics::model::Stage::Requested,
                        &target_backing,
                        target_namespace,
                        None,
                    )
                })?;
        let committed_backing = self
            .vfs
            .private_backing_path(&replacement.namespace, "chdir")?;
        authorize(
            capsec_semantics::model::Stage::Commit,
            &committed_backing,
            &replacement.namespace,
            Some(&replacement.object),
        )?;
        // The authorization callback may run arbitrary host policy code while
        // another process mutates the backing tree. Reopen the canonical
        // namespace from the authenticated root descriptor after that callback
        // and compare it with the exact retained target before publishing cwd.
        self.vfs
            .verify_retained_directory(&mut replacement, "chdir")?;
        let virtual_path = replacement.namespace.virtual_path().as_bytes().to_vec();
        self.ensure_live("chdir", Some(replacement.namespace.virtual_path.clone()))?;
        *cwd = replacement;
        Ok(virtual_path)
    }

    fn ensure_live(&self, operation: &str, path: Option<Arc<str>>) -> Result<(), VfsError> {
        if !self.alive.load(Ordering::Acquire) {
            return Err(VfsError::stale_session(operation, path));
        }
        self.vfs.ensure_live(operation, path)
    }
}

impl Drop for RuntimeVfsSession {
    fn drop(&mut self) {
        self.close();
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl VirtualFileSystem {
    /// Build the v1 `/project` mount from the exact authenticated project
    /// binding. Other armed roots remain native-only.
    /// @ref LLP 0023#1-the-mount-table-the-project-root-and-package-bindings
    pub fn from_armed_snapshot(snapshot: &ArmedSnapshot) -> Result<Self, VfsError> {
        let bindings = snapshot
            .root_bindings()
            .map_err(|_| VfsError::malformed("mount"))?;
        let project = bindings
            .iter()
            .filter(|binding| binding.logical_root == LogicalRoot::Project)
            .collect::<Vec<_>>();
        if project.len() != 1 || project[0].owner.is_some() {
            return Err(VfsError::malformed("mount"));
        }
        let project = project[0];
        let host_root = host_path_from_binding(project)?;
        let root_principal: Principal = serde_json::from_value(
            snapshot
                .document()
                .get("rootIdentity")
                .cloned()
                .ok_or_else(|| VfsError::malformed("mount"))?,
        )
        .map_err(|_| VfsError::malformed("mount"))?;
        if !root_principal.is_root() {
            return Err(VfsError::malformed("mount"));
        }
        Self::from_bindings(
            host_root,
            project.object.clone(),
            root_principal,
            bindings,
            Some(snapshot.digest().clone()),
        )
    }

    fn from_bindings(
        host_root: PathBuf,
        root_object: ObjectIdentity,
        root_principal: Principal,
        bindings: &[ArmedRootBinding],
        snapshot_digest: Option<Digest>,
    ) -> Result<Self, VfsError> {
        let public = MountDescriptor {
            virtual_path: Arc::from("/project"),
            logical_root: LogicalRoot::Project,
            attributes: MountAttributes {
                write_policy: MountWritePolicy::TypedProjectPolicy,
                symlink_policy: MountSymlinkPolicy::ContainedFollow,
                lifecycle: MountLifecycle::Session,
                metadata_only: false,
            },
        };
        let mount = Arc::new(BackingMount {
            host_root,
            root_object,
        });
        let project_components = bindings
            .iter()
            .find(|binding| binding.logical_root == LogicalRoot::Project)
            .map(|binding| binding.host_path.components.as_slice());
        let mut package_bindings = Vec::new();
        if let Some(project_components) = project_components {
            for binding in bindings
                .iter()
                .filter(|binding| binding.logical_root == LogicalRoot::Package)
            {
                let owner = binding
                    .owner
                    .clone()
                    .ok_or_else(|| VfsError::malformed("mount"))?;
                let relative = binding
                    .host_path
                    .components
                    .strip_prefix(project_components)
                    .ok_or_else(|| VfsError::malformed("mount"))?;
                let virtual_prefix = relative
                    .iter()
                    .map(|component| {
                        std::str::from_utf8(component.bytes())
                            .map(Arc::<str>::from)
                            .map_err(|_| VfsError::malformed("mount"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                package_bindings.push(PackageBinding {
                    owner,
                    virtual_prefix: virtual_prefix.into(),
                    root_object: binding.object.clone(),
                });
            }
        }
        package_bindings.sort_by(|left, right| {
            right
                .virtual_prefix
                .len()
                .cmp(&left.virtual_prefix.len())
                .then_with(|| left.owner.cmp(&right.owner))
        });
        if package_bindings
            .windows(2)
            .any(|pair| pair[0].virtual_prefix == pair[1].virtual_prefix)
        {
            return Err(VfsError::malformed("mount"));
        }
        let generation = next_vfs_identity("mount", None)?;
        Ok(Self {
            session: VfsSessionHandle(Arc::new(SessionIdentity {
                generation,
                alive: AtomicBool::new(true),
            })),
            snapshot_digest,
            mount,
            mounts: Arc::from([public]),
            root_principal,
            package_bindings: package_bindings.into(),
        })
    }

    pub fn session_handle(&self) -> VfsSessionHandle {
        self.session.clone()
    }

    pub(crate) fn snapshot_digest(&self) -> Option<&Digest> {
        self.snapshot_digest.as_ref()
    }

    pub(crate) fn root_principal(&self) -> &Principal {
        &self.root_principal
    }

    pub fn mounts(&self) -> &[MountDescriptor] {
        &self.mounts
    }

    /// The synthetic root's deterministic directory listing.
    pub fn mount_names(&self) -> impl ExactSizeIterator<Item = &str> {
        self.mounts
            .iter()
            .map(|mount| mount.virtual_path.trim_start_matches('/'))
    }

    /// Stop new use of every path and lease minted by this session.
    pub fn close(&self) {
        self.session.0.alive.store(false, Ordering::Release);
    }

    pub fn default_base(&self) -> Result<NamespacePath, VfsError> {
        self.resolve_bytes(&self.root_principal, b"/project", None)
    }

    pub(crate) fn private_backing_path(
        &self,
        namespace: &NamespacePath,
        operation: &str,
    ) -> Result<PathBuf, VfsError> {
        self.ensure_path_session(namespace, operation)?;
        if namespace.is_synthetic_root() {
            return Err(VfsError::synthetic_node(
                operation,
                namespace.virtual_path.clone(),
            ));
        }
        let mut path = self.mount.host_root.clone();
        for component in &namespace.virtual_components[1..] {
            path.push(component.as_ref());
        }
        Ok(path)
    }

    /// Translate a typed NamespacePath into private backing bytes. Callers must
    /// keep these bytes inside the native adapter and use `NamespacePath`'s
    /// virtual spelling for every JavaScript-visible value and error.
    fn private_backing_path_bytes(
        &self,
        namespace: &NamespacePath,
        operation: &str,
    ) -> Result<Vec<u8>, VfsError> {
        let path = self.private_backing_path(namespace, operation)?;
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            Ok(path.as_os_str().as_bytes().to_vec())
        }
        #[cfg(not(unix))]
        {
            path.to_str()
                .map(|path| path.as_bytes().to_vec())
                .ok_or_else(|| VfsError::malformed(operation))
        }
    }

    fn verified_canonical_root(
        &self,
        operation: &str,
        virtual_path: Arc<str>,
    ) -> Result<PathBuf, VfsError> {
        let root_metadata = std::fs::symlink_metadata(&self.mount.host_root)
            .map_err(|_| VfsError::stale_identity(operation, virtual_path.clone()))?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(VfsError::stale_identity(operation, virtual_path));
        }
        let root_object = object_identity_for_host_path(&self.mount.host_root)
            .map_err(|_| VfsError::stale_identity(operation, virtual_path.clone()))?;
        if root_object != self.mount.root_object {
            return Err(VfsError::stale_identity(operation, virtual_path));
        }
        std::fs::canonicalize(&self.mount.host_root)
            .map_err(|_| VfsError::stale_identity(operation, virtual_path))
    }

    fn retain_directory<F>(
        &self,
        namespace: NamespacePath,
        operation: &str,
        authorize_target: F,
    ) -> Result<RetainedDirectory, VfsError>
    where
        F: FnMut(&NamespacePath) -> Result<(), VfsError>,
    {
        self.ensure_path_session(&namespace, operation)?;
        if namespace.is_synthetic_root() {
            return Err(VfsError::synthetic_node(
                operation,
                namespace.virtual_path.clone(),
            ));
        }

        #[cfg(unix)]
        {
            self.open_contained_directory(namespace, operation, true, authorize_target)
        }

        #[cfg(windows)]
        {
            let _ = authorize_target;
            if namespace.virtual_components.len() != 1 {
                return Err(VfsError::host_code(
                    operation,
                    namespace.virtual_path.clone(),
                    "ERR_IBEX_UNSUPPORTED_TARGET",
                ));
            }
            let retained =
                self.open_authenticated_project_root(operation, namespace.virtual_path.clone())?;
            let object = object_identity_for_open_file(&retained)
                .map_err(|_| VfsError::stale_identity(operation, namespace.virtual_path.clone()))?;
            Ok(RetainedDirectory {
                namespace,
                object,
                retained,
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = authorize_target;
            Err(VfsError::host_code(
                operation,
                namespace.virtual_path.clone(),
                "ERR_IBEX_UNSUPPORTED_TARGET",
            ))
        }
    }

    fn verify_retained_directory(
        &self,
        retained: &mut RetainedDirectory,
        operation: &str,
    ) -> Result<(), VfsError> {
        self.ensure_path_session(&retained.namespace, operation)?;
        let safe_path = retained.namespace.virtual_path.clone();

        #[cfg(unix)]
        {
            let metadata = retained
                .retained
                .metadata()
                .map_err(|_| VfsError::stale_identity(operation, safe_path.clone()))?;
            let object = object_identity_for_metadata(&metadata)
                .map_err(|_| VfsError::stale_identity(operation, safe_path.clone()))?;
            if !metadata.is_dir() || object != retained.object {
                return Err(VfsError::stale_identity(operation, safe_path));
            }

            // A retained descriptor alone is not enough: the directory might
            // have been renamed or moved outside the binding. Reopen the exact
            // canonical namespace from a descriptor for the authenticated root,
            // refusing symlinks, and require that it reaches the retained object.
            let reopened = self
                .open_contained_directory(retained.namespace.clone(), operation, false, |_| Ok(()))
                .map_err(|error| {
                    if error.reason() == VfsReason::StaleSession {
                        error
                    } else {
                        VfsError::stale_identity(operation, safe_path.clone())
                    }
                })?;
            if reopened.object != retained.object {
                return Err(VfsError::stale_identity(operation, safe_path));
            }
            Ok(())
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt as _;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

            let metadata = retained
                .retained
                .metadata()
                .map_err(|_| VfsError::stale_identity(operation, safe_path.clone()))?;
            let object = object_identity_for_open_file(&retained.retained)
                .map_err(|_| VfsError::stale_identity(operation, safe_path.clone()))?;
            if !metadata.is_dir()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || object != retained.object
            {
                return Err(VfsError::stale_identity(operation, safe_path));
            }
            let reopened = self.open_authenticated_project_root(operation, safe_path.clone())?;
            let reopened_object = object_identity_for_open_file(&reopened)
                .map_err(|_| VfsError::stale_identity(operation, safe_path.clone()))?;
            if reopened_object != retained.object {
                return Err(VfsError::stale_identity(operation, safe_path));
            }
            Ok(())
        }

        #[cfg(not(any(unix, windows)))]
        {
            Err(VfsError::host_code(
                operation,
                safe_path,
                "ERR_IBEX_UNSUPPORTED_TARGET",
            ))
        }
    }

    #[cfg(unix)]
    fn open_authenticated_project_root(
        &self,
        operation: &str,
        safe_path: Arc<str>,
    ) -> Result<std::fs::File, VfsError> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let root = options.open(&self.mount.host_root).map_err(|error| {
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) || error.raw_os_error() == Some(libc::ELOOP)
            {
                VfsError::stale_identity(operation, safe_path.clone())
            } else {
                VfsError::host(operation, safe_path.clone(), &error)
            }
        })?;
        let metadata = root
            .metadata()
            .map_err(|error| VfsError::host(operation, safe_path.clone(), &error))?;
        let object = object_identity_for_metadata(&metadata)
            .map_err(|_| VfsError::stale_identity(operation, safe_path.clone()))?;
        if !metadata.is_dir() || object != self.mount.root_object {
            return Err(VfsError::stale_identity(operation, safe_path));
        }
        Ok(root)
    }

    /// Windows startup retains the authenticated `/project` object even while
    /// deeper descriptor-relative traversal remains fail-closed. Opening the
    /// reparse point itself and rejecting its attribute prevents a junction or
    /// symlink from being mistaken for the armed root.
    /// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
    #[cfg(windows)]
    fn open_authenticated_project_root(
        &self,
        operation: &str,
        safe_path: Arc<str>,
    ) -> Result<std::fs::File, VfsError> {
        use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };

        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
        let root = options
            .open(&self.mount.host_root)
            .map_err(|error| VfsError::host(operation, safe_path.clone(), &error))?;
        let metadata = root
            .metadata()
            .map_err(|error| VfsError::host(operation, safe_path.clone(), &error))?;
        let object = object_identity_for_open_file(&root)
            .map_err(|_| VfsError::stale_identity(operation, safe_path.clone()))?;
        if !metadata.is_dir()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || object != self.mount.root_object
        {
            return Err(VfsError::stale_identity(operation, safe_path));
        }
        Ok(root)
    }

    #[cfg(unix)]
    fn verify_directory_handle_in_current_mount(
        &self,
        handle: &std::fs::File,
        operation: &str,
        safe_path: Arc<str>,
        pause_for_test: bool,
    ) -> Result<(), VfsError> {
        if !directory_handle_descends_from_object(handle, &self.mount.root_object) {
            return Err(VfsError::stale_identity(operation, safe_path));
        }
        if pause_for_test {
            pause_before_cwd_mount_reverification(&self.mount.host_root);
        }
        // The downward descriptor walk proves how the target was reached; the
        // upward walk above proves its current ancestry. Reopening the mount
        // pathname last also refuses a root that was renamed out and replaced
        // while either walk was in progress.
        let _current_root = self.open_authenticated_project_root(operation, safe_path)?;
        Ok(())
    }

    #[cfg(unix)]
    fn open_contained_directory<F>(
        &self,
        namespace: NamespacePath,
        operation: &str,
        follow_symlinks: bool,
        mut authorize_target: F,
    ) -> Result<RetainedDirectory, VfsError>
    where
        F: FnMut(&NamespacePath) -> Result<(), VfsError>,
    {
        use std::collections::VecDeque;
        use std::ffi::CString;
        use std::os::fd::AsRawFd;

        const MAX_SYMLINKS: usize = 32;
        let safe_path = namespace.virtual_path.clone();
        let root = self.open_authenticated_project_root(operation, safe_path.clone())?;
        if follow_symlinks {
            pause_after_authenticated_cwd_root_open(&self.mount.host_root);
        }
        let caller = namespace.caller.clone();
        let mut final_namespace = namespace;
        let mut pending = final_namespace.virtual_components[1..]
            .iter()
            .cloned()
            .collect::<VecDeque<_>>();
        let mut current = root
            .try_clone()
            .map_err(|error| VfsError::host(operation, safe_path.clone(), &error))?;
        let mut physical_parent = Vec::<Arc<str>>::new();
        let mut symlink_count = 0usize;

        loop {
            let Some(component) = pending.pop_front() else {
                let metadata = current.metadata().map_err(|error| {
                    VfsError::host(operation, final_namespace.virtual_path.clone(), &error)
                })?;
                let object = object_identity_for_metadata(&metadata).map_err(|_| {
                    VfsError::stale_identity(operation, final_namespace.virtual_path.clone())
                })?;
                if !metadata.is_dir() || object != self.mount.root_object {
                    return Err(VfsError::stale_identity(
                        operation,
                        final_namespace.virtual_path.clone(),
                    ));
                }
                self.verify_directory_handle_in_current_mount(
                    &current,
                    operation,
                    final_namespace.virtual_path.clone(),
                    follow_symlinks,
                )?;
                return Ok(RetainedDirectory {
                    namespace: self.namespace_from_project_relative(&caller, Vec::new(), false)?,
                    object,
                    retained: current,
                });
            };
            let component_c =
                CString::new(component.as_bytes()).map_err(|_| VfsError::malformed(operation))?;
            let witnessed =
                stat_at_no_follow(current.as_raw_fd(), &component_c).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        VfsError::absent(operation, final_namespace.virtual_path.clone())
                    } else {
                        VfsError::host(operation, final_namespace.virtual_path.clone(), &error)
                    }
                })?;
            let witnessed_object = object_identity_for_unix_stat(&witnessed).map_err(|_| {
                VfsError::stale_identity(operation, final_namespace.virtual_path.clone())
            })?;
            let mut witnessed_components = physical_parent.clone();
            witnessed_components.push(component.clone());
            self.verify_authenticated_binding_root(
                &witnessed_components,
                &witnessed_object,
                operation,
                final_namespace.virtual_path.clone(),
            )?;

            if unix_stat_is_symlink(&witnessed) {
                if !follow_symlinks {
                    return Err(VfsError::stale_identity(
                        operation,
                        final_namespace.virtual_path.clone(),
                    ));
                }
                symlink_count += 1;
                if symlink_count > MAX_SYMLINKS {
                    return Err(VfsError::symlink_depth(
                        operation,
                        final_namespace.virtual_path.clone(),
                    ));
                }
                let target_bytes =
                    readlinkat_bytes(current.as_raw_fd(), &component_c).map_err(|error| {
                        VfsError::host(operation, final_namespace.virtual_path.clone(), &error)
                    })?;
                let after = stat_at_no_follow(current.as_raw_fd(), &component_c).map_err(|_| {
                    VfsError::stale_identity(operation, final_namespace.virtual_path.clone())
                })?;
                let after_object = object_identity_for_unix_stat(&after).map_err(|_| {
                    VfsError::stale_identity(operation, final_namespace.virtual_path.clone())
                })?;
                if after_object != witnessed_object || !unix_stat_is_symlink(&after) {
                    return Err(VfsError::stale_identity(
                        operation,
                        final_namespace.virtual_path.clone(),
                    ));
                }
                let target = std::str::from_utf8(&target_bytes)
                    .map_err(|_| VfsError::malformed(operation))?;
                if target.is_empty() || target.contains('\0') {
                    return Err(VfsError::malformed(operation));
                }
                let target_components = if target.starts_with('/') {
                    absolute_link_target_under_mount(&self.mount.host_root, target).map_err(
                        |_| {
                            VfsError::outside_mount(operation, final_namespace.virtual_path.clone())
                        },
                    )?
                } else {
                    relative_link_target_under_mount(&physical_parent, target).map_err(|_| {
                        VfsError::outside_mount(operation, final_namespace.virtual_path.clone())
                    })?
                };
                let mut combined = target_components;
                combined.extend(pending);
                let target_namespace =
                    self.namespace_from_project_relative(&caller, combined.clone(), false)?;
                // Authorize the complete substituted path before restarting
                // traversal. Authorizing only the raw link target leaves an
                // ancestor+pending-tail gap where the tail can enter another
                // authenticated binding before the next callback.
                authorize_target(&target_namespace)?;
                final_namespace = target_namespace;
                pending = combined.into_iter().collect();
                current = root.try_clone().map_err(|error| {
                    VfsError::host(operation, final_namespace.virtual_path.clone(), &error)
                })?;
                physical_parent.clear();
                continue;
            }

            let opened =
                openat_directory_no_follow(current.as_raw_fd(), &component_c).map_err(|error| {
                    if stat_at_no_follow(current.as_raw_fd(), &component_c)
                        .ok()
                        .and_then(|stat| object_identity_for_unix_stat(&stat).ok())
                        .as_ref()
                        != Some(&witnessed_object)
                    {
                        VfsError::stale_identity(operation, final_namespace.virtual_path.clone())
                    } else {
                        VfsError::host(operation, final_namespace.virtual_path.clone(), &error)
                    }
                })?;
            let metadata = opened.metadata().map_err(|error| {
                VfsError::host(operation, final_namespace.virtual_path.clone(), &error)
            })?;
            let opened_object = object_identity_for_metadata(&metadata).map_err(|_| {
                VfsError::stale_identity(operation, final_namespace.virtual_path.clone())
            })?;
            if !metadata.is_dir() || opened_object != witnessed_object {
                return Err(VfsError::stale_identity(
                    operation,
                    final_namespace.virtual_path.clone(),
                ));
            }
            physical_parent.push(component);
            if pending.is_empty() {
                let retained_namespace =
                    self.namespace_from_project_relative(&caller, physical_parent, false)?;
                self.verify_directory_handle_in_current_mount(
                    &opened,
                    operation,
                    retained_namespace.virtual_path.clone(),
                    follow_symlinks,
                )?;
                return Ok(RetainedDirectory {
                    namespace: retained_namespace,
                    object: opened_object,
                    retained: opened,
                });
            }
            current = opened;
        }
    }

    /// Translate an already-authenticated canonical host path beneath the
    /// project binding into its typed virtual identity. This is the only
    /// host-to-entry-label bridge: undecodable components are refused rather
    /// than lossily aliased.
    pub fn namespace_for_authenticated_project_path(
        &self,
        path: &std::path::Path,
    ) -> Result<NamespacePath, VfsError> {
        let virtual_path = virtual_path_for_authenticated_project_path(
            &self.mount.host_root,
            path,
            "entry-label",
        )?;
        self.resolve_root_bytes(virtual_path.as_bytes(), None)
    }

    /// Canonical virtual `file:///project/...` display identity for an
    /// authenticated file entry. Host components never enter the result.
    pub fn source_label_for_authenticated_project_path(
        &self,
        path: &std::path::Path,
    ) -> Result<SourceLabel, VfsError> {
        source_label_for_authenticated_project_path(&self.mount.host_root, path)
    }

    pub fn resolve_root_bytes(
        &self,
        input: &[u8],
        base: Option<&NamespacePath>,
    ) -> Result<NamespacePath, VfsError> {
        self.resolve_bytes(&self.root_principal, input, base)
    }

    /// Resolve a digest-bound file-entry URL as the authenticated session
    /// Root. This is the file-program counterpart to `resolve_root_bytes`: the
    /// caller cannot substitute a principal, and URL parsing remains entirely
    /// inside the virtual namespace.
    pub fn resolve_root_file_url(
        &self,
        url: &str,
        base: Option<&NamespacePath>,
    ) -> Result<NamespacePath, VfsError> {
        self.resolve_file_url(&self.root_principal, url, base)
    }

    /// Resolve strict UTF-8 path bytes using POSIX lexical rules. Containment is
    /// decided after dot-segment collapse and before any backing-store access.
    /// @ref LLP 0023#3-path-grammar-normalization-aliasing-and-containment
    pub fn resolve_bytes(
        &self,
        caller: &Principal,
        input: &[u8],
        base: Option<&NamespacePath>,
    ) -> Result<NamespacePath, VfsError> {
        let text = std::str::from_utf8(input).map_err(|_| VfsError::malformed("resolve"))?;
        self.resolve_text(caller, text, base, "resolve")
    }

    /// UTF-16 adapter entry point. Rust strings cannot contain a lone surrogate,
    /// so an adapter that starts from engine code units must validate here.
    pub fn resolve_utf16(
        &self,
        caller: &Principal,
        input: &[u16],
        base: Option<&NamespacePath>,
    ) -> Result<NamespacePath, VfsError> {
        let text = String::from_utf16(input).map_err(|_| VfsError::malformed("resolve"))?;
        self.resolve_text(caller, &text, base, "resolve")
    }

    /// Parse a file URL without ever converting it to a host URL. `%2F` is
    /// refused before decoding; `%5C` is an ordinary POSIX component byte.
    pub fn resolve_file_url(
        &self,
        caller: &Principal,
        url: &str,
        base: Option<&NamespacePath>,
    ) -> Result<NamespacePath, VfsError> {
        let Some(rest) = url
            .get(..5)
            .filter(|scheme| scheme.eq_ignore_ascii_case("file:"))
        else {
            return Err(VfsError::malformed("file-url"));
        };
        let mut rest = &url[rest.len()..];
        let end = rest.find(['?', '#']).unwrap_or(rest.len());
        rest = &rest[..end];
        let path = if let Some(authority_and_path) = rest.strip_prefix("//") {
            let slash = authority_and_path
                .find('/')
                .unwrap_or(authority_and_path.len());
            let authority = &authority_and_path[..slash];
            if !(authority.is_empty() || authority.eq_ignore_ascii_case("localhost")) {
                return Err(VfsError::malformed("file-url"));
            }
            authority_and_path.get(slash..).unwrap_or("")
        } else {
            rest
        };
        if !path.starts_with('/') {
            return Err(VfsError::malformed("file-url"));
        }
        let decoded = decode_file_url_path(path.as_bytes())?;
        let decoded = std::str::from_utf8(&decoded).map_err(|_| VfsError::malformed("file-url"))?;
        self.resolve_text(caller, decoded, base, "file-url")
    }

    fn resolve_text(
        &self,
        caller: &Principal,
        input: &str,
        base: Option<&NamespacePath>,
        operation: &str,
    ) -> Result<NamespacePath, VfsError> {
        self.ensure_live(operation, None)?;
        if input.is_empty() || input.contains('\0') {
            return Err(VfsError::malformed(operation));
        }
        let directory_intent = input.ends_with('/');
        let mut components = if input.starts_with('/') {
            Vec::<Arc<str>>::new()
        } else if let Some(base) = base {
            self.ensure_path_session(base, operation)?;
            base.virtual_components.to_vec()
        } else {
            vec![Arc::from(PROJECT_MOUNT)]
        };
        for component in input.split('/') {
            match component {
                "" | "." => {}
                ".." => {
                    components.pop();
                }
                component => {
                    if !virtual_component_is_mappable(component, cfg!(windows)) {
                        return Err(VfsError::malformed(operation));
                    }
                    components.push(Arc::from(component));
                }
            }
        }
        let virtual_path = virtual_path_string(&components);
        if components.is_empty() {
            return Ok(NamespacePath {
                session: self.session.clone(),
                caller: caller.clone(),
                virtual_components: components.into(),
                virtual_path,
                directory_intent,
                projection: None,
            });
        }
        if components.first().map(AsRef::as_ref) != Some(PROJECT_MOUNT) {
            return Err(VfsError::outside_mount(operation, virtual_path));
        }
        let relative = &components[1..];
        let projection = self.project_for_caller(caller, relative);
        Ok(NamespacePath {
            session: self.session.clone(),
            caller: caller.clone(),
            virtual_components: components.into(),
            virtual_path,
            directory_intent,
            projection: Some(projection),
        })
    }

    fn project_for_caller(&self, caller: &Principal, relative: &[Arc<str>]) -> PathProjection {
        let deepest_foreign = self
            .package_bindings
            .iter()
            .find(|binding| components_start_with(relative, &binding.virtual_prefix));
        if let Some(binding) = deepest_foreign.filter(|binding| &binding.owner == caller) {
            return PathProjection {
                logical_root: LogicalRoot::Package,
                binding_owner: Some(binding.owner.clone()),
                relative_components: relative[binding.virtual_prefix.len()..].into(),
            };
        }
        PathProjection {
            logical_root: LogicalRoot::Project,
            binding_owner: None,
            relative_components: relative.into(),
        }
    }

    fn namespace_from_project_relative(
        &self,
        caller: &Principal,
        relative: Vec<Arc<str>>,
        directory_intent: bool,
    ) -> Result<NamespacePath, VfsError> {
        self.ensure_live("read", None)?;
        let mut components = Vec::with_capacity(relative.len() + 1);
        components.push(Arc::from(PROJECT_MOUNT));
        components.extend(relative.iter().cloned());
        Ok(NamespacePath {
            session: self.session.clone(),
            caller: caller.clone(),
            virtual_path: virtual_path_string(&components),
            virtual_components: components.into(),
            directory_intent,
            projection: Some(self.project_for_caller(caller, &relative)),
        })
    }

    fn defining_source(&self, relative: &[Arc<str>]) -> (Principal, LogicalRoot, Arc<[Arc<str>]>) {
        if let Some(binding) = self
            .package_bindings
            .iter()
            .find(|binding| components_start_with(relative, &binding.virtual_prefix))
        {
            return (
                binding.owner.clone(),
                LogicalRoot::Package,
                relative[binding.virtual_prefix.len()..].into(),
            );
        }
        (
            self.root_principal.clone(),
            LogicalRoot::Project,
            relative.into(),
        )
    }

    /// Derive module identity from an already-authenticated canonical virtual
    /// file path. This performs no lookup: callers must first authenticate and
    /// canonicalize the backing object, then translate that exact path through
    /// `namespace_for_authenticated_project_path`.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    pub(crate) fn source_id_for_authenticated_module(
        &self,
        namespace: &NamespacePath,
    ) -> Result<SourceId, VfsError> {
        self.ensure_path_session(namespace, "source-id")?;
        if namespace.is_synthetic_root() || namespace.virtual_components.len() <= 1 {
            return Err(VfsError::synthetic_node(
                "source-id",
                namespace.virtual_path.clone(),
            ));
        }
        let relative = &namespace.virtual_components[1..];
        let (defining_principal, logical_root, lexical_components) = self.defining_source(relative);
        Ok(SourceId(SourceIdKind::File {
            defining_principal,
            logical_root,
            lexical_components,
        }))
    }

    /// Project an already-authenticated namespace entry into the versioned
    /// logical record used by the native module resolver ABI. The defining
    /// binding is derived from the mount table rather than accepted from the
    /// caller, so package identity appears exactly once and host spelling never
    /// enters the record.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    /// @ref LLP 0023#71-identity-not-text--and-a-runtime-handle
    pub(crate) fn resolver_logical_path_for_authenticated_entry(
        &self,
        namespace: &NamespacePath,
        session_handle: &str,
    ) -> Result<ResolverLogicalPath, VfsError> {
        self.ensure_path_session(namespace, "module-resolver-path")?;
        if namespace.is_synthetic_root() || namespace.virtual_components.is_empty() {
            return Err(VfsError::synthetic_node(
                "module-resolver-path",
                namespace.virtual_path.clone(),
            ));
        }
        let relative = &namespace.virtual_components[1..];
        let (defining_principal, logical_root, lexical_components) = self.defining_source(relative);
        let logical_path = LogicalPath {
            root: logical_root,
            components: lexical_components
                .iter()
                .map(|component| {
                    PathComponent::utf8(component.to_string())
                        .expect("resolved UTF-8 component is a canonical PathComponent")
                })
                .collect(),
            host_bound: None,
        };
        let binding_owner = (logical_root == LogicalRoot::Package).then_some(defining_principal);
        ResolverLogicalPath::new(
            session_handle,
            namespace.virtual_path().to_owned(),
            logical_path,
            binding_owner,
        )
    }

    fn verify_authenticated_binding_root(
        &self,
        relative: &[Arc<str>],
        object: &ObjectIdentity,
        operation: &str,
        virtual_path: Arc<str>,
    ) -> Result<(), VfsError> {
        if self
            .package_bindings
            .iter()
            .find(|binding| binding.virtual_prefix.as_ref() == relative)
            .is_some_and(|binding| &binding.root_object != object)
        {
            return Err(VfsError::stale_identity(operation, virtual_path));
        }
        Ok(())
    }

    fn ensure_live(&self, operation: &str, path: Option<Arc<str>>) -> Result<(), VfsError> {
        if !self.session.0.alive.load(Ordering::Acquire) {
            return Err(VfsError::stale_session(operation, path));
        }
        Ok(())
    }

    fn ensure_path_session(&self, path: &NamespacePath, operation: &str) -> Result<(), VfsError> {
        self.ensure_live(operation, Some(path.virtual_path.clone()))?;
        if !Arc::ptr_eq(&self.session.0, &path.session.0)
            || !path.session.0.alive.load(Ordering::Acquire)
        {
            return Err(VfsError::stale_session(
                operation,
                Some(path.virtual_path.clone()),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathProjection {
    logical_root: LogicalRoot,
    binding_owner: Option<Principal>,
    relative_components: Arc<[Arc<str>]>,
}

/// Pre-discovery authorization identity. It contains no host path and no
/// existence claim.
#[derive(Clone, Eq, PartialEq)]
pub struct NamespacePath {
    session: VfsSessionHandle,
    caller: Principal,
    virtual_components: Arc<[Arc<str>]>,
    virtual_path: Arc<str>,
    directory_intent: bool,
    projection: Option<PathProjection>,
}

impl fmt::Debug for NamespacePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NamespacePath")
            .field("virtual_path", &self.virtual_path)
            .field("directory_intent", &self.directory_intent)
            .field(
                "logical_root",
                &self.projection.as_ref().map(|p| p.logical_root),
            )
            .field(
                "binding_owner",
                &self
                    .projection
                    .as_ref()
                    .and_then(|p| p.binding_owner.as_ref()),
            )
            .finish()
    }
}

impl NamespacePath {
    pub(crate) fn session_generation(&self) -> u64 {
        self.session.generation()
    }

    pub(crate) fn caller(&self) -> &Principal {
        &self.caller
    }

    pub fn virtual_path(&self) -> &str {
        &self.virtual_path
    }

    pub fn directory_intent(&self) -> bool {
        self.directory_intent
    }

    pub fn is_synthetic_root(&self) -> bool {
        self.projection.is_none()
    }

    pub fn binding_owner(&self) -> Option<&Principal> {
        self.projection
            .as_ref()
            .and_then(|projection| projection.binding_owner.as_ref())
    }

    pub fn logical_path(&self) -> Option<LogicalPath> {
        self.projection.as_ref().map(|projection| LogicalPath {
            root: projection.logical_root,
            components: projection
                .relative_components
                .iter()
                .map(|component| {
                    PathComponent::utf8(component.to_string())
                        .expect("resolved UTF-8 component is a canonical PathComponent")
                })
                .collect(),
            host_bound: None,
        })
    }

    /// Virtual project-relative directory captured before a source read. This
    /// is the referrer the ingress binds into a `.load` submission credential.
    pub fn logical_referrer(&self) -> Result<LogicalPath, VfsError> {
        if self.is_synthetic_root() || self.virtual_components.len() < 2 {
            return Err(VfsError::synthetic_node(
                "referrer",
                self.virtual_path.clone(),
            ));
        }
        Ok(LogicalPath {
            root: LogicalRoot::Project,
            components: self.virtual_components[1..self.virtual_components.len() - 1]
                .iter()
                .map(|component| {
                    PathComponent::utf8(component.to_string())
                        .expect("resolved UTF-8 component is canonical")
                })
                .collect(),
            host_bound: None,
        })
    }
}

/// The existence fact available after descriptor-relative discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExistenceWitness {
    Present(ObjectIdentity),
    Absent,
}

/// Post-discovery identity. The retained descriptor is deliberately private,
/// worker-local, non-cloneable, and non-serializable.
pub struct DiscoveredPath {
    namespace: NamespacePath,
    parent_object: ObjectIdentity,
    basename: Arc<str>,
    existence: ExistenceWitness,
    #[cfg(unix)]
    retained_parent: std::fs::File,
}

impl fmt::Debug for DiscoveredPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveredPath")
            .field("namespace", &self.namespace)
            .field("parent_object", &self.parent_object)
            .field("basename", &self.basename)
            .field("existence", &self.existence)
            .finish_non_exhaustive()
    }
}

impl DiscoveredPath {
    pub fn namespace(&self) -> &NamespacePath {
        &self.namespace
    }

    pub fn parent_object(&self) -> &ObjectIdentity {
        &self.parent_object
    }

    pub fn basename(&self) -> &str {
        &self.basename
    }

    pub fn existence(&self) -> &ExistenceWitness {
        &self.existence
    }

    pub fn witnessed_object(&self) -> Option<&ObjectIdentity> {
        match &self.existence {
            ExistenceWitness::Present(object) => Some(object),
            ExistenceWitness::Absent => None,
        }
    }
}

/// Post-commit identity retaining the exact final object read by this operation.
pub struct CommittedPath {
    discovered: DiscoveredPath,
    final_object: ObjectIdentity,
    retained_handle_id: u64,
    #[cfg(unix)]
    retained_final: std::fs::File,
}

impl fmt::Debug for CommittedPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommittedPath")
            .field("discovered", &self.discovered)
            .field("final_object", &self.final_object)
            .field("retained_handle", &"<opaque>")
            .finish()
    }
}

impl CommittedPath {
    pub fn discovered(&self) -> &DiscoveredPath {
        &self.discovered
    }

    pub fn namespace(&self) -> &NamespacePath {
        self.discovered.namespace()
    }

    pub fn final_object(&self) -> &ObjectIdentity {
        &self.final_object
    }

    pub(crate) fn retained_handle_id(&self) -> u64 {
        self.retained_handle_id
    }
}

/// Module-cache identity. It is a tagged structured key, never a display URL.
/// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
/// — file identity uses defining-principal plus lexical binding-relative path.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SourceId(SourceIdKind);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)] // Loader migration will consume the non-file arms of the closed algebra.
enum SourceIdKind {
    File {
        defining_principal: Principal,
        logical_root: LogicalRoot,
        lexical_components: Arc<[Arc<str>]>,
    },
    Builtin {
        key: Arc<str>,
    },
    SyntheticModule {
        session_identity: Digest,
        source_identity: Arc<str>,
    },
}

impl fmt::Debug for SourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceId(<authenticated>)")
    }
}

impl SourceId {
    #[cfg(test)]
    pub(crate) fn file_for_test(
        defining_principal: Principal,
        logical_root: LogicalRoot,
        lexical_components: Vec<Arc<str>>,
    ) -> Self {
        Self(SourceIdKind::File {
            defining_principal,
            logical_root,
            lexical_components: lexical_components.into(),
        })
    }

    pub(crate) fn builtin(key: impl Into<Arc<str>>) -> Self {
        Self(SourceIdKind::Builtin { key: key.into() })
    }

    #[allow(dead_code)]
    pub(crate) fn synthetic_module(
        session_identity: Digest,
        source_identity: impl Into<Arc<str>>,
    ) -> Self {
        Self(SourceIdKind::SyntheticModule {
            session_identity,
            source_identity: source_identity.into(),
        })
    }

    pub fn defining_principal(&self) -> Option<&Principal> {
        match &self.0 {
            SourceIdKind::File {
                defining_principal, ..
            } => Some(defining_principal),
            _ => None,
        }
    }

    /// Compare an opaque native cache spelling without disclosing the
    /// authenticated principal/path payload to callers. The runtime bundler
    /// uses this only after validating a v4 provenance sidecar, so a generated
    /// original must be the exact file identity retained by the VFS read.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    pub fn authenticates_cache_key(&self, candidate: &str) -> bool {
        self.cache_key() == candidate
    }

    /// Recover only the defining principal from an opaque file cache key.
    ///
    /// The authenticated module loader uses this on a route-cache hit so the
    /// host can re-authorize the current frame against the exact target
    /// principal without probing the filesystem again.  The spelling is
    /// accepted only when strict JSON decoding followed by reconstruction
    /// produces the identical canonical cache key; project JavaScript never
    /// receives this parser or the decoded principal.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    pub(crate) fn file_defining_principal_from_cache_key(candidate: &str) -> Option<Principal> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct FileSourceIdWire {
            kind: String,
            defining_principal: Principal,
            logical_root: LogicalRoot,
            lexical_components: Vec<String>,
            source_id_schema: String,
        }

        let encoded = candidate.strip_prefix("ibex-source-id-v1:")?;
        let decoded = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        let text = std::str::from_utf8(&decoded).ok()?;
        let value = capsec_semantics::strict_json::parse_strict(text).ok()?;
        let wire: FileSourceIdWire = serde_json::from_value(value).ok()?;
        if wire.kind != "file"
            || wire.source_id_schema != "ibex.source-id.v1"
            || wire.lexical_components.is_empty()
            || !matches!(
                (&wire.defining_principal, wire.logical_root),
                (Principal::Root { .. }, LogicalRoot::Project)
                    | (Principal::Package { .. }, LogicalRoot::Package)
            )
            || wire
                .lexical_components
                .iter()
                .any(|component| PathComponent::utf8(component.clone()).is_err())
        {
            return None;
        }
        let source_id = Self(SourceIdKind::File {
            defining_principal: wire.defining_principal.clone(),
            logical_root: wire.logical_root,
            lexical_components: wire
                .lexical_components
                .into_iter()
                .map(Arc::<str>::from)
                .collect::<Vec<_>>()
                .into(),
        });
        source_id
            .authenticates_cache_key(candidate)
            .then_some(wire.defining_principal)
    }

    /// Canonical, collision-free wire spelling used only inside the native
    /// module-loader cache. The tagged JCS payload preserves the complete
    /// `SourceId` algebra; base64url makes it safe as an own-property key
    /// without turning the human-facing `SourceLabel` into cache identity.
    ///
    /// This stays crate-private because it contains authenticated principal
    /// material. Native passes it only to the bootstrap-captured loader
    /// dispatcher, never to a JavaScript-reachable resolver or module field.
    /// @ref LLP 0023#23-module-identity-is-a-tagged-algebra-keyed-on-the-defining-principal
    pub(crate) fn cache_key(&self) -> String {
        let value = match &self.0 {
            SourceIdKind::File {
                defining_principal,
                logical_root,
                lexical_components,
            } => serde_json::json!({
                "kind": "file",
                "definingPrincipal": defining_principal,
                "logicalRoot": logical_root,
                "lexicalComponents": lexical_components,
                "sourceIdSchema": "ibex.source-id.v1",
            }),
            SourceIdKind::Builtin { key } => serde_json::json!({
                "kind": "builtin",
                "key": key,
                "sourceIdSchema": "ibex.source-id.v1",
            }),
            SourceIdKind::SyntheticModule {
                session_identity,
                source_identity,
            } => serde_json::json!({
                "kind": "synthetic-module",
                "sessionIdentity": session_identity,
                "sourceIdentity": source_identity,
                "sourceIdSchema": "ibex.source-id.v1",
            }),
        };
        let canonical = capsec_semantics::canonical::to_jcs_bytes(&value)
            .expect("SourceId canonical encoding cannot fail");
        format!("ibex-source-id-v1:{}", URL_SAFE_NO_PAD.encode(canonical))
    }
}

/// Deterministic display identity. This type cannot be used where a SourceId is
/// required, so display strings cannot silently become module-cache keys.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SourceLabel(Arc<str>);

impl SourceLabel {
    pub fn file(namespace: &NamespacePath) -> Result<Self, VfsError> {
        if namespace.is_synthetic_root() {
            return Err(VfsError::synthetic_node(
                "source-label",
                namespace.virtual_path.clone(),
            ));
        }
        Ok(Self(Arc::from(file_url_for_virtual_path(
            namespace.virtual_path(),
        ))))
    }

    pub fn synthetic(identity: impl Into<Arc<str>>) -> Result<Self, VfsError> {
        let identity = identity.into();
        if identity.is_empty() || identity.contains('\0') {
            return Err(VfsError::malformed("source-label"));
        }
        Ok(Self(identity))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceUse {
    Script,
    Module,
}

/// Opaque proof returned by the Host's typed decision path. Only crate code can
/// construct one; VFS consumers cannot self-assert authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationReceipt {
    evidence_digest: Digest,
}

impl AuthorizationReceipt {
    pub(crate) fn new(evidence_digest: Digest) -> Self {
        Self { evidence_digest }
    }

    pub(crate) fn from_structured_decision(
        evidence: &capsec_semantics::decision::StructuredDecisionEvidence,
    ) -> Result<Self, VfsError> {
        let bytes =
            serde_json::to_vec(evidence).map_err(|_| VfsError::malformed("typed-read-evidence"))?;
        Ok(Self::new(digest_bytes(
            b"ibex/vfs-typed-decision/1\0",
            &bytes,
        )))
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

pub enum ReadAuthorization<'a> {
    Requested(&'a NamespacePath),
    Discovery(&'a DiscoveredPath),
    Commit(&'a CommittedPath),
    Repeat(&'a CommittedPath),
}

impl fmt::Debug for ReadAuthorization<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested(path) => formatter.debug_tuple("Requested").field(path).finish(),
            Self::Discovery(path) => formatter.debug_tuple("Discovery").field(path).finish(),
            Self::Commit(path) => formatter.debug_tuple("Commit").field(path).finish(),
            Self::Repeat(path) => formatter.debug_tuple("Repeat").field(path).finish(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedReadEvidence {
    requested_decision: Digest,
    traversal_decisions: Arc<[Digest]>,
    discovery_decision: Digest,
    commit_decision: Digest,
    repeat_decision: Digest,
    parent_object: ObjectIdentity,
    final_object: ObjectIdentity,
    content_digest: Digest,
    evidence_digest: Digest,
}

impl AuthenticatedReadEvidence {
    pub fn requested_decision(&self) -> &Digest {
        &self.requested_decision
    }

    pub fn traversal_decisions(&self) -> &[Digest] {
        &self.traversal_decisions
    }

    pub fn commit_decision(&self) -> &Digest {
        &self.commit_decision
    }

    pub fn discovery_decision(&self) -> &Digest {
        &self.discovery_decision
    }

    pub fn repeat_decision(&self) -> &Digest {
        &self.repeat_decision
    }

    pub fn parent_object(&self) -> &ObjectIdentity {
        &self.parent_object
    }

    pub fn final_object(&self) -> &ObjectIdentity {
        &self.final_object
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    /// Digest consumed by the linear evaluation credential.
    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

/// Immutable bytes plus their logical referrer and exact authorization/object
/// evidence. No method exposes the backing host path.
#[derive(Clone, Debug)]
pub struct AuthenticatedRead {
    bytes: Arc<[u8]>,
    logical_referrer: LogicalPath,
    source_id: Option<SourceId>,
    source_label: SourceLabel,
    evidence: AuthenticatedReadEvidence,
}

/// Descriptor-authenticated metadata for a resolve-only module bridge. The
/// target's parent and final descriptors remain live through the Repeat
/// decision, but no source bytes are read and no host spelling is returned.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedMetadata {
    source_id: SourceId,
    source_label: SourceLabel,
}

impl AuthenticatedMetadata {
    pub(crate) fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    pub(crate) fn source_label(&self) -> &SourceLabel {
        &self.source_label
    }
}

impl AuthenticatedRead {
    pub fn bytes(&self) -> Arc<[u8]> {
        self.bytes.clone()
    }

    pub fn logical_referrer(&self) -> &LogicalPath {
        &self.logical_referrer
    }

    pub fn source_id(&self) -> Option<&SourceId> {
        self.source_id.as_ref()
    }

    pub fn source_label(&self) -> &SourceLabel {
        &self.source_label
    }

    pub fn evidence(&self) -> &AuthenticatedReadEvidence {
        &self.evidence
    }

    pub fn into_bytes(self) -> Arc<[u8]> {
        self.bytes
    }
}

/// Session-layer result of a typed `.load` read. The linear evaluation capsule
/// has already consumed the exact VFS evidence digest; callers cannot replace
/// either bytes or evidence independently.
#[derive(Debug)]
pub struct AuthenticatedVfsScriptRead {
    capsule: crate::engine::evaluation::ImmutableByteCapsule,
    logical_referrer: LogicalPath,
    source_id: Option<SourceId>,
    file_source_label: SourceLabel,
    evidence: AuthenticatedReadEvidence,
}

impl AuthenticatedVfsScriptRead {
    pub(crate) fn new(
        capsule: crate::engine::evaluation::ImmutableByteCapsule,
        logical_referrer: LogicalPath,
        source_id: Option<SourceId>,
        file_source_label: SourceLabel,
        evidence: AuthenticatedReadEvidence,
    ) -> Self {
        Self {
            capsule,
            logical_referrer,
            source_id,
            file_source_label,
            evidence,
        }
    }

    pub fn logical_referrer(&self) -> &LogicalPath {
        &self.logical_referrer
    }

    pub fn file_source_label(&self) -> &SourceLabel {
        &self.file_source_label
    }

    /// Authenticated module-cache identity for a file-program read. `.load`
    /// reads are scripts and therefore return `None` by construction.
    pub fn source_id(&self) -> Option<&SourceId> {
        self.source_id.as_ref()
    }

    pub fn evidence(&self) -> &AuthenticatedReadEvidence {
        &self.evidence
    }

    pub fn into_capsule(self) -> crate::engine::evaluation::ImmutableByteCapsule {
        self.capsule
    }
}

impl VirtualFileSystem {
    /// Authenticate a resolve-only file target with the same requested,
    /// discovery, commit, and repeat descriptor lifetime as a source read,
    /// without reading the target body.
    /// @ref LLP 0023#21-staged-authorization-identity
    pub(crate) fn metadata_authenticated<F>(
        &self,
        namespace: NamespacePath,
        mut authorize: F,
    ) -> Result<AuthenticatedMetadata, VfsError>
    where
        F: for<'a> FnMut(ReadAuthorization<'a>) -> Result<AuthorizationReceipt, VfsError>,
    {
        const OPERATION: &str = "metadata";
        self.ensure_path_session(&namespace, OPERATION)?;
        if namespace.is_synthetic_root() {
            return Err(VfsError::synthetic_node(
                OPERATION,
                namespace.virtual_path.clone(),
            ));
        }
        if namespace.virtual_components.len() <= 1 {
            return Err(VfsError::host_code(
                OPERATION,
                namespace.virtual_path.clone(),
                "EISDIR",
            ));
        }

        let _requested = authorize(ReadAuthorization::Requested(&namespace))?;

        #[cfg(unix)]
        let (discovered, _traversal_decisions) =
            self.discover_contained(namespace, &mut authorize)?;

        #[cfg(unix)]
        let _discovery = authorize(ReadAuthorization::Discovery(&discovered))?;

        #[cfg(unix)]
        let committed = self.commit_no_follow(discovered)?;

        #[cfg(not(unix))]
        {
            let _ = authorize;
            return Err(VfsError::host_code(
                OPERATION,
                namespace.virtual_path.clone(),
                "ERR_IBEX_UNSUPPORTED_TARGET",
            ));
        }

        #[cfg(unix)]
        {
            let _commit = authorize(ReadAuthorization::Commit(&committed))?;
            let before = committed.retained_final.metadata().map_err(|error| {
                VfsError::host(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                    &error,
                )
            })?;
            if !before.is_file() {
                return Err(VfsError::host_code(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                    if before.is_dir() { "EISDIR" } else { "EINVAL" },
                ));
            }
            if committed.namespace().directory_intent {
                return Err(VfsError::host_code(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                    "ENOTDIR",
                ));
            }
            let _repeat = authorize(ReadAuthorization::Repeat(&committed))?;
            let after = committed.retained_final.metadata().map_err(|error| {
                VfsError::host(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                    &error,
                )
            })?;
            let after_object = object_identity_for_metadata(&after).map_err(|_| {
                VfsError::stale_identity(OPERATION, committed.namespace().virtual_path.clone())
            })?;
            if after_object != committed.final_object
                || metadata_changed_during_read(&before, &after)
            {
                return Err(VfsError::stale_identity(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                ));
            }

            let relative = &committed.namespace().virtual_components[1..];
            let (defining_principal, logical_root, lexical_components) =
                self.defining_source(relative);
            Ok(AuthenticatedMetadata {
                source_id: SourceId(SourceIdKind::File {
                    defining_principal,
                    logical_root,
                    lexical_components,
                }),
                source_label: SourceLabel::file(committed.namespace())?,
            })
        }
    }

    /// Perform an authenticated whole-file read.
    ///
    /// The `Requested` callback runs before the first host lookup. Discovery,
    /// bounded contained-symlink traversal, and the final open are
    /// descriptor-relative; `Commit` runs with retained parent/final object
    /// evidence before any bytes are read.
    /// @ref LLP 0023#21-staged-authorization-identity
    pub(crate) fn read_authenticated<F>(
        &self,
        namespace: NamespacePath,
        source_use: SourceUse,
        mut authorize: F,
    ) -> Result<AuthenticatedRead, VfsError>
    where
        F: for<'a> FnMut(ReadAuthorization<'a>) -> Result<AuthorizationReceipt, VfsError>,
    {
        const OPERATION: &str = "read";
        self.ensure_path_session(&namespace, OPERATION)?;
        if namespace.is_synthetic_root() {
            return Err(VfsError::synthetic_node(
                OPERATION,
                namespace.virtual_path.clone(),
            ));
        }
        let requested = authorize(ReadAuthorization::Requested(&namespace))?;
        let relative = &namespace.virtual_components[1..];
        if relative.is_empty() {
            return Err(VfsError::host_code(
                OPERATION,
                namespace.virtual_path.clone(),
                "EISDIR",
            ));
        }

        #[cfg(unix)]
        let (discovered, traversal_decisions) =
            self.discover_contained(namespace, &mut authorize)?;

        #[cfg(unix)]
        let discovery = authorize(ReadAuthorization::Discovery(&discovered))?;

        #[cfg(unix)]
        let mut committed = self.commit_no_follow(discovered)?;

        #[cfg(not(unix))]
        {
            let _ = (source_use, authorize, requested);
            return Err(VfsError::host_code(
                OPERATION,
                namespace.virtual_path.clone(),
                "ERR_IBEX_UNSUPPORTED_TARGET",
            ));
        }

        #[cfg(unix)]
        {
            use std::io::{Read as _, Seek as _, SeekFrom};

            let commit = authorize(ReadAuthorization::Commit(&committed))?;
            let before = committed.retained_final.metadata().map_err(|error| {
                VfsError::host(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                    &error,
                )
            })?;
            if !before.is_file() {
                return Err(VfsError::host_code(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                    if before.is_dir() { "EISDIR" } else { "EINVAL" },
                ));
            }
            if committed.namespace().directory_intent {
                return Err(VfsError::host_code(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                    "ENOTDIR",
                ));
            }
            let repeat = authorize(ReadAuthorization::Repeat(&committed))?;
            committed
                .retained_final
                .seek(SeekFrom::Start(0))
                .map_err(|error| {
                    VfsError::host(
                        OPERATION,
                        committed.namespace().virtual_path.clone(),
                        &error,
                    )
                })?;
            let mut bytes = Vec::new();
            {
                let mut bounded = (&mut committed.retained_final)
                    .take(crate::session_constants::MAX_INPUT_BYTES as u64 + 1);
                bounded.read_to_end(&mut bytes).map_err(|error| {
                    VfsError::host(
                        OPERATION,
                        committed.namespace().virtual_path.clone(),
                        &error,
                    )
                })?;
            }
            let after = committed.retained_final.metadata().map_err(|error| {
                VfsError::host(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                    &error,
                )
            })?;
            let after_object = object_identity_for_metadata(&after).map_err(|_| {
                VfsError::stale_identity(OPERATION, committed.namespace().virtual_path.clone())
            })?;
            if after_object != committed.final_object
                || metadata_changed_during_read(&before, &after)
            {
                return Err(VfsError::stale_identity(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                ));
            }
            if bytes.len() > crate::session_constants::MAX_INPUT_BYTES {
                return Err(VfsError::input_too_large(
                    OPERATION,
                    committed.namespace().virtual_path.clone(),
                ));
            }

            let relative = &committed.namespace().virtual_components[1..];
            let (defining_principal, logical_root, lexical_components) =
                self.defining_source(relative);
            let source_id = (source_use == SourceUse::Module).then_some({
                SourceId(SourceIdKind::File {
                    defining_principal,
                    logical_root,
                    lexical_components,
                })
            });
            let source_label = SourceLabel::file(committed.namespace())?;
            let logical_referrer = LogicalPath {
                root: LogicalRoot::Project,
                components: relative[..relative.len() - 1]
                    .iter()
                    .map(|component| {
                        PathComponent::utf8(component.to_string())
                            .expect("resolved UTF-8 component is canonical")
                    })
                    .collect(),
                host_bound: None,
            };
            let content_digest = digest_bytes(b"ibex/vfs-content/1\0", &bytes);
            let parent_object = committed.discovered.parent_object.clone();
            let final_object = committed.final_object.clone();
            let ordered_decisions = std::iter::once(requested.evidence_digest())
                .chain(traversal_decisions.iter())
                .chain([
                    discovery.evidence_digest(),
                    commit.evidence_digest(),
                    repeat.evidence_digest(),
                ])
                .cloned()
                .collect::<Vec<_>>();
            let evidence_digest = digest_read_evidence(
                &ordered_decisions,
                &parent_object,
                &final_object,
                &content_digest,
                committed.namespace().virtual_path(),
            );
            Ok(AuthenticatedRead {
                bytes: bytes.into(),
                logical_referrer,
                source_id,
                source_label,
                evidence: AuthenticatedReadEvidence {
                    requested_decision: requested.evidence_digest,
                    traversal_decisions: traversal_decisions.into(),
                    discovery_decision: discovery.evidence_digest,
                    commit_decision: commit.evidence_digest,
                    repeat_decision: repeat.evidence_digest,
                    parent_object,
                    final_object,
                    content_digest,
                    evidence_digest,
                },
            })
        }
    }

    #[cfg(unix)]
    /// Walk one link at a time with link-object verification, a fixed depth
    /// bound, and target reauthorization before target lookup.
    /// @ref LLP 0023#4-symlinks-staged-discovery-contained-creation
    fn discover_contained<F>(
        &self,
        namespace: NamespacePath,
        authorize: &mut F,
    ) -> Result<(DiscoveredPath, Vec<Digest>), VfsError>
    where
        F: for<'a> FnMut(ReadAuthorization<'a>) -> Result<AuthorizationReceipt, VfsError>,
    {
        use std::collections::VecDeque;
        use std::ffi::CString;
        use std::os::fd::AsRawFd;

        const OPERATION: &str = "read";
        const MAX_SYMLINKS: usize = 32;
        let safe_path = namespace.virtual_path.clone();
        let root = self.open_authenticated_project_root(OPERATION, safe_path.clone())?;
        let caller = namespace.caller.clone();
        let directory_intent = namespace.directory_intent;
        let mut final_namespace = namespace;
        let mut pending = final_namespace.virtual_components[1..]
            .iter()
            .cloned()
            .collect::<VecDeque<_>>();
        let mut current = root
            .try_clone()
            .map_err(|error| VfsError::host(OPERATION, safe_path.clone(), &error))?;
        let mut physical_parent = Vec::<Arc<str>>::new();
        let mut symlink_count = 0usize;
        let mut traversal_decisions = Vec::new();

        loop {
            let component = pending
                .pop_front()
                .expect("nonempty mounted read path checked by caller");
            let component_c =
                CString::new(component.as_bytes()).map_err(|_| VfsError::malformed(OPERATION))?;
            let witnessed =
                stat_at_no_follow(current.as_raw_fd(), &component_c).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        VfsError::absent(OPERATION, final_namespace.virtual_path.clone())
                    } else {
                        VfsError::host(OPERATION, final_namespace.virtual_path.clone(), &error)
                    }
                })?;
            let witnessed_object = object_identity_for_unix_stat(&witnessed).map_err(|_| {
                VfsError::stale_identity(OPERATION, final_namespace.virtual_path.clone())
            })?;
            let parent_object =
                object_identity_for_metadata(&current.metadata().map_err(|error| {
                    VfsError::host(OPERATION, final_namespace.virtual_path.clone(), &error)
                })?)
                .map_err(|_| {
                    VfsError::stale_identity(OPERATION, final_namespace.virtual_path.clone())
                })?;

            let mut witnessed_components = physical_parent.clone();
            witnessed_components.push(component.clone());
            self.verify_authenticated_binding_root(
                &witnessed_components,
                &witnessed_object,
                OPERATION,
                final_namespace.virtual_path.clone(),
            )?;

            if unix_stat_is_symlink(&witnessed) {
                let mut link_components = physical_parent.clone();
                link_components.push(component.clone());
                let link_namespace = self.namespace_from_project_relative(
                    &caller,
                    link_components,
                    !pending.is_empty(),
                )?;
                let link = DiscoveredPath {
                    namespace: link_namespace,
                    parent_object,
                    basename: component.clone(),
                    existence: ExistenceWitness::Present(witnessed_object.clone()),
                    retained_parent: current,
                };
                let receipt = authorize(ReadAuthorization::Discovery(&link))?;
                traversal_decisions.push(receipt.evidence_digest);
                symlink_count += 1;
                if symlink_count > MAX_SYMLINKS {
                    return Err(VfsError::symlink_depth(
                        OPERATION,
                        link.namespace.virtual_path.clone(),
                    ));
                }

                let target_bytes = readlinkat_bytes(link.retained_parent.as_raw_fd(), &component_c)
                    .map_err(|error| {
                        VfsError::host(OPERATION, link.namespace.virtual_path.clone(), &error)
                    })?;
                let after = stat_at_no_follow(link.retained_parent.as_raw_fd(), &component_c)
                    .map_err(|_| {
                        VfsError::stale_identity(OPERATION, link.namespace.virtual_path.clone())
                    })?;
                let after_object = object_identity_for_unix_stat(&after).map_err(|_| {
                    VfsError::stale_identity(OPERATION, link.namespace.virtual_path.clone())
                })?;
                if after_object != witnessed_object || !unix_stat_is_symlink(&after) {
                    return Err(VfsError::stale_identity(
                        OPERATION,
                        link.namespace.virtual_path.clone(),
                    ));
                }
                let target = std::str::from_utf8(&target_bytes)
                    .map_err(|_| VfsError::malformed(OPERATION))?;
                if target.is_empty() || target.contains('\0') {
                    return Err(VfsError::malformed(OPERATION));
                }
                let target_components = if target.starts_with('/') {
                    absolute_link_target_under_mount(&self.mount.host_root, target).map_err(
                        |_| VfsError::outside_mount(OPERATION, link.namespace.virtual_path.clone()),
                    )?
                } else {
                    relative_link_target_under_mount(&physical_parent, target).map_err(|_| {
                        VfsError::outside_mount(OPERATION, link.namespace.virtual_path.clone())
                    })?
                };
                let mut combined = target_components;
                combined.extend(pending);
                if combined.is_empty() {
                    return Err(VfsError::host_code(
                        OPERATION,
                        link.namespace.virtual_path.clone(),
                        "EISDIR",
                    ));
                }
                let target_namespace = self.namespace_from_project_relative(
                    &caller,
                    combined.clone(),
                    directory_intent,
                )?;
                // Authorize the complete substituted path before restarting
                // traversal. Authorizing only the raw link target leaves an
                // ancestor+pending-tail gap where the tail can enter a foreign
                // binding before any further callback.
                let receipt = authorize(ReadAuthorization::Requested(&target_namespace))?;
                traversal_decisions.push(receipt.evidence_digest);

                final_namespace = target_namespace;
                pending = combined.into_iter().collect();
                current = root.try_clone().map_err(|error| {
                    VfsError::host(OPERATION, final_namespace.virtual_path.clone(), &error)
                })?;
                physical_parent.clear();
                continue;
            }

            if pending.is_empty() {
                return Ok((
                    DiscoveredPath {
                        namespace: final_namespace,
                        parent_object,
                        basename: component,
                        existence: ExistenceWitness::Present(witnessed_object),
                        retained_parent: current,
                    },
                    traversal_decisions,
                ));
            }

            let opened = match openat_directory_no_follow(current.as_raw_fd(), &component_c) {
                Ok(opened) => opened,
                Err(error) => {
                    if stat_at_no_follow(current.as_raw_fd(), &component_c)
                        .ok()
                        .and_then(|stat| object_identity_for_unix_stat(&stat).ok())
                        .as_ref()
                        != Some(&witnessed_object)
                    {
                        return Err(VfsError::stale_identity(
                            OPERATION,
                            final_namespace.virtual_path.clone(),
                        ));
                    }
                    return Err(VfsError::host(
                        OPERATION,
                        final_namespace.virtual_path.clone(),
                        &error,
                    ));
                }
            };
            let opened_object =
                object_identity_for_metadata(&opened.metadata().map_err(|error| {
                    VfsError::host(OPERATION, final_namespace.virtual_path.clone(), &error)
                })?)
                .map_err(|_| {
                    VfsError::stale_identity(OPERATION, final_namespace.virtual_path.clone())
                })?;
            if opened_object != witnessed_object {
                return Err(VfsError::stale_identity(
                    OPERATION,
                    final_namespace.virtual_path.clone(),
                ));
            }
            current = opened;
            physical_parent.push(component);
        }
    }

    #[cfg(unix)]
    fn commit_no_follow(&self, discovered: DiscoveredPath) -> Result<CommittedPath, VfsError> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};

        const OPERATION: &str = "read";
        let ExistenceWitness::Present(witnessed_object) = &discovered.existence else {
            return Err(VfsError::stale_identity(
                OPERATION,
                discovered.namespace.virtual_path.clone(),
            ));
        };
        let basename_c = CString::new(discovered.basename.as_bytes())
            .map_err(|_| VfsError::malformed(OPERATION))?;
        let fd = unsafe {
            libc::openat(
                discovered.retained_parent.as_raw_fd(),
                basename_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            let current_object =
                stat_at_no_follow(discovered.retained_parent.as_raw_fd(), &basename_c)
                    .ok()
                    .and_then(|stat| object_identity_for_unix_stat(&stat).ok());
            if current_object.as_ref() != Some(witnessed_object) {
                return Err(VfsError::stale_identity(
                    OPERATION,
                    discovered.namespace.virtual_path.clone(),
                ));
            }
            return Err(VfsError::host(
                OPERATION,
                discovered.namespace.virtual_path.clone(),
                &error,
            ));
        }
        let final_file = unsafe { std::fs::File::from_raw_fd(fd) };
        let final_object =
            object_identity_for_metadata(&final_file.metadata().map_err(|error| {
                VfsError::host(OPERATION, discovered.namespace.virtual_path.clone(), &error)
            })?)
            .map_err(|_| {
                VfsError::stale_identity(OPERATION, discovered.namespace.virtual_path.clone())
            })?;
        if &final_object != witnessed_object {
            return Err(VfsError::stale_identity(
                OPERATION,
                discovered.namespace.virtual_path.clone(),
            ));
        }
        let retained_handle_id =
            next_vfs_identity(OPERATION, Some(discovered.namespace.virtual_path.clone()))?;
        Ok(CommittedPath {
            discovered,
            final_object,
            retained_handle_id,
            retained_final: final_file,
        })
    }
}

#[cfg(test)]
type CwdRootOpenHook = Option<(std::path::PathBuf, std::sync::Arc<std::sync::Barrier>)>;

#[cfg(test)]
static CWD_ROOT_OPEN_HOOK: std::sync::OnceLock<std::sync::Mutex<CwdRootOpenHook>> =
    std::sync::OnceLock::new();

#[cfg(test)]
static CWD_MOUNT_REVERIFY_HOOK: std::sync::OnceLock<std::sync::Mutex<CwdRootOpenHook>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn pause_after_authenticated_cwd_root_open(path: &std::path::Path) {
    let hook = CWD_ROOT_OPEN_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .and_then(|hook| hook.as_ref().cloned());
    if let Some((target, barrier)) = hook {
        if target == path {
            barrier.wait();
            barrier.wait();
        }
    }
}

#[cfg(not(test))]
fn pause_after_authenticated_cwd_root_open(_: &std::path::Path) {}

#[cfg(test)]
fn pause_before_cwd_mount_reverification(path: &std::path::Path) {
    let hook = CWD_MOUNT_REVERIFY_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()
        .and_then(|hook| hook.as_ref().cloned());
    if let Some((target, barrier)) = hook {
        if target == path {
            barrier.wait();
            barrier.wait();
        }
    }
}

#[cfg(not(test))]
fn pause_before_cwd_mount_reverification(_: &std::path::Path) {}

#[cfg(unix)]
fn openat_directory_no_follow(
    parent_fd: std::os::fd::RawFd,
    basename: &std::ffi::CStr,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::FromRawFd;

    let fd = unsafe {
        libc::openat(
            parent_fd,
            basename.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a fresh, uniquely owned descriptor.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn directory_handle_descends_from_object(
    handle: &std::fs::File,
    expected_root: &ObjectIdentity,
) -> bool {
    use std::os::fd::AsRawFd;

    let Ok(mut current) = handle.try_clone() else {
        return false;
    };
    for _ in 0..1024 {
        let Ok(metadata) = current.metadata() else {
            return false;
        };
        let Ok(current_object) = object_identity_for_metadata(&metadata) else {
            return false;
        };
        if &current_object == expected_root {
            return true;
        }
        if !metadata.is_dir() {
            return false;
        }
        let Ok(parent) = openat_directory_no_follow(current.as_raw_fd(), c"..") else {
            return false;
        };
        let Ok(parent_metadata) = parent.metadata() else {
            return false;
        };
        let Ok(parent_object) = object_identity_for_metadata(&parent_metadata) else {
            return false;
        };
        if parent_object == current_object {
            return false;
        }
        current = parent;
    }
    false
}

#[cfg(unix)]
fn stat_at_no_follow(
    parent_fd: std::os::fd::RawFd,
    basename: &std::ffi::CStr,
) -> std::io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let status = unsafe {
        libc::fstatat(
            parent_fd,
            basename.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { stat.assume_init() })
    }
}

#[cfg(unix)]
fn unix_stat_is_symlink(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFLNK
}

#[cfg(unix)]
fn readlinkat_bytes(
    parent_fd: std::os::fd::RawFd,
    basename: &std::ffi::CStr,
) -> std::io::Result<Vec<u8>> {
    const MAX_LINK_BYTES: usize = 64 * 1024;
    let mut capacity = 256usize;
    loop {
        let mut bytes = vec![0u8; capacity];
        let length = unsafe {
            libc::readlinkat(
                parent_fd,
                basename.as_ptr(),
                bytes.as_mut_ptr().cast::<libc::c_char>(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let length = length as usize;
        if length < capacity {
            bytes.truncate(length);
            return Ok(bytes);
        }
        if capacity == MAX_LINK_BYTES {
            return Err(std::io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        capacity = (capacity * 2).min(MAX_LINK_BYTES);
    }
}

#[cfg(unix)]
fn relative_link_target_under_mount(
    physical_parent: &[Arc<str>],
    target: &str,
) -> Result<Vec<Arc<str>>, ()> {
    let mut components = physical_parent.to_vec();
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop().ok_or(())?;
            }
            component => components.push(Arc::from(component)),
        }
    }
    Ok(components)
}

#[cfg(unix)]
fn absolute_link_target_under_mount(
    host_root: &std::path::Path,
    target: &str,
) -> Result<Vec<Arc<str>>, ()> {
    fn normalized(path: &std::path::Path) -> Result<Vec<Vec<u8>>, ()> {
        use std::os::unix::ffi::OsStrExt;

        if !path.is_absolute() {
            return Err(());
        }
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::RootDir | std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    components.pop();
                }
                std::path::Component::Normal(component) => {
                    components.push(component.as_bytes().to_vec())
                }
                std::path::Component::Prefix(_) => return Err(()),
            }
        }
        Ok(components)
    }

    let root = normalized(host_root)?;
    let target = normalized(std::path::Path::new(target))?;
    let relative = target.strip_prefix(root.as_slice()).ok_or(())?;
    relative
        .iter()
        .map(|component| {
            std::str::from_utf8(component)
                .map(Arc::<str>::from)
                .map_err(|_| ())
        })
        .collect()
}

// A virtual component is passed to PathBuf only after namespace containment.
// On Windows, accepting characters which the native path parser reinterprets
// as separators, prefixes, alternate streams, wildcards, or device aliases
// would invalidate that ordering. POSIX retains backslash and colon as ordinary
// filename characters.
// @ref LLP 0023#3-path-grammar-normalization-aliasing-and-containment — virtual paths stay POSIX on
// every target, while Windows-unmappable components fail before translation.
fn virtual_component_is_mappable(component: &str, windows_target: bool) -> bool {
    if !windows_target {
        return true;
    }
    if component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character <= '\u{1f}'
                || matches!(character, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*')
        })
    {
        return false;
    }
    let device_stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .to_ascii_uppercase();
    if matches!(
        device_stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return false;
    }
    let numbered_device = device_stem
        .strip_prefix("COM")
        .or_else(|| device_stem.strip_prefix("LPT"));
    !matches!(
        numbered_device,
        Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
    )
}

fn decode_file_url_path(input: &[u8]) -> Result<Vec<u8>, VfsError> {
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] != b'%' {
            decoded.push(input[index]);
            index += 1;
            continue;
        }
        if index + 2 >= input.len() {
            return Err(VfsError::malformed("file-url"));
        }
        let high = hex(input[index + 1]).ok_or_else(|| VfsError::malformed("file-url"))?;
        let low = hex(input[index + 2]).ok_or_else(|| VfsError::malformed("file-url"))?;
        let byte = high << 4 | low;
        if byte == b'/' || (cfg!(windows) && byte == b'\\') {
            return Err(VfsError::encoded_separator("file-url"));
        }
        decoded.push(byte);
        index += 3;
    }
    Ok(decoded)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn virtual_path_string(components: &[Arc<str>]) -> Arc<str> {
    if components.is_empty() {
        Arc::from("/")
    } else {
        Arc::from(format!("/{}", components.join("/")))
    }
}

fn components_start_with(value: &[Arc<str>], prefix: &[Arc<str>]) -> bool {
    value.len() >= prefix.len()
        && value
            .iter()
            .zip(prefix)
            .all(|(value, prefix)| value == prefix)
}

/// Canonical virtual file label for an already-authenticated canonical entry
/// path beneath an already-authenticated canonical project root.
///
/// This pre-snapshot arming helper performs no filesystem access. Its arguments
/// must be the authenticated results of project discovery; it only enforces the
/// namespace mapping, strict UTF-8 tail, and canonical URL escaping.
pub fn source_label_for_authenticated_project_path(
    authenticated_project_root: &std::path::Path,
    authenticated_entry_path: &std::path::Path,
) -> Result<SourceLabel, VfsError> {
    let virtual_path = virtual_path_for_authenticated_project_path(
        authenticated_project_root,
        authenticated_entry_path,
        "entry-label",
    )?;
    if virtual_path == "/project" {
        return Err(VfsError::host_code(
            "entry-label",
            Arc::from(virtual_path),
            "EISDIR",
        ));
    }
    Ok(SourceLabel(Arc::from(file_url_for_virtual_path(
        &virtual_path,
    ))))
}

fn virtual_path_for_authenticated_project_path(
    authenticated_project_root: &std::path::Path,
    authenticated_path: &std::path::Path,
    operation: &str,
) -> Result<String, VfsError> {
    let relative = authenticated_path
        .strip_prefix(authenticated_project_root)
        .map_err(|_| VfsError::outside_mount(operation, Arc::from("/")))?;
    let mut virtual_path = String::from("/project");
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(VfsError::malformed(operation));
        };
        let component = component
            .to_str()
            .ok_or_else(|| VfsError::malformed(operation))?;
        if component.is_empty() || component.contains(['/', '\0']) {
            return Err(VfsError::malformed(operation));
        }
        virtual_path.push('/');
        virtual_path.push_str(component);
    }
    Ok(virtual_path)
}

fn host_path_from_binding(binding: &ArmedRootBinding) -> Result<PathBuf, VfsError> {
    if binding.host_path.root != LogicalRoot::Absolute || binding.host_path.host_bound != Some(true)
    {
        return Err(VfsError::malformed("mount"));
    }

    #[cfg(windows)]
    {
        let mut components = binding.host_path.components.iter();
        let prefix = components
            .next()
            .ok_or_else(|| VfsError::malformed("mount"))?;
        let prefix =
            std::str::from_utf8(prefix.bytes()).map_err(|_| VfsError::malformed("mount"))?;
        let mut path = PathBuf::from(format!("{prefix}{}", std::path::MAIN_SEPARATOR));
        for component in components {
            let component =
                std::str::from_utf8(component.bytes()).map_err(|_| VfsError::malformed("mount"))?;
            path.push(component);
        }
        return Ok(path);
    }

    #[cfg(unix)]
    {
        let mut path = PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
        for component in &binding.host_path.components {
            use std::os::unix::ffi::OsStrExt;
            path.push(std::ffi::OsStr::from_bytes(component.bytes()));
        }
        Ok(path)
    }

    #[cfg(not(any(unix, windows)))]
    {
        Err(VfsError::host_code(
            "mount",
            Arc::from("/project"),
            "ERR_IBEX_UNSUPPORTED_TARGET",
        ))
    }
}

#[cfg(unix)]
pub(crate) fn object_identity_for_metadata(
    metadata: &std::fs::Metadata,
) -> capsec_semantics::Result<ObjectIdentity> {
    use capsec_semantics::model::{NonEmptyString, ObjectPlatform};
    use std::os::unix::fs::MetadataExt;
    Ok(ObjectIdentity {
        platform: if cfg!(any(target_os = "macos", target_os = "ios")) {
            ObjectPlatform::Apple
        } else if cfg!(target_os = "android") {
            ObjectPlatform::Android
        } else {
            ObjectPlatform::Unix
        },
        volume: NonEmptyString::new(format!("dev:{}", metadata.dev()))
            .map_err(capsec_semantics::Error::InvalidModel)?,
        file: NonEmptyString::new(format!("ino:{}", metadata.ino()))
            .map_err(capsec_semantics::Error::InvalidModel)?,
    })
}

#[cfg(unix)]
fn object_identity_for_unix_stat(stat: &libc::stat) -> capsec_semantics::Result<ObjectIdentity> {
    use capsec_semantics::model::{NonEmptyString, ObjectPlatform};
    Ok(ObjectIdentity {
        platform: if cfg!(any(target_os = "macos", target_os = "ios")) {
            ObjectPlatform::Apple
        } else if cfg!(target_os = "android") {
            ObjectPlatform::Android
        } else {
            ObjectPlatform::Unix
        },
        volume: NonEmptyString::new(format!("dev:{}", stat.st_dev))
            .map_err(capsec_semantics::Error::InvalidModel)?,
        file: NonEmptyString::new(format!("ino:{}", stat.st_ino))
            .map_err(capsec_semantics::Error::InvalidModel)?,
    })
}

#[cfg(unix)]
pub(crate) fn metadata_changed_during_read(
    before: &std::fs::Metadata,
    after: &std::fs::Metadata,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    Digest::new(format!(
        "sha256-{}",
        URL_SAFE_NO_PAD.encode(hash.finalize())
    ))
    .expect("SHA-256 base64url is a canonical digest")
}

fn digest_read_evidence(
    decisions: &[Digest],
    parent: &ObjectIdentity,
    final_object: &ObjectIdentity,
    content: &Digest,
    virtual_path: &str,
) -> Digest {
    let parent = serde_json::to_vec(parent).expect("ObjectIdentity serialization cannot fail");
    let final_object =
        serde_json::to_vec(final_object).expect("ObjectIdentity serialization cannot fail");
    let mut hash = Sha256::new();
    hash.update(READ_EVIDENCE_DOMAIN);
    hash.update((decisions.len() as u64).to_be_bytes());
    for decision in decisions {
        let part = decision.as_str().as_bytes();
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    for part in [
        parent.as_slice(),
        final_object.as_slice(),
        content.as_str().as_bytes(),
        virtual_path.as_bytes(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Digest::new(format!(
        "sha256-{}",
        URL_SAFE_NO_PAD.encode(hash.finalize())
    ))
    .expect("SHA-256 base64url is a canonical digest")
}

fn file_url_for_virtual_path(path: &str) -> String {
    let mut result = String::from("file://");
    for byte in path.bytes() {
        if byte == b'/' || byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
        {
            result.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut result, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use capsec_semantics::model::{NonEmptyString, ObjectPlatform};
    use std::fs;

    fn root_principal(name: &str) -> Principal {
        Principal::Root {
            identity: NonEmptyString::new(name).unwrap(),
        }
    }

    fn test_vfs(root: &std::path::Path) -> VirtualFileSystem {
        let object = object_identity_for_host_path(root).unwrap();
        VirtualFileSystem::from_bindings(
            root.to_path_buf(),
            object,
            root_principal("test-project"),
            &[],
            None,
        )
        .unwrap()
    }

    fn package_principal(name: &str) -> Principal {
        serde_json::from_value(serde_json::json!({
            "kind": "package",
            "name": name,
            "integrity": "sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA",
            "locator": format!("{name}@1.0.0")
        }))
        .unwrap()
    }

    fn host_bound_path(path: &std::path::Path) -> LogicalPath {
        let components = path
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(component) => {
                    Some(PathComponent::utf8(component.to_str().unwrap().to_owned()).unwrap())
                }
                _ => None,
            })
            .collect();
        LogicalPath {
            root: LogicalRoot::Absolute,
            components,
            host_bound: Some(true),
        }
    }

    fn receipt(tag: &[u8]) -> AuthorizationReceipt {
        AuthorizationReceipt::new(digest_bytes(b"ibex/vfs-test-decision/1\0", tag))
    }

    #[test]
    fn runtime_vfs_sessions_isolate_cwd_backing_paths_and_teardown() {
        let process_cwd = std::env::current_dir().unwrap();
        let one = tempfile::tempdir().unwrap();
        let two = tempfile::tempdir().unwrap();
        fs::create_dir(one.path().join("one-sub")).unwrap();
        fs::create_dir(two.path().join("two-sub")).unwrap();
        let first =
            RuntimeVfsSession::new(NonZeroU64::new(101).unwrap(), test_vfs(one.path())).unwrap();
        let second =
            RuntimeVfsSession::new(NonZeroU64::new(202).unwrap(), test_vfs(two.path())).unwrap();

        assert_eq!(first.current_cwd().unwrap(), b"/project");
        assert_eq!(second.current_cwd().unwrap(), b"/project");
        assert_eq!(first.chdir(b"one-sub").unwrap(), b"/project/one-sub");
        assert_eq!(first.current_cwd().unwrap(), b"/project/one-sub");
        assert_eq!(second.current_cwd().unwrap(), b"/project");

        let first_path = first.resolve_private_path(b"child.txt").unwrap();
        let second_path = second.resolve_private_path(b"child.txt").unwrap();
        assert_eq!(first_path.virtual_path(), b"/project/one-sub/child.txt");
        assert_eq!(second_path.virtual_path(), b"/project/child.txt");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            assert_eq!(
                first_path.backing_path(),
                one.path().join("one-sub/child.txt").as_os_str().as_bytes()
            );
            assert_eq!(
                second_path.backing_path(),
                two.path().join("child.txt").as_os_str().as_bytes()
            );
        }
        #[cfg(not(unix))]
        {
            assert_eq!(
                first_path.backing_path(),
                one.path()
                    .join("one-sub/child.txt")
                    .to_str()
                    .unwrap()
                    .as_bytes()
            );
            assert_eq!(
                second_path.backing_path(),
                two.path().join("child.txt").to_str().unwrap().as_bytes()
            );
        }

        first.close();
        assert_eq!(
            first.current_cwd().unwrap_err().reason(),
            VfsReason::StaleSession
        );
        assert_eq!(second.current_cwd().unwrap(), b"/project");
        assert_eq!(std::env::current_dir().unwrap(), process_cwd);
    }

    #[test]
    fn runtime_vfs_chdir_is_atomic_detects_stale_base_and_recovers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("live")).unwrap();
        fs::write(temp.path().join("file"), b"not a directory").unwrap();
        let session =
            RuntimeVfsSession::new(NonZeroU64::new(303).unwrap(), test_vfs(temp.path())).unwrap();

        let error = session.chdir(b"file").unwrap_err();
        assert_eq!(error.reason(), VfsReason::HostError);
        assert_eq!(error.code(), "ENOTDIR");
        assert_eq!(session.current_cwd().unwrap(), b"/project");

        assert_eq!(session.chdir(b"live").unwrap(), b"/project/live");
        fs::rename(temp.path().join("live"), temp.path().join("moved")).unwrap();
        fs::create_dir(temp.path().join("live")).unwrap();
        assert_eq!(
            session.resolve_private_path(b"child").unwrap_err().reason(),
            VfsReason::StaleIdentity
        );
        assert_eq!(
            session.current_cwd().unwrap_err().reason(),
            VfsReason::StaleIdentity,
            "capturing a prompt referrer must not turn a stale retained cwd into trusted text"
        );

        assert_eq!(session.chdir(b"/project").unwrap(), b"/project");
        assert_eq!(
            session
                .resolve_private_path(b"child")
                .unwrap()
                .virtual_path(),
            b"/project/child"
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_vfs_chdir_rejects_replaced_package_root_ancestor() {
        let temp = tempfile::tempdir().unwrap();
        let package_root = temp.path().join("node_modules/a");
        let original = temp.path().join("original-package");
        let substitute = temp.path().join("substitute-package");
        fs::create_dir_all(package_root.join("sub")).unwrap();
        fs::create_dir_all(substitute.join("sub")).unwrap();
        let project_object = object_identity_for_host_path(temp.path()).unwrap();
        let package_object = object_identity_for_host_path(&package_root).unwrap();
        let bindings = vec![
            ArmedRootBinding {
                logical_root: LogicalRoot::Project,
                owner: None,
                logical_path: None,
                host_path: host_bound_path(temp.path()),
                object: project_object.clone(),
            },
            ArmedRootBinding {
                logical_root: LogicalRoot::Package,
                owner: Some(package_principal("a")),
                logical_path: None,
                host_path: host_bound_path(&package_root),
                object: package_object,
            },
        ];
        let vfs = VirtualFileSystem::from_bindings(
            temp.path().to_path_buf(),
            project_object,
            root_principal("test-project"),
            &bindings,
            None,
        )
        .unwrap();
        let session = RuntimeVfsSession::new(NonZeroU64::new(304).unwrap(), vfs).unwrap();

        fs::rename(&package_root, &original).unwrap();
        fs::rename(&substitute, &package_root).unwrap();

        let error = session.chdir(b"/project/node_modules/a/sub").unwrap_err();
        assert_eq!(error.reason(), VfsReason::StaleIdentity);
        assert_eq!(session.current_cwd().unwrap(), b"/project");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_vfs_chdir_authorizes_combined_symlink_tail_at_foreign_binding() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let package_root = temp.path().join("node_modules/pkg");
        fs::create_dir_all(package_root.join("sub")).unwrap();
        symlink("node_modules", temp.path().join("alias")).unwrap();
        let project_object = object_identity_for_host_path(temp.path()).unwrap();
        let root = root_principal("test-project");
        let package = package_principal("pkg");
        let bindings = vec![
            ArmedRootBinding {
                logical_root: LogicalRoot::Project,
                owner: None,
                logical_path: None,
                host_path: host_bound_path(temp.path()),
                object: project_object.clone(),
            },
            ArmedRootBinding {
                logical_root: LogicalRoot::Package,
                owner: Some(package.clone()),
                logical_path: None,
                host_path: host_bound_path(&package_root),
                object: object_identity_for_host_path(&package_root).unwrap(),
            },
        ];
        let vfs = VirtualFileSystem::from_bindings(
            temp.path().to_path_buf(),
            project_object,
            root.clone(),
            &bindings,
            None,
        )
        .unwrap();
        let principal_projection = vfs.clone();
        let session = RuntimeVfsSession::new(NonZeroU64::new(307).unwrap(), vfs).unwrap();
        let mut requested = Vec::new();
        let error = session
            .chdir_authorized(b"/project/alias/pkg/sub", |stage, _, namespace, _| {
                if stage == capsec_semantics::model::Stage::Requested {
                    let defining_principal = principal_projection
                        .source_id_for_authenticated_module(namespace)
                        .unwrap()
                        .defining_principal()
                        .cloned()
                        .unwrap();
                    requested.push((
                        namespace.virtual_path().to_owned(),
                        defining_principal.clone(),
                    ));
                    if defining_principal == package {
                        return Err(VfsError::policy_denied(
                            "chdir",
                            Arc::from(namespace.virtual_path()),
                            "foreign-binding-target-denied",
                        ));
                    }
                }
                Ok(())
            })
            .expect_err("the combined symlink tail must be denied at the package binding");
        assert_eq!(error.reason(), VfsReason::PolicyDenied);
        assert_eq!(
            error.safe_decision_id(),
            Some("foreign-binding-target-denied")
        );
        assert_eq!(
            requested,
            [
                ("/project/alias/pkg/sub".into(), root),
                ("/project/node_modules/pkg/sub".into(), package),
            ]
        );
        assert_eq!(session.current_cwd().unwrap(), b"/project");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_vfs_chdir_reverifies_after_commit_callback() {
        let temp = tempfile::tempdir().unwrap();
        let live = temp.path().join("live");
        let moved = temp.path().join("moved");
        let replacement = temp.path().join("replacement");
        fs::create_dir(&live).unwrap();
        fs::create_dir(&replacement).unwrap();
        let session =
            RuntimeVfsSession::new(NonZeroU64::new(305).unwrap(), test_vfs(temp.path())).unwrap();

        let error = session
            .chdir_authorized(b"/project/live", |stage, _, _, _| {
                if stage == capsec_semantics::model::Stage::Commit {
                    fs::rename(&live, &moved).unwrap();
                    fs::rename(&replacement, &live).unwrap();
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.reason(), VfsReason::StaleIdentity);
        assert_eq!(session.current_cwd().unwrap(), b"/project");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_vfs_chdir_root_a_b_a_swap_keeps_authenticated_descriptor() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("root");
        let original = outer.path().join("original");
        let substitute = outer.path().join("substitute");
        fs::create_dir_all(root.join("live")).unwrap();
        fs::create_dir_all(substitute.join("live")).unwrap();
        fs::write(root.join("live/marker"), b"authenticated").unwrap();
        fs::write(substitute.join("live/marker"), b"substitute").unwrap();
        let authentic_live = object_identity_for_host_path(&root.join("live")).unwrap();
        let session =
            RuntimeVfsSession::new(NonZeroU64::new(306).unwrap(), test_vfs(&root)).unwrap();
        let root_open_barrier = Arc::new(std::sync::Barrier::new(2));
        let mount_reverify_barrier = Arc::new(std::sync::Barrier::new(2));
        *CWD_ROOT_OPEN_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((root.clone(), root_open_barrier.clone()));
        *CWD_MOUNT_REVERIFY_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((root.clone(), mount_reverify_barrier.clone()));

        let result = std::thread::scope(|scope| {
            let worker = scope.spawn(|| session.chdir(b"/project/live"));

            root_open_barrier.wait();
            fs::rename(&root, &original).unwrap();
            fs::rename(&substitute, &root).unwrap();
            root_open_barrier.wait();

            mount_reverify_barrier.wait();
            fs::rename(&root, &substitute).unwrap();
            fs::rename(&original, &root).unwrap();
            mount_reverify_barrier.wait();
            worker.join().unwrap()
        });
        *CWD_ROOT_OPEN_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = None;
        *CWD_MOUNT_REVERIFY_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = None;

        assert_eq!(result.unwrap(), b"/project/live");
        let cwd = lock_recover(&session.cwd);
        assert_eq!(
            object_identity_for_open_file(&cwd.retained).unwrap(),
            authentic_live
        );
        drop(cwd);
        assert_eq!(
            session
                .resolve_private_path(b"marker")
                .unwrap()
                .virtual_path(),
            b"/project/live/marker"
        );
    }

    #[test]
    fn normalization_precedes_mount_containment() {
        let temp = tempfile::tempdir().unwrap();
        let vfs = test_vfs(temp.path());
        let base = vfs.default_base().unwrap();

        assert_eq!(
            vfs.resolve_root_bytes(b"./src//../README.md", Some(&base))
                .unwrap()
                .virtual_path(),
            "/project/README.md"
        );
        assert_eq!(
            vfs.resolve_root_bytes(b"/project/..", None)
                .unwrap()
                .virtual_path(),
            "/"
        );
        let error = vfs
            .resolve_root_bytes(b"/project/../etc/passwd", None)
            .unwrap_err();
        assert_eq!(error.reason(), VfsReason::OutsideMount);
        assert_eq!(error.virtual_path(), Some("/etc/passwd"));
        if !cfg!(windows) {
            assert_eq!(
                vfs.resolve_root_bytes(b"/project/a\\b:c", None)
                    .unwrap()
                    .virtual_path(),
                "/project/a\\b:c"
            );
        }
    }

    #[test]
    fn windows_native_path_syntax_is_refused_before_backing_translation() {
        for component in [
            "..\\outside",
            "C:\\Windows",
            "\\\\server",
            "file:stream",
            "question?",
            "wild*",
            "pipe|",
            "quote\"",
            "angle<",
            "control\u{001f}",
            "trailing.",
            "trailing ",
            "CON",
            "con.txt",
            "PRN",
            "AUX.log",
            "NUL",
            "COM1.js",
            "LPT9.log",
            "COM¹",
            "com².txt",
            "LPT³.log",
            "CONIN$",
            "CONOUT$",
        ] {
            assert!(
                !virtual_component_is_mappable(component, true),
                "Windows-dangerous component was accepted: {component:?}"
            );
        }
        for component in ["normal", "café", "COM10", "LPT0", "safe.name"] {
            assert!(
                virtual_component_is_mappable(component, true),
                "ordinary Windows component was refused: {component:?}"
            );
        }
        assert!(virtual_component_is_mappable("a\\b:c", false));
    }

    #[test]
    fn utf8_directory_intent_and_stale_session_are_typed() {
        let one = tempfile::tempdir().unwrap();
        let two = tempfile::tempdir().unwrap();
        let first = test_vfs(one.path());
        let second = test_vfs(two.path());
        assert_eq!(
            first
                .resolve_root_bytes(&[0xff], None)
                .unwrap_err()
                .reason(),
            VfsReason::MalformedInput
        );
        assert_eq!(
            first
                .resolve_utf16(&root_principal("test-project"), &[0xd800], None)
                .unwrap_err()
                .reason(),
            VfsReason::MalformedInput
        );
        let base = first.resolve_root_bytes(b"/project/dir/", None).unwrap();
        assert!(base.directory_intent());
        assert_eq!(
            second
                .resolve_root_bytes(b"child", Some(&base))
                .unwrap_err()
                .reason(),
            VfsReason::StaleSession
        );
        first.close();
        assert_eq!(
            first
                .resolve_root_bytes(b"/project/x", None)
                .unwrap_err()
                .reason(),
            VfsReason::StaleSession
        );
    }

    #[test]
    fn cross_session_and_closed_paths_never_reach_authorizer() {
        let one = tempfile::tempdir().unwrap();
        let two = tempfile::tempdir().unwrap();
        fs::write(one.path().join("x"), b"one").unwrap();
        fs::write(two.path().join("x"), b"two").unwrap();
        let first = test_vfs(one.path());
        let second = test_vfs(two.path());
        let foreign = first.resolve_root_bytes(b"/project/x", None).unwrap();
        let mut calls = 0;
        let error = second
            .read_authenticated(foreign, SourceUse::Script, |_| {
                calls += 1;
                Ok(receipt(b"allow"))
            })
            .unwrap_err();
        assert_eq!(error.reason(), VfsReason::StaleSession);
        assert_eq!(calls, 0);

        let stale = first.resolve_root_bytes(b"/project/x", None).unwrap();
        first.close();
        let error = first
            .read_authenticated(stale, SourceUse::Script, |_| {
                calls += 1;
                Ok(receipt(b"allow"))
            })
            .unwrap_err();
        assert_eq!(error.reason(), VfsReason::StaleSession);
        assert_eq!(calls, 0);
    }

    #[test]
    fn file_url_rules_are_posix_and_strip_decorations() {
        let temp = tempfile::tempdir().unwrap();
        let vfs = test_vfs(temp.path());
        let root = root_principal("test-project");

        assert_eq!(
            vfs.resolve_file_url(&root, "file://localhost/project/a%5Cb.js?one#two", None)
                .unwrap()
                .virtual_path(),
            "/project/a\\b.js"
        );
        assert_eq!(
            vfs.resolve_file_url(&root, "file:///project/%2e%2e/etc", None)
                .unwrap_err()
                .reason(),
            VfsReason::OutsideMount
        );
        for encoded in ["%2f", "%2F"] {
            assert_eq!(
                vfs.resolve_file_url(&root, &format!("file:///project/a{encoded}b"), None)
                    .unwrap_err()
                    .reason(),
                VfsReason::EncodedSeparator
            );
        }
        assert_eq!(
            vfs.resolve_file_url(&root, "file:///project/%FF", None)
                .unwrap_err()
                .reason(),
            VfsReason::MalformedInput
        );
        assert_eq!(
            vfs.resolve_file_url(&root, "file://remote/project/x", None)
                .unwrap_err()
                .reason(),
            VfsReason::MalformedInput
        );
        assert_eq!(
            vfs.resolve_file_url(&root, "file:///project/caf%C3%A9%25.js?v=1#x", None)
                .unwrap(),
            vfs.resolve_root_bytes("/project/café%.js".as_bytes(), None)
                .unwrap()
        );
        assert_eq!(
            vfs.resolve_file_url(&root, "file:///project/a%5Cb.js", None)
                .unwrap(),
            vfs.resolve_root_bytes(b"/project/a\\b.js", None).unwrap()
        );
        assert_eq!(
            vfs.resolve_file_url(&root, "file:///project/%", None)
                .unwrap_err()
                .reason(),
            VfsReason::MalformedInput
        );
    }

    #[test]
    fn pre_snapshot_and_instance_entry_labels_are_identical() {
        let temp = tempfile::tempdir().unwrap();
        let entry = temp.path().join("src").join("snow ☃\\file%.js");
        let vfs = test_vfs(temp.path());
        let direct = source_label_for_authenticated_project_path(temp.path(), &entry).unwrap();
        let mounted = vfs
            .source_label_for_authenticated_project_path(&entry)
            .unwrap();
        assert_eq!(direct, mounted);
        assert_eq!(
            direct.as_str(),
            "file:///project/src/snow%20%E2%98%83%5Cfile%25.js"
        );

        let outside = temp.path().parent().unwrap().join("outside.js");
        assert_eq!(
            source_label_for_authenticated_project_path(temp.path(), &outside)
                .unwrap_err()
                .reason(),
            vfs.source_label_for_authenticated_project_path(&outside)
                .unwrap_err()
                .reason()
        );
    }

    #[cfg(unix)]
    #[test]
    fn entry_label_helpers_identically_refuse_non_utf8_tail() {
        use std::os::unix::ffi::OsStringExt;

        let temp = tempfile::tempdir().unwrap();
        let entry = temp
            .path()
            .join(std::ffi::OsString::from_vec(vec![b'x', 0xff]));
        let vfs = test_vfs(temp.path());
        assert_eq!(
            source_label_for_authenticated_project_path(temp.path(), &entry)
                .unwrap_err()
                .reason(),
            VfsReason::MalformedInput
        );
        assert_eq!(
            vfs.source_label_for_authenticated_project_path(&entry)
                .unwrap_err()
                .reason(),
            VfsReason::MalformedInput
        );
    }

    #[test]
    fn requested_authorization_precedes_absence_and_host_lookup() {
        let temp = tempfile::tempdir().unwrap();
        let vfs = test_vfs(temp.path());
        let path = vfs.resolve_root_bytes(b"/project/secret", None).unwrap();
        let mut stages = Vec::new();
        let error = vfs
            .read_authenticated(path, SourceUse::Script, |stage| {
                stages.push(matches!(stage, ReadAuthorization::Requested(_)));
                Err(VfsError::policy_denied(
                    "read",
                    Arc::from("/project/secret"),
                    "decision:test-deny",
                ))
            })
            .unwrap_err();
        assert_eq!(stages, [true]);
        assert_eq!(error.reason(), VfsReason::PolicyDenied);

        let path = vfs.resolve_root_bytes(b"/project/absent", None).unwrap();
        let mut stages = 0;
        let error = vfs
            .read_authenticated(path, SourceUse::Script, |_| {
                stages += 1;
                Ok(receipt(b"allow"))
            })
            .unwrap_err();
        assert_eq!(stages, 1);
        assert_eq!(error.reason(), VfsReason::Absent);
    }

    #[test]
    fn root_directory_and_trailing_slash_reads_have_ordered_virtual_errors() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("dir")).unwrap();
        fs::write(temp.path().join("file"), b"file").unwrap();
        let vfs = test_vfs(temp.path());
        let host_spelling = temp.path().to_str().unwrap();

        let mut calls = 0;
        let synthetic = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/", None).unwrap(),
                SourceUse::Script,
                |_| {
                    calls += 1;
                    Ok(receipt(b"allow"))
                },
            )
            .unwrap_err();
        assert_eq!(synthetic.reason(), VfsReason::SyntheticNode);
        assert_eq!(calls, 0);

        let mount = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project", None).unwrap(),
                SourceUse::Script,
                |_| {
                    calls += 1;
                    Ok(receipt(b"allow"))
                },
            )
            .unwrap_err();
        assert_eq!(mount.code(), "EISDIR");
        assert_eq!(calls, 1, "mount type is reported only after requested auth");

        let mut directory_stages = Vec::new();
        let directory = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/dir", None).unwrap(),
                SourceUse::Script,
                |stage| {
                    directory_stages.push(match stage {
                        ReadAuthorization::Requested(_) => "requested",
                        ReadAuthorization::Discovery(_) => "discovery",
                        ReadAuthorization::Commit(_) => "commit",
                        ReadAuthorization::Repeat(_) => "repeat",
                    });
                    Ok(receipt(b"allow"))
                },
            )
            .unwrap_err();
        assert_eq!(directory.code(), "EISDIR");
        assert_eq!(directory_stages, ["requested", "discovery", "commit"]);

        let mut slash_stages = 0;
        let slash = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/file/", None).unwrap(),
                SourceUse::Script,
                |_| {
                    slash_stages += 1;
                    Ok(receipt(b"allow"))
                },
            )
            .unwrap_err();
        assert_eq!(slash.code(), "ENOTDIR");
        assert_eq!(slash_stages, 3);

        let denied = VfsError::policy_denied("read", Arc::from("/project/secret"), "decision:safe");
        for error in [synthetic, mount, directory, slash, denied] {
            assert!(!error.to_string().contains(host_spelling));
            assert!(error.virtual_path().unwrap().starts_with('/'));
        }
    }

    #[test]
    fn read_returns_immutable_bytes_referrer_and_object_evidence() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/main.js"), b"answer = 42;\n").unwrap();
        let vfs = test_vfs(temp.path());
        let path = vfs
            .resolve_root_bytes(b"/project/src/main.js", None)
            .unwrap();
        let mut stages = Vec::new();
        let read = vfs
            .read_authenticated(path, SourceUse::Script, |stage| {
                stages.push(match stage {
                    ReadAuthorization::Requested(_) => "requested",
                    ReadAuthorization::Discovery(_) => "discovery",
                    ReadAuthorization::Commit(_) => "commit",
                    ReadAuthorization::Repeat(_) => "repeat",
                });
                Ok(receipt(stages.last().unwrap().as_bytes()))
            })
            .unwrap();
        assert_eq!(stages, ["requested", "discovery", "commit", "repeat"]);
        assert_eq!(&*read.bytes(), b"answer = 42;\n");
        assert_eq!(read.logical_referrer().root, LogicalRoot::Project);
        assert_eq!(read.logical_referrer().components[0].bytes(), b"src");
        assert!(
            read.source_id().is_none(),
            "scripts have no module SourceId"
        );
        assert_eq!(read.source_label().as_str(), "file:///project/src/main.js");
        assert_ne!(
            read.evidence().parent_object(),
            read.evidence().final_object()
        );
        assert!(read.evidence().digest().as_str().starts_with("sha256-"));
    }

    #[test]
    fn whole_file_reads_enforce_the_generated_input_bound() {
        let temp = tempfile::tempdir().unwrap();
        let exact = vec![b'x'; crate::session_constants::MAX_INPUT_BYTES];
        let over = vec![b'y'; crate::session_constants::MAX_INPUT_BYTES + 1];
        fs::write(temp.path().join("exact.js"), &exact).unwrap();
        fs::write(temp.path().join("over.js"), &over).unwrap();
        let vfs = test_vfs(temp.path());

        let read = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/exact.js", None).unwrap(),
                SourceUse::Script,
                |_| Ok(receipt(b"allow")),
            )
            .unwrap();
        assert_eq!(
            read.bytes().len(),
            crate::session_constants::MAX_INPUT_BYTES
        );
        assert_eq!(read.bytes().as_ref(), exact.as_slice());

        let mut stages = 0;
        let error = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/over.js", None).unwrap(),
                SourceUse::Script,
                |_| {
                    stages += 1;
                    Ok(receipt(b"allow"))
                },
            )
            .unwrap_err();
        assert_eq!(stages, 4);
        assert_eq!(error.reason(), VfsReason::InputTooLarge);
        assert_eq!(error.code(), "ERR_IBEX_INPUT_TOO_LARGE");
        assert_eq!(error.virtual_path(), Some("/project/over.js"));
    }

    #[test]
    fn module_source_id_is_not_its_display_label() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("mod.js"), b"export default 1;\n").unwrap();
        let vfs = test_vfs(temp.path());
        let path = vfs.resolve_root_bytes(b"/project/mod.js", None).unwrap();
        let read = vfs
            .read_authenticated(path, SourceUse::Module, |_| Ok(receipt(b"allow")))
            .unwrap();
        assert!(read.source_id().is_some());
        assert_eq!(
            read.source_id().unwrap().defining_principal(),
            Some(&root_principal("test-project"))
        );
        assert_eq!(read.source_label().as_str(), "file:///project/mod.js");
        let cache_key = read.source_id().unwrap().cache_key();
        assert!(cache_key.starts_with("ibex-source-id-v1:"));
        assert_ne!(cache_key, read.source_label().as_str());
        let derived = vfs
            .source_id_for_authenticated_module(
                &vfs.resolve_root_bytes(b"/project/mod.js", None).unwrap(),
            )
            .unwrap();
        assert_eq!(derived, *read.source_id().unwrap());
        assert_eq!(derived.cache_key(), cache_key);
        assert_eq!(
            format!("{:?}", read.source_id().unwrap()),
            "SourceId(<authenticated>)"
        );
    }

    #[test]
    fn file_url_decorations_and_resolution_bases_do_not_change_source_id() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("dir")).unwrap();
        fs::write(temp.path().join("dir/mod.js"), b"module.exports = 1;\n").unwrap();
        let vfs = test_vfs(temp.path());
        let root_base = vfs.default_base().unwrap();
        let dir_base = vfs.resolve_root_bytes(b"/project/dir", None).unwrap();

        let from_root = vfs
            .resolve_root_bytes(b"dir/mod.js", Some(&root_base))
            .unwrap();
        let from_dir = vfs.resolve_root_bytes(b"mod.js", Some(&dir_base)).unwrap();
        let from_query = vfs
            .resolve_root_file_url("file:///project/dir/mod.js?v=1", None)
            .unwrap();
        let from_fragment = vfs
            .resolve_root_file_url("file:///project/dir/mod.js#fragment", None)
            .unwrap();

        let expected = vfs.source_id_for_authenticated_module(&from_root).unwrap();
        for namespace in [&from_dir, &from_query, &from_fragment] {
            assert_eq!(
                vfs.source_id_for_authenticated_module(namespace).unwrap(),
                expected
            );
            assert_eq!(
                SourceLabel::file(namespace).unwrap().as_str(),
                "file:///project/dir/mod.js"
            );
        }
    }

    #[test]
    fn defining_principal_not_calling_principal_keys_package_module() {
        let temp = tempfile::tempdir().unwrap();
        let package_root = temp.path().join("node_modules/foo");
        fs::create_dir_all(&package_root).unwrap();
        fs::write(package_root.join("util.js"), b"module.exports = {};\n").unwrap();
        let root = root_principal("test-project");
        let foo = package_principal("foo");
        let project_object = object_identity_for_host_path(temp.path()).unwrap();
        let bindings = vec![
            ArmedRootBinding {
                logical_root: LogicalRoot::Project,
                owner: None,
                logical_path: None,
                host_path: host_bound_path(temp.path()),
                object: project_object.clone(),
            },
            ArmedRootBinding {
                logical_root: LogicalRoot::Package,
                owner: Some(foo.clone()),
                logical_path: None,
                host_path: host_bound_path(&package_root),
                object: object_identity_for_host_path(&package_root).unwrap(),
            },
        ];
        let vfs = VirtualFileSystem::from_bindings(
            temp.path().to_path_buf(),
            project_object,
            root.clone(),
            &bindings,
            None,
        )
        .unwrap();

        let spelling = b"/project/node_modules/foo/util.js";
        let root_namespace = vfs.resolve_bytes(&root, spelling, None).unwrap();
        let owner_namespace = vfs.resolve_bytes(&foo, spelling, None).unwrap();
        assert_eq!(
            root_namespace.logical_path().unwrap().root,
            LogicalRoot::Project
        );
        assert_eq!(
            owner_namespace.logical_path().unwrap().root,
            LogicalRoot::Package
        );
        assert_eq!(owner_namespace.binding_owner(), Some(&foo));
        let root_read = vfs
            .read_authenticated(root_namespace, SourceUse::Module, |_| Ok(receipt(b"root")))
            .unwrap();
        let owner_read = vfs
            .read_authenticated(owner_namespace, SourceUse::Module, |_| Ok(receipt(b"foo")))
            .unwrap();

        assert_eq!(root_read.source_id(), owner_read.source_id());
        assert_eq!(root_read.source_label(), owner_read.source_label());
        assert_eq!(
            root_read.source_id().unwrap().defining_principal(),
            Some(&foo)
        );
    }

    #[cfg(unix)]
    #[test]
    fn hard_linked_package_entries_keep_distinct_principals_ids_and_labels() {
        let temp = tempfile::tempdir().unwrap();
        let a_root = temp.path().join("node_modules/a");
        let b_root = temp.path().join("node_modules/b");
        fs::create_dir_all(&a_root).unwrap();
        fs::create_dir_all(&b_root).unwrap();
        fs::write(a_root.join("same.js"), b"module.exports = {};\n").unwrap();
        fs::hard_link(a_root.join("same.js"), b_root.join("same.js")).unwrap();
        let root = root_principal("test-project");
        let a = package_principal("a");
        let b = package_principal("b");
        let project_object = object_identity_for_host_path(temp.path()).unwrap();
        let bindings = vec![
            ArmedRootBinding {
                logical_root: LogicalRoot::Project,
                owner: None,
                logical_path: None,
                host_path: host_bound_path(temp.path()),
                object: project_object.clone(),
            },
            ArmedRootBinding {
                logical_root: LogicalRoot::Package,
                owner: Some(a.clone()),
                logical_path: None,
                host_path: host_bound_path(&a_root),
                object: object_identity_for_host_path(&a_root).unwrap(),
            },
            ArmedRootBinding {
                logical_root: LogicalRoot::Package,
                owner: Some(b.clone()),
                logical_path: None,
                host_path: host_bound_path(&b_root),
                object: object_identity_for_host_path(&b_root).unwrap(),
            },
        ];
        let vfs = VirtualFileSystem::from_bindings(
            temp.path().to_path_buf(),
            project_object,
            root,
            &bindings,
            None,
        )
        .unwrap();
        let a_read = vfs
            .read_authenticated(
                vfs.resolve_bytes(&a, b"/project/node_modules/a/same.js", None)
                    .unwrap(),
                SourceUse::Module,
                |_| Ok(receipt(b"a")),
            )
            .unwrap();
        let b_read = vfs
            .read_authenticated(
                vfs.resolve_bytes(&b, b"/project/node_modules/b/same.js", None)
                    .unwrap(),
                SourceUse::Module,
                |_| Ok(receipt(b"b")),
            )
            .unwrap();

        assert_eq!(
            a_read.evidence().final_object(),
            b_read.evidence().final_object()
        );
        assert_eq!(a_read.source_id().unwrap().defining_principal(), Some(&a));
        assert_eq!(b_read.source_id().unwrap().defining_principal(), Some(&b));
        assert_ne!(a_read.source_id(), b_read.source_id());
        assert_eq!(
            a_read.source_label().as_str(),
            "file:///project/node_modules/a/same.js"
        );
        assert_eq!(
            b_read.source_label().as_str(),
            "file:///project/node_modules/b/same.js"
        );

        let b_first = vfs
            .read_authenticated(
                vfs.resolve_bytes(&b, b"/project/node_modules/b/same.js", None)
                    .unwrap(),
                SourceUse::Module,
                |_| Ok(receipt(b"b-first")),
            )
            .unwrap();
        let a_second = vfs
            .read_authenticated(
                vfs.resolve_bytes(&a, b"/project/node_modules/a/same.js", None)
                    .unwrap(),
                SourceUse::Module,
                |_| Ok(receipt(b"a-second")),
            )
            .unwrap();
        assert_eq!(a_read.source_id(), a_second.source_id());
        assert_eq!(a_read.source_label(), a_second.source_label());
        assert_eq!(b_read.source_id(), b_first.source_id());
        assert_eq!(b_read.source_label(), b_first.source_label());
    }

    #[test]
    fn package_owner_projection_is_shadowed_by_deeper_foreign_binding() {
        let temp = tempfile::tempdir().unwrap();
        let a_root = temp.path().join("node_modules/a");
        let b_root = a_root.join("node_modules/b");
        fs::create_dir_all(&b_root).unwrap();
        fs::write(a_root.join("a.js"), b"a").unwrap();
        fs::write(b_root.join("b.js"), b"b").unwrap();
        let root = root_principal("test-project");
        let a = package_principal("a");
        let b = package_principal("b");
        let project_object = object_identity_for_host_path(temp.path()).unwrap();
        let bindings = vec![
            ArmedRootBinding {
                logical_root: LogicalRoot::Project,
                owner: None,
                logical_path: None,
                host_path: host_bound_path(temp.path()),
                object: project_object.clone(),
            },
            ArmedRootBinding {
                logical_root: LogicalRoot::Package,
                owner: Some(a.clone()),
                logical_path: None,
                host_path: host_bound_path(&a_root),
                object: object_identity_for_host_path(&a_root).unwrap(),
            },
            ArmedRootBinding {
                logical_root: LogicalRoot::Package,
                owner: Some(b.clone()),
                logical_path: None,
                host_path: host_bound_path(&b_root),
                object: object_identity_for_host_path(&b_root).unwrap(),
            },
        ];
        let vfs = VirtualFileSystem::from_bindings(
            temp.path().to_path_buf(),
            project_object,
            root,
            &bindings,
            None,
        )
        .unwrap();

        let own_a = vfs
            .resolve_bytes(&a, b"/project/node_modules/a/a.js", None)
            .unwrap();
        assert_eq!(own_a.logical_path().unwrap().root, LogicalRoot::Package);
        assert_eq!(own_a.binding_owner(), Some(&a));

        let nested_b_seen_by_a = vfs
            .resolve_bytes(&a, b"/project/node_modules/a/node_modules/b/b.js", None)
            .unwrap();
        assert_eq!(
            nested_b_seen_by_a.logical_path().unwrap().root,
            LogicalRoot::Project
        );
        assert_eq!(nested_b_seen_by_a.binding_owner(), None);

        let own_b = vfs
            .resolve_bytes(&b, b"/project/node_modules/a/node_modules/b/b.js", None)
            .unwrap();
        assert_eq!(own_b.logical_path().unwrap().root, LogicalRoot::Package);
        assert_eq!(own_b.binding_owner(), Some(&b));
        let read = vfs
            .read_authenticated(nested_b_seen_by_a, SourceUse::Module, |_| {
                Ok(receipt(b"allow"))
            })
            .unwrap();
        assert_eq!(read.source_id().unwrap().defining_principal(), Some(&b));
    }

    #[test]
    fn authenticated_package_binding_root_replacement_is_stale() {
        let temp = tempfile::tempdir().unwrap();
        let package_root = temp.path().join("node_modules/a");
        let replacement = temp.path().join("replacement");
        fs::create_dir_all(&package_root).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(package_root.join("index.js"), b"authenticated").unwrap();
        fs::write(replacement.join("index.js"), b"attacker").unwrap();
        let project_object = object_identity_for_host_path(temp.path()).unwrap();
        let bindings = vec![
            ArmedRootBinding {
                logical_root: LogicalRoot::Project,
                owner: None,
                logical_path: None,
                host_path: host_bound_path(temp.path()),
                object: project_object.clone(),
            },
            ArmedRootBinding {
                logical_root: LogicalRoot::Package,
                owner: Some(package_principal("a")),
                logical_path: None,
                host_path: host_bound_path(&package_root),
                object: object_identity_for_host_path(&package_root).unwrap(),
            },
        ];
        let vfs = VirtualFileSystem::from_bindings(
            temp.path().to_path_buf(),
            project_object,
            root_principal("test-project"),
            &bindings,
            None,
        )
        .unwrap();
        fs::rename(&package_root, temp.path().join("old-package")).unwrap();
        fs::rename(&replacement, &package_root).unwrap();

        let mut decisions = 0;
        let error = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/node_modules/a/index.js", None)
                    .unwrap(),
                SourceUse::Module,
                |_| {
                    decisions += 1;
                    Ok(receipt(b"allow"))
                },
            )
            .unwrap_err();
        assert_eq!(error.reason(), VfsReason::StaleIdentity);
        assert_eq!(decisions, 1, "only the pre-lookup decision may run");
        assert!(!error.to_string().contains(temp.path().to_str().unwrap()));
    }

    #[test]
    fn root_replacement_is_refused_without_leaking_host_path() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("root");
        let replacement = outer.path().join("replacement");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(root.join("x"), b"old").unwrap();
        fs::write(replacement.join("x"), b"new").unwrap();
        let vfs = test_vfs(&root);
        fs::rename(&root, outer.path().join("old-root")).unwrap();
        fs::rename(&replacement, &root).unwrap();

        let path = vfs.resolve_root_bytes(b"/project/x", None).unwrap();
        let error = vfs
            .read_authenticated(path, SourceUse::Script, |_| Ok(receipt(b"allow")))
            .unwrap_err();
        assert_eq!(error.reason(), VfsReason::StaleIdentity);
        assert_eq!(error.virtual_path(), Some("/project/x"));
        assert!(!error.to_string().contains(outer.path().to_str().unwrap()));
    }

    #[cfg(windows)]
    #[test]
    fn windows_runtime_session_refuses_a_reparse_project_root() {
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("target");
        let junction = outer.path().join("junction");
        fs::create_dir(&target).unwrap();
        let output = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .expect("invoke Windows junction creation");
        assert!(
            output.status.success(),
            "create Windows project-root junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let object = object_identity_for_host_path(&junction).unwrap();
        let vfs = VirtualFileSystem::from_bindings(
            junction.clone(),
            object,
            root_principal("test-project"),
            &[],
            None,
        )
        .unwrap();
        let error = RuntimeVfsSession::new(NonZeroU64::new(303).unwrap(), vfs).unwrap_err();
        assert_eq!(error.reason(), VfsReason::StaleIdentity);
        assert_eq!(error.virtual_path(), Some("/project"));
        assert!(!error.to_string().contains(outer.path().to_str().unwrap()));
    }

    #[cfg(windows)]
    #[test]
    fn windows_retained_project_root_refuses_a_path_replacement() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("root");
        let replacement = outer.path().join("replacement");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&replacement).unwrap();
        let session =
            RuntimeVfsSession::new(NonZeroU64::new(404).unwrap(), test_vfs(&root)).unwrap();

        fs::rename(&root, outer.path().join("old-root")).unwrap();
        fs::rename(&replacement, &root).unwrap();

        let error = session.current_cwd().unwrap_err();
        assert_eq!(error.reason(), VfsReason::StaleIdentity);
        assert_eq!(error.virtual_path(), Some("/project"));
        assert!(!error.to_string().contains(outer.path().to_str().unwrap()));
    }

    #[test]
    fn committed_descriptor_survives_root_path_swap() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("root");
        let replacement = outer.path().join("replacement");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(root.join("x"), b"authenticated").unwrap();
        fs::write(replacement.join("x"), b"attacker").unwrap();
        let vfs = test_vfs(&root);
        let path = vfs.resolve_root_bytes(b"/project/x", None).unwrap();
        let mut swapped = false;
        let read = vfs
            .read_authenticated(path, SourceUse::Script, |stage| {
                if matches!(stage, ReadAuthorization::Commit(_)) {
                    fs::rename(&root, outer.path().join("old-root")).unwrap();
                    fs::rename(&replacement, &root).unwrap();
                    swapped = true;
                }
                Ok(receipt(b"allow"))
            })
            .unwrap();
        assert!(swapped);
        assert_eq!(&*read.bytes(), b"authenticated");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_authorization_binds_ancestor_and_pending_tail_before_lookup() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        // Deliberately omit `pkg/package.json`: the combined path must reach
        // authorization before traversal can disclose that its pending tail
        // is absent.
        fs::create_dir(temp.path().join("node_modules")).unwrap();
        symlink("node_modules", temp.path().join("alias")).unwrap();
        let vfs = test_vfs(temp.path());
        let combined = "/project/node_modules/pkg/package.json";
        let mut stages = Vec::new();
        let error = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/alias/pkg/package.json", None)
                    .unwrap(),
                SourceUse::Module,
                |stage| {
                    let label = match &stage {
                        ReadAuthorization::Requested(path) => {
                            format!("requested:{}", path.virtual_path())
                        }
                        ReadAuthorization::Discovery(path) => {
                            format!("discovery:{}", path.namespace().virtual_path())
                        }
                        ReadAuthorization::Commit(path) => {
                            format!("commit:{}", path.namespace().virtual_path())
                        }
                        ReadAuthorization::Repeat(path) => {
                            format!("repeat:{}", path.namespace().virtual_path())
                        }
                    };
                    stages.push(label);
                    if matches!(
                        &stage,
                        ReadAuthorization::Requested(path) if path.virtual_path() == combined
                    ) {
                        return Err(VfsError::policy_denied(
                            "read",
                            Arc::from(combined),
                            "combined-symlink-target-denied",
                        ));
                    }
                    Ok(receipt(stages.last().unwrap().as_bytes()))
                },
            )
            .expect_err("the combined symlink target must be authorizable before lookup");
        assert_eq!(error.reason(), VfsReason::PolicyDenied);
        assert_eq!(
            error.safe_decision_id(),
            Some("combined-symlink-target-denied")
        );
        assert_eq!(
            stages,
            [
                "requested:/project/alias/pkg/package.json",
                "discovery:/project/alias",
                "requested:/project/node_modules/pkg/package.json",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn contained_symlinks_reauthorize_targets_and_canonicalize_source_identity() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("real/dir")).unwrap();
        fs::write(temp.path().join("real/dir/file.js"), b"contained").unwrap();
        symlink("real/dir", temp.path().join("alias")).unwrap();
        symlink(
            temp.path().join("real/dir/file.js"),
            temp.path().join("absolute.js"),
        )
        .unwrap();
        let vfs = test_vfs(temp.path());

        let mut stages = Vec::new();
        let read = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/alias/file.js", None)
                    .unwrap(),
                SourceUse::Module,
                |stage| {
                    stages.push(match stage {
                        ReadAuthorization::Requested(path) => {
                            format!("requested:{}", path.virtual_path())
                        }
                        ReadAuthorization::Discovery(path) => {
                            format!("discovery:{}", path.namespace().virtual_path())
                        }
                        ReadAuthorization::Commit(path) => {
                            format!("commit:{}", path.namespace().virtual_path())
                        }
                        ReadAuthorization::Repeat(path) => {
                            format!("repeat:{}", path.namespace().virtual_path())
                        }
                    });
                    Ok(receipt(stages.last().unwrap().as_bytes()))
                },
            )
            .unwrap();
        assert_eq!(&*read.bytes(), b"contained");
        assert_eq!(
            read.source_label().as_str(),
            "file:///project/real/dir/file.js"
        );
        assert_eq!(read.evidence().traversal_decisions().len(), 2);
        assert_eq!(
            stages,
            [
                "requested:/project/alias/file.js",
                "discovery:/project/alias",
                "requested:/project/real/dir/file.js",
                "discovery:/project/real/dir/file.js",
                "commit:/project/real/dir/file.js",
                "repeat:/project/real/dir/file.js",
            ]
        );

        let direct = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/real/dir/file.js", None)
                    .unwrap(),
                SourceUse::Module,
                |_| Ok(receipt(b"direct")),
            )
            .unwrap();
        assert_eq!(read.source_id(), direct.source_id());
        assert_eq!(read.source_label(), direct.source_label());

        // Repeat from a fresh session in the opposite order: neither identity
        // nor display spelling may depend on which alias populated a cache
        // first.
        let reverse = test_vfs(temp.path());
        let direct_first = reverse
            .read_authenticated(
                reverse
                    .resolve_root_bytes(b"/project/real/dir/file.js", None)
                    .unwrap(),
                SourceUse::Module,
                |_| Ok(receipt(b"direct-first")),
            )
            .unwrap();
        let alias_second = reverse
            .read_authenticated(
                reverse
                    .resolve_root_bytes(b"/project/alias/file.js", None)
                    .unwrap(),
                SourceUse::Module,
                |_| Ok(receipt(b"alias-second")),
            )
            .unwrap();
        assert_eq!(direct_first.source_id(), alias_second.source_id());
        assert_eq!(direct_first.source_label(), alias_second.source_label());

        let absolute = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/absolute.js", None)
                    .unwrap(),
                SourceUse::Script,
                |_| Ok(receipt(b"allow")),
            )
            .unwrap();
        assert_eq!(&*absolute.bytes(), b"contained");
        assert_eq!(
            absolute.source_label().as_str(),
            "file:///project/real/dir/file.js"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_depth_and_link_object_races_fail_closed() {
        use std::os::unix::fs::symlink;

        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), b"secret").unwrap();
        let root = tempfile::tempdir().unwrap();
        symlink(outside.path().join("secret"), root.path().join("escape")).unwrap();
        let vfs = test_vfs(root.path());
        let error = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/escape", None).unwrap(),
                SourceUse::Script,
                |_| Ok(receipt(b"allow")),
            )
            .unwrap_err();
        assert_eq!(error.reason(), VfsReason::OutsideMount);
        assert!(!error.to_string().contains(outside.path().to_str().unwrap()));

        fs::write(root.path().join("end"), b"end").unwrap();
        for index in (0..33).rev() {
            let target = if index == 32 {
                "end".to_owned()
            } else {
                format!("link-{}", index + 1)
            };
            symlink(target, root.path().join(format!("link-{index}"))).unwrap();
        }
        let error = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/link-0", None).unwrap(),
                SourceUse::Script,
                |_| Ok(receipt(b"allow")),
            )
            .unwrap_err();
        assert_eq!(error.reason(), VfsReason::SymlinkDepthExceeded);
        assert_eq!(error.code(), "ELOOP");

        symlink("end", root.path().join("racy")).unwrap();
        fs::write(root.path().join("other"), b"other").unwrap();
        let mut swapped = false;
        let error = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/racy", None).unwrap(),
                SourceUse::Script,
                |stage| {
                    if matches!(stage, ReadAuthorization::Discovery(_)) && !swapped {
                        fs::rename(root.path().join("racy"), root.path().join("old-link")).unwrap();
                        symlink("other", root.path().join("racy")).unwrap();
                        swapped = true;
                    }
                    Ok(receipt(b"allow"))
                },
            )
            .unwrap_err();
        assert!(swapped);
        assert_eq!(error.reason(), VfsReason::StaleIdentity);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_substitution_is_safe_at_every_authorization_boundary() {
        use std::os::unix::fs::symlink;

        for boundary in ["requested", "discovery", "commit", "repeat"] {
            let temp = tempfile::tempdir().unwrap();
            let target = temp.path().join("target");
            let attacker = temp.path().join("attacker");
            fs::write(&target, b"authenticated").unwrap();
            fs::write(&attacker, b"attacker").unwrap();
            let vfs = test_vfs(temp.path());
            let path = vfs.resolve_root_bytes(b"/project/target", None).unwrap();
            let mut substituted = false;
            let result = vfs.read_authenticated(path, SourceUse::Script, |stage| {
                let current = match stage {
                    ReadAuthorization::Requested(_) => "requested",
                    ReadAuthorization::Discovery(_) => "discovery",
                    ReadAuthorization::Commit(_) => "commit",
                    ReadAuthorization::Repeat(_) => "repeat",
                };
                if current == boundary && !substituted {
                    fs::rename(&target, temp.path().join("retained")).unwrap();
                    symlink(&attacker, &target).unwrap();
                    if boundary == "repeat" {
                        fs::write(temp.path().join("retained"), b"changed").unwrap();
                    }
                    substituted = true;
                }
                Ok(receipt(current.as_bytes()))
            });
            assert!(substituted, "boundary {boundary} was not exercised");
            match boundary {
                "requested" => {
                    let read = result.unwrap();
                    assert_eq!(&*read.bytes(), b"attacker");
                    assert_eq!(read.evidence().traversal_decisions().len(), 2);
                }
                "discovery" => {
                    let error = result.unwrap_err();
                    assert_eq!(error.reason(), VfsReason::StaleIdentity);
                }
                "commit" => assert_eq!(&*result.unwrap().bytes(), b"authenticated"),
                "repeat" => {
                    let error = result.unwrap_err();
                    assert_eq!(error.reason(), VfsReason::StaleIdentity);
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn object_substitution_after_discovery_is_stale_and_hardlink_keys_stay_lexical() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.js");
        let attacker = temp.path().join("attacker.js");
        fs::write(&target, b"authenticated").unwrap();
        fs::write(&attacker, b"attacker").unwrap();
        let vfs = test_vfs(temp.path());
        let path = vfs.resolve_root_bytes(b"/project/target.js", None).unwrap();
        let error = vfs
            .read_authenticated(path, SourceUse::Script, |stage| {
                if matches!(stage, ReadAuthorization::Discovery(_)) {
                    fs::rename(&target, temp.path().join("retained.js")).unwrap();
                    fs::hard_link(&attacker, &target).unwrap();
                }
                Ok(receipt(b"allow"))
            })
            .unwrap_err();
        assert_eq!(error.reason(), VfsReason::StaleIdentity);

        let original = temp.path().join("original.js");
        let alias = temp.path().join("alias.js");
        fs::write(&original, b"same object").unwrap();
        fs::hard_link(&original, &alias).unwrap();
        let original = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/original.js", None)
                    .unwrap(),
                SourceUse::Module,
                |_| Ok(receipt(b"allow")),
            )
            .unwrap();
        let alias = vfs
            .read_authenticated(
                vfs.resolve_root_bytes(b"/project/alias.js", None).unwrap(),
                SourceUse::Module,
                |_| Ok(receipt(b"allow")),
            )
            .unwrap();
        assert_eq!(
            original.evidence().final_object(),
            alias.evidence().final_object()
        );
        assert_ne!(original.source_id(), alias.source_id());
        assert_ne!(original.source_label(), alias.source_label());
    }

    #[test]
    fn evidence_identity_uses_platform_object_not_host_spelling() {
        let identity = ObjectIdentity {
            platform: ObjectPlatform::Unix,
            volume: NonEmptyString::new("dev:1").unwrap(),
            file: NonEmptyString::new("ino:2").unwrap(),
        };
        let digest = digest_read_evidence(
            &[
                digest_bytes(b"a", b"a"),
                digest_bytes(b"b", b"b"),
                digest_bytes(b"d", b"d"),
                digest_bytes(b"e", b"e"),
            ],
            &identity,
            &identity,
            &digest_bytes(b"c", b"c"),
            "/project/x",
        );
        assert!(digest.as_str().starts_with("sha256-"));
    }
}
