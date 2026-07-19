//! Capability management for the security model
//!
//! This implements the capability-based security system described by LLP 0013
//! and the generated-policy algebra in LLP 0014.

use super::SecurityMode;
use crate::host::policy::PolicyFile;
use crate::module_loader::RUNTIME_GATED_NODE_BUILTINS;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;

const MAX_AUDIT_LOG_ENTRIES: usize = 1024;

/// A capability grant record
#[derive(Debug, Clone)]
pub struct CapabilityGrant {
    /// The capability string (canonical form)
    pub capability: String,
    /// Canonical form for operations that mutate a symlink entry itself rather
    /// than the final target (`lchown`, `lutimes`, `lchmod`).
    pub capability_no_follow_final: String,
    /// The module that was granted the capability
    pub module_id: String,
    /// Optional constraint (e.g., path pattern, host pattern)
    pub constraint: Option<String>,
    /// Whether this is a denial (revocation)
    pub denied: bool,
}

/// The resolved runtime principal for a module: the policy **selector**
/// (package name) plus, when available, a **locator** (lockfile identity /
/// resolved path) so coexisting versions stay distinguishable in the audit log.
///
/// @ref LLP 0013#resolved-questions — package name is the policy selector; the
/// runtime principal is name + resolved locator.
#[derive(Debug, Clone, Default)]
pub struct PackagePrincipal {
    pub name: String,
    pub locator: Option<String>,
}

impl PackagePrincipal {
    /// Policy selectors for this principal, most-specific first: the resolved
    /// locator (e.g. a `name@version` pin or path) when it is distinct from the
    /// bare name, then the name itself. Callers consult them in order so a
    /// version/locator-specific policy entry takes precedence over the name-level
    /// default that survives version bumps (RFC Resolved Q1). (ENG-22621)
    fn selectors(&self) -> impl Iterator<Item = &str> {
        self.locator
            .as_deref()
            .filter(|loc| *loc != self.name.as_str())
            .into_iter()
            .chain(std::iter::once(self.name.as_str()))
    }
}

/// Per-package import-graph policy. `None` on an axis means "unrestricted";
/// `Some(list)` means "only these are allowed" (an explicit empty list denies
/// everything on that axis).
///
/// @ref LLP 0013#policy — the import graph is the primary gate for builtins.
#[derive(Debug, Clone, Default)]
pub struct ImportPolicy {
    pub builtins: Option<Vec<String>>,
    pub packages: Option<Vec<String>>,
}

/// Manages capability grants and checks
pub struct CapabilityManager {
    mode: SecurityMode,
    /// Monotonic identity of every input that can change a legacy capability
    /// decision. Retained native resources use it only as an invalidation key:
    /// a match permits reuse of an already successful decision for the exact
    /// same principal stack and resource, while a mismatch forces the normal
    /// policy path before the next external effect.
    authorization_generation: AtomicU64,
    /// Production-visible diagnostic counter used by hot-path regressions. It
    /// counts full legacy decisions, not generation-only lease checks.
    authorization_check_count: AtomicUsize,
    /// Grants by numeric module ID (and `*` for global grants).
    grants: RwLock<HashMap<String, Vec<CapabilityGrant>>>,
    /// Grants keyed by package **selector** (package name).
    package_grants: RwLock<HashMap<String, Vec<CapabilityGrant>>>,
    /// Bridge from a numeric module principal to its resolved package principal.
    module_to_package: RwLock<HashMap<String, PackagePrincipal>>,
    /// Per-package import-graph policy.
    import_policy: RwLock<HashMap<String, ImportPolicy>>,
    /// Memo of import decisions that resolved to ALLOWED, keyed principal →
    /// allowed specifiers. `decide_import` is pure in (`module_to_package`,
    /// `import_policy`), so a hit is exactly the recomputation — and since
    /// `gate_and_record` records only would-denies, skipping it for an allowed
    /// decision drops no audit entry. Denials are never memoized (every denied
    /// import re-runs the full path and records). Invalidated when either
    /// input changes: `apply_policy` clears it, `register_module_package`
    /// purges the re-registered principal. Bounded by the real import graph
    /// (registered principals × specifiers they successfully import).
    /// (ENG-22644) @ref LLP 0013#policy
    import_allowed_memo: RwLock<HashMap<String, HashSet<String>>>,
    /// Capability classes (e.g. `fs:write`, `process:spawn`) that require
    /// stack-intersection enforcement. Empty = off (the default).
    deputy_classes: RwLock<HashSet<String>>,
    /// Capabilities the root principal may acquire at runtime (the dynamic
    /// "prompt" ceiling). @ref LLP 0013#interaction-with-user-facing-dynamic-permissions
    ceiling: RwLock<Vec<String>>,
    /// Host-boundary fence from `HostConfig.root_dir`: the symlink-resolved
    /// root every `fs:*` capability value must fall inside. Unlike the policy
    /// plane above, the fence denies in EVERY mode and no grant can widen past
    /// it — see `fence_denial`. Plain fields (not locked): set once via
    /// `set_host_boundary` before the manager is shared. (ENG-23876)
    /// @ref LLP 0002#host-boundary-constraints
    fs_root: Option<String>,
    /// Host-boundary fence from `HostConfig.allowed_hosts`: normalized host
    /// entries every outbound `network:*` capability value must match. Local
    /// listener authority is governed by `network:listen`, not this legacy
    /// remote-host allowlist. (ENG-23876, ENG-24285)
    allowed_hosts: Option<Vec<String>>,
    /// Audit log of capability checks
    audit_log: RwLock<VecDeque<AuditEntry>>,
    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    conformance_observer: RwLock<ConformanceObserver>,
}

#[cfg(any(test, feature = "capsec-conformance-observer"))]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservedCapabilityDecision {
    pub terminal_branch_id: String,
    pub module_id: String,
    pub capability: String,
    pub decision: bool,
    pub allowed: bool,
    pub fence: Option<String>,
}

#[cfg(any(test, feature = "capsec-conformance-observer"))]
#[derive(Default)]
struct ConformanceObserver {
    terminal_branch_id: Option<String>,
    decisions: Vec<ObservedCapabilityDecision>,
}

/// An entry in the capability audit log.
///
/// `decision` is the real policy answer (would this be allowed?). `allowed` is
/// what was returned to the caller — identical to `decision` except in `Audit`
/// mode, where a would-deny (`decision == false`) still returns `allowed ==
/// true` so the operation proceeds and the compat corpus can observe it.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: std::time::SystemTime,
    pub module_id: String,
    /// Resolved package principal, when the module id was registered.
    pub package: Option<PackagePrincipal>,
    pub capability: String,
    pub constraint: Option<String>,
    pub decision: bool,
    pub allowed: bool,
    pub mode: SecurityMode,
}

impl AuditEntry {
    /// A decision that policy would have denied. In `Enforce` this was blocked;
    /// in `Audit` it was allowed to proceed but recorded here.
    pub fn is_would_deny(&self) -> bool {
        !self.decision
    }
}

const ALWAYS_ALLOWED: [&str; 2] = ["crypto:random", "time:now"];

/// The first-party root/principal id. `currentPrincipalId()` reports `0` for
/// code whose nearest JS frame is first-party (or for which no user frame is
/// attributable); every registered third-party package has a non-zero principal.
/// @ref LLP 0013#policy
const ROOT_PRINCIPAL: &str = "0";

/// The synthetic principal Ibex's module loader uses for its own file reads
/// (`Host::resolve_module`). Not a real package; trusted runtime infrastructure
/// gated by the import graph, not the capability system. @ref LLP 0013#policy
const MODULE_LOADER_PRINCIPAL: &str = "module-loader";

/// Mirror of the engine's `kNoUserPrincipal` (0xFFFFFFFE): reported by
/// `getCurrentPackageId` when the stack has NO attributable user frame — a deputy
/// op run detached from its scheduling package's frame
/// (`Promise.resolve(x).then(fs.readFileSync)`). It is DISTINCT from first-party
/// root "0" and MUST fail closed: trusting it (as a root-0 default would) lets any
/// package launder a deputy op across the async boundary into trusted root.
/// @ref LLP 0013#policy
const NO_USER_PRINCIPAL: &str = "4294967294";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsNormalizationMode {
    FollowFinal,
    NoFollowFinal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FsResourceKind {
    Pattern,
    Value,
}

impl CapabilityManager {
    /// Create a new capability manager
    pub fn new(mode: SecurityMode) -> Self {
        Self {
            mode,
            authorization_generation: AtomicU64::new(1),
            authorization_check_count: AtomicUsize::new(0),
            grants: RwLock::new(HashMap::new()),
            package_grants: RwLock::new(HashMap::new()),
            module_to_package: RwLock::new(HashMap::new()),
            import_policy: RwLock::new(HashMap::new()),
            import_allowed_memo: RwLock::new(HashMap::new()),
            deputy_classes: RwLock::new(HashSet::new()),
            ceiling: RwLock::new(Vec::new()),
            fs_root: None,
            allowed_hosts: None,
            audit_log: RwLock::new(VecDeque::with_capacity(MAX_AUDIT_LOG_ENTRIES)),
            #[cfg(any(test, feature = "capsec-conformance-observer"))]
            conformance_observer: RwLock::new(ConformanceObserver::default()),
        }
    }

    /// Configure the host-boundary fence (`HostConfig.root_dir` /
    /// `HostConfig.allowed_hosts`). The root is normalized exactly like checked
    /// `fs:*` values (absolutized, symlinks resolved) so containment compares
    /// resolved-to-resolved; host entries are normalized like `network:*`
    /// resources. Takes `&mut self`: called once from `Host::new` before the
    /// manager is shared. (ENG-23876)
    pub fn set_host_boundary(&mut self, root_dir: Option<&Path>, allowed_hosts: Option<&[String]>) {
        self.fs_root = root_dir.map(|root| {
            normalize_fs_resource(
                &root.to_string_lossy(),
                FsNormalizationMode::FollowFinal,
                FsResourceKind::Value,
            )
        });
        self.allowed_hosts = allowed_hosts.map(|hosts| {
            hosts
                .iter()
                .map(|h| normalize_network_resource(h))
                .collect()
        });
    }

    /// Apply policy file allow/deny rules
    pub fn apply_policy(&self, policy: &PolicyFile) {
        for cap in &policy.allow {
            self.grant("*", cap, None);
        }
        for cap in &policy.deny {
            self.deny("*", cap, None);
        }
        for (module_id, module_policy) in &policy.modules {
            for cap in &module_policy.allow {
                self.grant(module_id, cap, None);
            }
            for cap in &module_policy.deny {
                self.deny(module_id, cap, None);
            }
        }
        // @ref LLP 0013#policy — per-package declarations grant host
        // capabilities and constrain the import graph, keyed by the package
        // selector (name). Coexisting `name@version` entries are separate keys.
        for (selector, package_policy) in &policy.packages {
            for cap in &package_policy.capabilities {
                self.grant_package(selector, cap);
            }
            for cap in &package_policy.deny {
                self.deny_package(selector, cap);
            }
            if package_policy.builtins.is_some() || package_policy.packages.is_some() {
                if let Ok(mut map) = self.import_policy.write() {
                    map.insert(
                        selector.clone(),
                        ImportPolicy {
                            builtins: package_policy.builtins.clone(),
                            packages: package_policy.packages.clone(),
                        },
                    );
                }
            }
        }
        // @ref LLP 0013#phase-5 — optional deputy hardening classes.
        if !policy.deputy_classes.is_empty() {
            self.set_deputy_classes(policy.deputy_classes.iter().cloned());
        }
        // @ref LLP 0013 — §dynamic permissions — the runtime-grant ceiling.
        if !policy.ceiling.is_empty() {
            if let Ok(mut c) = self.ceiling.write() {
                *c = policy
                    .ceiling
                    .iter()
                    .map(|s| normalize_capability(s))
                    .collect();
                self.bump_authorization_generation();
            }
        }
        // The import policy just changed: every memoized allowed-import
        // decision is stale. Cleared LAST so a check that raced the partial
        // application above cannot leave a decision computed against the old
        // policy behind. (In practice apply_policy runs once, at host setup,
        // before user code.) (ENG-22644)
        if let Ok(mut memo) = self.import_allowed_memo.write() {
            memo.clear();
        }
    }

    /// Is `capability` within the runtime-grant ceiling (may root acquire it at
    /// runtime)? @ref LLP 0013 — §dynamic permissions
    fn within_ceiling(&self, capability: &str) -> bool {
        let normalized = normalize_capability(capability);
        self.ceiling
            .read()
            .map(|c| c.iter().any(|g| matches_capability(g, &normalized)))
            .unwrap_or(false)
    }

    /// Whether the policy declares a ceiling — i.e. the app opted into
    /// fine-grained dynamic (user-facing) permissions. When it has, the root
    /// principal is governed by the normal allow-list + dynamic-grant precedence
    /// bounded by the ceiling; when it has not, root is trusted (ambient app
    /// authority). @ref LLP 0013 — §dynamic permissions
    fn ceiling_configured(&self) -> bool {
        // Fail closed on a poisoned lock: assume a ceiling is configured so root
        // is gated (not blanket-trusted) rather than silently ambient.
        self.ceiling.read().map(|c| !c.is_empty()).unwrap_or(true)
    }

    /// Runtime-grant `capability` to the root principal, bounded by the ceiling
    /// (the static artifact is the ceiling; prompts move the floor). Returns
    /// whether the grant was applied. @ref LLP 0013 — §dynamic permissions
    pub fn runtime_grant_root(&self, capability: &str) -> bool {
        if !self.within_ceiling(capability) {
            return false;
        }
        self.grant("0", capability, None);
        true
    }

    /// Runtime-revoke a previously runtime-granted capability from root.
    pub fn runtime_revoke_root(&self, capability: &str) {
        let normalized = normalize_capability(capability);
        if let Ok(mut grants) = self.grants.write() {
            if let Some(list) = grants.get_mut("0") {
                let previous_len = list.len();
                list.retain(|g| g.denied || g.capability != normalized);
                if list.len() != previous_len {
                    self.bump_authorization_generation();
                }
            }
        }
    }

    /// Tri-state grant status for the root principal: 1 = granted now, 2 =
    /// prompt (not granted but within the ceiling, so acquirable), 0 = denied
    /// (neither). @ref LLP 0013 — §dynamic permissions — grant status is tri-state
    /// at the host surface, not boolean.
    pub fn grant_status(&self, capability: &str) -> u8 {
        // The host-boundary fence caps the tri-state: a capability outside it
        // is denied and not acquirable by prompt either. (ENG-23876)
        let normalized =
            normalize_capability_value_with_fs_mode(capability, FsNormalizationMode::FollowFinal);
        if self.fence_denial(&normalized).is_some() {
            return 0;
        }
        if self.decide("0", capability, FsNormalizationMode::FollowFinal) {
            1
        } else if self.within_ceiling(capability) {
            2
        } else {
            0
        }
    }

    /// Register the resolved package principal for a numeric module id.
    pub fn register_module_package(&self, module_id: &str, package: &str, locator: Option<&str>) {
        if let Ok(mut map) = self.module_to_package.write() {
            map.insert(
                module_id.to_string(),
                PackagePrincipal {
                    name: package.to_string(),
                    locator: locator.map(|s| s.to_string()),
                },
            );
            self.bump_authorization_generation();
        }
        // The principal's package resolution just changed (typically
        // unregistered→registered, which flips it from trusted to policied):
        // drop any allowed-import decisions memoized under the old resolution.
        // Registration precedes any code attributed to this principal running,
        // so no check for it can race this purge. (ENG-22644)
        if let Ok(mut memo) = self.import_allowed_memo.write() {
            memo.remove(module_id);
        }
    }

    fn principal_for(&self, module_id: &str) -> Option<PackagePrincipal> {
        self.module_to_package
            .read()
            .ok()
            .and_then(|map| map.get(module_id).cloned())
    }

    /// A runtime **package self-grant** (the legacy `Exact.setModuleCapabilities`
    /// / `require(spec, { needs })` path). This is a permissive/dev convenience
    /// only: under enforce the generated policy artifact is the SOLE grant source
    /// (LLP 0014), so a package must not be able to escalate its own capabilities
    /// at runtime. Audit records the would-deny but applies the grant so it can
    /// observe-and-proceed like permissive mode. Distinct from
    /// `runtime_grant_root`, which is the ceiling-bounded dynamic-permission path.
    /// (ENG-22695/ENG-22770)
    pub fn runtime_self_grant(&self, module_id: &str, capability: &str) {
        if matches!(self.mode, SecurityMode::Permissive | SecurityMode::Audit) {
            self.grant(module_id, capability, None);
        }
        let normalized = normalize_capability(capability);
        if self.mode != SecurityMode::Permissive {
            self.record(AuditEntry {
                timestamp: std::time::SystemTime::now(),
                module_id: module_id.to_string(),
                package: self.principal_for(module_id),
                capability: format!("self-grant:{}", normalized),
                constraint: None,
                decision: false,
                allowed: self.mode == SecurityMode::Audit,
                mode: self.mode,
            });
        }
    }

    /// Grant a capability to a package selector.
    pub fn grant_package(&self, selector: &str, capability: &str) {
        if let Ok(mut grants) = self.package_grants.write() {
            grants
                .entry(selector.to_string())
                .or_default()
                .push(CapabilityGrant {
                    capability: normalize_capability(capability),
                    capability_no_follow_final: normalize_capability_no_follow_final(capability),
                    module_id: selector.to_string(),
                    constraint: None,
                    denied: false,
                });
            self.bump_authorization_generation();
        }
    }

    /// Deny a capability to a package selector.
    pub fn deny_package(&self, selector: &str, capability: &str) {
        if let Ok(mut grants) = self.package_grants.write() {
            grants
                .entry(selector.to_string())
                .or_default()
                .push(CapabilityGrant {
                    capability: normalize_capability(capability),
                    capability_no_follow_final: normalize_capability_no_follow_final(capability),
                    module_id: selector.to_string(),
                    constraint: None,
                    denied: true,
                });
            self.bump_authorization_generation();
        }
    }

    /// Check if a capability is granted.
    ///
    /// @ref LLP 0013#phase-1 — computes the real policy decision, records it,
    /// and returns whether the operation may proceed. In `Audit` mode a
    /// would-deny is logged but still returns `true`; in `Enforce` mode the
    /// returned value is the decision itself.
    pub fn check(&self, module_id: &str, capability_str: &str) -> bool {
        self.check_with_fs_mode(module_id, capability_str, FsNormalizationMode::FollowFinal)
    }

    /// Check a capability for a symlink-owning filesystem operation (`lchown`,
    /// `lutimes`, `lchmod`). The checked resource and grants resolve
    /// intermediate symlinks but leave the final component as the link entry
    /// the syscall mutates.
    pub fn check_no_follow_final(&self, module_id: &str, capability_str: &str) -> bool {
        self.check_with_fs_mode(
            module_id,
            capability_str,
            FsNormalizationMode::NoFollowFinal,
        )
    }

    fn check_with_fs_mode(
        &self,
        module_id: &str,
        capability_str: &str,
        fs_mode: FsNormalizationMode,
    ) -> bool {
        self.authorization_check_count
            .fetch_add(1, Ordering::Relaxed);
        let normalized = normalize_capability_value_with_fs_mode(capability_str, fs_mode);
        if self.fence_denies(module_id, &normalized) {
            return false;
        }
        let decision =
            self.mode == SecurityMode::Permissive || self.decide(module_id, &normalized, fs_mode);
        self.gate_and_record(module_id, normalized, decision)
    }

    /// Which host-boundary fence (if any) denies this normalized capability
    /// value. The fence is the embedder's `HostConfig.root_dir` /
    /// `allowed_hosts` sandbox: a hard boundary on the host itself, distinct
    /// from the policy plane — it applies in EVERY mode (Permissive and Audit
    /// do not bypass it, unlike policy would-denies) and to every principal
    /// including root and the module loader, and no policy grant can widen
    /// past it. Fields configured here were previously accepted but silently
    /// unenforced — a fail-open embedding API. (ENG-23876)
    /// @ref LLP 0002#host-boundary-constraints
    fn fence_denial(&self, capability: &str) -> Option<&'static str> {
        let mut parts = capability.splitn(3, ':');
        let scope = parts.next().unwrap_or("");
        let action = parts.next().unwrap_or("");
        let resource = parts.next();
        match scope {
            "fs" => {
                let root = self.fs_root.as_deref()?;
                // A resource-less `fs:<action>` value claims authority over
                // ANY path, which necessarily exceeds the fence: deny. Checked
                // values are symlink-resolved by normalization, and the root
                // was resolved the same way, so prefix containment is sound.
                let inside = resource.is_some_and(|path| {
                    path == root || path_prefix_match(&format!("{root}/**"), path)
                });
                (!inside).then_some("root_dir")
            }
            "network" if action != "listen" => {
                let hosts = self.allowed_hosts.as_deref()?;
                // Endpoint values are `<host>` or `<host>:<port>`; an entry
                // without a port covers the host across ports via the same
                // scope-specific matcher grants use (`example.com` does not
                // match `example.com.evil`). A resource-less `network:<action>`
                // claims any endpoint: deny.
                let allowed = resource.is_some_and(|endpoint| {
                    hosts.iter().any(|h| network_endpoint_match(h, endpoint))
                });
                (!allowed).then_some("allowed_hosts")
            }
            _ => None,
        }
    }

    /// Apply the host-boundary fence to a normalized capability value: on a
    /// fence miss, record the denial (tagged with which fence fired, so audit
    /// output distinguishes it from a policy would-deny) and deny. (ENG-23876)
    fn fence_denies(&self, module_id: &str, normalized: &str) -> bool {
        let Some(fence) = self.fence_denial(normalized) else {
            return false;
        };
        self.record(AuditEntry {
            timestamp: std::time::SystemTime::now(),
            module_id: module_id.to_string(),
            package: self.principal_for(module_id),
            capability: normalized.to_string(),
            constraint: Some(format!("host-boundary:{fence}")),
            decision: false,
            allowed: false,
            mode: self.mode,
        });
        #[cfg(any(test, feature = "capsec-conformance-observer"))]
        self.record_conformance_decision(module_id, normalized, false, false, Some(fence));
        true
    }

    /// Apply mode gating to a real policy `decision`, record it, and return
    /// whether the operation may proceed. Extracted from `check`/`check_import`/
    /// `check_stack`, which shared this sequence verbatim.
    ///
    /// Only would-deny decisions (`!decision`) are recorded. The audit report
    /// reads only would-denies, so recording allowed ops both (a) let a burst of
    /// allowed traffic evict earlier would-denies from the bounded FIFO log —
    /// silently dropping a grant the operator needs when authoring a policy to
    /// move from audit to enforce (ENG-22635) — and (b) paid a heap alloc +
    /// write-lock + `SystemTime::now()` on every allowed syscall, the hot path
    /// under enforce/audit (ENG-22644).
    fn gate_and_record(&self, module_id: &str, capability: String, decision: bool) -> bool {
        // Permissive and Audit let everything proceed; only Enforce blocks.
        let allowed = self.mode != SecurityMode::Enforce || decision;
        #[cfg(any(test, feature = "capsec-conformance-observer"))]
        self.record_conformance_decision(module_id, &capability, decision, allowed, None);
        if !decision {
            self.record(AuditEntry {
                timestamp: std::time::SystemTime::now(),
                module_id: module_id.to_string(),
                package: self.principal_for(module_id),
                capability: capability.clone(),
                constraint: None,
                decision,
                allowed,
                mode: self.mode,
            });
        }
        allowed
    }

    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    fn record_conformance_decision(
        &self,
        module_id: &str,
        capability: &str,
        decision: bool,
        allowed: bool,
        fence: Option<&str>,
    ) {
        let Ok(mut observer) = self.conformance_observer.write() else {
            return;
        };
        let Some(terminal_branch_id) = observer.terminal_branch_id.clone() else {
            return;
        };
        observer.decisions.push(ObservedCapabilityDecision {
            terminal_branch_id,
            module_id: module_id.to_string(),
            capability: capability.to_string(),
            decision,
            allowed,
            fence: fence.map(str::to_string),
        });
    }

    fn record(&self, entry: AuditEntry) {
        if let Ok(mut log) = self.audit_log.write() {
            if log.len() == MAX_AUDIT_LOG_ENTRIES {
                log.pop_front();
            }
            log.push_back(entry);
        }
    }

    fn explicit_policy_decision(
        &self,
        module_id: &str,
        capability: &str,
        fs_mode: FsNormalizationMode,
    ) -> Option<bool> {
        // Module-specific (numeric id) grants first.
        if let Ok(grants) = self.grants.read() {
            if matches_denials(grants.get(module_id), capability, fs_mode) {
                return Some(false);
            }
            if matches_grants(grants.get(module_id), capability, fs_mode) {
                return Some(true);
            }
        }

        // Package-selector grants next. Consult the version/locator-specific
        // selector before the bare name so a policy can pin a coexisting version
        // (RFC Resolved Q1); the first selector with a matching deny/grant wins.
        // (ENG-22621)
        if let Some(principal) = self.principal_for(module_id) {
            if let Ok(grants) = self.package_grants.read() {
                for selector in principal.selectors() {
                    if matches_denials(grants.get(selector), capability, fs_mode) {
                        return Some(false);
                    }
                    if matches_grants(grants.get(selector), capability, fs_mode) {
                        return Some(true);
                    }
                }
            }
        }

        // Global grants last.
        if let Ok(grants) = self.grants.read() {
            if matches_denials(grants.get("*"), capability, fs_mode) {
                return Some(false);
            }
            if matches_grants(grants.get("*"), capability, fs_mode) {
                return Some(true);
            }
        }

        None
    }

    /// The real policy decision, independent of mode gating. Precedence:
    /// always-allowed → module deny/allow → package deny/allow → global
    /// deny/allow → default-deny.
    fn decide(&self, module_id: &str, capability: &str, fs_mode: FsNormalizationMode) -> bool {
        if ALWAYS_ALLOWED.iter().any(|cap| cap == &capability) {
            return true;
        }

        // No attributable user frame (a deputy op detached from its scheduling
        // package's frame): fail closed, never trusted. Must be checked before the
        // root-trust fallback below — the engine reports this distinctly from
        // first-party root exactly so it does not inherit root's trust.
        if module_id == NO_USER_PRINCIPAL {
            return false;
        }

        // Ibex's own module loader reads module source files as runtime
        // infrastructure under this synthetic principal. Which modules may be
        // loaded is governed by the import gate (`check_import`), not the
        // capability system, so the loader's file reads are trusted here — else
        // `--capsec enforce` would deny the app reading its own bundle. Real app
        // and package code never runs under this principal. @ref LLP 0013#policy
        if module_id == MODULE_LOADER_PRINCIPAL {
            return true;
        }

        if let Some(decision) = self.explicit_policy_decision(module_id, capability, fs_mode) {
            return decision;
        }

        // The first-party root principal carries the app's own authority: absent
        // an explicit grant or denial above, it is trusted so `--capsec enforce`
        // is usable without the app self-granting its operational needs (reading
        // its own bundle/files), and only third-party packages (non-zero
        // principals) are gated — mirroring `decide_import`'s trust of the
        // first-party principal (RFC Resolved Q1). The exception is an app that
        // opted into dynamic user-facing permissions (a ceiling is configured):
        // then root falls through to default-deny so a capability outside the
        // ceiling stays denied and the tri-state permission model holds.
        // @ref LLP 0013#policy
        if module_id == ROOT_PRINCIPAL && !self.ceiling_configured() {
            return true;
        }

        // Default deny in enforce/audit mode.
        false
    }

    /// Check whether the calling principal may mint an authority-bearing handle
    /// carrying `capability`. This intentionally requires an explicit policy
    /// grant and bypasses root's ambient fallback: root may perform its own
    /// operations, but turning an operation into a passable possession token must
    /// not widen an exact grant into subtree authority. @ref LLP 0013#delegation-and-authority-flow
    pub fn check_handle_mint(&self, module_id: &str, capability_str: &str) -> bool {
        let normalized = normalize_capability_value_with_fs_mode(
            capability_str,
            FsNormalizationMode::FollowFinal,
        );
        if self.fence_denies(module_id, &normalized) {
            return false;
        }
        let decision = self.mode == SecurityMode::Permissive
            || (module_id != NO_USER_PRINCIPAL
                && self
                    .explicit_policy_decision(
                        module_id,
                        &normalized,
                        FsNormalizationMode::FollowFinal,
                    )
                    .unwrap_or(false));
        self.gate_and_record(module_id, normalized, decision)
    }

    /// Import-graph gate. Returns whether the load proceeds under the active
    /// mode; the real decision is logged as a synthetic `import:<specifier>`
    /// capability so audit reports surface would-deny imports.
    ///
    /// @ref LLP 0013#policy — builtins are reachable by `require`, so this is
    /// the primary containment gate for them.
    pub fn check_import(&self, module_id: &str, specifier: &str) -> bool {
        // Fast path for the steady-state require() loop: a previously-computed
        // ALLOWED decision for this (principal, specifier) short-circuits the
        // policy walk and the `import:<specifier>` render. An allowed decision
        // proceeds in every mode and records nothing (gate_and_record logs
        // would-denies only), so the hit is observably identical to
        // recomputing; see the field docs for the invalidation contract.
        // (ENG-22644)
        if let Ok(memo) = self.import_allowed_memo.read() {
            if memo
                .get(module_id)
                .is_some_and(|specs| specs.contains(specifier))
            {
                return true;
            }
        }
        let decision =
            self.mode == SecurityMode::Permissive || self.decide_import(module_id, specifier);
        if decision {
            if let Ok(mut memo) = self.import_allowed_memo.write() {
                memo.entry(module_id.to_string())
                    .or_default()
                    .insert(specifier.to_string());
            }
        }
        self.gate_and_record(module_id, format!("import:{}", specifier), decision)
    }

    fn decide_import(&self, module_id: &str, specifier: &str) -> bool {
        // No attributable user frame (a detached callback with no package frame,
        // e.g. `Promise.resolve("fs").then(globalThis.require)`): fail closed,
        // never trusted — must be checked before the unregistered=trusted
        // fallback below, exactly as decide() does for capability checks, so an
        // import cannot be laundered through a detached require. (ENG-22696)
        if module_id == NO_USER_PRINCIPAL {
            return false;
        }
        // Unregistered principals are first-party/root (trusted): allow.
        let Some(principal) = self.principal_for(module_id) else {
            return true;
        };
        let Ok(map) = self.import_policy.read() else {
            // Fail closed on a poisoned lock rather than silently allowing.
            return false;
        };
        if is_builtin_specifier(specifier) {
            selected_import_axis(&map, &principal, |p| p.builtins.as_ref())
                .map(|list| list.iter().any(|b| import_specifier_matches(b, specifier)))
                .unwrap_or(true)
        } else {
            selected_import_axis(&map, &principal, |p| p.packages.as_ref())
                .map(|list| {
                    // Match on the package *selector*, not the raw specifier: fold
                    // a subpath/deep import to its package (`lodash/fp` -> `lodash`)
                    // so the runtime agrees with how the generator authors the
                    // list, and treat a relative/absolute specifier as an
                    // intra-package import (not a cross-package edge) so a package
                    // can load its own files. (ENG-22637)
                    match package_selector_of_specifier(specifier) {
                        None => true,
                        Some(selector) => list.iter().any(|p| {
                            p == specifier
                                || package_selector_of_specifier(p).as_deref() == Some(&selector)
                        }),
                    }
                })
                .unwrap_or(true)
        }
    }

    /// Configure the capability classes that require stack-intersection
    /// enforcement. `["fs:write", "process:spawn"]` is the typical set.
    ///
    /// @ref LLP 0013#phase-5
    pub fn set_deputy_classes<I, S>(&self, classes: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let Ok(mut set) = self.deputy_classes.write() {
            set.clear();
            for c in classes {
                set.insert(normalize_capability(&c.into()));
            }
            self.bump_authorization_generation();
        }
    }

    fn is_deputy_class(&self, capability: &str) -> bool {
        let class = capability_class(capability);
        self.deputy_classes
            .read()
            .map(|set| set.contains(&class) || set.contains(capability))
            .unwrap_or(false)
    }

    /// Whether any deputy capability classes are configured (Phase 5 opt-in).
    /// @ref LLP 0013#phase-5
    pub fn has_deputy_classes(&self) -> bool {
        self.deputy_classes
            .read()
            .map(|set| !set.is_empty())
            .unwrap_or(false)
    }

    /// Stack-intersection check (optional deputy hardening, Phase 5). For a
    /// capability whose class is configured for stack intersection, the
    /// effective permission is the AND of every principal on the call stack —
    /// a deputy holding `fs:write` cannot be driven to write on behalf of a
    /// caller that lacks it. For all other capabilities this defers to the
    /// normal top-principal check.
    ///
    /// `stack` is ordered innermost-first (index 0 is the direct caller). It is
    /// provided by frame-derived attribution (Phase 2/3); in Phase 1 callers
    /// pass a single-element stack and this reduces to `check`. For a job that
    /// drains detached from its scheduling frame (a promise/microtask reaction),
    /// the engine appends the schedule-time principal (Hermes patch 0008), so the
    /// stack already carries the true causal chain — see the ENG-22631 note below.
    ///
    /// @ref LLP 0013#phase-5
    pub fn check_stack(&self, stack: &[&str], capability_str: &str) -> bool {
        self.check_stack_with_fs_mode(stack, capability_str, FsNormalizationMode::FollowFinal)
    }

    pub fn check_stack_no_follow_final(&self, stack: &[&str], capability_str: &str) -> bool {
        self.check_stack_with_fs_mode(stack, capability_str, FsNormalizationMode::NoFollowFinal)
    }

    fn check_stack_with_fs_mode(
        &self,
        stack: &[&str],
        capability_str: &str,
        fs_mode: FsNormalizationMode,
    ) -> bool {
        self.authorization_check_count
            .fetch_add(1, Ordering::Relaxed);
        let normalized = normalize_capability_value_with_fs_mode(capability_str, fs_mode);
        let top = stack.first().copied().unwrap_or("");
        if self.fence_denies(top, &normalized) {
            return false;
        }

        let decision = if self.mode == SecurityMode::Permissive {
            true
        } else if self.is_deputy_class(&normalized) && stack.len() > 1 {
            // Walk-and-AND: every principal on the stack must be granted. The stack
            // includes the schedule-time principal appended by the engine for a
            // detached async job (ENG-22631), so this AND spans the async causal
            // chain, not just the frames live at the moment of the check.
            stack
                .iter()
                .all(|principal| self.decide(principal, &normalized, fs_mode))
        } else {
            // A genuinely single-principal deputy-class stack: a package (deputy or
            // not) acting for itself. This includes a granted package's own async
            // continuation (`queueMicrotask(() => this.read())`) — the engine's
            // schedule-time capture appends the scheduler, but it equals the running
            // principal there and collapses, so the stack stays len==1 and is NOT
            // false-denied. The async-detached laundering case that used to fall
            // here (`Promise.resolve(x).then(deputy.method)`, ungranted scheduler)
            // is now closed upstream: the engine appends the DISTINCT scheduling
            // principal, making that stack len>1 so it takes the AND branch above.
            // (ENG-22631 — the sound fix, replacing the reverted blunt len==1 deny
            // that false-denied every legitimate async deputy-class op.) Residual:
            // a deputy that itself re-schedules across a further async hop is
            // "deputy by design," out of scope by default (RFC Open Q3).
            self.decide(top, &normalized, fs_mode)
        };
        self.gate_and_record(top, normalized, decision)
    }

    /// Grant a capability to a module
    pub fn grant(&self, module_id: &str, capability: &str, constraint: Option<String>) {
        if let Ok(mut grants) = self.grants.write() {
            let module_grants = grants.entry(module_id.to_string()).or_insert_with(Vec::new);
            module_grants.push(CapabilityGrant {
                capability: normalize_capability(capability),
                capability_no_follow_final: normalize_capability_no_follow_final(capability),
                module_id: module_id.to_string(),
                constraint,
                denied: false,
            });
            self.bump_authorization_generation();
        }
    }

    /// Deny a capability to a module
    pub fn deny(&self, module_id: &str, capability: &str, constraint: Option<String>) {
        if let Ok(mut grants) = self.grants.write() {
            let module_grants = grants.entry(module_id.to_string()).or_insert_with(Vec::new);
            module_grants.push(CapabilityGrant {
                capability: normalize_capability(capability),
                capability_no_follow_final: normalize_capability_no_follow_final(capability),
                module_id: module_id.to_string(),
                constraint,
                denied: true,
            });
            self.bump_authorization_generation();
        }
    }

    /// Current invalidation identity for retained legacy-resource leases.
    pub fn authorization_generation(&self) -> u64 {
        self.authorization_generation.load(Ordering::Acquire)
    }

    /// Number of full legacy capability decisions performed by this manager.
    pub fn authorization_check_count(&self) -> usize {
        self.authorization_check_count.load(Ordering::Relaxed)
    }

    fn bump_authorization_generation(&self) {
        // Mutation APIs publish their locked data before this release update.
        // Wrapping would permit an ancient lease to compare equal after 2^64
        // mutations, so exhaust the process instead of silently reusing it.
        self.authorization_generation
            .fetch_update(Ordering::Release, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .expect("legacy capability generation exhausted");
    }

    /// Get the audit log
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log
            .read()
            .map(|entries| entries.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Clear the audit log
    pub fn clear_audit_log(&self) {
        if let Ok(mut log) = self.audit_log.write() {
            log.clear();
        }
    }

    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    pub fn begin_conformance_observation(&self, terminal_branch_id: &str) {
        if let Ok(mut observer) = self.conformance_observer.write() {
            observer.terminal_branch_id = Some(terminal_branch_id.to_string());
            observer.decisions.clear();
        }
    }

    #[cfg(any(test, feature = "capsec-conformance-observer"))]
    pub fn take_conformance_observations(&self) -> Vec<ObservedCapabilityDecision> {
        let Ok(mut observer) = self.conformance_observer.write() else {
            return Vec::new();
        };
        observer.terminal_branch_id = None;
        std::mem::take(&mut observer.decisions)
    }

    /// Summarize would-deny decisions for operator-facing audit output.
    /// Returns an empty string when nothing was flagged.
    ///
    /// @ref LLP 0021#wp9--make-complete-enforcement-the-default-and-remove-weakening-paths —
    /// `ibex capsec audit` is the separate foreground diagnostic workflow;
    /// ordinary production execution never selects this legacy reporter.
    pub fn audit_report(&self) -> String {
        let Ok(log) = self.audit_log.read() else {
            return String::new();
        };
        // Deduplicate would-deny entries by (principal, capability).
        let mut seen: Vec<(String, String)> = Vec::new();
        for entry in log.iter().filter(|e| e.is_would_deny()) {
            let principal = entry
                .package
                .as_ref()
                .map(|p| match &p.locator {
                    Some(loc) => format!("{} ({})", p.name, loc),
                    None => p.name.clone(),
                })
                .unwrap_or_else(|| format!("module:{}", entry.module_id));
            let key = (principal, entry.capability.clone());
            if !seen.contains(&key) {
                seen.push(key);
            }
        }
        if seen.is_empty() {
            return String::new();
        }
        let mut out = String::from("capability audit — would-deny under enforce mode:\n");
        for (principal, capability) in &seen {
            out.push_str(&format!("  {principal}  needs  {capability}\n"));
        }
        out
    }
}

/// The capability "class" — the `scope:action` prefix without the resource,
/// e.g. `fs:write:/etc/passwd` -> `fs:write`. Used to select which capabilities
/// are subject to stack-intersection enforcement.
fn capability_class(capability: &str) -> String {
    let mut parts = capability.splitn(3, ':');
    match (parts.next(), parts.next()) {
        (Some(scope), Some(action)) => format!("{scope}:{action}"),
        (Some(scope), None) => scope.to_string(),
        _ => capability.to_string(),
    }
}

/// Whether a require specifier names a builtin module (as opposed to a
/// dependency package). `node:`-prefixed specifiers, runtime-internal (`internal/*`)
/// specifiers, and the bare Node builtin names (and their subpaths) are builtins.
///
/// Classifying is security-load-bearing: a specifier that misses this and falls
/// to the `packages` branch defaults to *allow*, so an under-populated list is a
/// fail-open hole (a `builtins: []` package could still `require('dgram')`).
/// (ENG-22630)
fn is_builtin_specifier(specifier: &str) -> bool {
    // Builtin-alias namespaces: `node:` plus the runtime's own `exact:`/`bun:`
    // aliases (e.g. `exact:sqlite`, `bun:sqlite`, `bun:fs`; see modules.ts).
    // These MUST classify as builtins, else `builtins: []` fails open — the
    // alias falls through to the `packages` axis, which is allow-by-default.
    // Any `exact:`/`bun:` specifier is a runtime builtin namespace (an
    // unregistered one is denied by the builtins gate rather than allowed as a
    // package). (ENG-22697)
    if specifier.starts_with("node:")
        || specifier.starts_with("exact:")
        || specifier.starts_with("bun:")
    {
        return true;
    }
    // Runtime-internal modules are the loader's own trusted surface and must not
    // be importable from a package compartment, so they classify on the builtins
    // axis (a restricted package's allowlist won't include them). (ENG-22618)
    if specifier.starts_with("internal/") {
        return true;
    }
    // A builtin subpath (`fs/promises`, `stream/web`, `dns/promises`) shares the
    // root builtin's axis, so a subpath can't dodge a `builtins: []` fence.
    let root = specifier.split('/').next().unwrap_or(specifier);
    RUNTIME_GATED_NODE_BUILTINS.contains(&root)
}

/// Match a policy builtin entry against a require specifier, tolerating the
/// `node:` prefix on either side (`node:fs` in policy matches `fs`, etc.).
fn import_specifier_matches(policy_entry: &str, specifier: &str) -> bool {
    fn strip(s: &str) -> &str {
        s.strip_prefix("node:").unwrap_or(s)
    }
    let entry = strip(policy_entry);
    let spec = strip(specifier);
    if entry == spec {
        return true;
    }
    // A root builtin entry (`stream`) covers its subpaths (`stream/web`,
    // `stream/promises`). `is_builtin_specifier` classifies subpaths onto the
    // builtins axis by their root segment, so the allowlist match must agree —
    // otherwise a policy that lists the root would newly *deny* a subpath that
    // previously flowed through the unrestricted packages axis. A specific subpath
    // entry (`stream/web`) still matches only itself. (ENG-22630 review)
    if !entry.contains('/') {
        return spec.split('/').next() == Some(entry);
    }
    false
}

/// Fold a require specifier to its package selector, mirroring the build side's
/// `packageNameOfSpecifier` so generation and enforcement agree. Returns `None`
/// for relative/absolute specifiers (intra-package imports, not cross-package
/// edges) so they are not gated on the `packages` axis. (ENG-22637)
fn package_selector_of_specifier(specifier: &str) -> Option<String> {
    if specifier.starts_with('.') || specifier.starts_with('/') {
        return None;
    }
    let s = specifier.strip_prefix("node:").unwrap_or(specifier);
    let mut parts = s.split('/');
    let first = parts.next().filter(|p| !p.is_empty())?;
    if let Some(stripped) = first.strip_prefix('@') {
        let _ = stripped;
        // Scoped: keep two segments (`@scope/name`).
        parts
            .next()
            .filter(|p| !p.is_empty())
            .map(|second| format!("{first}/{second}"))
    } else {
        Some(first.to_string())
    }
}

// Resolve each import-policy axis (builtins / packages) independently across the
// principal's selectors, most-specific first. The first selector whose entry
// constrains that axis governs it; if no selector constrains it, the axis is
// unrestricted. Binding both axes to a single most-specific entry would let a
// version pin that restricts only one axis silently shadow the other axis that a
// bare-name entry constrains. Mirrors decide()'s per-selector precedence.
// (ENG-22621/ENG-22773)
fn selected_import_axis<'a, F>(
    map: &'a HashMap<String, ImportPolicy>,
    principal: &'a PackagePrincipal,
    axis: F,
) -> Option<&'a Vec<String>>
where
    F: Fn(&'a ImportPolicy) -> Option<&'a Vec<String>>,
{
    for selector in principal.selectors() {
        if let Some(list) = map.get(selector).and_then(&axis) {
            return Some(list);
        }
    }
    None
}

pub fn normalize_capability(capability: &str) -> String {
    normalize_capability_with_fs(
        capability,
        FsNormalizationMode::FollowFinal,
        FsResourceKind::Pattern,
    )
}

fn normalize_capability_no_follow_final(capability: &str) -> String {
    normalize_capability_with_fs(
        capability,
        FsNormalizationMode::NoFollowFinal,
        FsResourceKind::Pattern,
    )
}

fn normalize_capability_value_with_fs_mode(
    capability: &str,
    fs_mode: FsNormalizationMode,
) -> String {
    normalize_capability_with_fs(capability, fs_mode, FsResourceKind::Value)
}

fn normalize_capability_with_fs(
    capability: &str,
    fs_mode: FsNormalizationMode,
    fs_kind: FsResourceKind,
) -> String {
    let trimmed = capability.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut parts = trimmed.splitn(3, ':');
    let scope = parts.next().unwrap_or("").trim();
    let action = parts.next().unwrap_or("").trim();
    let resource = parts.next().unwrap_or("").trim();

    if action.is_empty() {
        return scope.to_lowercase();
    }

    let scope = match scope.to_lowercase().as_str() {
        "net" => "network".to_string(),
        other => other.to_string(),
    };
    let action = action.to_lowercase();
    let normalized_resource = match scope.as_str() {
        "fs" => normalize_fs_resource(resource, fs_mode, fs_kind),
        "env" => normalize_env_resource(resource),
        "network" => normalize_network_resource(resource),
        _ => resource.to_string(),
    };

    if normalized_resource.is_empty() {
        format!("{}:{}", scope, action)
    } else {
        format!("{}:{}:{}", scope, action, normalized_resource)
    }
}

fn normalize_env_resource(resource: &str) -> String {
    resource.trim().to_string()
}

fn normalize_network_resource(resource: &str) -> String {
    resource.trim().to_lowercase()
}

fn normalize_fs_resource(
    resource: &str,
    fs_mode: FsNormalizationMode,
    kind: FsResourceKind,
) -> String {
    let trimmed = resource.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let expanded = expand_tilde(trimmed);
    let mut path = PathBuf::from(expanded);
    if !path.is_absolute() {
        if let Ok(cwd) = std::env::current_dir() {
            path = cwd.join(path);
        }
    }

    // @ref LLP 0013#policy — path-scoped grants are matched against the
    // symlink-RESOLVED path, not the supplied spelling. A purely lexical
    // fallback let a write to `<granted>/link/newfile` (leaf not yet existing,
    // `link` a symlink out of the granted tree) match the `<granted>/**` grant
    // while the OS followed the symlink outside it. Both the checked value and
    // the grant pattern resolve through the same walk so they stay comparable
    // (e.g. macOS `/var` → `/private/var`). (ENG-22682)
    let has_wildcard = kind == FsResourceKind::Pattern && trimmed.contains('*');
    if !has_wildcard {
        let resolved = match fs_mode {
            FsNormalizationMode::FollowFinal => resolve_symlinks_partial(&path),
            FsNormalizationMode::NoFollowFinal => resolve_symlinks_partial_no_follow_final(&path),
        };
        return resolved.to_string_lossy().to_string();
    }

    // Wildcard pattern: resolve the fixed literal prefix (components before the
    // first wildcard-bearing component), then re-append the pattern tail. The
    // tail's components cannot be resolved (they are patterns, and the paths
    // they will match resolve on the value side).
    let mut prefix = PathBuf::new();
    let mut tail: Vec<Component> = Vec::new();
    let mut in_tail = false;
    for comp in path.components() {
        if !in_tail {
            if comp.as_os_str().to_string_lossy().contains('*') {
                in_tail = true;
                tail.push(comp);
            } else {
                prefix.push(comp.as_os_str());
            }
        } else {
            tail.push(comp);
        }
    }
    let mut resolved = resolve_symlinks_partial(&prefix);
    for comp in tail {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = resolved.pop();
            }
            other => resolved.push(other.as_os_str()),
        }
    }
    resolved.to_string_lossy().to_string()
}

/// Resolve `path` the way the kernel will when the operation executes: follow
/// symlinks in every component that exists (including dangling links, whose
/// targets an `O_CREAT` open would materialize), apply `.`/`..` against the
/// already-resolved prefix, and keep the not-yet-existing remainder literal.
/// Symlink expansion is bounded; past the bound the remaining components are
/// appended lexically (the actual syscall will fail with ELOOP anyway).
/// (ENG-22682)
fn resolve_symlinks_partial(path: &Path) -> PathBuf {
    resolve_symlinks_partial_with_mode(path, true)
}

fn resolve_symlinks_partial_no_follow_final(path: &Path) -> PathBuf {
    resolve_symlinks_partial_with_mode(path, false)
}

fn resolve_symlinks_partial_with_mode(path: &Path, follow_final: bool) -> PathBuf {
    // Fast path: the whole path exists — the kernel's own resolution.
    if follow_final {
        if let Ok(canon) = path.canonicalize() {
            return canon;
        }
    }
    // Fast path for create-like paths: when only the leaf is absent, canonicalize
    // the parent once and append the leaf. Fall through to the component walk
    // only when the final entry is itself a symlink or the parent is missing.
    // (ENG-22771)
    if let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) {
        if let Ok(parent_canon) = parent.canonicalize() {
            let candidate = parent_canon.join(file_name);
            match std::fs::symlink_metadata(&candidate) {
                Ok(md) if md.file_type().is_symlink() => {}
                _ => return candidate,
            }
        }
    }

    const MAX_LINK_EXPANSIONS: usize = 40;
    let mut expansions = 0usize;
    let mut out = PathBuf::new();
    let mut pending: VecDeque<std::ffi::OsString> = VecDeque::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(prefix) => out.push(prefix.as_os_str()),
            Component::RootDir => out.push(comp.as_os_str()),
            other => pending.push_back(other.as_os_str().to_os_string()),
        }
    }
    if out.as_os_str().is_empty() {
        // Relative input (callers absolutize first; keep a sane fallback).
        out = PathBuf::from(".");
    }

    while let Some(comp) = pending.pop_front() {
        if comp == "." {
            continue;
        }
        if comp == ".." {
            // `out` is already symlink-free, so lexical pop == kernel `..`.
            let _ = out.pop();
            continue;
        }
        let candidate = out.join(&comp);
        let is_final_component = pending.is_empty();
        let should_follow = follow_final || !is_final_component;
        let is_link = should_follow
            && std::fs::symlink_metadata(&candidate)
                .map(|md| md.file_type().is_symlink())
                .unwrap_or(false);
        if is_link && expansions < MAX_LINK_EXPANSIONS {
            if let Ok(target) = std::fs::read_link(&candidate) {
                expansions += 1;
                if target.is_absolute() {
                    // Restart resolution at the target's root (prefix + root
                    // dir on Windows, `/` elsewhere); the remaining components
                    // join the front of the queue.
                    let mut root = PathBuf::new();
                    for tcomp in target.components() {
                        match tcomp {
                            Component::Prefix(prefix) => root.push(prefix.as_os_str()),
                            Component::RootDir => root.push(tcomp.as_os_str()),
                            _ => break,
                        }
                    }
                    out = root;
                }
                let target_comps: Vec<std::ffi::OsString> = target
                    .components()
                    .filter(|c| !matches!(c, Component::Prefix(_) | Component::RootDir))
                    .map(|c| c.as_os_str().to_os_string())
                    .collect();
                for tcomp in target_comps.into_iter().rev() {
                    pending.push_front(tcomp);
                }
                continue;
            }
        }
        out = candidate;
    }
    out
}

fn expand_tilde(path: &str) -> String {
    if path == "~" || path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            if path == "~" {
                return home.to_string_lossy().to_string();
            }
            let tail = path.trim_start_matches("~/");
            return home.join(tail).to_string_lossy().to_string();
        }
    }
    path.to_string()
}

fn grant_capability_for_mode(grant: &CapabilityGrant, fs_mode: FsNormalizationMode) -> &str {
    match fs_mode {
        FsNormalizationMode::FollowFinal => &grant.capability,
        FsNormalizationMode::NoFollowFinal => &grant.capability_no_follow_final,
    }
}

fn matches_grants(
    grants: Option<&Vec<CapabilityGrant>>,
    capability: &str,
    fs_mode: FsNormalizationMode,
) -> bool {
    if let Some(list) = grants {
        for grant in list {
            if grant.denied {
                continue;
            }
            if matches_capability(grant_capability_for_mode(grant, fs_mode), capability) {
                return true;
            }
        }
    }
    false
}

fn matches_denials(
    grants: Option<&Vec<CapabilityGrant>>,
    capability: &str,
    fs_mode: FsNormalizationMode,
) -> bool {
    if let Some(list) = grants {
        for grant in list {
            if !grant.denied {
                continue;
            }
            if matches_capability(grant_capability_for_mode(grant, fs_mode), capability) {
                return true;
            }
        }
    }
    false
}

fn matches_capability(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern == value {
        return true;
    }

    let pattern_parts: Vec<&str> = pattern.splitn(3, ':').collect();
    let value_parts: Vec<&str> = value.splitn(3, ':').collect();

    if pattern_parts.len() > value_parts.len() {
        return false;
    }

    for (index, pattern_part) in pattern_parts.iter().enumerate() {
        let value_part = value_parts[index];
        if *pattern_part == "*" || *pattern_part == value_part {
            continue;
        }
        if index == pattern_parts.len() - 1 {
            let value_tail = value_parts[index..].join(":");
            if pattern_parts.first() == Some(&"network")
                && network_endpoint_match(pattern_part, &value_tail)
            {
                return true;
            }
            if path_prefix_match(pattern_part, &value_tail) {
                return true;
            }
        }
        return false;
    }

    true
}

fn network_endpoint_match(pattern: &str, value: &str) -> bool {
    // Network endpoint capabilities are emitted as `host:port` for socket
    // operations and, depending on URL parser shape, fetch/WebSocket authorities.
    // A policy resource without a port grants that host across ports, but it must
    // not become a generic string prefix (`example.com` must not match
    // `example.com.evil`). Keep this scope-specific so generic capability
    // resources remain exact unless they use `/**`.
    fn split_endpoint(endpoint: &str) -> Option<(&str, Option<&str>)> {
        if endpoint.starts_with('[') {
            let end = endpoint.find(']')?;
            let host = &endpoint[1..end];
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return None;
            }
            let remainder = &endpoint[end + 1..];
            return match remainder {
                "" => Some((host, None)),
                suffix if suffix.starts_with(':') => {
                    let port = &suffix[1..];
                    port.parse::<u16>().ok().map(|_| (host, Some(port)))
                }
                _ => None,
            };
        }
        if endpoint.contains(['[', ']']) || endpoint.is_empty() {
            return None;
        }
        // A whole unbracketed IPv6 literal is a host-only policy resource.
        // Never reinterpret its final hextet as a decimal port. Concrete
        // host+port resources emitted by native code are always bracketed.
        if endpoint.bytes().filter(|byte| *byte == b':').count() > 1 {
            return endpoint
                .parse::<std::net::Ipv6Addr>()
                .ok()
                .map(|_| (endpoint, None));
        }
        match endpoint.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {
                Some((host, Some(port)))
            }
            Some(_) => None,
            None => Some((endpoint, None)),
        }
    }
    let Some((pattern_host, pattern_port)) = split_endpoint(pattern) else {
        return false;
    };
    let Some((value_host, value_port)) = split_endpoint(value) else {
        return false;
    };
    pattern_host == value_host && pattern_port.is_none_or(|port| value_port == Some(port))
}

fn path_prefix_match(pattern: &str, value: &str) -> bool {
    // @ref LLP 0002#host-boundary-constraints — native Windows separators
    // must not change the root_dir fence's tree semantics.
    // Windows path normalization emits native `\` separators, while policy
    // patterns and older callers may use `/`. Compare one canonical separator
    // spelling so a host-boundary root remains a real containment fence on
    // Windows instead of rejecting every descendant (or depending on how the
    // path was originally spelled).
    #[cfg(windows)]
    let (pattern, value) = (pattern.replace('\\', "/"), value.replace('\\', "/"));
    if !pattern.ends_with("/**") {
        return false;
    }
    let base = &pattern[..pattern.len() - 3];
    if value == base {
        return true;
    }
    if base.ends_with('/') {
        value.starts_with(base)
    } else {
        value
            .strip_prefix(base)
            .is_some_and(|remainder| remainder.starts_with('/'))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_observer_records_every_gate_result_under_the_expected_terminal() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.grant("7", "fs:read:/tmp/allowed", None);
        manager.begin_conformance_observation("terminal.fs.read");
        assert!(manager.check("7", "fs:read:/tmp/allowed"));
        assert!(!manager.check("7", "fs:read:/tmp/denied"));
        let observations = manager.take_conformance_observations();
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().all(|row| {
            row.terminal_branch_id == "terminal.fs.read"
                && row.module_id == "7"
                && row.fence.is_none()
        }));
        let resource_leaf = |capability: &str| {
            capability
                .splitn(3, ':')
                .nth(2)
                .and_then(|resource| Path::new(resource).file_name())
                .map(std::ffi::OsStr::to_owned)
        };
        assert_eq!(
            resource_leaf(&observations[0].capability),
            Some(std::ffi::OsString::from("allowed"))
        );
        assert_eq!(
            (observations[0].decision, observations[0].allowed),
            (true, true)
        );
        assert_eq!(
            resource_leaf(&observations[1].capability),
            Some(std::ffi::OsString::from("denied"))
        );
        assert_eq!(
            (observations[1].decision, observations[1].allowed),
            (false, false)
        );
        assert!(manager.take_conformance_observations().is_empty());
    }

    #[test]
    fn retained_resource_generation_tracks_every_authority_mutation() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.apply_policy(&PolicyFile {
            ceiling: vec!["sqlite:write".into()],
            ..Default::default()
        });
        let initial = manager.authorization_generation();
        manager.grant("0", "sqlite:write", None);
        let granted = manager.authorization_generation();
        assert!(granted > initial);

        let before_checks = manager.authorization_check_count();
        assert!(manager.check("0", "sqlite:write"));
        assert_eq!(manager.authorization_check_count(), before_checks + 1);

        manager.runtime_revoke_root("sqlite:write");
        let revoked = manager.authorization_generation();
        assert!(revoked > granted);
        assert!(!manager.check("0", "sqlite:write"));
        assert_eq!(manager.authorization_check_count(), before_checks + 2);

        manager.register_module_package("7", "sqlite-client", Some("sqlite-client@1"));
        assert!(manager.authorization_generation() > revoked);
    }

    // ENG-23876 — the host-boundary fence (`HostConfig.root_dir` /
    // `allowed_hosts`) must deny outside-the-fence operations in EVERY mode,
    // for every principal, and must not be widenable by policy grants. The
    // fence root here is a non-existent path so symlink resolution keeps it
    // literal and the assertions are platform-stable.
    #[test]
    fn host_boundary_root_dir_fences_fs_in_every_mode() {
        for mode in [
            SecurityMode::Permissive,
            SecurityMode::Audit,
            SecurityMode::Enforce,
        ] {
            let mut manager = CapabilityManager::new(mode);
            manager.set_host_boundary(Some(Path::new("/fence-root")), None);

            // Inside the fence: root principal is trusted (or mode allows).
            assert!(
                manager.check("0", "fs:read:/fence-root/data.txt"),
                "inside-fence read denied under {mode:?}"
            );
            assert!(manager.check("0", "fs:read:/fence-root"));
            // Outside: denied regardless of mode.
            assert!(
                !manager.check("0", "fs:read:/fence-root-sibling/data.txt"),
                "boundary must not be a string prefix match"
            );
            assert!(
                !manager.check("0", "fs:write:/outside/data.txt"),
                "outside-fence write allowed under {mode:?}"
            );
            // The module loader is fenced too: root_dir bounds ALL file access.
            assert!(!manager.check("module-loader", "fs:read:/outside/mod.js"));
            // A resource-less fs capability claims any path: denied.
            assert!(!manager.check("0", "fs:read"));
            // A blanket policy grant cannot widen past the fence.
            manager.grant("*", "fs:read", None);
            assert!(!manager.check("0", "fs:read:/outside/data.txt"));
            // Non-fs capabilities are untouched by the fs fence.
            assert!(manager.check("0", "crypto:random"));
        }
    }

    #[test]
    fn host_boundary_allowed_hosts_fences_outbound_network_in_every_mode() {
        for mode in [
            SecurityMode::Permissive,
            SecurityMode::Audit,
            SecurityMode::Enforce,
        ] {
            let mut manager = CapabilityManager::new(mode);
            manager.set_host_boundary(None, Some(&["api.example.com".to_string()]));

            assert!(manager.check("0", "network:fetch:api.example.com"));
            // A port-less entry covers the host across ports.
            assert!(manager.check("0", "network:connect:api.example.com:443"));
            assert!(
                !manager.check("0", "network:fetch:evil.example.com"),
                "unlisted host allowed under {mode:?}"
            );
            // Not a generic string prefix.
            assert!(!manager.check("0", "network:fetch:api.example.com.evil"));
            // `allowed_hosts` is an outbound remote-host compatibility fence,
            // not a local bind-address fence. Listen authority remains an
            // independent policy decision for both address families.
            assert!(manager.check("0", "network:listen:127.0.0.1:8080"));
            assert!(manager.check("0", "network:listen:[::1]:8080"));
            // Resource-less network capability claims any endpoint: denied.
            assert!(!manager.check("0", "network:fetch"));
            // A blanket grant cannot widen past the fence.
            manager.grant("*", "network:fetch", None);
            assert!(!manager.check("0", "network:fetch:evil.example.com"));
            // fs is untouched by the network fence (root is trusted absent a
            // ceiling, so this holds under Enforce too).
            assert!(manager.check("0", "fs:read:/anywhere"));
        }
    }

    #[test]
    fn host_boundary_empty_allowed_hosts_denies_all_outbound_network() {
        let mut manager = CapabilityManager::new(SecurityMode::Permissive);
        manager.set_host_boundary(None, Some(&[]));
        assert!(!manager.check("0", "network:fetch:api.example.com"));
        assert!(!manager.check("0", "network:connect:127.0.0.1:8080"));
        assert!(!manager.check("0", "network:connect:[::1]:8080"));
        assert!(manager.check("0", "network:listen:127.0.0.1:8080"));
        assert!(manager.check("0", "network:listen:[::1]:8080"));
    }

    #[test]
    fn host_boundary_allowed_hosts_matches_ipv6_outbound_endpoints() {
        let mut manager = CapabilityManager::new(SecurityMode::Permissive);
        manager.set_host_boundary(None, Some(&["::1".to_string()]));
        assert!(manager.check("0", "network:connect:[::1]:443"));
        assert!(manager.check("0", "network:fetch:[::1]:443"));
        assert!(!manager.check("0", "network:connect:[::2]:443"));
    }

    // The fence must hold at every checking chokepoint, not just `check`:
    // stack-intersection checks, handle minting, and the tri-state grant
    // status (an outside-fence capability is not acquirable by prompt).
    #[test]
    fn host_boundary_fence_covers_stack_mint_and_grant_status() {
        let mut manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.set_host_boundary(
            Some(Path::new("/fence-root")),
            Some(&["api.example.com".to_string()]),
        );
        manager.grant("0", "fs:read", None);
        manager.grant("0", "network:fetch", None);

        assert!(!manager.check_stack(&["0"], "fs:read:/outside/data.txt"));
        assert!(manager.check_stack(&["0"], "fs:read:/fence-root/data.txt"));
        assert!(!manager.check_handle_mint("0", "fs:read:/outside/data.txt"));
        assert!(manager.check_handle_mint("0", "fs:read:/fence-root/data.txt"));
        assert_eq!(manager.grant_status("network:fetch:evil.example.com"), 0);
        assert_eq!(manager.grant_status("network:fetch:api.example.com"), 1);
    }

    // Fence denials are recorded (allowed=false even in Audit) and tagged so
    // audit output distinguishes them from policy would-denies.
    #[test]
    fn host_boundary_fence_denials_are_recorded_with_fence_tag() {
        let mut manager = CapabilityManager::new(SecurityMode::Audit);
        manager.set_host_boundary(Some(Path::new("/fence-root")), None);
        assert!(!manager.check("0", "fs:read:/outside/data.txt"));
        let log = manager.audit_log();
        let entry = log.last().expect("fence denial must be recorded");
        assert_eq!(entry.constraint.as_deref(), Some("host-boundary:root_dir"));
        assert!(!entry.decision);
        assert!(
            !entry.allowed,
            "audit mode must not let the fence fail open"
        );
    }

    #[test]
    fn normalize_capability_aliases_net_to_network() {
        assert_eq!(
            normalize_capability("NET:FETCH:Api.Example.Com"),
            "network:fetch:api.example.com"
        );
        assert_eq!(
            normalize_capability("network:fetch:Api.Example.Com"),
            "network:fetch:api.example.com"
        );
    }

    #[test]
    fn matches_capability_allows_base_grants_for_parameterized_values() {
        assert!(matches_capability(
            "network:fetch",
            "network:fetch:api.example.com"
        ));
        assert!(matches_capability(
            "network:fetch:api.example.com",
            "network:fetch:api.example.com:443"
        ));
        assert!(!matches_capability(
            "network:fetch:api.example.com",
            "network:fetch:api.example.com.evil:443"
        ));
        assert!(matches_capability("fs:read", "fs:read:/tmp/file.txt"));
        assert!(!matches_capability(
            "network:fetch:api.example.com",
            "network:fetch:other.example.com"
        ));
    }

    #[test]
    fn network_endpoint_matching_canonicalizes_ipv6_without_suffix_widening() {
        assert!(network_endpoint_match("::1", "[::1]:443"));
        assert!(network_endpoint_match("[::1]", "[::1]:443"));
        assert!(network_endpoint_match("[::1]:443", "[::1]:443"));
        assert!(!network_endpoint_match("[::1]:80", "[::1]:443"));
        assert!(!network_endpoint_match("::1", "[::10]:443"));
        assert!(!network_endpoint_match("[::1]", "[::1].evil:443"));
        assert!(!network_endpoint_match("[::1]", "[::1]:not-a-port"));
        assert!(!network_endpoint_match("[::1]", "[::1]:65536"));
        assert!(!network_endpoint_match("[::1]", "[::1"));
        assert!(!network_endpoint_match("[not-ipv6]", "[not-ipv6]:443"));

        assert!(matches_capability(
            "network:connect:::1",
            "network:connect:[::1]:443"
        ));
        assert!(matches_capability(
            "network:connect:[::1]",
            "network:connect:[::1]:443"
        ));
        assert!(!matches_capability(
            "network:connect:[::1]:80",
            "network:connect:[::1]:443"
        ));
    }

    #[test]
    fn matches_capability_does_not_treat_resource_prefixes_as_exact_matches() {
        let root = normalize_capability("fs:read:/tmp/exact-capabilities");
        let child = normalize_capability("fs:read:/tmp/exact-capabilities/file.txt");
        assert!(!matches_capability(&root, &child));
    }

    // @ref LLP 0014#set-algebra-and-cascade — runtime wildcard matching uses
    // the same conservative algebra as generated-policy review: `*` is a whole
    // capability segment, and path prefixes use trailing `/**` with a boundary
    // check. Ad hoc substring wildcards fail closed. (ENG-22709)
    #[test]
    fn wildcard_matching_uses_policy_algebra() {
        assert!(matches_capability(
            "network:*",
            "network:fetch:api.example.com"
        ));
        assert!(matches_capability(
            "network:fetch:*",
            "network:fetch:api.example.com"
        ));
        assert!(matches_capability("fs:read:/app/**", "fs:read:/app"));
        assert!(matches_capability(
            "fs:read:/app/**",
            "fs:read:/app/config.json"
        ));
        assert!(!matches_capability(
            "fs:read:/app/**",
            "fs:read:/app2/config.json"
        ));
        assert!(!matches_capability(
            "fs:read:/app/*.json",
            "fs:read:/app/config.json"
        ));
        assert!(!matches_capability(
            "network:fetch:*.example.com",
            "network:fetch:api.example.com"
        ));
    }

    // @ref LLP 0013#policy — a path-scoped grant is matched against the
    // symlink-RESOLVED path, so a symlinked component cannot smuggle a write
    // outside the granted subtree even when the leaf does not yet exist (the
    // O_CREAT case, where the old lexical fallback kept the syntactic prefix).
    // (ENG-22682)
    //
    // Unix-only: the test plants a real symlink to exercise the escape, so its
    // assertions are meaningless without one — gate the whole test rather than
    // let it assert ordinary-path semantics on non-Unix. (ENG-22702)
    #[cfg(unix)]
    #[test]
    fn path_scoped_grants_resolve_symlinks_and_deny_escaping_writes() {
        use std::process::id;
        use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        // A private, canonicalized scratch base (macOS `TMPDIR` is itself a
        // symlink under /var → /private/var, so canonicalize before baking
        // paths into grant strings).
        let base = std::env::temp_dir().join(format!(
            "ibex-symlink-escape-{}-{}",
            id(),
            COUNTER.fetch_add(1, AtomicOrdering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("granted")).unwrap();
        std::fs::create_dir_all(base.join("granted").join("real")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        let base = base.canonicalize().unwrap();
        // granted/link -> outside (escapes the granted subtree).
        #[cfg(unix)]
        std::os::unix::fs::symlink(base.join("outside"), base.join("granted").join("link"))
            .unwrap();

        let grant =
            normalize_capability(&format!("fs:write:{}/granted/**", base.to_string_lossy()));

        // Escaping write through the symlinked component: leaf does not exist,
        // but the parent resolves outside the grant → denied.
        let escaping = normalize_capability(&format!(
            "fs:write:{}/granted/link/newfile",
            base.to_string_lossy()
        ));
        assert!(
            !matches_capability(&grant, &escaping),
            "a write through a symlink escaping the granted tree must not match \
             (grant={grant}, value={escaping})"
        );

        // Positive control: an ordinary in-tree write (no symlink) still matches.
        let in_tree = normalize_capability(&format!(
            "fs:write:{}/granted/real/newfile",
            base.to_string_lossy()
        ));
        assert!(
            matches_capability(&grant, &in_tree),
            "an ordinary write inside the granted tree must still match \
             (grant={grant}, value={in_tree})"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    // @ref LLP 0013#policy — link-own metadata syscalls mutate the symlink
    // entry itself, so their fs:write gate must leave the final symlink
    // unresolved while still resolving intermediate symlinks. (ENG-22716)
    #[cfg(unix)]
    #[test]
    fn link_own_metadata_checks_match_the_link_path_not_the_target() {
        use std::process::id;
        use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let base = std::env::temp_dir().join(format!(
            "ibex-link-own-{}-{}",
            id(),
            COUNTER.fetch_add(1, AtomicOrdering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("links")).unwrap();
        std::fs::create_dir_all(base.join("targets")).unwrap();
        let base = base.canonicalize().unwrap();
        let target = base.join("targets").join("file.txt");
        let link = base.join("links").join("file.link");
        std::fs::write(&target, "target").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let target_grant = CapabilityManager::new(SecurityMode::Enforce);
        target_grant.grant(
            "module-a",
            &format!("fs:write:{}", target.to_string_lossy()),
            None,
        );
        assert!(
            target_grant.check("module-a", &format!("fs:write:{}", link.to_string_lossy())),
            "ordinary fs checks still follow the final symlink"
        );
        assert!(
            !target_grant
                .check_no_follow_final("module-a", &format!("fs:write:{}", link.to_string_lossy())),
            "link-own checks must not accept a grant on the target"
        );

        let link_grant = CapabilityManager::new(SecurityMode::Enforce);
        link_grant.grant(
            "module-a",
            &format!("fs:write:{}", link.to_string_lossy()),
            None,
        );
        assert!(
            link_grant
                .check_no_follow_final("module-a", &format!("fs:write:{}", link.to_string_lossy())),
            "a grant on the link path must authorize link-own metadata"
        );

        let subtree_grant = CapabilityManager::new(SecurityMode::Enforce);
        subtree_grant.grant(
            "module-a",
            &format!("fs:write:{}/links/**", base.to_string_lossy()),
            None,
        );
        assert!(
            subtree_grant
                .check_no_follow_final("module-a", &format!("fs:write:{}", link.to_string_lossy())),
            "a subtree grant containing the link entry must match"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn capability_manager_matches_js_style_base_grants_and_network_aliases() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);

        manager.grant("module-a", "network:fetch", None);
        manager.grant("module-b", "net:fetch", None);

        assert!(manager.check("module-a", "network:fetch:api.example.com"));
        assert!(manager.check("module-b", "network:fetch:api.example.com"));
        assert!(!manager.check("module-a", "network:connect:api.example.com"));
    }

    #[test]
    fn capability_audit_log_is_bounded() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);

        for index in 0..(MAX_AUDIT_LOG_ENTRIES + 50) {
            let capability = format!("network:fetch:api-{index}.example.com");
            manager.check("module-a", &capability);
        }

        let log = manager.audit_log();
        assert_eq!(log.len(), MAX_AUDIT_LOG_ENTRIES);
        assert!(log
            .first()
            .expect("bounded log should keep newest entries")
            .capability
            .contains("api-50"));
        assert!(log
            .last()
            .expect("bounded log should keep newest entries")
            .capability
            .contains(&format!("api-{}", MAX_AUDIT_LOG_ENTRIES + 49)));
    }

    // @ref LLP 0013#phase-1 — audit vs enforce semantics for the same ungranted
    // capability: audit proceeds (returns true) while recording a would-deny;
    // enforce blocks (returns false).
    #[test]
    fn audit_mode_proceeds_but_records_would_deny() {
        let manager = CapabilityManager::new(SecurityMode::Audit);
        // Ungranted capability (network resource is not path-canonicalized, so
        // the recorded string is stable across platforms).
        assert!(
            manager.check("module-a", "network:fetch:api.example.com"),
            "audit mode must let the operation proceed"
        );
        let log = manager.audit_log();
        let entry = log.last().expect("an entry was recorded");
        assert!(entry.allowed, "audit returns allowed=true");
        assert!(!entry.decision, "the real decision was deny");
        assert!(entry.is_would_deny());
        assert!(manager
            .audit_report()
            .contains("network:fetch:api.example.com"));
    }

    #[test]
    fn enforce_mode_denies_ungranted() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        assert!(!manager.check("module-a", "fs:read:/etc/passwd"));
        manager.grant("module-a", "fs:read:/etc/passwd", None);
        assert!(manager.check("module-a", "fs:read:/etc/passwd"));
    }

    #[test]
    fn permissive_allows_and_reports_nothing() {
        let manager = CapabilityManager::new(SecurityMode::Permissive);
        assert!(manager.check("module-a", "fs:read:/etc/passwd"));
        assert_eq!(manager.audit_report(), "");
    }

    // @ref LLP 0013#policy — a capability granted to a package selector is
    // available to any module resolved to that package principal.
    #[test]
    fn package_grant_resolves_via_principal() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.grant_package("node-fetch", "network:fetch");
        manager.register_module_package("1234", "node-fetch", Some("node-fetch@3.3.2"));

        // Registered module inherits the package grant.
        assert!(manager.check("1234", "network:fetch:api.example.com"));
        // An unregistered module does not.
        assert!(!manager.check("9999", "network:fetch:api.example.com"));

        // A would-deny for the registered module carries the resolved principal +
        // locator (only would-denies are recorded — the granted read above is
        // allowed and intentionally not logged).
        assert!(!manager.check("1234", "fs:read:/secret"));
        let log = manager.audit_log();
        let entry = log
            .iter()
            .find(|e| e.module_id == "1234")
            .expect("would-deny entry for registered module");
        let principal = entry.package.as_ref().expect("principal resolved");
        assert_eq!(principal.name, "node-fetch");
        assert_eq!(principal.locator.as_deref(), Some("node-fetch@3.3.2"));
    }

    // @ref LLP 0013#resolved-questions — (ENG-22621) — the name selector is the
    // default (survives version bumps); a version/locator-specific selector pins
    // a coexisting version and takes precedence.
    #[test]
    fn version_locator_selector_overrides_name() {
        let m = CapabilityManager::new(SecurityMode::Enforce);
        // Name-level grant applies to every resolved version of the package.
        m.grant_package("lodash", "network:fetch");
        // A version/locator-specific deny pins one coexisting version.
        m.deny_package("lodash@2.0.0-evil", "network:fetch");
        m.register_module_package("1", "lodash", Some("lodash@1.0.0"));
        m.register_module_package("2", "lodash", Some("lodash@2.0.0-evil"));
        // The clean version inherits the name-level grant.
        assert!(m.check("1", "network:fetch:api.example.com"));
        // The pinned version is denied — the locator selector wins over the name.
        assert!(!m.check("2", "network:fetch:api.example.com"));
    }

    // @ref LLP 0013#resolved-questions — (ENG-22621) — import-policy axes resolve
    // independently across selectors: a version pin that constrains only the
    // packages axis must NOT unrestrict the builtins axis a bare-name entry set.
    #[test]
    fn import_policy_axes_resolve_independently_across_selectors() {
        use crate::host::policy::PackagePolicy;
        let m = CapabilityManager::new(SecurityMode::Enforce);
        let mut policy = PolicyFile::default();
        policy.packages.insert(
            "foo".to_string(),
            PackagePolicy {
                builtins: Some(vec![]), // bare name: deny all builtins
                ..Default::default()
            },
        );
        policy.packages.insert(
            "foo@1.0.0".to_string(),
            PackagePolicy {
                packages: Some(vec!["allowed-dep".to_string()]), // pin: only the packages axis
                ..Default::default()
            },
        );
        m.apply_policy(&policy);
        m.register_module_package("1", "foo", Some("foo@1.0.0"));
        // The version pin constrains only `packages`; the bare name's empty
        // `builtins` still governs the builtins axis → node:fs denied.
        assert!(!m.check_import("1", "node:fs"));
        // And the pin's packages allowlist still applies.
        assert!(m.check_import("1", "allowed-dep"));
        assert!(!m.check_import("1", "other-dep"));
    }

    // @ref LLP 0013#resolved-questions — (ENG-22621) — a bare-name grant with no
    // version pin applies to every coexisting version, since each version's
    // selectors fall back to the bare name.
    #[test]
    fn bare_name_selector_matches_all_versions() {
        let m = CapabilityManager::new(SecurityMode::Enforce);
        m.grant_package("shared-pkg", "fs:read");
        m.register_module_package("10", "shared-pkg", Some("shared-pkg@1.0.0"));
        m.register_module_package("20", "shared-pkg", Some("shared-pkg@2.0.0"));
        assert!(m.check("10", "fs:read:/tmp/x"));
        assert!(m.check("20", "fs:read:/tmp/x"));
    }

    #[test]
    fn package_deny_beats_grant() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.grant_package("evil", "network:fetch");
        manager.deny_package("evil", "network:fetch:evil.example.com");
        manager.register_module_package("7", "evil", None);
        assert!(manager.check("7", "network:fetch:ok.example.com"));
        assert!(!manager.check("7", "network:fetch:evil.example.com"));
    }

    // @ref LLP 0013#policy — (ENG-22697) — `builtins: []` must deny the runtime's
    // `exact:`/`bun:` builtin aliases, not just `node:`/bare builtins: an alias
    // that classifies as a package would fall to the allow-by-default packages
    // axis (fail open).
    #[test]
    fn builtins_deny_covers_exact_and_bun_aliases() {
        assert!(is_builtin_specifier("exact:sqlite"));
        assert!(is_builtin_specifier("bun:sqlite"));
        assert!(is_builtin_specifier("bun:fs"));
        assert!(is_builtin_specifier("node:test"));
        let m = CapabilityManager::new(SecurityMode::Enforce);
        let mut policy = PolicyFile::default();
        policy.packages.insert(
            "evil".to_string(),
            crate::host::policy::PackagePolicy {
                builtins: Some(vec![]), // deny all builtins
                ..Default::default()
            },
        );
        m.apply_policy(&policy);
        m.register_module_package("1", "evil", None);
        for alias in [
            "exact:sqlite",
            "bun:sqlite",
            "bun:fs",
            "fs",
            "node:fs",
            "node:test",
        ] {
            assert!(
                !m.check_import("1", alias),
                "alias should be denied: {alias}"
            );
        }
    }

    // @ref LLP 0013#policy — (ENG-22696) — an import with no attributable user
    // frame (a detached require callback) fails closed, never trusted.
    #[test]
    fn import_from_no_user_principal_fails_closed() {
        let m = CapabilityManager::new(SecurityMode::Enforce);
        // NO_USER_PRINCIPAL is the sentinel the engine reports for a detached
        // callback; the import must be denied even though it is "unregistered".
        assert!(!m.check_import(NO_USER_PRINCIPAL, "node:fs"));
        // A genuinely unregistered (first-party/root) principal still imports.
        assert!(m.check_import("999", "node:fs"));
    }

    // @ref LLP 0013 — §self-grant (ENG-22695/ENG-22770) — the runtime package
    // self-grant path (Exact.setModuleCapabilities / require({needs})) is
    // refused under enforce; audit preserves the legacy observable grant while
    // recording the would-deny so compatibility probes do not perturb behavior.
    #[test]
    fn runtime_self_grant_is_refused_under_enforce_but_preserved_outside_enforce() {
        let enforce = CapabilityManager::new(SecurityMode::Enforce);
        enforce.register_module_package("1", "evil", None);
        enforce.runtime_self_grant("1", "fs:read");
        assert!(
            !enforce.check("1", "fs:read:/etc/passwd"),
            "self-grant must not stick under enforce"
        );

        let audit = CapabilityManager::new(SecurityMode::Audit);
        audit.runtime_self_grant("2", "fs:read");
        // Audit lets ops proceed and preserves the legacy self-grant effect, but
        // records that the self-grant would be denied under enforce.
        assert!(
            audit.decide("2", "fs:read:/etc/passwd", FsNormalizationMode::FollowFinal),
            "self-grant sticks under audit to avoid changing observable behavior"
        );
        let audit_log = audit.audit_log();
        let entry = audit_log
            .last()
            .expect("audit self-grant should record a would-deny");
        assert_eq!(entry.capability, "self-grant:fs:read");
        assert!(entry.allowed);
        assert!(!entry.decision);

        let permissive = CapabilityManager::new(SecurityMode::Permissive);
        permissive.runtime_self_grant("3", "fs:read");
        // Permissive keeps the dev convenience (though permissive allows anyway).
        assert!(
            permissive.decide("3", "fs:read:/etc/passwd", FsNormalizationMode::FollowFinal),
            "self-grant works under permissive"
        );
    }

    // The first-party root principal ("0") carries the app's own authority: it
    // is trusted (ambient) so --capsec enforce is usable, while third-party
    // packages stay gated. @ref LLP 0013#policy
    #[test]
    fn root_principal_is_trusted_without_a_ceiling() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        // No ceiling configured: root is trusted for its operational needs …
        assert!(manager.check("0", "fs:read:/app/data"));
        assert!(manager.check("0", "fs:write:/app/out"));
        assert!(manager.check("0", "process:spawn"));
        // … but a registered third-party package with no grant is still denied.
        manager.register_module_package("7", "evil-pkg", None);
        assert!(!manager.check("7", "fs:write:/app/out"));
    }

    #[test]
    fn handle_mint_requires_explicit_grant_even_for_root() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.grant("0", "fs:read:/app/data", None);
        assert!(manager.check("0", "fs:read:/app/data/child.txt"));
        assert!(manager.check_handle_mint("0", "fs:read:/app/data"));
        assert!(!manager.check_handle_mint("0", "fs:read:/app/data/**"));

        manager.grant("0", "fs:read:/app/sub/**", None);
        assert!(manager.check_handle_mint("0", "fs:read:/app/sub/**"));
        assert!(!manager.check_handle_mint("0", "fs:read:/app/sub2/**"));
    }

    // Ibex's module loader reads module files under a synthetic principal that is
    // trusted here (the import gate governs which modules load, not this check),
    // so --capsec enforce can load the app's own bundle. @ref LLP 0013#policy
    #[test]
    fn module_loader_principal_is_trusted() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        assert!(manager.check("module-loader", "fs:read:/Caches/app.bundle.js"));
    }

    // When the app opts into dynamic (user-facing) permissions — a ceiling is
    // configured — root is NOT blanket-trusted: it is governed by the normal
    // allow-list + dynamic-grant precedence bounded by the ceiling, so a
    // capability outside the ceiling stays denied and the tri-state permission
    // model holds. Explicit grants/denials still win for root. @ref LLP 0013 — §dynamic permissions
    #[test]
    fn ceiling_restores_root_gating_for_dynamic_permissions() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.apply_policy(&PolicyFile {
            ceiling: vec!["network:fetch".to_string()],
            ..Default::default()
        });
        // In-ceiling but not yet granted: denied until a runtime grant moves the
        // floor (the tri-state prompt state).
        assert!(!manager.check("0", "network:fetch:api.example.com"));
        assert!(manager.runtime_grant_root("network:fetch:api.example.com"));
        assert!(manager.check("0", "network:fetch:api.example.com"));
        // Outside the ceiling: root stays denied — no ambient escape hatch, and a
        // runtime request cannot exceed the ceiling.
        assert!(!manager.check("0", "device:location"));
        assert!(!manager.runtime_grant_root("device:location"));
    }

    // The `env:read:<key>` check that every `process.env` read funnels through
    // must discriminate per principal: a package granted env:read may read (any
    // key, and the whole-env `env:read:*` form); one that is not is denied — even
    // if it can reach `process`. Default-deny leaves no ambient env authority.
    // @ref LLP 0013#mechanism-3
    #[test]
    fn env_read_is_gated_per_principal() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.grant_package("env-reader", "env:read");
        manager.register_module_package("10", "env-reader", None);
        manager.register_module_package("20", "snoop-pkg", None);

        // Granted package: any specific key and the whole-env form.
        assert!(manager.check("10", "env:read:SECRET_TOKEN"));
        assert!(manager.check("10", "env:read:*"));
        // Ungranted package: both forms denied — no laundering the environment.
        assert!(!manager.check("20", "env:read:SECRET_TOKEN"));
        assert!(!manager.check("20", "env:read:*"));
        // An unregistered/first-party module has no ambient env authority either.
        assert!(!manager.check("999", "env:read:SECRET_TOKEN"));
    }

    // @ref LLP 0013#policy — import-graph gate. Absent axis = unrestricted;
    // explicit list = allowlist; explicit empty list denies everything.
    #[test]
    fn import_policy_gates_builtins() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        let policy = PolicyFile {
            packages: HashMap::from([(
                "node-fetch".to_string(),
                crate::host::policy::PackagePolicy {
                    capabilities: vec!["network:fetch".to_string()],
                    builtins: Some(vec![
                        "node:http".to_string(),
                        "node:https".to_string(),
                        "node:test".to_string(),
                    ]),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        manager.apply_policy(&policy);
        manager.register_module_package("42", "node-fetch", None);

        assert!(manager.check_import("42", "node:http"));
        assert!(manager.check_import("42", "https")); // node: prefix tolerated
        assert!(manager.check_import("42", "test")); // generated/runtime node list agrees
        assert!(!manager.check_import("42", "node:fs")); // not in allowlist
        assert!(!manager.check_import("42", "fs"));

        // Unregistered principal (first-party/root) is unrestricted.
        assert!(manager.check_import("1", "node:fs"));
    }

    #[test]
    fn import_policy_audit_mode_proceeds() {
        let manager = CapabilityManager::new(SecurityMode::Audit);
        let policy = PolicyFile {
            packages: HashMap::from([(
                "evil".to_string(),
                crate::host::policy::PackagePolicy {
                    builtins: Some(vec![]), // deny all builtins
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        manager.apply_policy(&policy);
        manager.register_module_package("5", "evil", None);
        // Audit proceeds...
        assert!(manager.check_import("5", "node:child_process"));
        // ...but records the would-deny.
        assert!(manager.audit_report().contains("import:node:child_process"));
    }

    // ENG-22644 — the allowed-import memo must be invalidated when its inputs
    // change, or a decision computed under the old state would leak through.
    #[test]
    fn import_memo_is_purged_when_a_principal_is_registered() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        let policy = PolicyFile {
            packages: HashMap::from([(
                "evil".to_string(),
                crate::host::policy::PackagePolicy {
                    builtins: Some(vec![]), // deny all builtins
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        manager.apply_policy(&policy);

        // Unregistered principal is trusted: allowed (and memoized).
        assert!(manager.check_import("9", "node:fs"));
        assert!(manager.check_import("9", "node:fs"));

        // Registration flips the principal from trusted to policied; the memo
        // entry for it must not survive.
        manager.register_module_package("9", "evil", None);
        assert!(!manager.check_import("9", "node:fs"));
    }

    #[test]
    fn import_memo_is_cleared_when_policy_is_applied() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.register_module_package("7", "leftpad", None);

        // No import policy yet: unrestricted (allowed, memoized).
        assert!(manager.check_import("7", "node:fs"));

        // Applying a policy that restricts the package must defeat the memo.
        let policy = PolicyFile {
            packages: HashMap::from([(
                "leftpad".to_string(),
                crate::host::policy::PackagePolicy {
                    builtins: Some(vec![]), // deny all builtins
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        manager.apply_policy(&policy);
        assert!(!manager.check_import("7", "node:fs"));
    }

    #[test]
    fn denied_imports_are_never_memoized_and_keep_recording() {
        let manager = CapabilityManager::new(SecurityMode::Audit);
        let policy = PolicyFile {
            packages: HashMap::from([(
                "evil".to_string(),
                crate::host::policy::PackagePolicy {
                    builtins: Some(vec![]),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        manager.apply_policy(&policy);
        manager.register_module_package("5", "evil", None);

        // Two denied (audit: proceed-but-record) imports → two audit entries,
        // proving the second denial was not short-circuited by any memo.
        assert!(manager.check_import("5", "node:fs"));
        assert!(manager.check_import("5", "node:fs"));
        let denials = manager
            .audit_log()
            .iter()
            .filter(|e| e.capability == "import:node:fs" && e.is_would_deny())
            .count();
        assert_eq!(denials, 2);

        // An allowed import is memoized (hit returns without recording), and
        // repeated allowed imports never add entries either way.
        assert!(manager.check_import("1", "node:fs"));
        assert!(manager.check_import("1", "node:fs"));
        assert_eq!(manager.audit_log().len(), 2);
    }

    // @ref LLP 0013#phase-5 — stack-intersection: a deputy holding fs:write
    // cannot be driven to write for a caller that lacks it, but only for
    // capability classes that opted in.
    #[test]
    fn stack_intersection_ands_deputy_classes() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.set_deputy_classes(["fs:write", "process:spawn"]);
        // The deputy (a library) has fs:write; the caller (an app package) does not.
        manager.grant("deputy", "fs:write", None);
        // Caller alone: allowed for its own top-principal checks that it holds.
        // Stack [caller, deputy]: fs:write is deputy-class → AND → caller lacks it.
        assert!(
            !manager.check_stack(&["caller", "deputy"], "fs:write:/tmp/x"),
            "caller lacking fs:write must not borrow the deputy's authority"
        );
        // Grant the caller too → now the AND passes.
        manager.grant("caller", "fs:write", None);
        assert!(manager.check_stack(&["caller", "deputy"], "fs:write:/tmp/x"));
    }

    #[test]
    fn stack_intersection_only_applies_to_configured_classes() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.set_deputy_classes(["fs:write"]);
        manager.grant("deputy", "network:fetch", None);
        // network:fetch is NOT a deputy class → normal top-principal check.
        // Top principal is the innermost caller (index 0). Grant it.
        manager.grant("caller", "network:fetch", None);
        assert!(manager.check_stack(&["caller", "deputy"], "network:fetch:x.example.com"));
        // A single-element stack reduces to the normal check.
        assert!(!manager.check_stack(&["nobody"], "fs:write:/tmp/x"));
    }

    #[test]
    fn deputy_classes_off_by_default() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.grant("deputy", "fs:write", None);
        // No deputy classes configured → stack intersection is off; the top
        // principal's grant is what matters.
        assert!(manager.check_stack(&["deputy", "caller"], "fs:write:/tmp/x"));
    }

    #[test]
    fn capability_class_extracts_scope_action() {
        assert_eq!(capability_class("fs:write:/etc/passwd"), "fs:write");
        assert_eq!(capability_class("process:spawn"), "process:spawn");
        assert_eq!(capability_class("crypto"), "crypto");
    }

    #[test]
    fn security_mode_from_policy_str() {
        assert_eq!(
            SecurityMode::from_policy_str("strict"),
            Some(SecurityMode::Enforce)
        );
        assert_eq!(
            SecurityMode::from_policy_str("audit"),
            Some(SecurityMode::Audit)
        );
        assert_eq!(SecurityMode::from_policy_str("bogus"), None);
        // Surrounding whitespace must be trimmed — "enforce " must not become an
        // unrecognized value that silently degrades an Auto run. (review follow-up)
        assert_eq!(
            SecurityMode::from_policy_str("  enforce\n"),
            Some(SecurityMode::Enforce)
        );
        assert_eq!(
            SecurityMode::from_policy_str("AUDIT "),
            Some(SecurityMode::Audit)
        );
    }

    // ENG-22630 review: a root builtin allowlist entry covers its subpaths, so the
    // classification (by root segment) and the allowlist match agree.
    #[test]
    fn import_specifier_matches_root_covers_subpaths() {
        assert!(import_specifier_matches("stream", "stream/web"));
        assert!(import_specifier_matches("node:stream", "stream/promises"));
        assert!(import_specifier_matches("fs", "node:fs/promises"));
        assert!(import_specifier_matches("stream", "stream"));
        // A specific subpath entry matches only itself, not the root or siblings.
        assert!(import_specifier_matches("stream/web", "stream/web"));
        assert!(!import_specifier_matches("stream/web", "stream"));
        assert!(!import_specifier_matches("stream/web", "stream/promises"));
        // Not a prefix-of-name false positive.
        assert!(!import_specifier_matches("stream", "streamx"));
    }

    // ENG-22621: version/locator selector precedence in the import axis too.
    #[test]
    fn import_policy_version_locator_selector_precedence() {
        let m = CapabilityManager::new(SecurityMode::Enforce);
        m.register_module_package("7", "left-pad", Some("left-pad@9.9.9-evil"));
        // A version-pinned import policy denies a builtin the name-level entry allows.
        if let Ok(mut map) = m.import_policy.write() {
            map.insert(
                "left-pad".to_string(),
                ImportPolicy {
                    builtins: Some(vec!["node:fs".to_string()]),
                    packages: None,
                },
            );
            map.insert(
                "left-pad@9.9.9-evil".to_string(),
                ImportPolicy {
                    builtins: Some(vec![]),
                    packages: None,
                },
            );
        }
        // The pinned version's empty builtins list (more specific) wins over the
        // name-level `node:fs` allowance.
        assert!(!m.check_import("7", "node:fs"));
    }
}
