//! Capability management for the security model
//!
//! This implements the capability-based security system described in
//! SECURITY_DESIGN.md and JS_RUNTIME_SECURITY.md.

use super::SecurityMode;
use crate::host::policy::PolicyFile;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;

const MAX_AUDIT_LOG_ENTRIES: usize = 1024;

/// A capability grant record
#[derive(Debug, Clone)]
pub struct CapabilityGrant {
    /// The capability string (canonical form)
    pub capability: String,
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
    /// Grants by numeric module ID (and `*` for global grants).
    grants: RwLock<HashMap<String, Vec<CapabilityGrant>>>,
    /// Grants keyed by package **selector** (package name).
    package_grants: RwLock<HashMap<String, Vec<CapabilityGrant>>>,
    /// Bridge from a numeric module principal to its resolved package principal.
    module_to_package: RwLock<HashMap<String, PackagePrincipal>>,
    /// Per-package import-graph policy.
    import_policy: RwLock<HashMap<String, ImportPolicy>>,
    /// Capability classes (e.g. `fs:write`, `process:spawn`) that require
    /// stack-intersection enforcement. Empty = off (the default).
    deputy_classes: RwLock<HashSet<String>>,
    /// Capabilities the root principal may acquire at runtime (the dynamic
    /// "prompt" ceiling). @ref LLP 0013#interaction-with-user-facing-dynamic-permissions
    ceiling: RwLock<Vec<String>>,
    /// Audit log of capability checks
    audit_log: RwLock<VecDeque<AuditEntry>>,
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

impl CapabilityManager {
    /// Create a new capability manager
    pub fn new(mode: SecurityMode) -> Self {
        Self {
            mode,
            grants: RwLock::new(HashMap::new()),
            package_grants: RwLock::new(HashMap::new()),
            module_to_package: RwLock::new(HashMap::new()),
            import_policy: RwLock::new(HashMap::new()),
            deputy_classes: RwLock::new(HashSet::new()),
            ceiling: RwLock::new(Vec::new()),
            audit_log: RwLock::new(VecDeque::with_capacity(MAX_AUDIT_LOG_ENTRIES)),
        }
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
        // @ref LLP 0013 §dynamic permissions — the runtime-grant ceiling.
        if !policy.ceiling.is_empty() {
            if let Ok(mut c) = self.ceiling.write() {
                *c = policy
                    .ceiling
                    .iter()
                    .map(|s| normalize_capability(s))
                    .collect();
            }
        }
    }

    /// Is `capability` within the runtime-grant ceiling (may root acquire it at
    /// runtime)? @ref LLP 0013 §dynamic permissions
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
    /// authority). @ref LLP 0013 §dynamic permissions
    fn ceiling_configured(&self) -> bool {
        // Fail closed on a poisoned lock: assume a ceiling is configured so root
        // is gated (not blanket-trusted) rather than silently ambient.
        self.ceiling.read().map(|c| !c.is_empty()).unwrap_or(true)
    }

    /// Runtime-grant `capability` to the root principal, bounded by the ceiling
    /// (the static artifact is the ceiling; prompts move the floor). Returns
    /// whether the grant was applied. @ref LLP 0013 §dynamic permissions
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
                list.retain(|g| g.denied || g.capability != normalized);
            }
        }
    }

    /// Tri-state grant status for the root principal: 1 = granted now, 2 =
    /// prompt (not granted but within the ceiling, so acquirable), 0 = denied
    /// (neither). @ref LLP 0013 §dynamic permissions — grant status is tri-state
    /// at the host surface, not boolean.
    pub fn grant_status(&self, capability: &str) -> u8 {
        if self.decide("0", capability) {
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
        }
    }

    fn principal_for(&self, module_id: &str) -> Option<PackagePrincipal> {
        self.module_to_package
            .read()
            .ok()
            .and_then(|map| map.get(module_id).cloned())
    }

    /// Grant a capability to a package selector.
    pub fn grant_package(&self, selector: &str, capability: &str) {
        if let Ok(mut grants) = self.package_grants.write() {
            grants
                .entry(selector.to_string())
                .or_default()
                .push(CapabilityGrant {
                    capability: normalize_capability(capability),
                    module_id: selector.to_string(),
                    constraint: None,
                    denied: false,
                });
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
                    module_id: selector.to_string(),
                    constraint: None,
                    denied: true,
                });
        }
    }

    /// Check if a capability is granted.
    ///
    /// @ref LLP 0013#phase-1 — computes the real policy decision, records it,
    /// and returns whether the operation may proceed. In `Audit` mode a
    /// would-deny is logged but still returns `true`; in `Enforce` mode the
    /// returned value is the decision itself.
    pub fn check(&self, module_id: &str, capability_str: &str) -> bool {
        let normalized = normalize_capability(capability_str);
        let decision = self.mode == SecurityMode::Permissive || self.decide(module_id, &normalized);
        self.gate_and_record(module_id, normalized, decision)
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
        if !decision {
            self.record(AuditEntry {
                timestamp: std::time::SystemTime::now(),
                module_id: module_id.to_string(),
                package: self.principal_for(module_id),
                capability,
                constraint: None,
                decision,
                allowed,
                mode: self.mode,
            });
        }
        allowed
    }

    fn record(&self, entry: AuditEntry) {
        if let Ok(mut log) = self.audit_log.write() {
            if log.len() == MAX_AUDIT_LOG_ENTRIES {
                log.pop_front();
            }
            log.push_back(entry);
        }
    }

    /// The real policy decision, independent of mode gating. Precedence:
    /// always-allowed → module deny/allow → package deny/allow → global
    /// deny/allow → default-deny.
    fn decide(&self, module_id: &str, capability: &str) -> bool {
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

        // Module-specific (numeric id) grants first.
        if let Ok(grants) = self.grants.read() {
            if matches_denials(grants.get(module_id), capability) {
                return false;
            }
            if matches_grants(grants.get(module_id), capability) {
                return true;
            }
        }

        // Package-selector grants next. Consult the version/locator-specific
        // selector before the bare name so a policy can pin a coexisting version
        // (RFC Resolved Q1); the first selector with a matching deny/grant wins.
        // (ENG-22621)
        if let Some(principal) = self.principal_for(module_id) {
            if let Ok(grants) = self.package_grants.read() {
                for selector in principal.selectors() {
                    if matches_denials(grants.get(selector), capability) {
                        return false;
                    }
                    if matches_grants(grants.get(selector), capability) {
                        return true;
                    }
                }
            }
        }

        // Global grants last.
        if let Ok(grants) = self.grants.read() {
            if matches_denials(grants.get("*"), capability) {
                return false;
            }
            if matches_grants(grants.get("*"), capability) {
                return true;
            }
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

    /// Import-graph gate. Returns whether the load proceeds under the active
    /// mode; the real decision is logged as a synthetic `import:<specifier>`
    /// capability so audit reports surface would-deny imports.
    ///
    /// @ref LLP 0013#policy — builtins are reachable by `require`, so this is
    /// the primary containment gate for them.
    pub fn check_import(&self, module_id: &str, specifier: &str) -> bool {
        let decision =
            self.mode == SecurityMode::Permissive || self.decide_import(module_id, specifier);
        self.gate_and_record(module_id, format!("import:{}", specifier), decision)
    }

    fn decide_import(&self, module_id: &str, specifier: &str) -> bool {
        // Unregistered principals are first-party/root (trusted): allow.
        let Some(principal) = self.principal_for(module_id) else {
            return true;
        };
        let policy = self.import_policy.read().ok();
        // Version/locator-specific import policy takes precedence over the
        // name-level default, mirroring the capability selector precedence. (ENG-22621)
        let Some(policy) = policy
            .as_ref()
            .and_then(|m| principal.selectors().find_map(|selector| m.get(selector)))
        else {
            // Governed for capabilities but not for imports: unrestricted axis.
            return true;
        };
        if is_builtin_specifier(specifier) {
            match &policy.builtins {
                None => true,
                Some(list) => list.iter().any(|b| import_specifier_matches(b, specifier)),
            }
        } else {
            match &policy.packages {
                None => true,
                // Match on the package *selector*, not the raw specifier: fold a
                // subpath/deep import to its package (`lodash/fp` -> `lodash`) so
                // the runtime agrees with how the generator authors the list, and
                // treat a relative/absolute specifier as an intra-package import
                // (not a cross-package edge) so a package can load its own files.
                // (ENG-22637)
                Some(list) => match package_selector_of_specifier(specifier) {
                    None => true,
                    Some(selector) => list.iter().any(|p| {
                        p == specifier
                            || package_selector_of_specifier(p).as_deref() == Some(&selector)
                    }),
                },
            }
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
    /// pass a single-element stack and this reduces to `check`.
    ///
    /// @ref LLP 0013#phase-5
    pub fn check_stack(&self, stack: &[&str], capability_str: &str) -> bool {
        let normalized = normalize_capability(capability_str);
        let top = stack.first().copied().unwrap_or("");

        let decision = if self.mode == SecurityMode::Permissive {
            true
        } else if self.is_deputy_class(&normalized) && stack.len() > 1 {
            // Walk-and-AND: every principal on the stack must be granted.
            stack
                .iter()
                .all(|principal| self.decide(principal, &normalized))
        } else {
            // NOTE (ENG-22631): the async-detached deputy laundering case
            // (`Promise.resolve(x).then(deputy.method)`) collects a len==1 stack
            // of just [deputy] — the scheduling caller's frame has already
            // returned. It is NOT soundly closable here: a len==1 package stack is
            // ALSO the normal shape of a granted package running its own async /
            // timer continuation, and the two are indistinguishable from the stack
            // alone, so a blunt deny would false-deny every legitimate async
            // deputy-class op by a granted package. The sound fix is to capture the
            // scheduling principal into the microtask/job (an async-context
            // propagation extension of Hermes patch 0007, RFC Open Q3), which
            // requires an engine change. Until then this remains a documented
            // residual of the opt-in deputy hardening (deputy-by-design is out of
            // scope by default; the synchronous case above is fully closed).
            self.decide(top, &normalized)
        };
        self.gate_and_record(top, normalized, decision)
    }

    /// Grant a capability to a module
    pub fn grant(&self, module_id: &str, capability: &str, constraint: Option<String>) {
        if let Ok(mut grants) = self.grants.write() {
            let module_grants = grants.entry(module_id.to_string()).or_insert_with(Vec::new);
            module_grants.push(CapabilityGrant {
                capability: normalize_capability(capability),
                module_id: module_id.to_string(),
                constraint,
                denied: false,
            });
        }
    }

    /// Deny a capability to a module
    pub fn deny(&self, module_id: &str, capability: &str, constraint: Option<String>) {
        if let Ok(mut grants) = self.grants.write() {
            let module_grants = grants.entry(module_id.to_string()).or_insert_with(Vec::new);
            module_grants.push(CapabilityGrant {
                capability: normalize_capability(capability),
                module_id: module_id.to_string(),
                constraint,
                denied: true,
            });
        }
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

    /// Summarize would-deny decisions for operator-facing audit output.
    /// Returns an empty string when nothing was flagged.
    ///
    /// @ref LLP 0013#phase-1 — `ibex run --capsec audit` feeds the compat
    /// corpus: the would-deny set is exactly the grants an app must declare
    /// before it can move to `--capsec enforce`.
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
    if specifier.starts_with("node:") {
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
    NODE_BUILTINS.contains(&root)
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
        match parts.next().filter(|p| !p.is_empty()) {
            Some(second) => Some(format!("{first}/{second}")),
            None => None,
        }
    } else {
        Some(first.to_string())
    }
}

/// Node builtin module names (roots) reachable without the `node:` prefix. A
/// specifier's first path segment is matched against this, so subpaths like
/// `fs/promises` or `stream/web` classify as builtins too. Derived from the
/// runtime's supported builtins; keep in sync as coverage grows. (ENG-22630)
const NODE_BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "sqlite",
    "stream",
    "string_decoder",
    "sys",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
];

pub fn normalize_capability(capability: &str) -> String {
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
        "fs" => normalize_fs_resource(resource),
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

fn normalize_fs_resource(resource: &str) -> String {
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

    let has_wildcard = trimmed.contains('*');
    if !has_wildcard {
        if let Ok(canon) = path.canonicalize() {
            return canon.to_string_lossy().to_string();
        }
    }

    normalize_path_components(&path)
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

fn normalize_path_components(path: &Path) -> String {
    let mut normalized = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized.to_string_lossy().to_string()
}

fn matches_grants(grants: Option<&Vec<CapabilityGrant>>, capability: &str) -> bool {
    if let Some(list) = grants {
        for grant in list {
            if grant.denied {
                continue;
            }
            if matches_capability(&grant.capability, capability) {
                return true;
            }
        }
    }
    false
}

fn matches_denials(grants: Option<&Vec<CapabilityGrant>>, capability: &str) -> bool {
    if let Some(list) = grants {
        for grant in list {
            if !grant.denied {
                continue;
            }
            if matches_capability(&grant.capability, capability) {
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
    if pattern.contains('*') {
        return wildcard_match(pattern, value);
    }

    let pattern_parts: Vec<&str> = pattern.splitn(3, ':').collect();
    let value_parts: Vec<&str> = value.splitn(3, ':').collect();

    if pattern_parts.len() > value_parts.len() {
        return false;
    }

    pattern_parts
        .iter()
        .zip(value_parts.iter())
        .all(|(pattern_part, value_part)| pattern_part == value_part)
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let mut pattern_iter = pattern.split('*');
    let mut remainder = value;

    if let Some(first) = pattern_iter.next() {
        if !first.is_empty() {
            if let Some(stripped) = remainder.strip_prefix(first) {
                remainder = stripped;
            } else {
                return false;
            }
        }
    }

    for part in pattern_iter {
        if part.is_empty() {
            continue;
        }
        if let Some(index) = remainder.find(part) {
            remainder = &remainder[index + part.len()..];
        } else {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(matches_capability("fs:read", "fs:read:/tmp/file.txt"));
        assert!(!matches_capability(
            "network:fetch:api.example.com",
            "network:fetch:other.example.com"
        ));
    }

    #[test]
    fn matches_capability_does_not_treat_resource_prefixes_as_exact_matches() {
        let root = normalize_capability("fs:read:/tmp/exact-capabilities");
        let child = normalize_capability("fs:read:/tmp/exact-capabilities/file.txt");
        assert!(!matches_capability(&root, &child));
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

    // @ref LLP 0013#resolved-questions (ENG-22621) — the name selector is the
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

    #[test]
    fn package_deny_beats_grant() {
        let manager = CapabilityManager::new(SecurityMode::Enforce);
        manager.grant_package("evil", "network:fetch");
        manager.deny_package("evil", "network:fetch:evil.example.com");
        manager.register_module_package("7", "evil", None);
        assert!(manager.check("7", "network:fetch:ok.example.com"));
        assert!(!manager.check("7", "network:fetch:evil.example.com"));
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
    // model holds. Explicit grants/denials still win for root. @ref LLP 0013 §dynamic permissions
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
                    builtins: Some(vec!["node:http".to_string(), "node:https".to_string()]),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        manager.apply_policy(&policy);
        manager.register_module_package("42", "node-fetch", None);

        assert!(manager.check_import("42", "node:http"));
        assert!(manager.check_import("42", "https")); // node: prefix tolerated
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
