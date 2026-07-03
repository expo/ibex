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
        let decision = if self.mode == SecurityMode::Permissive {
            true
        } else {
            self.decide(module_id, &normalized)
        };
        // Permissive and Audit let everything proceed; only Enforce blocks.
        let allowed = if self.mode == SecurityMode::Enforce {
            decision
        } else {
            true
        };

        self.record(AuditEntry {
            timestamp: std::time::SystemTime::now(),
            module_id: module_id.to_string(),
            package: self.principal_for(module_id),
            capability: normalized,
            constraint: None,
            decision,
            allowed,
            mode: self.mode,
        });

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

        // Module-specific (numeric id) grants first.
        if let Ok(grants) = self.grants.read() {
            if matches_denials(grants.get(module_id), capability) {
                return false;
            }
            if matches_grants(grants.get(module_id), capability) {
                return true;
            }
        }

        // Package-selector grants next.
        if let Some(principal) = self.principal_for(module_id) {
            if let Ok(grants) = self.package_grants.read() {
                if matches_denials(grants.get(&principal.name), capability) {
                    return false;
                }
                if matches_grants(grants.get(&principal.name), capability) {
                    return true;
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
        let decision = if self.mode == SecurityMode::Permissive {
            true
        } else {
            self.decide_import(module_id, specifier)
        };
        let allowed = if self.mode == SecurityMode::Enforce {
            decision
        } else {
            true
        };

        self.record(AuditEntry {
            timestamp: std::time::SystemTime::now(),
            module_id: module_id.to_string(),
            package: self.principal_for(module_id),
            capability: format!("import:{}", specifier),
            constraint: None,
            decision,
            allowed,
            mode: self.mode,
        });

        allowed
    }

    fn decide_import(&self, module_id: &str, specifier: &str) -> bool {
        // Unregistered principals are first-party/root (trusted): allow.
        let Some(principal) = self.principal_for(module_id) else {
            return true;
        };
        let policy = self.import_policy.read().ok();
        let Some(policy) = policy.as_ref().and_then(|m| m.get(&principal.name)) else {
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
                Some(list) => list.iter().any(|p| p == specifier),
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
            self.decide(top, &normalized)
        };
        let allowed = if self.mode == SecurityMode::Enforce {
            decision
        } else {
            true
        };

        self.record(AuditEntry {
            timestamp: std::time::SystemTime::now(),
            module_id: top.to_string(),
            package: self.principal_for(top),
            capability: normalized,
            constraint: None,
            decision,
            allowed,
            mode: self.mode,
        });

        allowed
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
/// dependency package). `node:`-prefixed specifiers and the bare Node builtin
/// names are builtins.
fn is_builtin_specifier(specifier: &str) -> bool {
    if let Some(rest) = specifier.strip_prefix("node:") {
        let _ = rest;
        return true;
    }
    NODE_BUILTINS.contains(&specifier)
}

/// Match a policy builtin entry against a require specifier, tolerating the
/// `node:` prefix on either side (`node:fs` in policy matches `fs`, etc.).
fn import_specifier_matches(policy_entry: &str, specifier: &str) -> bool {
    fn strip(s: &str) -> &str {
        s.strip_prefix("node:").unwrap_or(s)
    }
    strip(policy_entry) == strip(specifier)
}

/// Node builtin module names that are reachable without the `node:` prefix.
/// Kept intentionally small — extend as import policy coverage grows.
const NODE_BUILTINS: &[&str] = &[
    "assert",
    "buffer",
    "child_process",
    "crypto",
    "dns",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "net",
    "os",
    "path",
    "process",
    "querystring",
    "stream",
    "tls",
    "url",
    "util",
    "vm",
    "zlib",
];

fn normalize_capability(capability: &str) -> String {
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

        // Audit entries carry the resolved principal + locator.
        let log = manager.audit_log();
        let entry = log
            .iter()
            .find(|e| e.module_id == "1234")
            .expect("entry for registered module");
        let principal = entry.package.as_ref().expect("principal resolved");
        assert_eq!(principal.name, "node-fetch");
        assert_eq!(principal.locator.as_deref(), Some("node-fetch@3.3.2"));
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
    fn security_mode_helpers() {
        assert!(SecurityMode::Enforce.enforces());
        assert!(!SecurityMode::Audit.enforces());
        assert!(SecurityMode::Audit.evaluates());
        assert!(SecurityMode::Enforce.evaluates());
        assert!(!SecurityMode::Permissive.evaluates());
        assert_eq!(
            SecurityMode::from_policy_str("strict"),
            Some(SecurityMode::Enforce)
        );
        assert_eq!(
            SecurityMode::from_policy_str("audit"),
            Some(SecurityMode::Audit)
        );
        assert_eq!(SecurityMode::from_policy_str("bogus"), None);
    }
}
