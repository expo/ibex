//! Capability management for the security model
//!
//! This implements the capability-based security system described in
//! SECURITY_DESIGN.md and JS_RUNTIME_SECURITY.md.

use super::SecurityMode;
use crate::host::policy::PolicyFile;
use std::collections::{HashMap, VecDeque};
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

/// Manages capability grants and checks
pub struct CapabilityManager {
    mode: SecurityMode,
    /// Grants by module ID
    grants: RwLock<HashMap<String, Vec<CapabilityGrant>>>,
    /// Audit log of capability checks
    audit_log: RwLock<VecDeque<AuditEntry>>,
}

/// An entry in the capability audit log
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: std::time::SystemTime,
    pub module_id: String,
    pub capability: String,
    pub constraint: Option<String>,
    pub granted: bool,
}

const ALWAYS_ALLOWED: [&str; 2] = ["crypto:random", "time:now"];

impl CapabilityManager {
    /// Create a new capability manager
    pub fn new(mode: SecurityMode) -> Self {
        Self {
            mode,
            grants: RwLock::new(HashMap::new()),
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
    }

    /// Check if a capability is granted
    pub fn check(&self, module_id: &str, capability_str: &str) -> bool {
        let normalized = normalize_capability(capability_str);
        let granted = self.check_internal(module_id, &normalized);

        // Log the check
        let entry = AuditEntry {
            timestamp: std::time::SystemTime::now(),
            module_id: module_id.to_string(),
            capability: normalized,
            constraint: None,
            granted,
        };

        if let Ok(mut log) = self.audit_log.write() {
            if log.len() == MAX_AUDIT_LOG_ENTRIES {
                log.pop_front();
            }
            log.push_back(entry);
        }

        granted
    }

    fn check_internal(&self, module_id: &str, capability: &str) -> bool {
        if ALWAYS_ALLOWED.iter().any(|cap| cap == &capability) {
            return true;
        }

        // In legacy mode, everything is allowed
        if self.mode == SecurityMode::Permissive {
            return true;
        }

        // Check grants
        if let Ok(grants) = self.grants.read() {
            if matches_denials(grants.get(module_id), capability) {
                return false;
            }
            if matches_grants(grants.get(module_id), capability) {
                return true;
            }

            if matches_denials(grants.get("*"), capability) {
                return false;
            }
            if matches_grants(grants.get("*"), capability) {
                return true;
            }
        }

        // Default deny in strict mode
        false
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
}

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
        let manager = CapabilityManager::new(SecurityMode::Strict);

        manager.grant("module-a", "network:fetch", None);
        manager.grant("module-b", "net:fetch", None);

        assert!(manager.check("module-a", "network:fetch:api.example.com"));
        assert!(manager.check("module-b", "network:fetch:api.example.com"));
        assert!(!manager.check("module-a", "network:connect:api.example.com"));
    }

    #[test]
    fn capability_audit_log_is_bounded() {
        let manager = CapabilityManager::new(SecurityMode::Strict);

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
}
