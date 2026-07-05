//! Authority-bearing capability handles (attenuators).
//!
//! @ref LLP 0013#delegation-and-authority-flow — passed attenuated handles are the primary
//! delegation mechanism between packages. A handle carries a capability grant
//! fixed at creation; host operations mediated by a handle check *possession*
//! (the handle's grant), not the identity of the calling frame — so a package
//! with no ambient `fs` can still use a handle it was handed, but only within
//! that handle's grant. `scoped()` re-attenuates to a narrower grant; revoking
//! an ancestor fail-closes every derived handle (the revocation cascade).

use std::collections::HashMap;
use std::sync::RwLock;

use super::capability::normalize_capability;

/// One authority-bearing handle: the capability it carries, its parent (for the
/// revocation cascade), and whether it has been revoked directly.
struct HandleGrant {
    capability: String,
    parent: Option<u64>,
    revoked: bool,
}

/// Process-global registry of live handles. Ids are drawn from the OS RNG so a
/// package cannot forge possession by guessing an integer.
#[derive(Default)]
pub struct HandleRegistry {
    handles: RwLock<HashMap<u64, HandleGrant>>,
}

/// Does `grant` (a handle's capability) cover `request` (an attempted op)?
/// `scope:action` must match exactly; the grant's resource must be a path/prefix
/// of the request's resource (with `/` boundaries and an optional trailing
/// `/**`). An empty grant resource covers the whole scope:action.
fn grant_covers(grant: &str, request: &str) -> bool {
    let g: Vec<&str> = grant.splitn(3, ':').collect();
    let r: Vec<&str> = request.splitn(3, ':').collect();
    if g.len() < 2 || r.len() < 2 {
        return grant == request;
    }
    if g[0] != r[0] || g[1] != r[1] {
        return false;
    }
    let g_res = g.get(2).copied().unwrap_or("");
    let r_res = r.get(2).copied().unwrap_or("");
    if g_res.is_empty() || g_res == "*" {
        return true; // whole scope:action
    }
    let base = normalize_handle_resource_for_match(trim_resource_pattern_suffix(g_res));
    let request = normalize_handle_resource_for_match(r_res);
    if request == base {
        return true;
    }
    if base == "/" {
        return request.starts_with('/');
    }
    let mut prefix = String::with_capacity(base.len() + 1);
    prefix.push_str(&base);
    if !prefix.ends_with('/') {
        prefix.push('/');
    }
    request.starts_with(&prefix)
}

fn trim_resource_pattern_suffix(resource: &str) -> &str {
    resource
        .strip_suffix("/**")
        .or_else(|| resource.strip_suffix("\\**"))
        .unwrap_or(resource)
}

fn normalize_handle_resource_for_match(resource: &str) -> String {
    let mut normalized = String::with_capacity(resource.len());
    let mut previous_was_separator = false;
    for ch in resource.chars() {
        let ch = if ch == '\\' { '/' } else { ch };
        if ch == '/' {
            if !previous_was_separator {
                normalized.push('/');
            }
            previous_was_separator = true;
        } else {
            normalized.push(ch);
            previous_was_separator = false;
        }
    }
    while normalized.len() > 1 && normalized.ends_with('/') && !normalized.ends_with(":/") {
        normalized.pop();
    }
    normalized
}

/// Intersect a parent grant with a `narrower` argument. `narrower` may be a full
/// capability (`scope:action:res`) — accepted only if the parent covers it — or
/// a bare sub-path appended to the parent's resource.
fn narrow(parent_cap: &str, narrower: &str) -> Option<String> {
    let candidate = if narrower.contains(':') {
        // Full capability string.
        normalize_capability(narrower)
    } else {
        // Bare sub-path: append to the parent's resource.
        let p: Vec<&str> = parent_cap.splitn(3, ':').collect();
        if p.len() < 2 {
            return None;
        }
        let base = trim_resource_pattern_suffix(p.get(2).copied().unwrap_or(""));
        let base = normalize_handle_resource_for_match(base);
        let sub = narrower.trim_start_matches(['/', '\\']);
        let child_resource = if base.is_empty() {
            sub.to_string()
        } else if sub.is_empty() {
            base
        } else if base.ends_with('/') {
            format!("{}{}", base, sub)
        } else {
            format!("{}/{}", base, sub)
        };
        let child = format!("{}:{}:{}", p[0], p[1], child_resource);
        normalize_capability(&child)
    };
    // Both branches converge here: a child grant is valid only if the parent
    // still covers it. `normalize_capability` collapses `..`, so a bare sub-path
    // like "../secret" (fs:read:/app/images -> fs:read:/app/secret) or repeated
    // "../.." traversal normalizes to a path the parent does not cover and is
    // rejected — attenuation can only narrow, never widen. (ENG-22617/ENG-22628)
    grant_covers(parent_cap, &candidate).then_some(candidate)
}

impl HandleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh random handle id, or `None` on OS-RNG failure. Handle ids are
    /// unforgeable possession tokens, so on RNG failure we fail closed (mint no
    /// handle) rather than fall back to an address-derived value — a predictable
    /// id would undermine the whole possession model; no handle is safer than a
    /// guessable one. (ENG-22622)
    fn random_id() -> Option<u64> {
        // Masked to 53 bits so the id round-trips exactly through a JS number
        // (which the engine passes across the boundary); still a 2^53 space, so
        // unforgeable by guessing.
        const MASK53: u64 = (1u64 << 53) - 1;
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).ok()?;
        let id = u64::from_le_bytes(bytes) & MASK53;
        Some(if id == 0 { 1 } else { id })
    }

    /// Generate a fresh id that does not collide with a live handle. Returns
    /// `None` (fail closed — no handle minted) on RNG failure or if no free id is
    /// found within a bounded number of attempts, so a duplicate id can never
    /// overwrite an existing live handle's grant. (ENG-22622)
    fn fresh_id(map: &HashMap<u64, HandleGrant>) -> Option<u64> {
        Self::fresh_id_with(map, Self::random_id)
    }

    /// Collision/RNG-failure core of `fresh_id`, split out so the failure modes
    /// can be exercised deterministically with an injected generator. (ENG-22622)
    fn fresh_id_with<F: FnMut() -> Option<u64>>(
        map: &HashMap<u64, HandleGrant>,
        mut gen: F,
    ) -> Option<u64> {
        for _ in 0..8 {
            let id = gen()?; // None (RNG failure) short-circuits → fail closed
            if !map.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }

    /// Mint a handle carrying `capability`. The caller is responsible for having
    /// verified the frame holds `capability` first (the endowment layer).
    pub fn create(&self, capability: &str) -> u64 {
        if let Ok(mut map) = self.handles.write() {
            if let Some(id) = Self::fresh_id(&map) {
                map.insert(
                    id,
                    HandleGrant {
                        capability: normalize_capability(capability),
                        parent: None,
                        revoked: false,
                    },
                );
                return id;
            }
        }
        0 // fail closed: RNG failure or (astronomically) no free id
    }

    /// Re-attenuate `parent` to a narrower grant. Returns 0 on failure (parent
    /// missing/dead, or the narrower grant is not within the parent).
    pub fn scoped(&self, parent: u64, narrower: &str) -> u64 {
        let parent_cap = {
            let map = match self.handles.read() {
                Ok(m) => m,
                Err(_) => return 0,
            };
            match map.get(&parent) {
                Some(g) if !g.revoked => g.capability.clone(),
                _ => return 0,
            }
        };
        if !self.is_live(parent) {
            return 0;
        }
        let child_cap = match narrow(&parent_cap, narrower) {
            Some(c) => c,
            None => return 0,
        };
        if let Ok(mut map) = self.handles.write() {
            if let Some(id) = Self::fresh_id(&map) {
                map.insert(
                    id,
                    HandleGrant {
                        capability: child_cap,
                        parent: Some(parent),
                        revoked: false,
                    },
                );
                return id;
            }
        }
        0 // fail closed: RNG failure or (astronomically) no free id
    }

    /// Is the handle (and its whole ancestor chain) live — not directly revoked
    /// and no revoked ancestor?
    fn is_live(&self, id: u64) -> bool {
        let map = match self.handles.read() {
            Ok(m) => m,
            Err(_) => return false,
        };
        let mut cur = id;
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 4096 {
                return false; // cycle guard (ids are random; belt and braces)
            }
            match map.get(&cur) {
                Some(g) if g.revoked => return false,
                Some(g) => match g.parent {
                    Some(p) => cur = p,
                    None => return true,
                },
                None => return false,
            }
        }
    }

    /// Possession check: is the handle live and does its grant cover `request`?
    pub fn check(&self, id: u64, request: &str) -> bool {
        if !self.is_live(id) {
            return false;
        }
        let map = match self.handles.read() {
            Ok(m) => m,
            Err(_) => return false,
        };
        match map.get(&id) {
            Some(g) => grant_covers(&g.capability, &normalize_capability(request)),
            None => false,
        }
    }

    /// Revoke a handle. Descendants fail-close on their next check via the
    /// ancestor walk (no eager sweep needed).
    pub fn revoke(&self, id: u64) {
        if let Ok(mut map) = self.handles.write() {
            if let Some(g) = map.get_mut(&id) {
                g.revoked = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_covers_within_grant_only() {
        let r = HandleRegistry::new();
        let h = r.create("fs:read:/app/images");
        assert!(r.check(h, "fs:read:/app/images/logo.png"));
        assert!(r.check(h, "fs:read:/app/images"));
        assert!(!r.check(h, "fs:read:/etc/passwd"));
        assert!(!r.check(h, "fs:write:/app/images/x")); // action mismatch
    }

    #[test]
    fn grant_covers_accepts_platform_native_path_separators() {
        assert!(grant_covers(
            "fs:read:C:\\workspace\\app\\images",
            "fs:read:C:\\workspace\\app\\images\\logo.png"
        ));
        assert!(grant_covers(
            "fs:read:C:\\workspace\\app\\images",
            "fs:read:C:/workspace/app/images/logo.png"
        ));
        assert!(grant_covers(
            "fs:read:C:\\workspace\\app\\images\\**",
            "fs:read:C:/workspace/app/images/cache/logo.png"
        ));
        assert!(!grant_covers(
            "fs:read:C:\\workspace\\app\\images",
            "fs:read:C:\\workspace\\app\\images2\\logo.png"
        ));
    }

    #[test]
    fn scoped_handles_accept_platform_native_path_separators() {
        let r = HandleRegistry::new();
        let h = r.create("fs:read:C:\\workspace\\app\\images");
        assert_ne!(h, 0);
        let child = r.scoped(h, "cache\\logo.png");
        assert_ne!(child, 0);
        assert!(r.check(child, "fs:read:C:\\workspace\\app\\images\\cache\\logo.png"));
        assert!(r.check(child, "fs:read:C:/workspace/app/images/cache/logo.png"));
        assert!(!r.check(child, "fs:read:C:\\workspace\\app\\images2\\cache\\logo.png"));
    }

    #[test]
    fn scoped_narrows_and_cannot_widen() {
        let r = HandleRegistry::new();
        let h = r.create("fs:read:/app/images");
        let c = r.scoped(h, "cache");
        assert!(c != 0);
        assert!(r.check(c, "fs:read:/app/images/cache/x"));
        assert!(!r.check(c, "fs:read:/app/images/other.png")); // narrowed out
                                                               // cannot scope wider than the parent
        assert_eq!(r.scoped(h, "fs:read:/etc"), 0);
    }

    #[test]
    fn scoped_rejects_dotdot_traversal_outside_grant() {
        // ENG-22617/ENG-22628: a bare sub-path with `..` must not escape the
        // parent handle's subtree even though normalization collapses the `..`.
        let r = HandleRegistry::new();
        let h = r.create("fs:read:/app/images");
        assert!(h != 0);
        // Sibling escape: /app/images/../secret -> /app/secret (not covered).
        assert_eq!(r.scoped(h, "../secret"), 0);
        // Deep parent traversal to an absolute-looking target.
        assert_eq!(r.scoped(h, "../../../../etc/passwd"), 0);
        // Traversal buried after a legitimate-looking prefix.
        assert_eq!(r.scoped(h, "cache/../../../etc"), 0);
        // A genuine nested sub-path still works and stays contained.
        let c = r.scoped(h, "cache/thumbs");
        assert!(c != 0);
        assert!(r.check(c, "fs:read:/app/images/cache/thumbs/x"));
        assert!(!r.check(c, "fs:read:/app/secret"));
    }

    #[test]
    fn fresh_id_fails_closed_on_rng_failure() {
        // ENG-22622: an RNG failure (generator yields None) must fail closed —
        // no id minted — rather than fall back to a weak/predictable value.
        let map: HashMap<u64, HandleGrant> = HashMap::new();
        assert_eq!(HandleRegistry::fresh_id_with(&map, || None), None);
    }

    #[test]
    fn fresh_id_retries_past_collisions_then_gives_up() {
        // ENG-22622: a duplicate id must never overwrite a live handle. The
        // generator is forced to collide with an occupied slot before yielding a
        // free one; a run of pure collisions fails closed instead of overwriting.
        let mut map: HashMap<u64, HandleGrant> = HashMap::new();
        map.insert(
            42,
            HandleGrant {
                capability: "fs:read:/app".into(),
                parent: None,
                revoked: false,
            },
        );
        // First two draws collide with the occupied id 42, third is free.
        let seq = std::cell::RefCell::new(vec![42u64, 42u64, 99u64].into_iter());
        let got = HandleRegistry::fresh_id_with(&map, || seq.borrow_mut().next());
        assert_eq!(got, Some(99));
        assert!(map.contains_key(&42)); // untouched
                                        // A generator that only ever collides gives up (fail closed).
        assert_eq!(HandleRegistry::fresh_id_with(&map, || Some(42)), None);
    }

    #[test]
    fn revocation_cascades_to_descendants() {
        let r = HandleRegistry::new();
        let h = r.create("fs:read:/app/images");
        let c = r.scoped(h, "cache");
        let gc = r.scoped(c, "thumbs");
        assert!(r.check(gc, "fs:read:/app/images/cache/thumbs/x"));
        r.revoke(h); // revoke the root
        assert!(!r.check(h, "fs:read:/app/images/logo.png"));
        assert!(!r.check(c, "fs:read:/app/images/cache/x")); // cascaded
        assert!(!r.check(gc, "fs:read:/app/images/cache/thumbs/x")); // cascaded
        assert_eq!(r.scoped(c, "more"), 0); // cannot re-attenuate a dead handle
    }
}
