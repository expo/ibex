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
    let base = g_res.trim_end_matches("/**").trim_end_matches('/');
    if r_res == base {
        return true;
    }
    let mut prefix = String::with_capacity(base.len() + 1);
    prefix.push_str(base);
    prefix.push('/');
    r_res.starts_with(&prefix)
}

/// Intersect a parent grant with a `narrower` argument. `narrower` may be a full
/// capability (`scope:action:res`) — accepted only if the parent covers it — or
/// a bare sub-path appended to the parent's resource.
fn narrow(parent_cap: &str, narrower: &str) -> Option<String> {
    if narrower.contains(':') {
        let candidate = normalize_capability(narrower);
        return grant_covers(parent_cap, &candidate).then_some(candidate);
    }
    // Bare sub-path: append to the parent's resource.
    let p: Vec<&str> = parent_cap.splitn(3, ':').collect();
    if p.len() < 2 {
        return None;
    }
    let base = p.get(2).copied().unwrap_or("").trim_end_matches("/**");
    let base = base.trim_end_matches('/');
    let sub = narrower.trim_start_matches('/');
    let child = if base.is_empty() {
        format!("{}:{}:{}", p[0], p[1], sub)
    } else {
        format!("{}:{}:{}/{}", p[0], p[1], base, sub)
    };
    Some(normalize_capability(&child))
}

impl HandleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn random_id() -> u64 {
        // Masked to 53 bits so the id round-trips exactly through a JS number
        // (which the engine passes across the boundary); still a 2^53 space, so
        // unforgeable by guessing.
        const MASK53: u64 = (1u64 << 53) - 1;
        let mut bytes = [0u8; 8];
        let raw = if getrandom::getrandom(&mut bytes).is_err() {
            // Fall back to an address-derived value; still not a small counter.
            let boxed = Box::new(0u8);
            let addr = Box::into_raw(boxed) as u64;
            unsafe { drop(Box::from_raw(addr as *mut u8)) };
            addr ^ 0x9E37_79B9_7F4A_7C15
        } else {
            u64::from_le_bytes(bytes)
        };
        let id = raw & MASK53;
        if id == 0 {
            1
        } else {
            id
        }
    }

    /// Mint a handle carrying `capability`. The caller is responsible for having
    /// verified the frame holds `capability` first (the endowment layer).
    pub fn create(&self, capability: &str) -> u64 {
        let id = Self::random_id();
        if let Ok(mut map) = self.handles.write() {
            map.insert(
                id,
                HandleGrant {
                    capability: normalize_capability(capability),
                    parent: None,
                    revoked: false,
                },
            );
        }
        id
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
        let id = Self::random_id();
        if let Ok(mut map) = self.handles.write() {
            map.insert(
                id,
                HandleGrant {
                    capability: child_cap,
                    parent: Some(parent),
                    revoked: false,
                },
            );
        }
        id
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
