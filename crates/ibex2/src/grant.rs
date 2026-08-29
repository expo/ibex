//! The authority model: carried, not inferred.
//!
//! LLP 0067 R2 binds a capability grant to the identity of the binding a
//! module was handed at instantiation. Nothing here inspects a call stack,
//! because nothing in Ibex 2 is permitted to.
//!
//! Under D1 and D2 the binary question — *may this module reach the network at
//! all?* — is answered structurally: a module that was not injected `fetch`
//! has no expression that evaluates to one. So what lives here is only the
//! **parameterized** half of LLP 0059.000 §4: the four questions asked against
//! a grant the caller already provably holds.
//!
//! This is pure Rust and needs no engine, which is why it is the first thing
//! built.
//!
//! @ref LLP 0067#3-the-check — the parameterized questions the boundary asks
//! @ref LLP 0059.000#4-capability-summary — the six capabilities and their granularity

use std::collections::BTreeSet;

/// An origin, for the two network capabilities.
///
/// Compared by exact tuple equality. Wildcards are deliberately absent: an
/// origin pattern language is where per-origin grants quietly become
/// all-origin grants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Origin {
    pub fn new(scheme: &str, host: &str, port: u16) -> Self {
        // Scheme and host are case-insensitive per RFC 3986; normalize once at
        // construction so comparison is a plain equality test everywhere else.
        Self {
            scheme: scheme.to_ascii_lowercase(),
            host: host.to_ascii_lowercase(),
            port,
        }
    }
}

/// A filesystem subtree, for `fs.read` and `fs.write`.
///
/// Paths are compared by **whole components**. A prefix grant on `/home/user`
/// must not admit `/home/user2`, which a naive string `starts_with` would —
/// that is the standard way a per-prefix grant turns into a wider one than
/// anybody wrote down.
///
/// Paths reaching here are expected to be already resolved through the virtual
/// filesystem namespace (LLP 0059.000 §3.11), so `..` has no meaning at this
/// layer and is rejected rather than interpreted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathPrefix(Vec<String>);

impl PathPrefix {
    /// Build a prefix from an absolute, already-resolved path.
    ///
    /// Returns `None` for a relative path or one still carrying `.`/`..`,
    /// because admitting either would mean deciding traversal semantics here,
    /// where the answer cannot be checked against the real filesystem.
    pub fn new(path: &str) -> Option<Self> {
        if !path.starts_with('/') {
            return None;
        }
        let mut components = Vec::new();
        for component in path.split('/') {
            match component {
                "" => continue,
                "." | ".." => return None,
                other => components.push(other.to_string()),
            }
        }
        Some(Self(components))
    }

    /// Does this prefix cover `path`?
    ///
    /// A prefix covers itself and everything beneath it. An unresolvable path
    /// is covered by nothing — refusing is the only safe reading of a path
    /// this layer cannot interpret.
    pub fn covers(&self, path: &str) -> bool {
        match Self::new(path) {
            Some(target) => target.0.starts_with(&self.0),
            None => false,
        }
    }
}

/// One operation the boundary is asked to admit.
///
/// Every variant carries the parameter its grant is scoped by. There is no
/// unparameterized variant, and adding one would be the moment per-origin and
/// per-prefix stopped meaning anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// `fetch` to an origin. Capability `net.fetch`.
    Fetch { origin: Origin },
    /// A WebSocket to an origin. Capability `net.websocket`.
    WebSocket { origin: Origin },
    /// Read a path. Capability `fs.read`.
    FsRead { path: String },
    /// Write a path. Capability `fs.write`.
    FsWrite { path: String },
    /// Read one environment variable by name. Capability `env.read`.
    EnvRead { name: String },
    /// Open a database by path. Capability `sqlite.open`.
    SqliteOpen { path: String },
}

/// One grant. The parameter is the scope, and there is always a scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grant {
    Fetch(Origin),
    WebSocket(Origin),
    FsRead(PathPrefix),
    FsWrite(PathPrefix),
    EnvRead(String),
    SqliteOpen(PathPrefix),
}

impl Grant {
    fn admits(&self, operation: &Operation) -> bool {
        match (self, operation) {
            (Grant::Fetch(granted), Operation::Fetch { origin }) => granted == origin,
            (Grant::WebSocket(granted), Operation::WebSocket { origin }) => granted == origin,
            (Grant::FsRead(prefix), Operation::FsRead { path }) => prefix.covers(path),
            (Grant::FsWrite(prefix), Operation::FsWrite { path }) => prefix.covers(path),
            (Grant::EnvRead(granted), Operation::EnvRead { name }) => granted == name,
            (Grant::SqliteOpen(prefix), Operation::SqliteOpen { path }) => prefix.covers(path),
            // Cross-kind pairs are not merely false, they are the whole point:
            // an `fs.read` grant admits no network operation, and the match
            // above is exhaustive over kinds so a new capability cannot be
            // added without deciding what admits it.
            _ => false,
        }
    }
}

/// The authority a single binding carries.
///
/// This is the value LLP 0060 D1 is about. It is handed to a binding at module
/// instantiation and consulted at the boundary. It is never derived from a
/// frame, a `Domain`, or a job queue, and there is deliberately no constructor
/// that reads ambient state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct GrantSet {
    grants: BTreeSet<Grant>,
}

impl GrantSet {
    /// The empty set: holds nothing, admits nothing.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn with(mut self, grant: Grant) -> Self {
        self.grants.insert(grant);
        self
    }

    /// The environment variables this set may read, in a stable order.
    ///
    /// `process.env` is a **snapshot**, not a live proxy (LLP 0059.000 §3.8),
    /// and the snapshot is built from exactly this list — so a module cannot
    /// see a variable it was not granted, with no check at read time. The
    /// capability is the object's contents.
    /// This set with every filesystem prefix realized — symlinks followed,
    /// case settled — for checking a realized request path against
    /// (`stdlib::fs::realize`). Other families are unchanged.
    pub fn realized_fs(&self) -> GrantSet {
        let realize = |prefix: &PathPrefix| {
            let spelt = format!("/{}", prefix.0.join("/"));
            let real = crate::stdlib::fs::realize(std::path::Path::new(&spelt));
            PathPrefix::new(&real.to_string_lossy()).unwrap_or_else(|| prefix.clone())
        };
        GrantSet {
            grants: self
                .grants
                .iter()
                .map(|grant| match grant {
                    Grant::FsRead(prefix) => Grant::FsRead(realize(prefix)),
                    Grant::FsWrite(prefix) => Grant::FsWrite(realize(prefix)),
                    other => other.clone(),
                })
                .collect(),
        }
    }

    pub fn readable_env(&self) -> Vec<&str> {
        self.grants
            .iter()
            .filter_map(|grant| match grant {
                Grant::EnvRead(name) => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Is `operation` admitted by any grant in this set?
    ///
    /// Fails closed: an empty set admits nothing, and no operation has a
    /// default-allow path.
    pub fn permits(&self, operation: &Operation) -> bool {
        self.grants.iter().any(|grant| grant.admits(operation))
    }

    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
}

impl GrantSet {
    /// Parse a grant spec: one grant per line, `capability target`.
    ///
    /// Fixed at creation, because a grant set that can be added to after the
    /// fact is ambient authority wearing a struct (LLP 0067 §2). Blank lines
    /// and `#` comments are ignored.
    ///
    /// ```text
    /// net.fetch http://127.0.0.1:8080
    /// fs.read   /data
    /// env.read  NODE_ENV
    /// ```
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut set = GrantSet::none();
        for (index, line) in spec.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let capability = parts.next().unwrap_or_default();
            let target = parts
                .next()
                .ok_or_else(|| format!("line {}: `{capability}` needs a target", index + 1))?;
            let grant = match capability {
                "net.fetch" | "net.websocket" => {
                    let url = url::Url::parse(target)
                        .map_err(|e| format!("line {}: bad origin `{target}`: {e}", index + 1))?;
                    let host = url
                        .host_str()
                        .ok_or_else(|| format!("line {}: origin has no host", index + 1))?;
                    let port = url.port_or_known_default().ok_or_else(|| {
                        format!("line {}: no default port for `{}`", index + 1, url.scheme())
                    })?;
                    let origin = Origin::new(url.scheme(), host, port);
                    if capability == "net.fetch" {
                        Grant::Fetch(origin)
                    } else {
                        Grant::WebSocket(origin)
                    }
                }
                "fs.read" | "fs.write" | "sqlite.open" => {
                    let prefix = PathPrefix::new(target).ok_or_else(|| {
                        format!(
                            "line {}: `{target}` must be an absolute, resolved path",
                            index + 1
                        )
                    })?;
                    match capability {
                        "fs.read" => Grant::FsRead(prefix),
                        "fs.write" => Grant::FsWrite(prefix),
                        _ => Grant::SqliteOpen(prefix),
                    }
                }
                "env.read" => Grant::EnvRead(target.to_string()),
                other => return Err(format!("line {}: unknown capability `{other}`", index + 1)),
            };
            set = set.with(grant);
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(host: &str) -> Origin {
        Origin::new("https", host, 443)
    }

    #[test]
    fn empty_set_admits_nothing() {
        let set = GrantSet::none();
        assert!(!set.permits(&Operation::Fetch {
            origin: origin("example.com")
        }));
        assert!(!set.permits(&Operation::EnvRead {
            name: "PATH".into()
        }));
        assert!(!set.permits(&Operation::FsRead {
            path: "/tmp/x".into()
        }));
    }

    #[test]
    fn fetch_grant_is_per_origin() {
        let set = GrantSet::none().with(Grant::Fetch(origin("api.example.com")));
        assert!(set.permits(&Operation::Fetch {
            origin: origin("api.example.com")
        }));
        assert!(!set.permits(&Operation::Fetch {
            origin: origin("evil.example.com")
        }));
        // A different port is a different origin.
        assert!(!set.permits(&Operation::Fetch {
            origin: Origin::new("https", "api.example.com", 8443)
        }));
        // ...and a different scheme is too.
        assert!(!set.permits(&Operation::Fetch {
            origin: Origin::new("http", "api.example.com", 443)
        }));
    }

    #[test]
    fn origin_comparison_is_case_insensitive_on_scheme_and_host() {
        let set = GrantSet::none().with(Grant::Fetch(Origin::new("HTTPS", "API.Example.COM", 443)));
        assert!(set.permits(&Operation::Fetch {
            origin: origin("api.example.com")
        }));
    }

    #[test]
    fn a_fetch_grant_does_not_admit_a_websocket() {
        let set = GrantSet::none().with(Grant::Fetch(origin("api.example.com")));
        assert!(!set.permits(&Operation::WebSocket {
            origin: origin("api.example.com")
        }));
    }

    #[test]
    fn path_prefix_matches_whole_components_only() {
        let prefix = PathPrefix::new("/home/user").expect("absolute");
        assert!(prefix.covers("/home/user"));
        assert!(prefix.covers("/home/user/notes.txt"));
        assert!(prefix.covers("/home/user/deep/nested/file"));
        // The bug this test exists for: a string prefix would admit these.
        assert!(!prefix.covers("/home/user2"));
        assert!(!prefix.covers("/home/username/secrets"));
        assert!(!prefix.covers("/home"));
        assert!(!prefix.covers("/etc/passwd"));
    }

    #[test]
    fn unresolved_and_relative_paths_are_admitted_by_nothing() {
        let prefix = PathPrefix::new("/home/user").expect("absolute");
        assert!(!prefix.covers("/home/user/../../etc/passwd"));
        assert!(!prefix.covers("/home/user/./notes.txt"));
        assert!(!prefix.covers("home/user/notes.txt"));
        assert_eq!(PathPrefix::new("relative/path"), None);
        assert_eq!(PathPrefix::new("/home/../etc"), None);
    }

    #[test]
    fn redundant_separators_do_not_change_coverage() {
        let prefix = PathPrefix::new("/home//user/").expect("absolute");
        assert!(prefix.covers("/home/user/notes.txt"));
        assert!(!prefix.covers("/home/user2"));
    }

    #[test]
    fn read_and_write_are_separate_grants() {
        let set = GrantSet::none().with(Grant::FsRead(PathPrefix::new("/data").unwrap()));
        assert!(set.permits(&Operation::FsRead {
            path: "/data/x".into()
        }));
        assert!(!set.permits(&Operation::FsWrite {
            path: "/data/x".into()
        }));
    }

    #[test]
    fn env_read_is_per_variable_name() {
        let set = GrantSet::none().with(Grant::EnvRead("NODE_ENV".into()));
        assert!(set.permits(&Operation::EnvRead {
            name: "NODE_ENV".into()
        }));
        // The canonical supply-chain case from LLP 0059.000 §3.8.
        assert!(!set.permits(&Operation::EnvRead {
            name: "AWS_SECRET_ACCESS_KEY".into()
        }));
        // Names are compared exactly; no prefix or case folding.
        assert!(!set.permits(&Operation::EnvRead {
            name: "node_env".into()
        }));
        assert!(!set.permits(&Operation::EnvRead {
            name: "NODE_ENV_EXTRA".into()
        }));
    }

    #[test]
    fn a_spec_parses_into_the_grants_it_names() {
        let set = GrantSet::parse(
            "# a comment\n\nnet.fetch http://127.0.0.1:8080\nfs.read /data\nenv.read NODE_ENV\n",
        )
        .unwrap();
        assert!(set.permits(&Operation::Fetch {
            origin: Origin::new("http", "127.0.0.1", 8080)
        }));
        assert!(set.permits(&Operation::FsRead {
            path: "/data/x".into()
        }));
        assert!(set.permits(&Operation::EnvRead {
            name: "NODE_ENV".into()
        }));
        // And nothing beyond them.
        assert!(!set.permits(&Operation::Fetch {
            origin: Origin::new("http", "127.0.0.1", 9090)
        }));
        assert!(!set.permits(&Operation::FsWrite {
            path: "/data/x".into()
        }));
    }

    #[test]
    fn an_empty_spec_grants_nothing_and_a_bad_one_is_refused() {
        assert!(GrantSet::parse("").unwrap().is_empty());
        assert!(GrantSet::parse("net.fetch").is_err());
        assert!(GrantSet::parse("nonsense.cap x").is_err());
        assert!(GrantSet::parse("fs.read relative/path").is_err());
        assert!(GrantSet::parse("net.fetch not-a-url").is_err());
    }

    #[test]
    fn several_grants_compose_without_widening_each_other() {
        let set = GrantSet::none()
            .with(Grant::Fetch(origin("api.example.com")))
            .with(Grant::FsRead(PathPrefix::new("/data").unwrap()))
            .with(Grant::EnvRead("NODE_ENV".into()));
        assert!(set.permits(&Operation::Fetch {
            origin: origin("api.example.com")
        }));
        assert!(set.permits(&Operation::FsRead {
            path: "/data/x".into()
        }));
        assert!(set.permits(&Operation::EnvRead {
            name: "NODE_ENV".into()
        }));
        assert!(!set.permits(&Operation::FsWrite {
            path: "/data/x".into()
        }));
        assert!(!set.permits(&Operation::Fetch {
            origin: origin("other.example.com")
        }));
        assert!(!set.permits(&Operation::EnvRead {
            name: "AWS_SECRET_ACCESS_KEY".into()
        }));
    }
}
