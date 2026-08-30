//! The standard library for a consumer with no engine.
//!
//! `rules/NOT-DOING.md` sets the bar: a no-JS consumer — Exact 2's plan
//! runner is one — gets the same standard library with no engine in the
//! process at all. This is that surface. It is not a second implementation:
//! every function here is the one the JavaScript bindings call, behind the
//! same `boundary::admit`, and the grants are the same `GrantSet` a manifest
//! section parses to. What is stated in Rust is LLP 0067's model: a consumer
//! is *endowed* with bindings that carry their grant — the module parameter
//! list, as a struct — and a request is checked against the grant the binding
//! carries, never against who is calling.
//!
//! Synchronous, deliberately. These are the primitives; an executor is the
//! consumer's, and a runner with its own loop puts them on its own workers.
//!
//! @ref LLP 0068#1-the-shape — bindings that carry their grant
//! @ref LLP 0067#3-the-check — one chokepoint, the grant the binding carries

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::boundary::HostError;
use crate::grant::{GrantSet, Operation};
use crate::secrets::{self, SecretStore};
use crate::stdlib::fetch::{self, Request, Response, Transport};
use crate::stdlib::fs::{self, FsOp, FsResult, Stat};

/// The host: the platform's transport and its secret store, and nothing
/// else. One per process is the expected shape; it is the analogue of the
/// runtime, without an engine.
pub struct Host {
    transport: Arc<dyn Transport>,
    secrets: Arc<dyn SecretStore>,
}

impl Host {
    /// The platform's transport (`NSURLSession` on Apple platforms) and its
    /// secret store (the Keychain there; a file per secret elsewhere).
    pub fn new() -> Self {
        Self::with_transport(crate::transport::default_transport())
    }

    pub fn with_transport(transport: Box<dyn Transport>) -> Self {
        Self {
            transport: Arc::from(transport),
            secrets: Arc::from(secrets::default_store()),
        }
    }

    /// This host over another secret store — the memory store for a consumer
    /// that must leave no trace, a test's own (LLP 0069 §3).
    pub fn with_secret_store(mut self, store: Box<dyn SecretStore>) -> Self {
        self.secrets = Arc::from(store);
        self
    }

    /// Endow a consumer with `grants`: the bindings a module receives as
    /// parameters, each carrying this grant set for its whole life.
    pub fn endow(&self, grants: GrantSet) -> Bindings {
        let grants = Arc::new(grants);
        Bindings {
            fetch: Fetch {
                transport: Arc::clone(&self.transport),
                grants: Arc::clone(&grants),
            },
            fs: Fs {
                grants: Arc::clone(&grants),
            },
            secrets: Secrets {
                store: Arc::clone(&self.secrets),
                grants: Arc::clone(&grants),
            },
            env: Env { grants },
        }
    }
}

impl Default for Host {
    fn default() -> Self {
        Self::new()
    }
}

/// What a consumer holds: `fetch`, `fs`, `secrets`, and `process.env`, as a
/// module has them, over one grant set.
pub struct Bindings {
    pub fetch: Fetch,
    pub fs: Fs,
    pub secrets: Secrets,
    pub env: Env,
}

/// The secrets a consumer keeps across launches, carrying their grant
/// (`secret.keep <name>`, LLP 0069). Every call admits the name first; a
/// denial never reaches the platform's store.
#[derive(Clone)]
pub struct Secrets {
    store: Arc<dyn SecretStore>,
    grants: Arc<GrantSet>,
}

impl Secrets {
    fn admit(&self, name: &str) -> Result<(), HostError> {
        crate::boundary::admit(
            &self.grants,
            &Operation::SecretKeep {
                name: name.to_string(),
            },
        )
    }

    /// The names this binding may keep, in a stable order — what a host
    /// reads into a snapshot before its consumer boots.
    pub fn names(&self) -> Vec<&str> {
        self.grants.kept_secrets()
    }

    /// The kept value under `name`; `None` when nothing is kept.
    pub fn get(&self, name: &str) -> Result<Option<String>, HostError> {
        self.admit(name)?;
        self.store.get(name)
    }

    /// Keep `value` under `name`, replacing what was there.
    pub fn set(&self, name: &str, value: &str) -> Result<(), HostError> {
        self.admit(name)?;
        self.store.set(name, value)
    }

    /// Forget `name`; forgetting what was never kept is not an error.
    pub fn forget(&self, name: &str) -> Result<(), HostError> {
        self.admit(name)?;
        self.store.forget(name)
    }
}

/// `fetch`, carrying its grant. Rust owns redirects, header folding, and the
/// error taxonomy; the platform owns the connection.
#[derive(Clone)]
pub struct Fetch {
    transport: Arc<dyn Transport>,
    grants: Arc<GrantSet>,
}

impl Fetch {
    pub fn send(&self, request: Request) -> Result<Response, HostError> {
        fetch::fetch(self.transport.as_ref(), &self.grants, request)
    }

    pub fn get(&self, url: &str) -> Result<Response, HostError> {
        self.send(Request::get(url))
    }
}

/// `fs`, carrying its grant. Paths are absolute, normalized lexically and
/// checked as spelt and as the filesystem will really resolve them
/// (LLP 0067 §3); a two-path operation needs read on the source and write on
/// the destination.
#[derive(Clone)]
pub struct Fs {
    grants: Arc<GrantSet>,
}

impl Fs {
    fn run(
        &self,
        op: FsOp,
        path: &str,
        destination: Option<&str>,
        data: Option<&[u8]>,
    ) -> Result<FsResult, HostError> {
        let path = fs::normalize(path)?;
        let destination = match destination {
            Some(destination) => Some(fs::normalize(destination)?),
            None => None,
        };
        fs::admit(&self.grants, op, &path, destination.as_deref())?;
        fs::perform(op, &path, destination.as_deref(), data)
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, HostError> {
        match self.run(FsOp::ReadFile, path, None, None)? {
            FsResult::Bytes(bytes) => Ok(bytes),
            FsResult::Text(text) => Ok(text.into_bytes()),
            other => Err(unexpected(other)),
        }
    }

    pub fn write_file(&self, path: &str, data: &[u8]) -> Result<(), HostError> {
        self.run(FsOp::WriteFile, path, None, Some(data))
            .map(|_| ())
    }

    pub fn append_file(&self, path: &str, data: &[u8]) -> Result<(), HostError> {
        self.run(FsOp::AppendFile, path, None, Some(data))
            .map(|_| ())
    }

    pub fn read_dir(&self, path: &str) -> Result<Vec<String>, HostError> {
        match self.run(FsOp::ReadDir, path, None, None)? {
            FsResult::Names(names) => Ok(names),
            other => Err(unexpected(other)),
        }
    }

    pub fn mkdir(&self, path: &str) -> Result<(), HostError> {
        self.run(FsOp::Mkdir, path, None, None).map(|_| ())
    }

    pub fn remove(&self, path: &str) -> Result<(), HostError> {
        self.run(FsOp::Remove, path, None, None).map(|_| ())
    }

    pub fn stat(&self, path: &str) -> Result<Stat, HostError> {
        match self.run(FsOp::Stat, path, None, None)? {
            FsResult::Stat(stat) => Ok(stat),
            other => Err(unexpected(other)),
        }
    }

    pub fn rename(&self, from: &str, to: &str) -> Result<(), HostError> {
        self.run(FsOp::Rename, from, Some(to), None).map(|_| ())
    }

    pub fn copy_file(&self, from: &str, to: &str) -> Result<(), HostError> {
        self.run(FsOp::CopyFile, from, Some(to), None).map(|_| ())
    }

    pub fn realpath(&self, path: &str) -> Result<String, HostError> {
        match self.run(FsOp::Realpath, path, None, None)? {
            FsResult::Text(text) => Ok(text),
            FsResult::Bytes(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
            other => Err(unexpected(other)),
        }
    }
}

fn unexpected(result: FsResult) -> HostError {
    HostError::Failed(format!("unexpected filesystem result: {result:?}"))
}

/// `process.env`, carrying its grant: a snapshot of exactly the variables the
/// grant names. An ungranted variable is absent — not refused, absent — which
/// is the whole capability model in one object (LLP 0059.000 §3.8).
#[derive(Clone)]
pub struct Env {
    grants: Arc<GrantSet>,
}

impl Env {
    pub fn get(&self, name: &str) -> Option<String> {
        if !self.grants.readable_env().contains(&name) {
            return None;
        }
        std::env::var(name).ok()
    }

    pub fn snapshot(&self) -> BTreeMap<String, String> {
        self.grants
            .readable_env()
            .into_iter()
            .filter_map(|name| {
                std::env::var(name)
                    .ok()
                    .map(|value| (name.to_string(), value))
            })
            .collect()
    }
}

#[cfg(test)]
mod secrets_tests {
    use super::*;
    use crate::secrets::MemoryStore;
    use crate::stdlib::fetch::Transport;

    /// A transport that is never reached.
    struct NoTransport;
    impl Transport for NoTransport {
        fn send(&self, _request: &Request) -> Result<crate::stdlib::fetch::Response, HostError> {
            Err(HostError::Failed("no transport in this test".into()))
        }
    }

    fn host() -> Host {
        Host::with_transport(Box::new(NoTransport)).with_secret_store(Box::new(MemoryStore::new()))
    }

    #[test]
    fn a_granted_secret_is_kept_read_and_forgotten() {
        let app = host().endow(GrantSet::parse("secret.keep castle.session\n").unwrap());
        assert_eq!(app.secrets.names(), vec!["castle.session"]);
        assert_eq!(app.secrets.get("castle.session").unwrap(), None);
        app.secrets.set("castle.session", "t0k").unwrap();
        assert_eq!(
            app.secrets.get("castle.session").unwrap().as_deref(),
            Some("t0k")
        );
        app.secrets.forget("castle.session").unwrap();
        assert_eq!(app.secrets.get("castle.session").unwrap(), None);
    }

    #[test]
    fn an_ungranted_secret_is_denied_before_any_store_is_asked() {
        let store = Box::new(MemoryStore::with([("other".to_string(), "v".to_string())]));
        let app = host()
            .with_secret_store(store)
            .endow(GrantSet::parse("secret.keep castle.session\n").unwrap());
        for result in [
            app.secrets.get("other").map(|_| ()),
            app.secrets.set("other", "x"),
            app.secrets.forget("other"),
        ] {
            assert_eq!(
                result,
                Err(HostError::Denied {
                    capability: "secret.keep"
                })
            );
        }
        // Two consumers over one host share the store but not the authority.
        let other = host().endow(GrantSet::none());
        assert!(other.secrets.names().is_empty());
        assert!(other.secrets.get("castle.session").is_err());
    }
}
