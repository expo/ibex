# LLP 0069: Secrets — a fourth binding, and the `secret.keep` grant

**Type:** Spec
**Status:** Draft
**Systems:** Rust Stdlib, CapSec, Host ABI, Platform
**Author:** Claude (Fable 5) for Charlie Cheever
**Date:** 2026-08-30
**Revised:** 2026-08-30 (§1: the name grammar tightened to `[a-z0-9._-]{1,64}`, never only dots — LLP 0070 adopted one rule for names that become path components, and its review found the original grammar admitted `.`, `..`, unbounded length, and case variants a case-insensitive filesystem folds into one file)
**Related:** LLP 0067 (§2 the families, §3 the check, §8 "a family is added with a measured call site and a test, never ahead of one"), LLP 0068 (`Host`, `endow`, `Bindings`; §2 synchronous by design; §4 Exact 2), LLP 0059.000 §4 (`storage.local` — a different thing, see §4 below), LLP 0057 §3 (Rust owns semantics, the platform owns the mechanism), exact2 LLP 1018 (the call site: a session token that survives a launch, read before the first frame), `rules/NOT-DOING.md` (the bar: a no-JS consumer gets the same standard library)

## Summary

Exact 2's first request (exact2 LLP 1016) returns a bearer token, and the app
must keep it across launches. That is a *secret* — small, per-app, encrypted at
rest where the platform can, never in a plan or a log — and no family in
LLP 0067 §2 covers it: `fs.write` would put it in a plain file, `env.read` is
a snapshot of the process environment, and `storage.local` (0059.000 §4) is a
web-shaped preference store. This document adds the family and the binding,
in the shape 0067 and 0068 already have:

```text
secret.keep castle.session          # may this name be read, replaced, and forgotten?
```

```rust
let app = host.endow(GrantSet::parse("net.fetch https://api.castle.xyz\nsecret.keep castle.session\n")?);
app.secrets.names();                                   // ["castle.session"] — the load list
app.secrets.get("castle.session")?;                    // Ok(None) until kept; Err(Denied) for an ungranted name
app.secrets.set("castle.session", r#"{"token":"…"}"#)?;
app.secrets.forget("castle.session")?;
```

`Secrets` is the fourth field of `Bindings`, beside `fetch`, `fs`, and `env`
(and, since LLP 0070, `kv`), and carries the grant set like the others. Behind it is one trait,
`SecretStore`, with the platform's credential store: the **Keychain** on
Apple platforms (through an Objective-C++ shim beside the `NSURLSession`
one), a **`0600` file per secret** under `$XDG_DATA_HOME/<app>/secrets/`
elsewhere, and a **memory store** for tests and for consumers that must never
touch a real one (Exact's agent mode). Synchronous, as 0068 §2 says every
binding is: a Keychain read is bounded and local, and the consumer that needs
it needs it *before its first frame*.

## 1. The family

| family | grant | the question |
|---|---|---|
| `secret.keep` | name | may this secret be read, replaced, and forgotten? |

One grant, three operations. `fs` splits read from write because reading a
file and writing it are different authorities held by different modules; a
secret the consumer *keeps* is its own — a consumer that may read the token
may replace it on the next login and forget it on logout, and no case named a
read-only secret. Names are exact matches, one per line, as `env.read` is: no
prefixes, because a prefix grammar is where a per-name grant becomes an
all-names grant. A name is `[a-z0-9._-]{1,64}` and never only dots; anything
else is refused at parse. Lowercase and bounded because a name becomes a path
component (LLP 0070 §1 states the shared rule and the case-insensitive
filesystem that forces it).

The grant is also the **load list**: `Secrets::names()` is what a host reads
into a snapshot before its consumer boots (exact2 LLP 1018 D3), so an
ungranted secret is absent rather than refused — `process.env`'s rule
(0059.000 §3.8) one more time.

## 2. The binding and the check

`boundary::admit` gains `Operation::SecretKeep { name }` and
`capability_name` answers `"secret.keep"`; `grant.rs` gains
`Grant::SecretKeep(String)`, the `admits` arm (exact equality, cross-kind
false as ever), the `parse` arm, and `GrantSet::kept_secrets()`. Every
`Secrets` method admits first and only then touches the store, so a denial
never reaches the platform and carries no detail about what would have been
admitted (0067 §3).

`SecretStore` is the platform half:

```rust
pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<String>, HostError>;
    fn set(&self, name: &str, value: &str) -> Result<(), HostError>;
    fn forget(&self, name: &str) -> Result<(), HostError>;
}
```

Values are UTF-8 strings: a consumer that keeps a record keeps it as JSON, as
the web's `localStorage` would. `Host::new()` picks the platform store;
`Host::with_secret_store(Box<dyn SecretStore>)` replaces it — the memory
store, or a test's.

## 3. The backends

- **Apple — the Keychain** (`secrets/darwin.rs`, `engine/darwin_keychain.mm`,
  linking `Security.framework`). Generic-password items, `kSecAttrService` =
  the app's identity, `kSecAttrAccount` = the name. `set` is `SecItemUpdate`
  then `SecItemAdd` on `errSecItemNotFound`; `forget` treats
  `errSecItemNotFound` as done. On iOS the item is
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: readable after the
  first unlock (a background fetch can use it), never restored to another
  device from a backup. On macOS the item goes to the **login keychain** —
  `kSecUseDataProtectionKeychain` is deliberately not set, because the
  data-protection keychain needs an application-identifier entitlement, which
  on macOS means a bundle and a provisioning profile; the login keychain
  works for a bare signed binary, and its ACL trusts the app that created
  the item by its code signature's designated requirement. That last fact is
  the consumer's to respect: an ad-hoc-signed binary has a per-build
  requirement and is asked again after every rebuild; a binary signed with a
  team identity is not (exact2 LLP 1018 D7).
- **Elsewhere — a file per secret** (`secrets/mod.rs::FileStore`) under
  `$XDG_DATA_HOME/<app>/secrets/<name>` (`~/.local/share` when unset), created
  `0600` in a `0700` directory, written whole to a temporary file and renamed
  into place. Not encrypted: the platform's own secret service (libsecret,
  the Windows credential vault) arrives with a consumer that runs there and
  needs it, as a second `SecretStore`, not a second binding.
- **Memory** (`MemoryStore`): a map behind a mutex. Tests; and the store a
  consumer selects when it must leave no trace — a scripted drive against
  real credentials must not write a developer's keychain.

**The app's identity** — the Keychain service, the XDG directory — is what
the platform knows the process as: the main bundle's identifier on Apple
platforms, the executable's file name when there is no bundle, and elsewhere
the executable's file name. A consumer that wants another name constructs the
store itself (`KeychainStore::new(service)`, `FileStore::new(dir)`).

## 4. What it is not

Not `storage.local` (0059.000 §4): that is a preference store for web-shaped
modules — plain, larger, no encryption expectation — and it still waits for
its call site. Not a cache; not a database; not a place for anything a plan
or a log may show. Not asynchronous (0068 OQ3 holds: if every consumer wraps
these in the same future type, that type comes here, not before). Not a
manifest section yet — the grant line is its seed (0068 §4).

## 5. Tests

`grant.rs`: `secret.keep` parses, admits its exact name and nothing else, and
crosses no kind. `host.rs`: a `Bindings` over a memory store gets, sets, and
forgets a granted name, is denied an ungranted one, and lists exactly the
granted names. `secrets/mod.rs`: the file store round-trips under a
temporary directory with `0600` on the file, refuses a bad name, and
forgetting an absent name is not an error. `secrets/darwin.rs` (Apple, in the
test binary's own process, a unique name per run so no other build's item is
ever touched): the Keychain round-trips, `get` after `forget` is `None`.
`cargo test -p ibex2 --no-default-features` runs them all — the consumer's
build shape (0068 OQ1).

## 6. Open questions

**OQ1 — Deletion on iOS.** Keychain items outlive the app. A consumer that
wants "delete the app = sign out" wipes its names on first launch, keyed by a
marker in a directory the platform deletes with the app. Whether that is the
consumer's job or a `SecretStore` option is decided by the second consumer
who wants it.

**OQ2 — The data-protection keychain on macOS.** Strictly better (no ACL
prompt, ever; per-app by entitlement), and it needs a bundle with a
provisioning profile. When a consumer ships a macOS bundle, a store option
selects it.
