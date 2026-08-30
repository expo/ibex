# LLP 0070: KV — a fifth binding, and the `storage.kv` grant

**Type:** Spec
**Status:** Draft
**Systems:** Rust Stdlib, CapSec, Host ABI, Platform
**Author:** Claude (Fable 5) for Charlie Cheever
**Date:** 2026-08-30
**Revised:** 2026-08-30 (after the Grok 4.6 / Codex review, same day: keys spelt in lowercase base32 rather than base64url and the shared name grammar lowercased and bounded — a case-insensitive filesystem folds mixed-case spellings into one file, so exact grants and distinct keys were not exact on default APFS; symlinks refused as scopes and keys; directory entries synced; no temp-directory fallback; scope and key grammar enforced in the binding so a consumer's store never sees what the family refuses; review artifacts under `llp/reviews/0070-*`)
**Related:** LLP 0067 (§2 the families, §3 the check, §8 "a family is added with a measured call site and a test, never ahead of one" — here the author named it, 2026-08-30), LLP 0068 (`Host`, `endow`, `Bindings`; §2 synchronous by design; §4 Exact 2), LLP 0069 (the fourth binding this one is shaped after, and what a *secret* is that this is not), LLP 0059.000 §3.7 and §4 (`storage.local` — the JS surface this will back, still waiting for its call site), exact2 LLP 1018 (durable client state — the program; its D6, secrets, was the first slice and this is the rest)

## Summary

Exact 2's durable client state (exact2 LLP 1018) is more than its session
token: a cursor, a cache of settled data, a preference — state that survives
a launch and that a plan or a log *may* show. LLP 0069 deliberately refused
to hold it ("not a cache; not a database; not a place for anything a plan or
a log may show"), and no other family fits: `fs.write` grants a filesystem
subtree when what the consumer means is "my own state," and `env.read` is a
snapshot. This document adds the family and the binding, in the shape 0067,
0068, and 0069 already have:

```text
storage.kv castle.state          # may this scope be read, written, listed?
```

```rust
let app = host.endow(GrantSet::parse("storage.kv castle.state\n")?);
app.kv.set("castle.state", "cursor", b"42")?;          // bytes under a key
app.kv.get_text("castle.state", "rooms")?;             // Ok(None) until kept; Err(Denied) for an ungranted scope
app.kv.keys("castle.state")?;                          // every key, stable order
app.kv.delete("castle.state", "cursor")?;              // deleting the absent is not an error
```

`Kv` is the fifth field of `Bindings`, beside `fetch`, `fs`, `secrets`, and
`env`, and carries the grant set like the others. Behind it is one trait,
`KvStore`, with a **file per key** under the platform's app-state directory —
`~/Library/Application Support/<app>/kv/<scope>/` on Apple platforms,
`$XDG_DATA_HOME/<app>/kv/<scope>/` elsewhere — and a **memory store** for
tests and for consumers that must leave no trace. Synchronous, as 0068 §2
says every binding is.

## 1. The family

| family | grant | the question |
|---|---|---|
| `storage.kv` | scope | may this scope be read, written, listed, and deleted from? |

**The grant is the scope, and keys are free within it.** This is the fork
0069 §1 resolved the other way, and the reason differs with the content: a
secret is a *name* the consumer and the manifest both know in advance, so a
per-name grant is writable; kv keys are *data* — an args-key from a settled
request (exact2 LLP 1016 keys its re-requests by arguments), a cursor per
collection — unknowable at manifest-writing time. A per-key grant grammar
here would be unwritable the same way per-file grants were before package
prefixes (LLP 0065 OQ2), and the eventual workaround — a wildcard — is how a
per-name grant becomes an all-names grant. So the scope is the unit of
authority, granted exactly, one per line, no prefixes.

One grant covers read, write, delete, and list, as `secret.keep` covers its
three operations: kept state is the consumer's own, and no case named a
read-only scope. (A second consumer reading the first's scope is a handoff
of the binding, LLP 0067 §3 — not a grant shape.)

A scope name shares the secret-name grammar — `[a-z0-9._-]{1,64}`, and never
only dots — deliberately one rule for every name that becomes a path
component. Lowercase is what makes an exact grant exact on every filesystem:
default APFS is case-insensitive, so `castle.state` and `Castle.state` would
be two honest grants over one directory. Bounded, because a filesystem
bounds its components. (Adopting the shared rule surfaced that the 0069
grammar accepted `.`, `..`, unbounded length, and case variants; it no
longer does, for either family.)

A **key** is any UTF-8, 1–128 bytes. The bound is the file backend's name
budget — a key is stored under its base32 spelling, 205 characters at most,
which must fit a 255-byte filename on every filesystem — and it is a v1 rule
rather than a tunable: a consumer with longer keys hashes them itself and
owns the collision story. The grammar and the bound are enforced in the
binding, before the store, so a consumer-supplied `KvStore` never sees a
scope or key the family refuses. **Values are bytes** (`get_text`/`set_text` are
conveniences over them, an error when what is kept is not UTF-8): durable
state is serialized plan state as often as it is JSON, and a byte store
under a text store is the wrong layering.

## 2. The binding and the check

`boundary::admit` gains `Operation::StorageKv { scope }` and
`capability_name` answers `"storage.kv"`; `grant.rs` gains
`Grant::StorageKv(String)`, the `admits` arm (exact equality, cross-kind
false as ever — the same string granted as `secret.keep` admits no kv
operation), the `parse` arm, and `GrantSet::kv_scopes()`. Every `Kv` method
admits the scope first and only then touches the store, so a denial never
reaches the platform and carries no detail (0067 §3).

`KvStore` is the platform half:

```rust
pub trait KvStore: Send + Sync {
    fn get(&self, scope: &str, key: &str) -> Result<Option<Vec<u8>>, HostError>;
    fn set(&self, scope: &str, key: &str, value: &[u8]) -> Result<(), HostError>;
    fn delete(&self, scope: &str, key: &str) -> Result<(), HostError>;
    fn keys(&self, scope: &str) -> Result<Vec<String>, HostError>;
}
```

`Host::new()` picks the platform store; `Host::with_kv_store(Box<dyn
KvStore>)` replaces it.

## 3. The backends

- **A file per key** (`kv.rs::FileStore`) under `<base>/<app>/kv/<scope>/`,
  where `<base>` is `~/Library/Application Support` on Apple platforms and
  `$XDG_DATA_HOME` (`~/.local/share` when unset) elsewhere, and `<app>` is
  [LLP 0069 §3]'s app identity. The key is spelt in **lowercase base32**
  (RFC 4648 alphabet, no padding) — the one spelling that is a safe filename
  everywhere *including case-insensitive filesystems*, where a mixed-case
  encoding would fold two keys into one file, and that decodes back to
  exactly the key for `keys()` — so a key can never spell a path. Only the
  **canonical** spelling of an acceptable key is a key: `keys()` refuses a
  name whose trailing bits are set or whose decoding `get` would refuse, so
  filenames and keys stay one-to-one and a foreign file can neither shadow
  nor duplicate one. Only a **regular file** is a key, and a symlink is
  followed nowhere — not as a key (`get` refuses it) and not as a scope
  directory (every operation refuses) — so a planted link cannot turn a kv
  grant into a read or write of wherever it points. Files are `0600` in
  `0700` directories; each write goes whole to a temporary created fresh
  (`create_new`, a name unique to the call), is synced, renamed into place,
  and the directory entry is synced best-effort behind it — so a torn value
  is never renamed in and a crash after `set` returns keeps what was set,
  where the platform allows a directory sync. The same posture as the
  secrets `FileStore`, *without the claim* — owner-only is hygiene here, not
  protection, and nothing in a kv scope may need protection (§4). No
  Keychain and no platform credential store on any platform: that is the
  difference between this binding and 0069, not an implementation shortcut.
- **Memory** (`MemoryStore`): a map behind a mutex. Tests, and a consumer
  that must leave no trace.

When no durable base directory can be derived — no absolute `HOME`, no
`XDG_DATA_HOME` — the default store **refuses every operation** rather than
landing "durable" state in a temp directory a reboot may clear and another
user may own. A consumer that wants another directory constructs the store
itself (`FileStore::new(dir)`).

## 4. What it is not

Not secrets: anything that may not appear in a plan or a log stays behind
`secret.keep`, and the two families do not admit each other's operations
even for the same name. Not `fs`: a consumer with a kv grant can name no
path, and the store's directory layout is this document's, not API. Not a
database: no queries, no transactions across keys, no watch — the moment
state needs those it is a data source (exact2 LLP 1004 D4) or SQLite behind
its own grant (LLP 0059.000 §3.15), not a bigger kv. Not `localStorage`
yet: 0059.000 §3.7 still waits for a JavaScript call site, and when one
arrives it binds over a kv scope rather than a second store — one store,
one grant family. Not asynchronous (0068 OQ3 holds). And no `clear` or
delete-scope in v1: keys are deleted one by one, and an emptied scope
directory is left behind — named here so its absence is a decision, not an
oversight.

## 5. Tests

`grant.rs`: `storage.kv` parses, admits its exact scope and nothing else in
either prefix direction; cross-kind isolation is witnessed from
**single-family** sets in both directions (a combined set would admit both
operations and prove nothing); `.`/`..`/`...`/case-variant/prefix forms are
refused at parse. `host.rs`: a `Bindings` reads, writes, lists, and deletes
a granted scope; denial is proven with a store that panics on any touch, so
the test fails if admission ever moves after dispatch; an ungranted scope
is `Denied` even when ill-formed (the denial reveals nothing), while a
granted scope with a refused key is invalid before the store sees it; two
consumers endowed from **one** host share the store and not the authority;
an empty value is kept, not missing; non-UTF-8 bytes are an error as text
rather than a value. `kv.rs`: keys with slashes, dots, spaces, and unicode
round-trip through their filename spelling, against fixed vectors so the
encoding cannot drift; non-canonical, case-variant, impossible-length, and
empty names are not keys; the file store round-trips with `0600`/`0700` and
leaves no temporary behind; eight concurrent writers over one key never
leave a torn value or a temporary; a symlink is refused as a key and as a
scope; a refused scope or key creates nothing; listing an absent scope is
empty and foreign files — wrong alphabet, dotted, directories — are not
keys; the unavailable store refuses everything.
`cargo test -p ibex2 --no-default-features` runs them all — the consumer's
build shape (0068 OQ1).

## 6. Open questions

**OQ1 — Size.** No per-value or per-scope quota. The first consumer whose
scope grows past "obviously fine" names the number, and it becomes a
refusal at `set`, not a background eviction — an eviction policy is a cache,
and §4 says this is not one.

**OQ2 — Atomic read-modify-write.** Concurrent `set`s are already safe as
writes — each is a whole value renamed into place, so the last writer wins
and no reader ever sees a torn one (§3). What is not atomic is `get` then
`set`, and that races only with the consumer itself (one process owns a
scope in every named case). If a second process ever shares a scope, the
honest primitive is compare-and-set on the store trait; nothing is reserved
for it now.
