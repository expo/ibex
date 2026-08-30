# Review of LLP 0070 (KV — a fifth binding) and its implementation — xAI Grok family

**Reviewer family:** xAI Grok
**Provider / runtime:** grok 1.0.13 (5e9a58528b76) / `grok-4.6`
**Date:** 2026-08-30
**Target:** the uncommitted kv change in the working tree — `crates/ibex2/src/{kv.rs,grant.rs,boundary.rs,host.rs,secrets/mod.rs,lib.rs}`, `llp/0070` — judged against LLP 0067/0068/0069
**Method:** Headless single-turn CLI session (`grok -p`), read-only by instruction, over a packet snapshot plus the live sources (the reviewer noticed the tree had moved past the packet and reviewed the working tree)
**Scope:** Adversarial review. Priorities given: grant correctness, path safety of the hand-rolled key encoding, atomicity, spec-vs-code conformance, tests that cannot fail their claims.

## Disposition

The reviewer's verdict on the reviewed revision was **NOT READY**, on the key-identity
finding. Every finding was addressed the same day; the fixes and the stronger
tests are in the landed revision, and the reviewer's concrete probes are tests now.

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | HIGH | base64url filenames collide on case-insensitive APFS — distinct keys, one file | **Fixed** — keys spelt in lowercase base32 (RFC 4648, no padding); fixed vectors and a single-case assertion pin the encoding |
| 2 | MEDIUM | Scope names are unencoded path components: case-variant grants share a directory | **Fixed** — the shared name grammar is now `[a-z0-9._-]{1,64}`; a case-variant grant is refused at parse (LLP 0069 revised to match) |
| 3 | MEDIUM | Missing `HOME`/`XDG` silently lands durable state in a world-writable temp dir | **Fixed** — `for_app` returns `Option`; the default store with no durable base refuses every operation (`UnavailableStore`) |
| 4 | MEDIUM | The cross-kind test admits both operations and cannot witness isolation | **Fixed** — single-family sets in both directions, plus `fs.write` ↛ `storage.kv` |
| 5 | MEDIUM | Spec corpus disagreement: 0067 still said three families; 0068 still said `Bindings { fetch, fs, env }`; 0069's grammar unrevised; `llp/current` missing 0070 | **Fixed** — 0067 §2/§8 revised (five families; author-required call sites), 0068 and 0069 revised with the reason, 0070 linked into `llp/current` |
| 6 | MEDIUM | The 1–128-byte key rule enforced only inside the stock stores | **Fixed** — `host::Kv` validates scope and key after admission, before any store |
| 7 | LOW | "Two consumers share the store" test built two hosts; denial proven only by the returned error | **Fixed** — one host endowed twice (kv and the same hole in the secrets test), and a store that panics on any touch proves denial precedes dispatch |
| 8 | LOW | `keys()` lists a planted directory under a canonical name | **Fixed** — only regular files are keys; tested |
| 9 | LOW | Tmp path is `open`+`truncate`, plantable as a symlink | **Fixed** — `create_new` (O_EXCL, refuses to follow) with a per-call unique name (pid + nanos + counter), cleanup on every error path |
| 10 | LOW | Directory entry never fsynced; a crash after rename can drop the write | **Fixed** — best-effort directory sync after create/rename/delete; the contract stated in 0070 §3 |
| 11 | LOW | Apple `HOME` not checked for absoluteness (XDG is) | **Fixed** — both branches filter for an absolute base |
| 12 | NIT | `Host` doc comments deny kv's existence | **Fixed** |
| 13 | NIT | API shape notes: per-call scope strings vs a handle; `set_text` undocumented; empty-value untested; `storage.local` relation; no `clear` | **Partly fixed** — rustdoc and the empty-value test added; `storage.local`-binds-over-a-scope and no-`clear` are stated in 0070 §4; a scope handle is declined for v1 (parity with `secrets`; a handle can arrive with the first consumer that wants one) |
| 14 | NIT | Parse coverage missing `.`/`...`/case/prefix-direction refusals | **Fixed** |

Acknowledged, not fixed: a scope named `con`/`nul` is grammar-valid and reserved
on Windows. The file store's platform claims are Apple + XDG; Windows remains
compatibility-only, and the store trait is where a Windows backend would decide.
The reviewer's secrets-parity notes (temp-dir fallback, `create_new`, symlink
read, dir sync) are deliberately not swept into this change:
`issues/20260830-secrets-filestore-kv-parity.md` carries them.

## The review as written

I'll start with the review packet and the governing LLP docs, then statically check grant correctness, path safety, and spec-vs-code.The packet is large; I'll pull the rest of it plus the sibling secrets store and grant-check code for comparison.I'll now read the real grant, host, secrets, and boundary sources plus LLPs 0067–0070 so I can compare claims against the code.I’ll verify the base64url codec against RFC 4648 and hunt for case-insensitive filename collisions on Apple volumes.The on-disk `kv.rs` may have moved since the packet was captured — I’ll re-read it and compare with the packet so the review targets the right code.Reviewed the packet against the live sources it maps to (`crates/ibex2/src/kv.rs`, `grant.rs`, `host.rs`, `boundary.rs`, `secrets/mod.rs`, `llp/0070`). Two packet-era bugs (pid-only tmp, non-canonical decode) are already fixed in cwd; findings below are against **cwd**.

## Findings

1. **HIGH — base64url filenames collide on the Apple volume this store is for.**  
   `encode_key` is RFC 4648 base64url (canonical, verified against Python’s `urlsafe_b64encode`). That alphabet is **case-sensitive**. Default macOS APFS is **case-insensitive** (this crate already treats that as load-bearing: `crates/ibex2/tests/resolution.rs` around the `LOCKED.js` / `locked.js` case). Distinct keys whose encodings differ only by case are one file.

   Concrete pair (printable ASCII):
   - `"aaa"` → `YWFh`
   - `"aaG"` → `YWFH`
   - both case-fold to `ywfh`

   Reproduction on macOS:
   ```rust
   store.set("state", "aaa", b"one")?;
   store.set("state", "aaG", b"two")?;
   // get("aaa") and get("aaG") both read the same dirent
   // keys() typically returns only the first-created spelling
   ```
   Density is not exotic: thousands of 3-byte UTF-8 pairs collide the same way. `MemoryStore` keeps them distinct, so host tests on a memory store cannot fail this. Linux CI cannot either. `Host::new()` on Apple uses this FileStore (`kv.rs` `for_app`, lines 155–166).  
   Spec §3 still says base64url is “the one spelling that is a safe filename **everywhere**” — that claim is false on the primary backend.  
   Fix: a case-insensitive encoding (lowercase base32 fits 128-byte keys in 205 chars; lowercase hex does **not** fit 128 bytes in 255). Add a test that encodings are unique under ASCII case-fold, and a FileStore round-trip of `aaa`/`aaG`.

2. **MEDIUM — scope names are unencoded path components, so grant isolation is case-blind on APFS.**  
   ```169:172:crates/ibex2/src/kv.rs
   fn scope_dir(&self, scope: &str) -> Result<PathBuf, HostError> {
       check_scope(scope)?;
       Ok(self.dir.join(scope))
   }
   ```
   `storage.kv castle.state` and `storage.kv Castle.state` are different grants (`granted == scope` in `grant.rs:143`) but `…/kv/castle.state` and `…/kv/Castle.state` are the same directory on default APFS. Two bindings, each honestly granted a distinct scope, share durable state. Same class of bug as (1), at the grant boundary rather than the key. Restrict the grammar to lowercase, or encode the scope with the same case-safe codec as keys.

3. **MEDIUM — `HOME`/`XDG` missing silently stores durable state under `std::env::temp_dir()`.**  
   ```155:166:crates/ibex2/src/kv.rs
   .unwrap_or_else(std::env::temp_dir);
   ```
   Spec §3 names Application Support / XDG only. Unlike secrets (Keychain on Apple), **kv’s Apple default is this file store**. If `HOME` is unset, the path is `/tmp/<app>/kv/…`. `/tmp` is world-writable (sticky). Another local user who pre-creates `/tmp/<app>` owns the tree the victim then writes into (or plants symlinks under). Fail closed — return an error — instead of falling back to a shared temp directory. (Secrets has the same fallback off-Apple; kv inherits it onto Apple.)

4. **MEDIUM — the test named “crosses no kind” does not test `secret.keep` ↛ `storage.kv`.**  
   ```467:487:crates/ibex2/src/grant.rs
   fn storage_kv_is_per_scope_and_crosses_no_kind() {
       let set = GrantSet::parse("storage.kv castle.state\nsecret.keep castle.state\n")...
       let kv_only = GrantSet::parse("storage.kv castle.state\n").unwrap();
       assert!(!kv_only.permits(&Operation::SecretKeep { name: "castle.state".into() }));
   ```
   The combined set admits **both** operations, so it cannot witness isolation. The only cross-kind assert is kv-grant ↛ secret-op. A mistaken extra arm `(Grant::SecretKeep(g), Operation::StorageKv { scope }) if g == scope` would still pass. There is also no `fs.read`/`fs.write` ↛ `StorageKv` assert. The `admits` catch-all (`grant.rs:148`) makes the *code* fail-closed; the *test* cannot fail its claim. Add:
   ```rust
   let secret_only = GrantSet::parse("secret.keep castle.state\n").unwrap();
   assert!(!secret_only.permits(&Operation::StorageKv { scope: "castle.state".into() }));
   assert!(!GrantSet::parse("fs.write /tmp\n").unwrap()
       .permits(&Operation::StorageKv { scope: "tmp".into() }));
   ```

5. **MEDIUM — spec corpus disagrees with the new family.**  
   - LLP 0067 (Accepted) §2 still lists three families and says further families arrive only with a measured call site; 0070 Related waves this (“the author named it”) but does not patch 0067.  
   - LLP 0068 §1 still says `Bindings { fetch, fs, env }` and “the platform transport and nothing else.”  
   - LLP 0069 §1 still says a name is `[A-Za-z0-9._-]+` with no “never only dots”; this change *did* tighten `is_valid_name` (`secrets/mod.rs:42–48`) for both families. 0070 claims “it no longer does, for either family,” but 0069 was not revised.  
   - `llp/current/` still has 0069 and not 0070.  
   A later reader of the Accepted capability spec will not see `storage.kv`.

6. **MEDIUM — the 1–128-byte key rule is a family invariant enforced only inside the two stock stores.**  
   `Kv::get`/`set`/`delete` admit the **scope** then pass the key through (`host.rs:177–205`). `check_key` lives in `MemoryStore`/`FileStore` only. Spec §1 states the bound as a v1 rule, not a FileStore detail. A third `KvStore` (or a forgetful one that joins the raw key) never sees the grammar. Validate in `host::Kv` the same way `admit` is centralized, so denial/invalid never depend on the backend.

7. **LOW — “denied before any store is asked” / “two consumers share the store” is not what the host test does.**  
   ```472:475:crates/ibex2/src/host.rs
   // Two consumers over one host share the store but not the authority.
   let other = host().endow(GrantSet::none());
   ```
   `host()` builds a **new** `Host` and a **new** `MemoryStore`. `other` does not share the store. Denied-on-empty-grants is all that is asserted. The earlier loop against a pre-seeded store *does* prove ungranted `get` is not a hit (it would be `Ok(Some)` if admit were skipped). It does not prove `set`/`delete`/`keys` never touch the store; a panic-on-call store would. Copied from `secrets_tests` (same hole at `host.rs:399–402`).

8. **LOW — `keys()` treats any canonical encoding as a key, including directories.**  
   `keys()` (`kv.rs:291–311`) does not check `file_type()`. A planted directory whose name is `encode_key("x")` is listed; `get` then `Failed` (Is a directory) rather than `None`. Spec: foreign files are not keys. Filter to regular files, or document.

9. **LOW — `FileStore::set` still `open`+`truncate`s the tmp path (no `create_new` / `O_NOFOLLOW`).**  
   Tmp is now `.tmp.{pid}.{counter}` (`kv.rs:256–261`) — unique among live writers, matching secrets. The first write of a process is still `.tmp.{pid}.0`, which is plantable as a symlink in the 0700 scope dir. Same-UID only. Secrets has the same shape. Use `OpenOptions::create_new(true)` (and `O_NOFOLLOW` on Unix) so a planted name is `AlreadyExists`, not a truncate-through-symlink of some other file.

10. **LOW — durability of the directory entry is not claimed and not done.**  
    File contents are `sync_all`’d before `rename` (`kv.rs:272–274`). The parent directory is never fsynced. A crash after rename can drop the new dirent; readers then see the previous key or nothing. Same as secrets. Either fsync the scope dir after rename, or have OQ2 say crash-durability is not offered.

11. **LOW — `for_app` on Apple does not require `HOME` to be absolute; XDG does.**  
    Non-Apple: `.filter(|p| p.is_absolute())`. Apple: `Path::new(&h).join("Library/Application Support")` even if `HOME` is relative. Inconsistent; a relative `HOME` writes kv relative to cwd.

12. **NIT — `Host` comments still deny kv’s existence.**  
    ```29:40:crates/ibex2/src/host.rs
    /// The host: the platform's transport and its secret store, and nothing else.
    ...
    /// The platform's transport … and its secret store …
    ```
    The struct has `kv`. Spec §2 says `Host::new()` picks the platform kv store (true in `with_transport`).

13. **NIT — API shape before a consumer.**  
    - Every call repeats `scope: &str` instead of a handle from `scopes()`/`admit` once (`app.kv.scope("castle.state")?`). A typo is `Denied`, not a type error.  
    - `set_text` has no rustdoc; `get_text` does (`host.rs:182–200`).  
    - Empty value is `Some(b"")`, missing is `None` — correct, untested.  
    - `storage.kv` vs future JS `storage.local` (0059.000 §3.7) are two capability names for one store; worth one sentence in 0070 so the JS call site does not grow a second grant family.  
    - No `clear` / delete-scope; empty scope dirs are left behind. Fine for v1 if named.

14. **NIT — grant-parse coverage vs spec §5.**  
    Spec: “`.`/`..`/prefix forms are refused at parse.” The grant test hits `..` and `../x`, not `.` or `...` (those exist only at the store). `storage.kv castle` ↛ `castle.state` (no prefix) is also untested. Cheap to add.

## Checked and sound

- **Grant admission.** `Grant::StorageKv` admits by exact string equality; the `admits` match is exhaustive over kinds with `_ => false`. Parse refuses an invalid scope via `is_valid_scope` → `is_valid_name`. Empty spec / missing target / unknown capability fail closed.
- **Cross-family in code (not in tests).** Same string as `secret.keep` does not admit `StorageKv` unless a kv grant is also present. `fs.*` cannot admit it. `capability_name` → `"storage.kv"`; `Denied` carries no grant detail (`boundary.rs:132–151`).
- **Deny-then-touch.** Every `Kv` method (`get`/`get_text`/`set`/`set_text`/`delete`/`keys`) calls `admit` before the store (`host.rs:177–211`). Ungranted + bad key is `Denied`, not `InvalidArgument`.
- **Scope grammar as a path component.** `[A-Za-z0-9._-]+` and not only dots; `/`, `\\`, NUL, spaces, `..` as a name are refused at parse and again at the store. `GrantSet::with(StorageKv(".."))` still dies at `check_scope` before `join`. Keys never reach the filesystem unencoded.
- **Encoder.** Unpadded base64url matches the stdlib codec; 128-byte keys encode to 171 chars (≤ 255); encoded names never start with `.` (tmp / `.DS_Store` cannot collide with a key). `\`/`NUL`/slashes in keys are encoded away.
- **Decoder (cwd).** Trailing-bit aliases are rejected (`encode_key(key) == name` plus `check_key`); `aWQ` ↔ `"id"`, `aWR` → `None`; empty / over-long decodes are not keys. (Packet decoder lacked this; cwd has it.)
- **Tmp+rename (cwd).** `.tmp.{pid}.{counter}` with `AtomicU64`, `write_all` + `sync_all`, close, `rename`, unlink tmp on rename failure. Same-process writers no longer share a tmp. Cross-process live PIDs don’t collide. (Packet used `.tmp.{pid}` only; that *was* a HIGH; cwd matches secrets.)
- **Missing / delete-absent.** `NotFound` → `None` / `Ok(())`. `keys()` on a missing scope is `[]`. Unix `0600`/`0700` attempted (chmod errors ignored).
- **MemoryStore.** Mutex + `BTreeMap<(scope,key)>`; scopes stay apart; `keys()` order matches FileStore’s sort (UTF-8).
- **Windows reserved *key* encodings.** Canonical UTF-8 encodings of 1–3 byte keys are not `CON`/`PRN`/`AUX`/`NUL`/`COMn`/`LPTn` (checked). (A **scope** named `CON` is still a valid grant; see Windows as compatibility-only.)
- **Wiring.** `Operation`/`Grant`/`capability_name`/`Bindings.kv`/`Host::with_kv_store`/`pub mod kv` are consistent; `kv_scopes()` is BTree-stable.

## Verdict

**NOT READY** — default FileStore key identity is not one-to-one on Apple APFS, so two legal keys can be one file; that has to change before this API gets a consumer.
