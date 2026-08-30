# Round-2 review of LLP 0070 (KV) as landed in `6b86e3b21` — xAI Grok family

**Reviewer family:** xAI Grok
**Provider / runtime:** grok 1.0.13 (5e9a58528b76) / `grok-4.6`, reasoning effort `xhigh`
**Date:** 2026-08-30
**Target:** commit `6b86e3b21` — the reviewer noticed uncommitted follow-up edits appearing in the working tree mid-review (the codex round-2 fixes being applied) and deliberately pinned itself to the commit
**Method:** `grok -p … -m grok-4.6 --reasoning-effort xhigh`; static inspection, no edits, no builds
**Scope:** Verify round-1 dispositions against the landed code, then hunt fresh.

## Disposition

Verdict on the reviewed commit: **READY** — every round-1 disposition verified
present and none wrong; six LOW/NIT residuals. All six were addressed the same
day in the follow-up commit (several coincide with the codex round-2 findings,
which the working-tree edits it observed were already fixing).

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | LOW | Symlink refusal is check-then-act (lstat → `create_dir_all`/`read` windows), not `O_NOFOLLOW`; spec claimed "followed nowhere" | **Narrowed, root hardened** — the store root is checked too; 0070 §3 now scopes the same-user check-vs-use race out with the LLP 0062 §4 threat-model reason instead of overclaiming |
| 2 | LOW | After a catalog recase (`me` → `ME` by Finder/sync tooling), `keys()` hides the key while `get` still reads it | **Fixed** — the canonical-lookup change makes `get`/`delete` verify the stored spelling, so listing and lookup agree (absent both ways); `set` reclaims the slot. A recased dirent lingers as a foreign file until then — inside the accepted foreign-occupant residue |
| 3 | LOW | First-create ancestor directories never fsynced | **Fixed** — sync every created entry up to the first pre-existing ancestor |
| 4 | LOW | Error-path unlink deletes whatever holds the colliding tmp name | **Fixed** — bounded retry on `AlreadyExists`; cleanup only of what this call created |
| 5 | LOW | Spec drift: 0068 §3's whole-surface sentence; 0069's "fourth field beside fetch, fs, env" | **Fixed** — 0068 §3 names where each binding's tests live (and `tests/kv.rs` now exists); 0069's Summary names kv |
| 6 | NIT | `grant.rs` header still said "the four questions"; 0070's shadow/duplicate sentence overclaimed against the accepted canonical-foreign-file residue; `UnavailableStore` blamed unset variables when a relative `HOME` also lands there | **Fixed** — all three reworded |

## The review as written

I'll start by reading the review skill and the round-1 artifacts, then inspect commit `6b86e3b21` and the live files it touched.The review stays in this session: no file writes, no cargo. Next I’ll pull the reviewer persona, the round-1 artifacts, and the landed commit.I’ll pull the commit diff next and read the live sources, then check whether those files have drifted from `6b86e3b21`.HEAD is the commit and those files are clean. I’ll read the live sources and the reconciled LLPs next.Next I’ll check `app_identity`, the reconciled LLPs, and a few edge cases around the base32 codec and `create_dir_all` TOCTOU.The codec is RFC-correct for long keys. I’m checking one durability gap around ancestor directory sync, then I’ll write the round-2 report.The live `kv.rs` no longer matches the first read — another session may have edited it. I’ll pin the review to commit `6b86e3b21`, not the working tree.Review target is commit `6b86e3b21` (687-line `kv.rs` as committed). Uncommitted edits to `kv.rs` and `grant.rs` appeared in the working tree during this pass and were ignored.

## Round-1 dispositions verified

Every claimed fix in the Grok/Codex artifacts is present in `6b86e3b21` for the scenario round 1 actually demonstrated:

| Claimed fix | Landed? |
|---|---|
| Lowercase `[a-z0-9._-]{1,64}`, never only dots | Yes — `secrets::is_valid_name` (`secrets/mod.rs:45-52`); parse and store both use it |
| Lowercase canonical base32 keys | Yes — RFC 4648 alphabet `a-z2-7`, no pad; `encode_key("a") == "me"`; `decode_key` requires `check_key` and `encode_key(key) == name` |
| `create_new` + per-call tmp (`pid` + nanos + counter) + error-path unlink | Yes — `kv.rs:349-381` |
| Symlink refused as scope and as key (stable plant) | Yes — `scope_dir` lstat; `get` refuses non-regular; `keys` skips non-files; Unix test |
| Directory fsync after create/rename/delete | Yes — best-effort `sync_dir` of `self.dir` and the scope dir |
| No `temp_dir()` fallback; `for_app` → `Option`; `UnavailableStore` | Yes — both `HOME` branches require `is_absolute()` |
| Binding-level grammar after admit | Yes — `host.rs:168-180` |
| Panic-on-touch store; single-family cross-kind both ways + `fs.write`; case/`.`/`...`; empty value; concurrent writers | Yes |

No claimed fix is **wrong**. Residuals of the symlink, tmp-collision, and dir-sync fixes are below; they are not the round-1 bugs returning.

## Findings

1. **LOW** — Symlink refusal is check-then-act, not `O_NOFOLLOW`. Spec §3 says a symlink is followed nowhere.  
   `FileStore::get` (`kv.rs:321-335`) `lstat`s, refuses non-regular files, then `std::fs::read` (follows). `FileStore::set` (`kv.rs:338-341`) `lstat`s the scope, then `create_dir_all` on a separately joined path (`kv.rs:235-236`), which follows a directory symlink (`path.is_dir()`).  
   **Failure:** same-UID attacker with write on the 0700 kv root plants `kv/<scope>` as a symlink to `/elsewhere` in the window after `lstat` returns `NotFound` and before `create_dir_all`. First `set` of a new scope `chmod 0700`s the target and installs the value there. Same window on `get`: replace a regular key file with a symlink between `lstat` and `open`; `get` returns the outside file. Stable plants (the round-1 case) are refused.

2. **LOW** — On a case-insensitive volume, `keys()` and `get()` disagree after a catalog recase.  
   `decode_key` requires `encode_key(&key) == name` (`kv.rs:312`). `get`/`set` open `encode_key(key)` and the OS folds case.  
   **Failure:** store writes key `"a"` as `me`. Finder or a sync tool recases the dirent to `ME`. `keys()` sees `ME`, decode returns `None`, the key vanishes from the list. `get("state", "a")` still opens `me` and returns the bytes. A consumer that lists then deletes every key leaves that file behind.

3. **LOW** — First-write durability does not fsync created ancestors.  
   `ensure_dir` (`kv.rs:235-249`) fsyncs `self.dir` (`…/<app>/kv`) and the scope dir. It does not fsync `<app>` (or Application Support) when `create_dir_all` just created them. `fsync(kv)` does not persist the `kv` dirent inside `<app>`.  
   **Failure:** first `set` of a new app identity returns `Ok`; power loss before `<app>` is synced drops the whole subtree. Spec §3 claims a crash after `set` returns keeps what was set, where directory sync is allowed. Later writes into an already-durable store are fine.

4. **LOW** — `create_new` failure unlinks the colliding name, which may not be this call’s file.  
   `kv.rs:374-376`: any `written` `Err`, including `AlreadyExists` from `create_new`, does `remove_file(&tmp)`.  
   **Failure:** leftover `.tmp.{pid}.{nanos}.0` after PID reuse in the same nanosecond, or two PID-namespace processes sharing a volume both as PID 1. The second call deletes the first’s live tmp; the first’s `rename` then `NotFound`s. v1 OQ2 says one process owns a scope, so this is exotic — but the error path is still “delete whatever that name is,” not “delete only what we created.”

5. **LOW** — Same-day spec rewrites still disagree with the landed surface.  
   LLP 0068 §3 still says `cargo test -p ibex2 --test rust_consumer` runs “the whole surface” (fetch, fs, env, pure tier) — no kv, and that test still never calls `app.kv` (`crates/ibex2/tests/rust_consumer.rs:105-120`). LLP 0069 Summary still says `` `Secrets` is the fourth field of `Bindings`, beside `fetch`, `fs`, and `env` `` — kv is the fifth field (`host.rs:101-107`). 0067 §2/§8, 0068 §1, 0069 grammar, and `llp/current/0070` *were* reconciled.

6. **NIT** — `grant.rs:10-11` still says “the four questions.” LLP 0070 §3 still says “a foreign file can neither shadow nor duplicate” a key; the code comment at `kv.rs:408-412` correctly admits a canonical-named regular foreign file is indistinguishable (the residue round 1 accepted — not re-raised as a product bug). `UnavailableStore` (`kv.rs:149-152`) always blames unset `HOME`/`XDG_DATA_HOME`; Apple `for_app` also returns `None` when `HOME` is set but relative.

## Checked and sound

- **Hand-rolled base32.** Encoder/decoder match RFC 4648 unpadded lowercase (`f`→`my`, `foobar`→`mzxw6ytboi`; 128-byte key → 205 chars). `u32` accumulation does not corrupt long keys. Trailing-bit aliases (`mf`), uppercase (`ME`), empty, and impossible lengths are not keys. Alphabet has no `.`, so temps cannot collide with keys. Windows reserved names `con`/`prn`/`aux`/`nul`/`com1`/`lpt1` are not canonical encodings (length or alphabet).
- **Admit-then-validate.** `Kv::admit` (`host.rs:168-180`) admits the scope first, then `check_scope`/`check_key`. Ungranted + `../escape` is `Denied`, not `InvalidArgument`. Granted empty key is `InvalidArgument` and never reaches the store (panic store).
- **`for_app` → `Option`.** No `temp_dir()` fallback. `default_store` installs `UnavailableStore` on `None`. Both Apple `HOME` and XDG/`HOME` require an absolute base.
- **Panic-store test.** `UntouchableStore` panics on every method; denials and the granted empty-key path would fail the test if dispatch moved first. Two consumers from one `Host` share the `Arc` store (`host.rs:534-553`).
- **Grants.** Exact string equality; `_ => false` fail-closed; single-family cross-kind in both directions plus `fs.write` ↛ `storage.kv`. Parse refuses `.` / `..` / `...` / `Castle.state` / prefix both ways.
- **Write protocol (happy path).** `create_new` + `mode(0o600)` + `write_all` + `sync_all` + close + `rename` + `sync_dir(scope)`. Rename replaces a key-path symlink rather than writing through it. Concurrent test’s `own-{writer}` keys and leftover-tmp check are sound (the contended-key `ends_with("-iteration-0024")` is true after `join` because every thread’s last contended write is iteration 24).
- **`keys()`.** Regular files only; dotted names skipped; non-canonical encodings skipped. Memory scopes stay apart. Binding validates inputs before any `KvStore`, including a consumer-supplied one.

## Verdict

**READY** — round-1 isolation, identity, and fail-closed grant bugs are actually fixed; remaining issues are same-UID races, catalog-case listing drift, first-create ancestor sync, and leftover spec sentences, not a return of colliding keys or a silent `/tmp` store.
