# Round-2 review of LLP 0070 (KV) as landed in `6b86e3b21` — OpenAI Codex family

**Reviewer family:** OpenAI Codex
**Provider / runtime:** codex-cli 0.151.0 / `gpt-5.6-sol`, reasoning effort `ultra`
**Date:** 2026-08-30
**Target:** commit `6b86e3b21` — the landed kv binding, after round 1's fixes
**Method:** `codex exec --skip-git-repo-check -s read-only -m gpt-5.6-sol -c model_reasoning_effort="ultra"`; static inspection, no edits, no builds
**Scope:** Verify round-1 dispositions against the landed code, then hunt fresh — especially in what round 1's fixes introduced.

## Disposition

Verdict on the reviewed commit: **NOT READY** — four MEDIUMs, all real, all
fresh consequences of the reviewed design rather than round-1 bugs returning.
All were fixed the same day in the follow-up commit; every disposition below
names the fix.

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | MEDIUM | Canonical spelling enforced only when listing: on case-insensitive APFS, `get("a")` reads a planted `ME` that `keys()` refuses; `delete` can remove it | **Fixed** — the stored spelling now decides everywhere: `get`/`delete` verify the on-disk name (`occupies_canonical_name`, via `canonicalize`) and treat a case-variant occupant as absent; `set` evicts one so its own write cannot come back invisible; one test asserts identical observable behavior on case-sensitive and case-insensitive filesystems |
| 2 | MEDIUM | Symlink refusal bypassable through ancestors (a symlinked store root) and check/use races | **Fixed / narrowed** — the store root is now checked like the scope; the check-vs-use race is explicitly out of scope, and 0070 §3 now says so with the reason: the threat model is LLP 0062 §4's supply-chain integrity, not a sandbox against a local same-user adversary who can already write the app's state directory |
| 3 | MEDIUM | First-write durability incomplete: created ancestors (`<app>`, `kv`) never synced, so a crash can drop the new subtree after `set` returned | **Fixed** — `ensure_dir` finds the deepest pre-existing ancestor before creating, then syncs every created entry up to and including it |
| 4 | MEDIUM | Grant lines fail open: `storage.kv payments cache` grants `payments` instead of refusing | **Fixed** — anything after the target refuses the line, for every family; tested per family, full-line comments unaffected |
| 5 | LOW | A failed `create_new` unconditionally unlinks the colliding name — another writer's temporary | **Fixed** — `AlreadyExists` takes the next name (bounded retry); cleanup happens only after this call's create succeeded |
| 6 | LOW | `MemoryStore::with` preloads keys the binding refuses; `keys()` then lists what `get` rejects | **Fixed** — the constructor validates and panics loudly on a refused scope or key (it takes handed literals) |
| 7 | LOW | The codec pinned by only one independent vector | **Fixed** — RFC 4648 §10's vectors (`f`…`foobar`), lowercased and unpadded, asserted in both directions |
| 8 | LOW | LLP 0068 §3's named no-engine test does not cover secrets or kv | **Fixed** — `tests/kv.rs` runs the binding end-to-end with no engine (real `Host`, file store on disk, manifest-grammar grants, shared-store/denied-authority, survival across a second store); 0068 §3 now says where each binding's tests live |
| 9 | NIT | Apple secret-store diagnostic still advertised `[A-Za-z0-9._-]+` | **Fixed** |

## The review as written

I found four MEDIUM defects and several lower-severity gaps. Five round-1 dispositions are incomplete. I did not count any residue the prompt explicitly excluded. No files were modified, and no builds or tests were run.

## Findings

1. **MEDIUM — Canonical spelling is not enforced during lookup on case-insensitive filesystems.**  
   [`decode_key`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:294) rejects non-lowercase names when listing, but [`get`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:316) simply reads the computed lowercase path. On default APFS, plant regular file `ME`, while key `"a"` canonically encodes as `me`: `get("state", "a")` resolves and returns `ME`, while [`keys()`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:417) rejects it. `delete("state", "a")` can likewise delete that noncanonical file. This contradicts [LLP 0070’s canonical one-to-one claim](/Users/ccheever/projects/ibex/llp/0070-kv-a-fifth-binding.spec.md:118) and is distinct from the accepted canonical-named foreign-file residue. The codec-only `decode_key("ME")` test cannot witness filesystem folding. **Round-1 canonical-key disposition incomplete.**

2. **MEDIUM — Symlink refusal remains bypassable through ancestors and check/use races.**  
   [`scope_dir`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:216) checks only the final scope component, then every operation reopens it by pathname. If the store root `<app>/kv` is a symlink, `self.dir.join(scope)` follows it before the check; a normal target scope passes and KV reads/writes outside the state root. Similarly, [`get`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:321) checks a regular key with `symlink_metadata`, then separately calls `read`; swapping the dirent to a symlink between those calls makes the read follow it. Scope swaps affect `set`, `delete`, and `keys` similarly. Held directory handles plus relative no-follow operations are needed. **Direct pre-existing leaf symlinks are fixed; the broad “a symlink is followed nowhere” disposition is not.**

3. **MEDIUM — First-time directory creation is not fully durable.**  
   [`ensure_dir`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:235) may create `<base>/<app>/kv/<scope>`, then syncs only `kv` and `scope`. Syncing `kv` persists the `scope` entry, but not the new `kv` entry in `<app>` or a new `<app>` entry in `<base>`. Consequently, the first `set()` can return success and a crash can still lose the entire subtree, contrary to [LLP 0070’s post-return durability statement](/Users/ccheever/projects/ibex/llp/0070-kv-a-fifth-binding.spec.md:125). The rename and delete directory syncs themselves are present and correct. **Round-1 directory-fsync disposition incomplete.**

4. **MEDIUM — Malformed grant lines fail open because trailing fields are ignored.**  
   [`GrantSet::parse`](/Users/ccheever/projects/ibex/crates/ibex2/src/grant.rs:268) consumes `capability` and one `target` but never checks another `parts.next()`. Thus `storage.kv payments cache` succeeds and grants `payments` instead of rejecting the malformed line. A manifest typo can therefore grant access to an existing scope rather than stopping deployment. This also affects `secret.keep`; either reject a third token or define and parse an explicit inline-comment grammar. The strengthened parser tests omit this case.

5. **LOW — A failed exclusive open can delete another writer’s temporary.**  
   Temporary names use PID, time, and a per-process counter at [`kv.rs:349-359`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:349), but every open error triggers unconditional `remove_file(&tmp)` at [`kv.rs:374-376`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:374). Two PID-namespaced processes can both be PID 1 with counter 0 in the same clock tick: the loser gets `AlreadyExists`, unlinks the winner’s temporary, and the winner then cannot rename it. Cleanup must begin only after this call successfully created the file, and collisions should retry. The concurrency test uses threads in one process, so it cannot exercise this path. **Round-1 temporary/cleanup disposition incomplete.**

6. **LOW — The stock memory backend can still list keys the binding refuses.**  
   [`MemoryStore::with`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:82) accepts arbitrary preloaded keys, [`MemoryStore::keys`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:127) returns them unchanged, and [`Kv::keys`](/Users/ccheever/projects/ibex/crates/ibex2/src/host.rs:220) validates only the scope. Seed `("state", "", value)`: `keys("state")` returns `[""]`, while `get("state", "")` is `InvalidArgument`. Make the preload constructor validated/fallible and/or validate store outputs. **Binding input validation is fixed, but the `MemoryStore::with` portion of the round-1 finding remains.**

7. **LOW — The durable base32 format is independently pinned for only one byte.**  
   [`kv.rs:458-489`](/Users/ccheever/projects/ibex/crates/ibex2/src/kv.rs:458) has many round trips, but encoder and decoder can share the same multi-byte error; the only independent RFC vector is `"a" ↔ "me"` at lines 476–479. A coupled error after the first byte could pass while changing persistent filenames and stranding data across releases. Add RFC 4648 vectors such as `f`, `fo`, `foo`, `foob`, `fooba`, and `foobar`. The current codec is statically correct, but the artifacts’ “fixed vectors” claim is overstated.

8. **LOW — LLP 0068’s named no-engine integration test no longer covers the “whole surface.”**  
   [LLP 0068 §3](/Users/ccheever/projects/ibex/llp/0068-the-standard-library-for-a-rust-consumer.spec.md:57) says `cargo test -p ibex2 --test rust_consumer` runs the whole surface. In commit `6b86e3b21`, `crates/ibex2/tests/rust_consumer.rs:25-83` exercises only fetch, filesystem, environment, and pure helpers—neither secrets nor KV. A KV grant/behavior regression can leave that specifically named integration test green.

9. **NIT — The Apple secret-store diagnostic still advertises the obsolete grammar.**  
   [`secrets/darwin.rs:77-83`](/Users/ccheever/projects/ibex/crates/ibex2/src/secrets/darwin.rs:77) uses the tightened validator but reports `[A-Za-z0-9._-]+`. For example, `Upper` is rejected while the error says uppercase is allowed. The shared grammar behavior is correct; its platform diagnostic was not reconciled.

## Round-1 dispositions verified

- `[a-z0-9._-]{1,64}`, nonempty and not only dots, is shared by secret names and KV scopes; legal case-variant grants can no longer collide.
- Lowercase base32 is injective for legal keys, canonical re-encoding rejects trailing-bit aliases, and 128 bytes encode to 205 characters.
- `for_app` requires an absolute durable base, returns `Option`, and `default_store` uses `UnavailableStore`; no KV temp-directory fallback remains.
- Admission precedes binding input validation and store dispatch. Single-family cross-kind tests, the shared-host test, empty/non-UTF-8 tests, and direct leaf symlink/file-type tests now witness their stated cases.
- LLP 0067’s family table, LLP 0068’s `Bindings` shape, LLP 0069’s grammar, Host comments, and `llp/current/0070` were reconciled.

## Checked and sound

- The hand-rolled base32 bit packing and canonical decoder are correct by static inspection.
- Admit-then-validate correctly preserves denial nondisclosure while preventing invalid admitted inputs from reaching a store.
- The panic-on-touch store test is sound: dispatch before admission would panic and fail the test.
- Exact scope equality, cross-family rejection, stable ordering, direct `create_new`, file sync before rename, and post-rename/delete scope-directory sync are correct in the non-racy path.

**VERDICT: NOT READY — canonical lookup, symlink confinement, first-write durability, and fail-closed grant parsing still have MEDIUM defects.**
