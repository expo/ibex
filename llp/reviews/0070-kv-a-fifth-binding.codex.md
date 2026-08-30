# Review of LLP 0070 (KV — a fifth binding) and its implementation — OpenAI Codex family

**Reviewer family:** OpenAI Codex
**Provider / runtime:** codex-cli 0.151.0 / `gpt-5.6-sol`, reasoning effort `xhigh`
**Date:** 2026-08-30
**Target:** the packet snapshot of the uncommitted kv change — `crates/ibex2/src/{kv.rs,grant.rs,boundary.rs,host.rs,secrets/mod.rs,lib.rs}`, `llp/0070` — judged against LLP 0067/0068/0069
**Method:** `codex exec --skip-git-repo-check -s read-only`; the reviewer read the packet and the live sources, made no edits and ran no builds
**Scope:** Adversarial review. Priorities given: grant correctness, path safety of the hand-rolled key encoding, atomicity, spec-vs-code conformance, tests that cannot fail their claims.

## Disposition

The reviewer's verdict on the reviewed (packet) revision was **NOT READY**.
Findings 3 and 4 had already been fixed in the working tree while the review
ran (the tightened forms below land the rest of what they asked). Every
finding was addressed the same day; the reviewer's concrete probes are tests
now.

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | HIGH | Exact scope grants are not exact on case-insensitive filesystems; no length bound on scopes | **Fixed** — shared name grammar now `[a-z0-9._-]{1,64}` (LLP 0069 revised to match) |
| 2 | HIGH | The mixed-case base64url key mapping collides under case-insensitive comparison (`"\u{0001}"` → `AQ` vs `"i"` → `aQ`) | **Fixed** — lowercase base32, as the finding proposed |
| 3 | HIGH | One shared truncate-able temporary per process+scope: torn values, PID reuse/namespace collisions, plantable symlink, retained permissive mode | **Fixed** — `create_new` (exclusive, does not follow a planted link, owns the mode) with a per-call unique name (pid + nanos + counter), cleanup on every error path; concurrent-writer test |
| 4 | MEDIUM | Decoder accepts non-canonical aliases; `keys()` lists what `get()` refuses | **Fixed** (during the review window, as prescribed: `check_key(decoded)` + `encode_key(decoded) == name`; kept under base32, with fixed vectors) |
| 5 | MEDIUM | "Foreign files are not keys" too strong: no file-type check; a canonical-named regular foreign file is indistinguishable | **Fixed / narrowed** — only regular files are keys (directories and symlinks excluded, tested); the canonical-regular-file residue is stated in the code and 0070 §3 claims one-to-one for canonical names only |
| 6 | MEDIUM | Symlinks turn kv into an `fs.*` confused deputy (scope-dir and key-path links followed) | **Fixed** — a symlinked scope directory refuses every operation; `get` refuses anything but a regular file; `keys()` filters; tested |
| 7 | MEDIUM | Atomic visibility without durability: directories never fsynced | **Fixed** — best-effort directory sync after create/rename/delete; contract stated in 0070 §3 |
| 8 | MEDIUM | Durable store silently falls back to `temp_dir()` | **Fixed** — `for_app` returns `Option`; the no-base default store refuses loudly (`UnavailableStore`) |
| 9 | MEDIUM | Tests cannot fail their claims (returned-error-only denials; combined-set cross-kind; missing canonical/case/concurrency/symlink cases) | **Fixed** — panic-on-touch probe store; single-family cross-kind sets in both directions plus `fs.write`; canonical, case-variant, symlink, concurrent-writer, and foreign-entry tests |
| 10 | LOW | Public Rust API bypasses the grammar (`Grant::StorageKv` via `with`; keys validated only in stock stores) | **Fixed in the part that reaches a store** — `host::Kv` validates scope and key after admission, so a consumer's store never sees what the family refuses; validated newtypes declined for v1 (parity with the existing families, where `parse` is the validated constructor) |
| 11 | LOW | Spec corpus unreconciled: 0069's grammar text; 0067 §8's growth rule vs "the author named it" | **Fixed** — 0069 revised; 0067 §2 lists five families and §8 states the author-required form of a call site (LLP 0059.000 §6), which is how 0069 and 0070 both arrived; the shape-before-consumer risk stays visible as 0070 §6's open questions |

The reviewer's parity observations against the secrets `FileStore` are
deliberately not swept into this change:
`issues/20260830-secrets-filestore-kv-parity.md` carries them.

## The review as written

Review basis: the packet snapshot, treated as authoritative. I made no edits and ran no builds.

1. **HIGH — Exact scope grants do not provide exact storage isolation on case-insensitive filesystems.** `crates/ibex2/src/kv.rs:169-177` joins the scope verbatim: `self.dir.join(scope)`. The grammar permits case variants, while admission compares them exactly. On standard case-insensitive macOS volumes or Windows, bindings granted `storage.kv State` and `storage.kv state` use the same directory, so either can read or overwrite the other’s data. The same grammar also has no length bound: a 256-byte ASCII scope parses successfully but typically fails with `ENAMETOOLONG`. Scope names need a bounded, filesystem-independent, case-invariant encoding.

2. **HIGH — The base64url key mapping collides on case-insensitive filesystems.** `crates/ibex2/src/kv.rs:197-212` uses an alphabet containing both uppercase and lowercase characters. Because any UTF-8 key is allowed, key `"\u{0001}"` encodes as `AQ`, while `"i"` encodes as `aQ`; those are the same filename under case-insensitive comparison. Setting one can overwrite the other. A lowercase-only encoding such as unpadded base32, or another mapping proven injective under target filesystem comparison, is required.

3. **HIGH — All concurrent writers in one process and scope share one temporary file.** `crates/ibex2/src/kv.rs:242-266` uses:
   ```rust
   let tmp = scope_dir.join(format!(".tmp.{}", std::process::id()));
   options.write(true).create(true).truncate(true);
   ```
   If thread A writes key `a` and pauses before rename, thread B truncates the same temporary and writes key `b`; A can then successfully rename B’s bytes to `a`, while B fails because the temporary disappeared. Large writes can interleave into torn values. Two PID-namespace processes sharing a mounted store can both be PID 1 and reproduce the same collision; PID reuse also collides with crash leftovers. Because opening is neither exclusive nor no-follow, a planted `.tmp.<pid>` symlink can redirect the write, and an existing permissive temporary retains its mode despite `mode(0o600)`. Use a per-call unpredictable name, `create_new(true)` with retry, no-follow semantics where available, and cleanup on every error path.

4. **MEDIUM — The decoder accepts noncanonical aliases and `keys()` reports entries that `get()` cannot retrieve.** `crates/ibex2/src/kv.rs:214-229` never checks unused trailing bits, key length, emptiness, or re-encoding. For example, `decode_key("YR")` returns `"a"`, although `"a"` canonically encodes as `YQ`. Put a foreign file named `YR` in the directory: `keys()` reports `"a"` but `get("a")` returns `None`; adding both `YQ` and `YR` produces duplicate `"a"` entries. A filename encoding a 129-byte UTF-8 key is also listed although `get()` refuses that key. Require `check_key(decoded)` and `encode_key(decoded) == name`.

5. **MEDIUM — The “foreign files are not keys” claim and test are materially too strong.** `crates/ibex2/src/kv.rs:278-298` accepts any decodable directory entry without checking that it is a regular, non-symlink file. The test at `kv.rs:438-445` only creates `.DS_Store` and `not!akey`, both trivially rejected lexically. A directory, symlink, or ordinary foreign file named `YQ` is listed as key `"a"`. Canonical validation and file-type checks help, but an ordinary foreign file with a canonical name remains indistinguishable without a header or metadata; otherwise LLP 0070 §5 should narrow the claim.

6. **MEDIUM — Existing symlinks can turn KV into an `fs.*` confused deputy.** `crates/ibex2/src/kv.rs:169-181,233-245` follows a pre-existing scope-directory symlink, and `get()` follows a symlink at an encoded key path. For example, if `<kv>/state/YQ` points to a readable file outside the store, `kv.get("state", "a")` returns that file despite the binding having no `fs.read` grant. A scope symlink similarly redirects writes and listing. This requires prior manipulation of the store directory, but the spec explicitly discusses foreign contents and claims a KV grant cannot reach paths; the backend must reject symlinks and verify containment.

7. **MEDIUM — The write/delete protocol provides atomic visibility, not full durability.** `crates/ibex2/src/kv.rs:259-275` syncs the temporary file and renames it but never syncs the containing directory; deletion likewise removes without syncing the directory. After `set()` returns, a power loss can therefore lose the rename or restore the old name/value; first-time scope creation has the same metadata problem. A write or sync error also leaves the temporary behind. LLP 0070 describes durable state that survives launches, so either sync the relevant directories after creation/rename/delete or explicitly weaken the durability contract.

8. **MEDIUM — The default “durable” store silently becomes temporary storage.** `crates/ibex2/src/kv.rs:152-166` falls back to `std::env::temp_dir()` whenever the durable base cannot be derived. Launch with `HOME` absent and, off Apple, `XDG_DATA_HOME` absent: `set()` succeeds under `/tmp`, after which a reboot or temporary-file cleaner can erase supposedly durable state. Multiple users running the same executable can also contend for the same `/tmp/<app>` path. Failure to locate a durable base should be an error or an explicit ephemeral-store choice.

9. **MEDIUM — The security tests cannot fail several claims they purport to prove.**
   - `crates/ibex2/src/host.rs:449-471` uses an ordinary `MemoryStore` and only examines returned denials. Moving admission after a store mutation would still pass. Use a probe store that counts or panics on every method and assert zero calls.
   - `crates/ibex2/src/grant.rs:467-483` tests KV admission with both KV and secret grants present, so it cannot prove a secret-only grant does not admit KV. It only proves the reverse direction with `kv_only`.
   - `kv.rs:325-345,438-445` has no noncanonical, case-folding, concurrent-writer, symlink, or valid-looking foreign-entry cases.

10. **LOW — The public Rust API bypasses the stated scope/key grammar.** `Grant::StorageKv(String)` and `GrantSet::with` at `crates/ibex2/src/grant.rs:127,170-172` permit:
    ```rust
    GrantSet::none().with(Grant::StorageKv("../escape".into()))
    ```
    Admission succeeds for that exact string. The built-in stores revalidate it, but a store supplied through `with_kv_store` receives the invalid scope; key validation is likewise delegated entirely to each store. `MemoryStore::with` can also preload invalid keys that `keys()` later returns. Validated `KvScope`/`KvKey` newtypes, or validation in `Kv` before dispatch, would make the public contract enforceable.

11. **LOW — The governing specs are not fully reconciled.** LLP 0069 line 54 still specifies `[A-Za-z0-9._-]+`, which includes `.` and `..`, while this change makes `GrantSet::parse("secret.keep .")` fail. Separately, LLP 0067 line 157 requires a measured call site before adding a family, while LLP 0070 line 8 substitutes “the author named it”; the packet contains no measured consumer call site. That risks fixing the grant shape before the first consumer reveals whether it needs read-only access, CAS, or another semantic split.

Checked and sound:

- `Grant::StorageKv` admits only an exactly equal `Operation::StorageKv`; the wildcard arm fails closed and logical cross-family matching is sound.
- Every `Kv` public operation in the packet calls `admit` before dispatch; `get_text` and `set_text` inherit that ordering.
- Denials disclose only the static capability name `storage.kv`.
- Raw keys never enter a built-in filesystem path; the canonical encoder round-trips correctly and fits 128-byte keys within 255 bytes on case-sensitive filesystems.
- The memory backend separates scopes and returns keys in stable order.

**Verdict: NOT READY — exact scope/key isolation and concurrent writes are broken on supported/common filesystem configurations, with additional decoder, symlink, and durability gaps.**
