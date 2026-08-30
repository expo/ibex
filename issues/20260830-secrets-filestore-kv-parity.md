# Secrets `FileStore`: adopt the hardening the kv review forced

**Opened:** 2026-08-30
**Systems:** Rust Stdlib, CapSec
**Found by:** the LLP 0070 review (Grok 4.6 + Codex, artifacts under
`llp/reviews/0070-*`), as parity notes against `secrets/mod.rs::FileStore`.
Deliberately not swept into the kv change; the kv fixes are the template.

The kv `FileStore` (LLP 0070 §3) now does four things the secrets
`FileStore` (LLP 0069 §3, the non-Apple default) still does not:

1. **No temp-directory fallback.** `secrets::FileStore::for_app` still falls
   back to `std::env::temp_dir()` when `HOME`/`XDG_DATA_HOME` are absent —
   a world-writable, reboot-cleared directory another local user can
   pre-own. kv's `for_app` returns `Option` and `default_store()` hands out
   a store that refuses loudly (`kv::UnavailableStore`). On Apple the
   secrets default is the Keychain, so this is the off-Apple default path.
2. **`create_new` for the temporary.** `secrets` `set` still opens its
   temporary with `create(true).truncate(true)`, which follows a planted
   symlink and keeps a pre-existing file's mode; kv uses
   `create_new(true)` and a per-call unique name (pid + nanos + counter —
   secrets got pid + counter only).
3. **Symlink refusal on read.** `secrets` `get` follows a symlink at the
   secret's path; kv refuses anything that is not a regular file.
4. **Directory-entry sync.** kv fsyncs the directory (best-effort) after
   create/rename/delete so the entry survives a crash; secrets syncs only
   the file.

Also worth carrying over: the panic-on-touch probe-store pattern from
`host.rs::kv_tests` — the secrets denial test still proves denial only by
the returned error for `set`/`forget` (the pre-seeded `get` case does
witness it). The `HOME`-absoluteness check on the Apple branch of kv's
`for_app` has no secrets analog (Keychain), but `FileStore::for_app`'s
`HOME` fallback should filter for absoluteness the same way.

When fixed, note it in LLP 0069 §3 with a Revised line.
