# Two hermes-lean-sys build-support tests fail on a Windows host

**Status:** Closed (2026-10-06): both were fixture bugs; the extractor was sound
**Systems:** hermes-lean-sys, Windows
**Severity:** P3 (tests only; Linux and macOS hosts pass; no shipped behavior known to differ)
**Author:** Claude (Opus 5.5) for Charlie Cheever
**Date:** 2026-10-06

## What

`cargo test -p hermes-lean-sys` on the Windows NucBox (x86_64-pc-windows-msvc,
`core.autocrlf=false`) fails two tests, at main `6ee16b9` and identically on lane I1's
branch, so they predate I1:

- `host_independent_tar_names_and_collisions_are_refused`
  (`crates/hermes-lean-sys/tests/build_support.rs:171`): `expect_err` panics with
  `unsafe archive must fail: ()`, i.e. one fixture archive is **accepted** on Windows.
  Likely cause (diagnosed, not yet proven): the fixture writer uses
  `tar::Builder::append_data`, whose path handling on a Windows host converts `\` to `/`,
  so `dir\file` (and the `\\?\` and UNC cases) are written as ordinary `dir/file`-style
  names and the extractor rightly accepts them. The fixture is host-dependent; the
  extractor's backslash refusal is probably fine.
- `build_support::internal_tests::linux_layout_and_receipt_require_and_authenticate_both_icu_data_variants`
  (`crates/hermes-lean-sys/build_support.rs:1938`): the Linux v3 fixture's receipt does not
  authenticate on a Windows host (the I1 lane suspected an ICU filter digest computed over
  CRLF-converted text, unconfirmed).

Also reported by the I1 lane: one Windows-only `dead_code` clippy error in the same test
file.

## Why it matters

The first is the archive-safety check. On a Windows host it currently proves nothing about
backslash names, because the fixture never contains one. Confirm the diagnosis by writing
the GNU header name bytes directly (`header.as_gnu_mut().name`) so the archive is identical
on every host; if the extractor then refuses, only the test changes. If it does not, that is
a real extraction gap and becomes P1.

## Next

Run both tests on Windows with `--nocapture`, record the actual errors here, and fix the
test or the code. Add `hermes-lean-sys` to the Windows CI/check list so this can't recur.

## Resolution (2026-10-06, lane S3)

Both failures came from host-dependent fixtures. The extractor and the receipt check
are correct, and neither has a P1.

- **Tar names.** This is the diagnosis above, now confirmed. On Windows,
  `tar::Builder::append_data` passes the name through `Path` (`path2bytes`
  rewrites `\` to `/`, and `copy_path_into` refuses `Prefix`/`RootDir`
  components). So `dir\file` was written as `dir/file`, and the extractor
  rightly accepted it. `C:/file` and `\\?\C:\file` would never have been
  written at all. The extractor admits names from `path_bytes()`, which does not
  depend on the host. `write_archive` now puts names into the GNU header's name
  field verbatim, so the fixture bytes are the same on every host. With that
  change, all eight refusal cases are refused on Windows, macOS, and Linux.
- **ICU filter digest.** Confirmed with `--nocapture`: `records base ICU data
  filter digest sha256-c5d1b182… but selected filter has sha256-5060fef9…`.
  `scripts/icu74-filter-*.json` fell under `* text=auto`, so a Windows checkout
  wrote them with CRLF (`git ls-files --eol`: `i/lf w/crlf`). The test
  `include_bytes!`s them, and the installer's offline test does too. The fix is
  in `.gitattributes`: `scripts/icu74-filter-*.json text eol=lf`. They are
  digest-pinned inputs, so their bytes have to be the same on every host. An
  existing Windows checkout needs those two files checked out again.
- **Clippy.** `ArchiveEntry::Executable` is built only by the Unix permission
  test, so the variant and its match arm are now `#[cfg(unix)]`.

On Windows, `cargo test -p hermes-lean-sys` passes (31) and
`cargo test -p hermes-lean-sys-installer` passes (15; `install_offline` is
`#![cfg(unix)]` by design). `cargo clippy -p hermes-lean-sys --all-targets
--features link -D warnings` is clean. macOS `build_support` passes 41.
There is no Windows Rust CI job to add these to; the README's Windows
section now lists them in the Windows check list.
