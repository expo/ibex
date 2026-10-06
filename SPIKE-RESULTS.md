# Spike: ibex2 Intl shims on Windows against the OS ICU (`icu.dll`)

Branch `win-intl-spike` (from `origin/main` 6ee16b9a), 2026-10-06. A feasibility
spike, not production code. Comments in the patch are marked `SPIKE (win-intl-spike)`.

**Verdict: feasible, with caveats.** The existing ICU-C-API shims compile
against the Windows SDK's `<icu.h>`, link against the SDK's `icu.lib`, and
give the real `ibex2-runtime` on Windows a working `Intl.NumberFormat`,
`Intl.DateTimeFormat`, `Date#toLocale*String`, and locale case mapping. No ICU
data is bundled, and the binary grows by about 225 KiB. The caveats: (a) the
OS floor is per-API, and as written the number shim needs Windows 11; with
the 30-line iterator fallback in this branch the floor is Windows 10 2004.
(b) Windows' ICU data is Microsoft-modified CLDR 42 with tzdata 2022g, so its
output is not byte-identical to the Linux ICU 74 build. One existing Linux
assertion fails on Windows because of this.

## Machine

- Windows 11 25H2, build 26200.9457. The registry ProductName still says "Windows 10 Pro".
- `C:\Windows\System32\icu.dll` 72.1.0.4. `icuuc.dll`/`icuin.dll` have the same version but are pure forwarders into `icu.dll`.
- At runtime, `icu.dll` reports ICU 72.1.0.4, **CLDR 42.0**, Unicode **15.1** (Microsoft-updated; upstream 72 is 15.0), and **tzdata 2022g**. Source: `spike/win-intl/versions.cc`.
- MSVC 19.50.35730 (VS 18 Community), Windows SDK 10.0.26100.0, Rust 1.97.0 (via `rust-toolchain.toml`).

## 1. Compile: yes, with one change

`intl_icu.cc`, `intl_case_icu.cc`, and `intl_datetime_icu.cc` compile with
`cl /std:c++17 /EHsc /W4 /permissive-` against `<icu.h>` with **zero
warnings**. `intl_number_format.cc` is pure JSI and has no ICU dependency. The
only source change needed was the include switch (`#if defined(_WIN32)
#include <icu.h> #else <unicode/*.h> #endif`) plus one identifier:

- `UDAT_RELATED_YEAR_FIELD` is ICU `@internal`, and the SDK header strips
  internal API. It is replaced by its value, `34`, which has been stable since
  ICU 53 (`kRelatedYearField`). This is the only compile error the SDK header
  produced.

`UChar` is `char16_t` in `icu.h`, the same as ICU 74's C++ default, so the
`uint16_t` to `UChar` copies in the case shim are unchanged.

All 54 ICU C functions the shims call are declared by `icu.h`. `icu.h` gates
each declaration on the Windows release that first exported it, as
`NTDDI_VERSION` blocks. I found each function's gate in two ways: by analysing
the header's preprocessor nesting, and by recompiling at
`/DNTDDI_VERSION=<X> /FIsdkddkver.h`.

| Shim functions | Declared from | First Windows |
|---|---|---|
| `u_strToUpper/Lower`, `u_strFromUTF8/ToUTF8`, `u_strCaseCompare`, all `uloc_*`, `ucal_*`, `uenum_*`, `udat_*` (incl. `udat_formatForFields`), `udatpg_*`, `ufieldpositer_*`, `unumsys_*`, `ucurr_getDefaultFractionDigits` | `NTDDI_WIN10_RS3` | Windows 10 1709. These are also in the legacy `icuuc`/`icuin` (1703). |
| `unumf_openForSkeletonAndLocale`, `unumf_openResult`, `unumf_formatDouble`, `unumf_formatDecimal`, `unumf_close`, `unumf_closeResult` (also the fallback's `unumf_resultToString`, `unumf_resultGetAllFieldPositions`) | `NTDDI_WIN10_VB` | Windows 10 2004 (build 19041) |
| `unumf_resultAsValue`, `ufmtval_getString`, `ufmtval_nextPosition`, `ucfpos_open/close/constrainCategory/getField/getIndexes` | `NTDDI_WIN10_CO` | Windows 11 21H2 (build 22000) |

Measured: at `NTDDI_WIN10_RS3`, `_19H1`, `_VB`, and `_FE`, only `intl_icu.cc`
fails. At VB and FE it fails on just the CO-only names. At RS3 and 19H1 it
also loses `unumf_*`. The case and datetime shims compile at RS3.

**C-API alternative (implemented in this branch):** below `NTDDI_WIN10_CO`,
`intl_icu.cc` uses the ICU 62 path, `unumf_resultToString` plus
`unumf_resultGetAllFieldPositions` into a `UFieldPositionIterator`. It yields
the same `UNumberFormatFields` IDs and spans. Verified twice. First, the
harness output, including every field span, is byte-identical between the
default build and the `NTDDI_WIN10_VB` build. Second, a full runtime built
with `CXXFLAGS_x86_64_pc_windows_msvc=/DNTDDI_VERSION=NTDDI_WIN10_VB
/D_WIN32_WINNT=0x0A00` passes the same tests and gives byte-identical
`intl-check.js` output. That build's `icu.dll` imports drop to 8 `unumf_*`
symbols, all available from Windows 10 2004.

ICU version gaps between 72 and 74: none of the C APIs used postdate ICU 64
(`ufmtval`/`ucfpos`). The skeleton syntax that Rust generates was accepted for
every case in the existing `intl_number_format` suite (12/12 pass).

## 2. Link: yes, through the real crate

I chose the real-crate route, not a throwaway build. The patch:

- `crates/ibex2/build.rs`: compile the shims and the three `intl_*` JS
  bindings when `intl` is on and `target_os` is `linux` **or `windows`**.
- `crates/ibex2/src/**` and the `ibex2-runtime` tests: widen
  `all(feature = "intl", target_os = "linux")` to
  `any(target_os = "linux", windows)` (mechanical, 13 files).
- `crates/hermes-lean-sys/build.rs`: when the `icu` feature is on and the
  target is Windows, emit `cargo:rustc-link-lib=dylib=icu`. ICU link lines
  therefore still come from hermes-lean-sys alone, as the ownership comment in
  `ibex2/build.rs` requires. `ibex2`'s `intl` already enables
  `hermes-lean-sys/icu-full-data`, which implies `icu`.

**`icu.lib` is required.** `icuuc.lib`/`icuin.lib` alone are not enough.
`dumpbin /exports` shows that `icuuc.dll` (542 exports) and `icuin.dll` (416)
are pure forwarders to `icu.dll` and never gained the `unumf_*`, `ufmtval_*`,
or `ucfpos_*` exports. Microsoft documents that new APIs land only in
`icu.lib`/`icu.dll` from 1903 onward. The pinned Hermes bundle already links
`icuuc`+`icuin`, so in the final exe the linker resolves most shim symbols
there, and only the symbols missing from the legacy libraries (14 by default,
8 at the Win10 floor) come from `icu.dll`.

## 3. Run: yes, end to end in `ibex2-runtime`

`cargo build --release -p ibex2-runtime --bin ibex2 [--features intl]`
downloads and links the pinned Windows Hermes bundle (no Hermes Intl). The
results below come from `ibex2.exe run spike/win-intl/intl-check.js`.
Non-ASCII characters are escaped.

| Check | without `intl` | with `intl` (shims + OS ICU) |
|---|---|---|
| `typeof Intl` | `undefined` | `object` |
| `(1234.5).toLocaleString("de-DE")` | `1234.5` | `1.234,5` |
| `new Intl.NumberFormat("en-US",{style:"currency",currency:"USD"}).format(12.5)` | ReferenceError | `$12.50` |
| `new Intl.DateTimeFormat("en-US",{dateStyle:"medium",timeZone:"UTC"}).format(new Date(0))` | ReferenceError | `Jan 1, 1970` |
| `"i".toLocaleUpperCase("tr")` | `I` | `\u0130` (İ) |
| `"I".toLocaleLowerCase("tr")` | `i` | `\u0131` (ı) |
| `"é".toUpperCase()` | `\u00c9` | `\u00c9` (Hermes's own Win10 ICU fallback, both builds) |
| `formatToParts` de-DE -1234.5 | — | minusSign/integer/group/integer/decimal/fraction |
| ja-JP JPY 1234.5 / en-IN 1234567.891 | — | `\uffe51,235` / `12,34,567.891` |
| compact / percent / unit | — | `1.2M` / `12.3%` / `50 km/h` |
| DTF en-US full+long UTC | — | `Thursday, January 1, 1970 at 12:00:00 AM UTC` |
| DTF de-DE Europe/Berlin | — | `1. Januar 1970 um 01:00` |
| th-TH calendar / `asia/calcutta` | — | `buddhist` / `Asia/Calcutta` |
| `new Date(0).toLocaleString("en-US",{timeZone:"UTC"})` | `Jan 1, 1970, 12:00:00 AM` (Hermes fallback, ignores locale) | `1/1/1970, 12:00:00\u202fAM` |
| `new Date(0).toLocaleDateString("de-DE",{timeZone:"UTC"})` | `Jan 1, 1970` | `1.1.1970` |
| `Object.getOwnPropertyNames(Intl)` | — | `getCanonicalLocales,NumberFormat,DateTimeFormat` |

The existing Linux Intl integration suites now run on Windows, built at both
the Windows 11 and Windows 10 2004 API levels with identical results:

- `intl_number_format` 12/12 (1 ignored, same as Linux), `intl_case` 4/4, `intl_engine` 2/2, `structured_clone` 13/13 (including the Intl platform-object test).
- `intl_datetime` 10/11 (1 ignored as on Linux). **One failure:** `styles_time_zones_and_date_prototype_methods_share_the_binding` expects `12/31/69, 7:00\u202fPM`, but Windows produces `12/31/69, 7:00 PM` with an ASCII space. See risks.

The C++ harness (`spike/win-intl/harness.cc`) also drives every `ibex2_icu_*`
entry point directly against `icu.lib`. It is an independent check of the
shims without JSI or Rust.

## 4. Size

Release `ibex2.exe` (`ibex2-runtime`, default features):

| Build | Bytes | Delta |
|---|---|---|
| without `intl` | 10,945,024 | — |
| `intl`, Win11 API path (default NTDDI) | 11,174,912 | **+229,888 (+224.5 KiB, +2.1%)** |
| `intl`, Win10 2004 floor (`NTDDI_WIN10_VB`) | 11,174,400 | +229,376 |

The delta covers the C++ shims, the Rust Intl policy code, and the three
`.hbc` bindings. No ICU code or data is added, because `icu.dll` is the
operating system's. Linux, by comparison, links static ICU 74 plus its
full-data archive for `intl`. On Windows the D5/D6 budget question reduces to
the ~225 KiB of glue.

## 5. Risks

1. **Load-time failure from the import-table floor (most important).** The
   shims are bound through the import table, so a missing export makes the
   whole process fail to start ("entry point not found"), even if JavaScript
   never touches `Intl`.
   - Built with the SDK's default NTDDI (latest), the `intl` exe imports 7
     Windows 11-only symbols (`unumf_resultAsValue`, `ufmtval_*`, `ucfpos_*`)
     and **will not start on Windows 10**.
   - With the VB fallback the floor is **Windows 10 2004 (19041)**.
   - Before 1903 there is no `icu.dll` at all.
   - The non-`intl` build only imports `icuuc`/`icuin` (1703 floor, from Hermes) and is unaffected.
   - Mitigations: pin `NTDDI_VERSION=NTDDI_WIN10_VB` for the shims, and/or
     `/DELAYLOAD:icu.dll` with a startup probe that turns `Groups::INTL` into
     a clean `GroupError` when the OS is too old.
2. **OS ICU and CLDR drift.** Version data points:
   - This machine (Win11 25H2): ICU 72.1 / CLDR 42.
   - Public DLL listings show `icuuc.dll` 61.1 on Win10 1809 (17763), 64.2 on later Win10 builds, and 72.1 on Win11 24H2 (26100).

   The SDK header's NTDDI blocks (RS3, RS5, 19H1, VB, CO, ZN) mark where the
   C API surface grew. Every OS release can change ICU and CLDR, so outputs
   vary across a user base. Linux pins ICU 74 / CLDR 44 and is reproducible.
   Tests that assert exact strings need either Windows-specific expectations
   or normalisation.
3. **Microsoft-modified data, not upstream CLDR 42.** In `icu.dll`, every
   en_US `udat_open` time pattern (`full`/`long`/`medium`/`short`) uses an
   ASCII space before `a`. Upstream CLDR 42+ uses U+202F. The skeleton path
   (`udatpg` availableFormats) still yields U+202F in some patterns, for
   example `h:mm:ss a` from `toLocaleString` and the `12\u202fAM` hour-only
   case, which passes. So Windows output mixes both spaces depending on
   whether a style or a skeleton chose the pattern. This caused the one
   failing assertion. The Microsoft docs say ICU data is still being aligned
   with Windows, so further divergence is expected.
4. **Stale tzdata.** `ucal_getTZDataVersion()` reports **2022g** on a 2026
   build. Time-zone rule changes after late 2022 may be wrong in
   `DateTimeFormat`. Linux ICU 74 ships 2023c+.
5. **Default locale carries Windows user preferences.** `uloc_getDefault()`
   on Windows returns
   `en-US-u-ca-gregory-cu-usd-fw-sun-hc-h12-ms-ussystem`, built from the
   user's regional settings. The Rust policy layer resolved this to `en-US`
   in every observed path (`resolvedOptions().locale`). Production should
   still decide deliberately whether `-u-hc`/`-u-fw`/`-u-ms` preferences
   should leak into `DefaultLocale`, and add a test.
6. **Default time zone.** `ucal_getDefaultTimeZone` follows the Windows zone
   (`America/Los_Angeles` here). The tests' `TZ=UTC` process override still
   worked for explicit zones. Windows host-zone mapping goes through ICU's
   Windows ID table, which is also 2022-era.
7. **`@internal` enum value.** `UDAT_RELATED_YEAR_FIELD` (34) is hard-coded on
   Windows. It is stable in practice, but it is not API.
8. **Identity and receipts.** Linux records `LINKED_ICU_DATA_{ARCHIVE,DIGEST}`
   receipts. Windows has no archive to hash, because ICU is an OS component
   whose bytes change with Windows Update. This spike emits only a
   `linked_icu=windows-os-icu.dll` metadata marker. A production design must
   say how R-e identity treats an unpinnable OS library.
9. **Not checked here:** ARM64 Windows (the SDK has `icu.lib` for arm64), and
   running on an actual Windows 10 2004/22H2 machine. The floor comes from
   the header gates and the import tables, not from a run on that OS.

## Recommended production design

- **A `windows-os` ICU mode in hermes-lean-sys, selected automatically.** On
  `*-pc-windows-msvc`, hermes-lean-sys's `icu` feature means "link the OS
  `icu.dll`" (`rustc-link-lib=dylib=icu`). ICU link lines stay owned by
  hermes-lean-sys only. `icu-full-data` is a no-op on Windows; it must not
  panic or look for an archive. No consumer-visible feature is needed:
  `ibex2/intl` on Windows works without further configuration.
- **Shims.** Keep one source per shim, with the `_WIN32` include switch and
  the `kRelatedYearField` constant. On Windows, always compile the number
  shim's iterator path; it is simpler than making it depend on NTDDI. Compile
  all three Windows shims with `NTDDI_VERSION=NTDDI_WIN10_VB` so that the
  header itself rejects any accidental use of a newer API.
- **Floor and startup.** State a floor of Windows 10 2004. Link `icu.dll`
  with `/DELAYLOAD:icu.dll` (plus `delayimp.lib`). Probe once, with
  `LoadLibraryExW(L"icu.dll", …, LOAD_LIBRARY_SEARCH_SYSTEM32)` plus
  `GetProcAddress` for the newest symbol used, before validating
  `Groups::INTL`. If the probe fails, return the existing "INTL unavailable"
  `GroupError` instead of crashing at process start.
- **Identity.** Extend the receipt with a Windows variant that records the
  observed `u_getVersion`, CLDR, and tzdata versions as **runtime-reported,
  unpinned** facts, without an archive digest. R-e then treats Windows ICU as
  an OS dependency, like CoreFoundation on Apple, rather than a linked
  archive. Document that Windows Intl output follows the OS.
- **Tests.** Run the existing `intl_*` suites on Windows CI. Make exact-string
  assertions that are sensitive to CLDR whitespace platform-aware, or
  normalise U+202F. Add a Windows test asserting that `Groups::INTL`
  validates and that `typeof Intl === "object"`.
- **LLP.** Record the decision in LLP 0057.000 §5.1 (the "included, gated, or
  a crate" table) and in the D5 budget: on Windows, Intl costs ~225 KiB with
  no data.

## Reproduce

All scripts are in `spike/win-intl/`. Run them from PowerShell 5.1 on the
Windows host.

```powershell
. spike\win-intl\vcenv.ps1   # vcvars64 import (the vcvars half of C:\ExactTools\initialize-windows-native-env.ps1)
$env:CARGO_TARGET_DIR = "$PWD\target"
cargo build --release -p ibex2-runtime --bin ibex2                      # baseline
cargo build --release -p ibex2-runtime --bin ibex2 --features intl      # with Intl
target\release\ibex2.exe run spike\win-intl\intl-check.js
cargo test --release -p ibex2-runtime --features intl --no-fail-fast `
  --test intl_number_format --test intl_datetime --test intl_case --test intl_engine --test structured_clone
# Windows 10 2004 floor:
$env:CXXFLAGS_x86_64_pc_windows_msvc = '/DNTDDI_VERSION=NTDDI_WIN10_VB /D_WIN32_WINNT=0x0A00'
# Direct shim harness (no Rust/JSI); -Ntddi NTDDI_WIN10_VB for the floor build:
powershell -File spike\win-intl\harness.ps1
```

Harness output (identical at the default and `NTDDI_WIN10_VB` levels):

```
default_locale = en-US-u-ca-gregory-cu-usd-fw-sun-hc-h12-ms-ussystem
canonical(EN-us) = en-US
numbering(ar-EG) = arab
currency_digits(JPY)=0 (USD)=2
number[de-DE|](1234.5) = 1.234,5  fields=4
number[en-US|currency/USD](12.5) = $12.50  fields=4
number[en-IN|](1.23457e+06) = 12,34,567.891  fields=5
default_calendar(th-TH) = buddhist
hour_cycle(en-US)=12 (de-DE)=23
canonical_tz(asia/calcutta) = Asia/Calcutta
datetime[en-US|UTC|-|2,-1] pattern=MMM d, y -> Jan 1, 1970
datetime[de-DE|Europe/Berlin|yMMMMdjm|-1,-1] pattern=d. MMMM y 'um' HH:mm -> 1. Januar 1970 um 01:00
case[upper,tr] rc=0 -> U+0130
case[lower,tr] rc=0 -> U+0131
case[upper,de] rc=0 -> U+0053 U+0053
```
