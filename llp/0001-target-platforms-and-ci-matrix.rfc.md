# LLP 0001: Target Platforms and the CI Build Matrix

**Type:** RFC
**Status:** Draft
**Systems:** Build, Engine, Crypto, CI
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Related:** LLP 0000; exact LLP 0180 (Extract Ibex), exact LLP 0038 (Runtime Dependency Contract)

## Summary

Ibex must build and run on **macOS, iOS, tvOS, Android, Linux, and Windows**.
Today nothing in CI compiles ibex across these platforms — which is exactly how
a Linux build regression shipped undetected and kicked off the whole extraction
effort (exact LLP 0180 §1.2). This RFC defines the target-platform set, the
axes that matter beyond the OS name (architecture and crypto profile), and a
concrete CI build matrix — including which targets build today versus need
`build.rs` work.

## 1. Target platforms

### What's a distinct build target vs. a form factor

Not everything that "runs ibex" is a separate build:

- **Apple family** (share the CommonCrypto/Security crypto path, no OpenSSL):
  **macOS**, **iOS**, **tvOS** are distinct OS targets. iPadOS is covered by
  iOS; watchOS and visionOS are deferred until there's a concrete need.
- **Android**: **Android** is a distinct target (NDK cross-compile, Hermes-for-
  Android). **Android TV is NOT a separate build** — it's Android (same OS,
  same ABIs); the Android jobs cover it. Same for Wear OS / Chromebooks.
- **Linux** and **Windows** are distinct targets.

So the canonical target set is six OSes — macOS, iOS, tvOS, Android, Linux,
Windows — and "also runs on Android TV / iPadOS" is a coverage note, not a
matrix row.

### Current `build.rs` support (honest status)

| OS | build.rs arm | Crypto backend | Status |
|---|---|---|---|
| macOS | yes | CommonCrypto/Security | builds today |
| iOS | yes | CommonCrypto/Security (`EXACT_PLATFORM_IOS`) | builds today |
| Linux | yes | OpenSSL (`openssl-crypto`) | builds today |
| Windows | yes | `crypto_windows.cc`, `EXACT_NO_OPENSSL` | builds today |
| **Android** | **no** | needs OpenSSL (no platform backend) | **needs work** |
| **tvOS** | **no** | CommonCrypto (reuses iOS-family config) | **needs work** |

Android and tvOS have no `build.rs` target arm and no Hermes-for-platform
artifact path yet. The matrix should include them as **known-red** entries so
CI drives their support to green, rather than omitting them and pretending the
platform set is smaller than the product goal.

## 2. The axes that matter beyond OS

A platform name alone under-specifies the build. Two more axes carry real bug
risk:

### 2.1 Crypto profile (the axis that caused the original break)

Ibex's crypto is platform-dependent and is the single most fragile build axis:

- **Apple (macOS/iOS/tvOS):** CommonCrypto/Security — no OpenSSL.
- **Windows:** `crypto_windows.cc` + `EXACT_NO_OPENSSL`.
- **Linux / Android:** **no platform backend** → the `openssl-crypto` feature is
  **required** for real hashing/HMAC/sign. The default (no-OpenSSL) profile on
  Linux compiles but only registers asymmetric crypto as throwing stubs, and
  full hashing/HMAC is unavailable.

The matrix MUST therefore build **Linux in both profiles** (openssl-crypto and
the reduced no-OpenSSL default), because the no-OpenSSL reduced build is
literally what shipped broken — exercising only the openssl profile would miss
that class of regression again.

### 2.2 Architecture

- macOS, Windows, Linux: **arm64 + x86_64** (Linux also `aarch64` on native
  runners where available).
- iOS/tvOS: arm64 device + arm64/x86_64 simulator.
- Android: `arm64-v8a`, `armeabi-v7a`, `x86_64`.

Architecture catches fewer bugs than the crypto axis, but codegen/ABI and
pointer-width assumptions do surface here.

## 3. Proposed v1 matrix

Build (and, where the runner can execute the target, test) the following. Each
cell builds `--features openssl-crypto` where that's the platform's real profile
and the platform's native profile otherwise:

| OS | Arch | Crypto profile | Runner | Notes |
|---|---|---|---|---|
| Linux | x86_64 | openssl-crypto | ubuntu | primary |
| Linux | x86_64 | default (no-OpenSSL) | ubuntu | exercises the reduced build that shipped broken |
| Linux | aarch64 | openssl-crypto | ubuntu-arm (or cross) | |
| macOS | arm64 | CommonCrypto (default) | macos | tier-1 |
| macOS | x86_64 | CommonCrypto | macos | |
| iOS | arm64 (sim) | CommonCrypto | macos | cross-compile + simulator boot |
| tvOS | arm64 (sim) | CommonCrypto | macos | **known-red** until build.rs support lands |
| Windows | x86_64 | crypto_windows / NO_OPENSSL | windows | |
| Android | arm64-v8a | openssl-crypto | ubuntu + NDK | **known-red** until build.rs support lands |

Known-red rows are kept in the matrix (not `continue-on-error`-hidden) but their
failure is allowed to be tracked separately so the green rows still gate merges.
As Android/tvOS support lands, flip them to required.

## 4. What CI must handle per cell

- **Hermes artifacts.** Each platform needs its prebuilt Hermes
  (headers + lib). CI must run the appropriate `scripts/build-hermes-*.sh` (or
  fetch a cached/release artifact) before `cargo build`; these are not committed.
- **Hermes compiler (`hermesc`).** The default hermetic build needs `hermesc`
  for bootstrap bytecode; ensure it's present/fetched per runner.
- **Hermetic default.** Cells build the default (vendored) path; at least one
  cell should also run `IBEX_REGENERATE_RUNTIME=1` (with `bun`) to keep the
  regeneration path honest, but that is the non-default dev path.
- **Caching.** Cargo + Hermes-artifact caching per (OS, arch) to keep wall-clock
  sane.

## 5. Sequencing

1. Land the matrix for the four targets that build today (macOS, iOS, Linux,
   Windows) + the Linux dual-profile row — immediate regression protection.
2. Add tvOS (Apple-family `build.rs` arm; small) and flip from known-red.
3. Add Android (`build.rs` target arm + Hermes-for-Android artifacts + NDK
   toolchain in CI) — the largest gap.
4. Add arm64 rows as native runners allow.

## Open questions

- Where do per-platform Hermes artifacts come from in CI — built from source per
  run (slow), cached, or published as release assets and fetched?
- Should tvOS/iOS go beyond "compiles" to a simulator smoke test, and Android to
  an emulator smoke test, or is cross-compile-only sufficient for v1?
- Do we add arm64 Windows, or defer until there's demand?
