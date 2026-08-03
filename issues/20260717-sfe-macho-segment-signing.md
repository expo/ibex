# Mach-O segment embedding + signing state machine

**Status:** Open
**Impact:** 5
**Urgency:** 4
**Ease:** 2
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Mach-O segment embedding + signing state machine” shows the issue reaches a security, correctness, release, or core product boundary; delay compounds an active rollout, reliability, or verification risk, while the repair crosses several runtime, host, protocol, or policy seams, with specific cited code, progress, or acceptance criteria.
**Progress:** In Progress
**Severity:** P2
**Systems:** Build, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §2b/§2c
**Depends-on:** sfe-envelope-format, sfe-static-hermes-macos

A trailer-appended Mach-O cannot be code-signed (`LC_CODE_SIGNATURE`
must terminate `__LINKEDIT`; Apple TN2206 — the reason postject/libsui
exist), so macOS uses a **dedicated segment** injected by deterministic
load-command insertion (precommitted layout: segment name, placement,
alignment, padding); ELF keeps the appended trailer. Sequence: strip
linker signature (stub-core bytes defined over stripped form) → inject
segment → record unsigned digest → ad-hoc sign (seals the segment) →
record signed digest. Boot validation per format (ELF: bounded EOF
magic scan, single candidate; Mach-O: exactly one `LC_CODE_SIGNATURE`
terminating `__LINKEDIT`, the segment present once, signature coverage
includes it). Distribution: raw signed binary + online notarization
ticket (standalone binaries cannot be stapled; dmg/pkg — not zip — as
the distributor's staplable containers); publisher requirements stated
(Developer ID, hardened runtime, secure timestamp); rcodesign named
for future deterministic signing. Provenance split: immutable build
statement (from `compile`) + optional publisher statement
(DSSE/in-toto-style envelope).

**Done when:** byte-level signing vectors (ad-hoc + Developer ID,
minimum macOS, signature replacement, notarization verification) pass;
two-clean-builder unsigned-core reproducibility holds on both formats.

## Progress — 2026-07-17

The thin little-endian Mach-O injector now uses the precommitted
`__IBEX,__payload` segment/section, inserts its 152-byte command immediately
before `__LINKEDIT`, places the envelope at the former `__LINKEDIT` offset,
zero-pads its allocation to 16 KiB, and relocates `__LINKEDIT` plus supported
linkedit-relative offsets. The compiled stub reserves `0x1000` bytes of header
space. Injection refuses a remaining signature, duplicates, nonzero or
insufficient slack, unsupported Mach-O shapes, and malformed linkedit layout.

The phase smoke now byte-compares two unsigned injected images, ad-hoc signs
one, verifies it with `codesign --verify --strict`, and executes the signed
binary directly after deleting source. Boot additionally requires one
terminal code-signature superblob in terminal `__LINKEDIT`, after the unique
payload. Synthetic malformed-layout tests are green. Developer ID/hardened
runtime, minimum-OS, signature-replacement, notarization, and two-clean-builder
release vectors remain, so this issue is not complete.

## Historical remaining list (verified 2026-07-31)

- The injection/refusal mechanism is built, but the acceptance signing
  vectors are absent: no Developer ID / hardened-runtime / notarization
  coverage, no minimum-macOS (`LC_BUILD_VERSION`) handling, and no
  strip→inject→sign→re-sign replacement vector (ad-hoc signing is a
  shell smoke in scripts/test-sfe-phase0.sh, not a byte-level vector).
- "Synthetic malformed-layout tests are green" overstates: the refusals
  (leftover signature, duplicates, bad slack, malformed linkedit) are
  implemented in crates/sfe-format/src/macho.rs but only two `#[test]`s
  exist and neither is a malformed-layout test; nothing in tests/
  references `macho::`.
- Two-clean-builder reproducibility currently means two checkouts on
  one builder, macOS-arm only per run; scripts/test-sfe-phase0.sh is
  not wired into CI.

## LLP 0047 reconciliation — 2026-08-01

This is milestone 5 distribution evidence. Milestone 0 now has a required
format/catalog/stub/producer gate, but the phase-0 signed relocation shell
smoke itself is still not CI and does not satisfy the missing Developer ID,
minimum-OS, replacement, notarization, or two-clean-builder vectors above.

## Implementation checkpoint — 2026-08-02

Release construction and the installed-user final-image gate now parse
`LC_BUILD_VERSION` and refuse when the executable's actual minimum macOS
version is newer than the catalog's authenticated baseline. The current
macOS arm64 stub declares 11.0 and is conservatively cataloged at 14.0. The
complete current-source kit passes strict codesign inspection after
inject-then-sign and the final-image system-library/RPATH audit. Developer ID,
hardened-runtime/notarization, signature-replacement, and macOS two-clean-
builder evidence remain open.

## Implementation checkpoint — 2026-08-02 (signing vectors)

The credential-free acceptance vectors are now complete. Unit coverage mutates
realistic thin Mach-O layouts and proves refusal for an extant or duplicate
signature command, duplicate payload, nonzero/insufficient command slack,
nonterminal or truncated `__LINKEDIT`, trailing bytes, an invalid signature
magic or range, and a zero-sized signature. The installed-user gate removes the
ad-hoc signature from a completed application, proves that the authenticated
stub-core, inner graph identity, and CompilePlan are unchanged while platform-
signature validation becomes false, replaces the signature with the hardened-
runtime option, verifies it strictly with the system `codesign`, rechecks those
exact identities, relocates the result after source/catalog withdrawal, and
completes real Fetch. Signature
removal is deliberately not treated as a byte inverse of Apple's signer; the
stable unsigned build identity and the independently authenticated inner
identity/signature state are the contracts.

The minimum-platform, malformed/refusal, and credential-free hardened-runtime
vectors above therefore no longer remain. Release closure still requires a
real Developer ID hardened-runtime signature with secure timestamp,
notarization verification (and an
appropriate staplable distribution container if offline Gatekeeper validation
is required), plus an independent matching-toolchain macOS reproducibility
receipt. On 2026-08-02 the matching Xcode 26.6 MacBook Air was unreachable;
the reachable Mac mini has Xcode 26.4.1 and cannot count as an identical-
builder comparison against the Xcode 26.6 producer.

The receipt path now makes that distinction executable rather than relying on
job naming. Release-kit evidence records a builder id, clean Git commit/tree,
host tuple, Rust/Cargo, C compiler, linker, Xcode, and SDK. Reproducibility
report v2 refuses reused/unidentified builder ids, dirty or different source,
and every mismatched toolchain field before accepting equal unsigned artifact
identities. Synthetic pass, copied-receipt, wrong-compiler, and dirty-source
vectors run in the SFE foundation gate. The Xcode 26.6 second physical build
itself remains pending while that machine is offline.

## Implementation checkpoint — 2026-08-03

The configured Developer ID certificate has now signed a fresh completed
standalone with `--options runtime --timestamp`. The result carries the
hardened-runtime flag, expected Developer ID authority/team, and an Apple
timestamp; strict system verification, Ibex inspection, relocation, and Fetch
all pass. `spctl`'s remaining refusal is exactly `Unnotarized Developer ID`.
There is no configured `notarytool` keychain profile or API-key credential on
this builder, so the notarization/ticket leg still requires publisher input.

The matching Xcode 26.6 MacBook Air is now reachable and produced an
independent default/debugger-enabled Hermes build. Both architectures of the
three SFE static inputs have identical member sequences, sizes, and extracted
object-file digests across the two Macs. Their raw fat-archive digests differed
only because the archive headers retained build-time member timestamps and
numeric owner/group ids. Reconstructing each thin slice with Apple's
deterministic `libtool -D`, then recreating the universal archive in canonical
architecture order, makes all three real inputs byte-identical.

`scripts/build-hermes.sh` now performs that transform before publishing its
cache, which also rotates the source-profile cache key because the builder
script is authenticated build authority. The SFE foundation gate covers two
synthetic builder timestamps, byte convergence, idempotence, and exported
symbol preservation. The exact pre-fix physical archives also converge under
the checked transform. The issue remains open until two fresh full release-kit
receipts from the rotated cache key pass the strict comparator and the signed
artifact is notarized.
