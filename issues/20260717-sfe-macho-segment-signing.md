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
