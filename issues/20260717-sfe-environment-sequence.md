# Compiled-mode environment: capture, default-deny sanitize, broker

**Status:** Open
**Impact:** 5
**Urgency:** 4
**Ease:** 2
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Compiled-mode environment: capture, default-deny sanitize, broker” shows the issue reaches a security, correctness, release, or core product boundary; delay compounds an active rollout, reliability, or verification risk, while the repair crosses several runtime, host, protocol, or policy seams, with specific cited code, progress, or acceptance criteria.
**Progress:** In Progress
**Severity:** P2
**Systems:** Runtime, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 §4, LLP 0022
**Depends-on:** sfe-stub-crate-and-contract

Capture at the earliest executable-controlled hook (platform pre-init
shim before Ibex-controlled constructors; constructor-ordering probes
on both tuples; no pre-main async runtime in the stub; anything
earlier classified outside the boundary with `DYLD_*`/`LD_PRELOAD`).
Sanitize default-deny: clear the entire real environ, restore only the
contract-pinned allowlist (register item 2 decides contents; the
diagnostics toggle is stderr-pinned with count-only scrub reporting).
Broker: app `process.env` served from the base snapshot via the
capability gate with a mutable overlay; children inherit the overlay
exactly. Generate the consumer-to-disposition inventory separating
privileged security controls (`NODE_TLS_REJECT_UNAUTHORIZED`,
`NODE_EXTRA_CA_CERTS`, `EXACT_ALLOW_INSECURE_CRYPTO`, the
`NODE_ENV=test` crypto fallback, `__exactHostEnv`) — moved to a typed
internal config surface answering from the closed profile, inert even
when app-written — from intentional app-behavior reads (debug/terminal)
that keep Node semantics. Name/value algebra stated (non-UTF-8,
duplicates, case folding); enumeration returns the snapshot/overlay
view as a documented LLP 0022 exception; root reads flow through the
exact-name broker gate against the embedded policy's env selectors;
package principals keep per-principal classification.

**Done when:** every profiled variable + child-inheritance + inertness
(via both `process.env` and `__exactHostEnv`) + cross-principal
isolation fixtures pass; LLP 0022 revision landed.

## Progress — 2026-07-17

`ibex/compiled-environment-profile/1` is now generated from the CapSec
source-derived implementation manifest plus a small reviewed classification
authority. All 155 observed startup-environment consumers are classified;
exact names fail closed to `privileged-control`, reviewed debug/terminal reads
are `application-behavior`, and every dynamic consumer has an explicit capture,
broker, or typed-dispatch disposition. New unclassified dynamic consumers fail
drift. The canonical profile, schema, generated Rust/TypeScript digest
constants, and mutation tests are present. Register item 2 remains explicit:
the real-environment restore allowlist is empty and the artifact reports
`releaseEligible: false` until the author decides it. Pre-init capture,
sanitization, typed-control migration, broker overlays, and isolation fixtures
remain implementation work.

## Progress — 2026-07-18

The compiled stub now owns a platform early hook: ELF uses `.preinit_array` and
macOS uses an ordered image constructor. It copies the raw process environment
before the stub's constructor probe, replaces the real environment with only
the build-generated contract allowlist, and refuses boot if capture,
sanitization, or constructor ordering is incoherent. The allowlist is generated
directly from the pinned canonical profile (currently empty); scrubbed/restored
counts cover every captured entry. The immutable Rust projection retains raw
bytes, applies first-wins duplicate semantics, and records names outside the
canonical CapSec vocabulary. The stub source is included in the source-derived
environment inventory, so this capture evidence rotates the profile digest.

Exact reads and enumeration now come from that immutable broker base rather
than the sanitized real environment. Armed enumeration authorizes every key
through the existing requested/commit exact-name gate before disclosure; the
existing JS proxy remains the mutable write/delete overlay used by child
flattening. The signed relocation fixture proves a launch-only value survives
capture/scrub and reaches the application together with reserved-word argv.

The remaining work is privileged-control migration/inertness, child-process and
cross-principal isolation fixtures, and the LLP 0022 enumeration revision.
Author decision 2 still controls the restore allowlist and therefore release
eligibility.
