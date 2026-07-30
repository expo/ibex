# Transform-fingerprint registry contract for external producers

**Status:** Open
**Systems:** Module loader, Transforms, CapSec
**Author:** Claude Fable 5 (Claude Code)
**Date:** 2026-07-29

**Filed:** 2026-07-29 (Exact LLP 0416 D2 resolution — non-negotiable
precondition for the adapter-1 root/app-principal lane)
**Related:** Exact LLP 0416 §D2, Exact LLP 0413 §9.5, LLP 0027
(transform_fingerprint composition), LLP 0028 (oxc-only authority)

**Impact:** 5
**Urgency:** 3
**Ease:** 2
**Confidence:** 3
**Score reviewed:** 2026-07-29
**Score rationale:** Adapter-1 publications structurally fail
`verify_current_transform_fingerprint_v1` because the fingerprint
authority is ibex's pinned toolchain; Exact's Phase 2 root-principal lane
is blocked until an external producer can register a verifiable
fingerprint. New dimensions needed: define-table, JSX-runtime mode,
condition sets (per the D2 measurement).

Design the contract by which an external, host-authorized producer (the
Exact dev server / build) declares its transform pipeline as a fingerprint
ibex admission can verify — without weakening the one-transform-authority
principle (LLP 0028): the registry names what transformed the source, it
does not let arbitrary producers claim ibex's own fingerprint.

## Acceptance

- An adapter-1 publication admits with fingerprint currency verified
  against a registered external-producer fingerprint.
- A publication claiming an unregistered or mismatched fingerprint
  refuses.

**LLP:** design drafted as `llp/0043-registered-external-transform-fingerprints.rfc.md` (Draft, 2026-07-30); this ticket tracks implementation once the design is reviewed.
