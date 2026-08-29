# Capsec in Ibex 2: made whole, and bounded

**Status:** Open
**Impact:** 4
**Urgency:** 3
**Ease:** 3
**Confidence:** 4
**Severity:** P2
**Systems:** CapSec, Module Loader, Runtime, Build
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-28
**Related:** LLP 0057 §6 OQ2 (the decision and the list), LLP 0065 OQ2 (package-level grants), LLP 0062 §3–§4 (the freeze and the non-goals), LLP 0058.000.001 (the program to tombstone)

Charlie's requirement: capsec ends up either fully implemented, understood,
testable, and usable — or absent. Exact 2 is expected to run npm
dependencies, so it stays, and this is what "whole" means. Four items; when
the fourth is done the list is closed, not extended.

1. **One page.** A spec that states the model in full (LLP 0057 OQ2 has the
   paragraph; LLP 0060 and LLP 0062 R1–R5 have the pieces) and the non-goals.
   Probably a rewrite of LLP 0060 rather than a new number.
2. **Package-level grants.** Manifest sections name packages
   (`[react]`, `[@scope/pkg]`), resolved to canonical-path prefixes under
   `node_modules`; file-keyed sections stay for first-party code. Refuse a
   manifest that names a package not installed. Tests: a package granted an
   origin reaches it from any of its files; a file inside it cannot borrow a
   sibling package's grant; the same package reached under two names is one
   grant set (LLP 0065 §4.1).
3. **The freeze under `caps`.** `boot_floor` already measures it; `caps`
   refuses a regression past 2 ms.
4. **Tombstone LLP 0058.000.001's program.** G1–G6, graduation manifest,
   tier definitions, five-platform receipts, policy generations, revocation
   ancestry: moved to `llp/tombstones/` with a note saying why. Its §7
   vertical-slice items that are good *tests* (timers ordering, `fs`
   refusal/cancellation, teardown with queued jobs) become tests, not gates.
   LLP 0058.000 and 0058.000.000 get a pass for what still applies once
   there is no patched runtime beside this one.

Explicitly not on the list: compartments, attribution of callers, receipts
beyond the artifact-to-engine key, and anything whose evidence is a proof
rather than a failing test. Adding an item here requires removing one.

**Done when:** a manifest for a real npm dependency graph can be written by
hand in a few lines, every grant and denial in it has a test, the freeze is
a `caps` number, and the corpus has one document that says all of this.
