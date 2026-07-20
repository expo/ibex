# Platform Decision LLP for the 0.2 window close

**Status:** In Progress
**Severity:** P2
**Systems:** Runtime, Build
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0028 §4d, LLP 0001, LLP 0026

**Blocked-on-decision** (register item 1 — the choice is Charlie's;
this ticket drafts the Decision once made). Window close makes every
non-advertised tuple (Windows x64, macOS x64, …) refuse script entries,
and the compat evaluator also serves audit/diagnostics there — closing
the window IS a platform-support decision. The Decision LLP covers
production, audit, diagnostics, and runtime-TypeScript behavior on
every retained tuple: either advertise native-runner artifacts per
tuple (Windows: LLP 0026's patched-Hermes question) or explicit
de-support, reconciling LLP 0001 and LLP 0026. CI tuple requirements
derive from the accepted matrix ("every advertised tuple", never a
hard-coded pair).

**Done when:** Decision LLP accepted; LLP 0001/0026 reconciled; CI
matrix derived from it. Blocks `oxc-window-close`.

## Progress — 2026-07-18

The author selected macOS arm64 and Linux x64 as the evidence-gated 0.2 native
source/module targets, with all other tuples explicitly unsupported until
independently promoted. Draft LLP 0031 records the complete production,
audit, diagnostics, runtime-TypeScript, SFE, and CapSec-advertisement
consequences. Acceptance, governing-doc reconciliation, and generated CI
authority remain before this issue is complete.
