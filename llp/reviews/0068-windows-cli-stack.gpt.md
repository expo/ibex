# Review of LLP 0068 Windows CLI stack reserve

**Family:** Codex (same family as author; independent parent agent)
**Provider/runtime:** OpenAI Codex desktop multi-agent collaboration
**Date:** 2026-10-04
**Redacted:** No
**Method:** Parent read the proposed amendment and the Microsoft `/STACK` and
Cargo named-binary linker documentation before production implementation.

Approved scope: the existing build script sets an 8 MiB stack reserve only for
the Hermes-enabled Windows MSVC `ibex2` binary. Main-thread ownership, engine
guards and exit/panic behavior remain unchanged. The named-binary instruction
must not impose the CLI's allocation policy on embedders or other artifacts.

Review conditions: assert actual 100/500-module source and precompiled results;
inspect the full and run-only CLI's 4 KiB initial commit and 8 MiB reserve, and
verify absence of leakage to library/example/test/no-engine artifacts. Preserve
the distinction between the CLI's async pump budget and the runtime's explicit
deadline API; use the existing deadline suite to qualify the latter.

This is an independent agent review, not a cross-family model review.

After qualification, the parent read the final four-line target guard, actual
source/AOT value assertions and error/budget regression, and reviewed the PE
header evidence. The implementation and its reported limits were approved for
a scoped commit; no blocking issue remained.
