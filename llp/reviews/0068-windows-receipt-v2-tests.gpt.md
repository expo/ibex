# Review of Windows receipt-v2 workflow tests

**Family:** Codex (same family as author; independent parent agent)
**Provider/runtime:** OpenAI Codex desktop multi-agent collaboration
**Date:** 2026-10-04
**Redacted:** No
**Method:** Parent read the current workflow-security test and concrete Windows
failure before implementation.

Approved scope: normalize CRLF at workflow-text ingestion only; preserve the
actual publisher/receipt code and malformed archive checks. Resolve usable
Windows Python without assuming `python3`, and report `spawn.error` explicitly.
Split the privilege-dependent real symlink case from extra entries and changed
bytes. Only unavailable Windows symlink creation may be skipped, with a visible
reason. Record qualification in existing LLP 0068.

The actual new Hermes pin and receipt-v2/runtime qualification remain required;
the old installed distribution is preserved. No production engine, receipt,
publisher or workflow change is authorized by this test-only correction.

This is an independent agent review, not a cross-family model review.

## Independent implementation review

A separate Codex agent reviewed the final three-path diff and the retained
qualification logs before landing. No blocker was found: CRLF handling is
confined to text ingestion, Python spawn and abnormal-exit failures cannot
satisfy negative validator assertions, and the Windows symlink-privilege skip
leaves all other archive checks active. The review verified that the reported
9 passing workflow cases / 1 privilege skip, 645 workspace tests / 23 existing
ignores, 177 engine-free tests / 1 ignore, 205 bindings tests / 1 ignore, exact
100/500 CLI outputs, and old-engine digest refusal match the retained logs.
The reviewer did not rerun builds or independently rehash every engine input.
No production publisher, receipt, or runtime behavior was changed.
