# Review of LLP 0068 standalone Windows setup

**Family:** Codex (same family as author; independent parent agent)
**Provider/runtime:** OpenAI Codex desktop multi-agent collaboration
**Date:** 2026-10-04
**Redacted:** No
**Method:** Parent read the canonical README/build-path and primary-migration
audit before the documentation and builder hint were changed.

Approved scope: document Windows prerequisites, the exact existing vanilla
builder, separate receipt producer, and full/run-only CLI commands; print the
receipt command after the Windows builder succeeds. Preserve the separate
producer's symbol checks and engine/compiler identity. Add qualification to
the existing Windows section of LLP 0068, with no runtime policy change.

Review conditions: qualify a genuinely fresh source download and Hermes build,
without either Ibex path override or old-checkout artifacts. Use a private
cache/install, then run current full/run-only source/AOT graph checks and
runtime tests, and inspect DLL dependencies. Record the concrete native-tool
path-length failure of the first overlong synthetic cache and retain that
evidence; the shorter fresh-cache retry remains independent of the old cache.

The primary checkout's unrelated old history, its refs and ignored artifacts,
and any global CLI/PATH installation are separate decisions after qualification
and review of the exact backup inventory. This change does not migrate them.

This is an independent agent review, not a cross-family model review.

The parent reviewed the final README, builder hint and LLP qualification after
the cold build, source/AOT checks and runtime rerun. No blocker remained. The
initial HTTP fixture timeout and long-path build failure are explicitly bounded
observations; neither was concealed by a timeout relaxation or runtime change.
The scoped documentation/setup increment was approved for commit and push.
