# Linux runtime and Snapback2 publication code review — r1.sol

**Date:** 2026-09-11
**Model / effort:** gpt-5.6-sol / xhigh
**Runtime:** codex-cli 0.153.4
**Session:** `01a090df-03c1-74d1-bcd7-995f13180df4`
**Interval:** 2026-09-11T14:28:49Z – 2026-09-11T14:40:51Z
**Ibex target:** `f9f352057a1e5a5ee361e8c634890a8285ad85b8`
**Snapback target:** `b0489fd1e02419574ebd058b49c26d0be9f18867`
**Method:** Fresh mutually blind read-only source-capsule review; one reviewer,
no subagents, clones, builds, remote commands, web access or edits. Reviewer
received no peer findings. The two projects were reviewed together because
this publication depends on the Linux engine port. This is a code review,
not author acceptance of an LLP or production qualification.

First-round findings are historical and are not silently rewritten when
fixed or declined. Dispositions and later source-bound evidence are recorded
in Snapback's `benchmarks/runs/2026-09-11-snapback2-release-0024-linux/`.

## Received review text

## Verdicts

- **Ibex2 `f9f352057…`: NOT READY**
- **Snapback2 `b0489fd1e…`: NOT READY**

## Findings

### Ibex2

- **High — Vanilla Linux can still build without required Intl.**  
  [build-hermes-linux.sh:27](/Users/ccheever/release-inputs/snapback2-linux-20260911/ibex-f9f352057/scripts/build-hermes-linux.sh:27), [build-hermes-linux.sh:81](/Users/ccheever/release-inputs/snapback2-linux-20260911/ibex-f9f352057/scripts/build-hermes-linux.sh:81)  
  With `HERMES_ENABLE_INTL=false`, `--vanilla` preserves the false value. The resulting unpatched engine can receive the same vanilla receipt and later pass the publisher’s engine-description check despite lacking the mandated Hermes+Intl profile.  
  **Minimal correction:** make vanilla Linux unconditionally enable Intl, or reject a false Intl environment setting before configuring CMake.

- **Medium — The receipt can bind the wrong platform’s compiler.**  
  [hermes-input-receipt.mjs:105](/Users/ccheever/release-inputs/snapback2-linux-20260911/ibex-f9f352057/scripts/hermes-input-receipt.mjs:105), [bytecode.rs:356](/Users/ccheever/release-inputs/snapback2-linux-20260911/ibex-f9f352057/crates/ibex2/src/bytecode.rs:356)  
  The receipt producer hashes the first unsorted `hermesc-*` entry. If Mac and Linux tools coexist, a Linux receipt can record the Mac compiler; the actual build selects `hermesc-linux-x64` and then refuses the mismatched digest. The scanner is inherited, but adding Linux artifacts makes this ambiguity newly reachable.  
  **Minimal correction:** select the exact host OS/architecture compiler using the same mapping as `bytecode.rs`, honor an explicit compiler path, and fail if it is absent.

- **Medium — The supplied Linux loader test contradicts the new case-sensitive behavior.**  
  [loader.rs:660](/Users/ccheever/release-inputs/snapback2-linux-20260911/ibex-f9f352057/crates/ibex2/src/loader.rs:660), [resolution.rs:487](/Users/ccheever/release-inputs/snapback2-linux-20260911/ibex-f9f352057/crates/ibex2/tests/resolution.rs:487)  
  On a case-sensitive filesystem, `require("./LOCKED.js")` now correctly returns a resolution error when only `locked.js` exists. The test still requires no error and two successful module calls. Therefore the capsule does not support the reported Linux `46/46` result as written.  
  **Minimal correction:** make the test detect filesystem case behavior: expect refusal on case-sensitive filesystems and shared canonical identity on case-folding filesystems.

### Snapback2

- **High — A mismatched resume selection is rebuilt, not failed closed.**  
  [publish.mjs:496](/Users/ccheever/release-inputs/snapback2-linux-20260911/snapback-b0489fd1e/snapback2/scripts/publish.mjs:496), [publish.mjs:508](/Users/ccheever/release-inputs/snapback2-linux-20260911/snapback-b0489fd1e/snapback2/scripts/publish.mjs:508), [publish.mjs:815](/Users/ccheever/release-inputs/snapback2-linux-20260911/snapback-b0489fd1e/snapback2/scripts/publish.mjs:815)  
  When an existing resume contains a different platform selection or imported integrity, `loadResume` returns `undefined`; `stagePublication` then deletes and rebuilds the staging directory. That silently changes the immutable candidate instead of refusing the mismatched resume. The generic invalid-resume rebuild behavior is inherited, but the new exact-selection branch adopts it.  
  **Minimal correction:** when `resume.json` exists, throw on selection or integrity mismatch. Only prepare anew when no resume exists, or behind an explicit restage operation.

- **Medium — `--stage-only` can contact the npm registry.**  
  [publish.mjs:133](/Users/ccheever/release-inputs/snapback2-linux-20260911/snapback-b0489fd1e/snapback2/scripts/publish.mjs:133), [consumer-smoke.mjs:119](/Users/ccheever/release-inputs/snapback2-linux-20260911/snapback-b0489fd1e/snapback2/scripts/consumer-smoke.mjs:119), [publish.mjs:1124](/Users/ccheever/release-inputs/snapback2-linux-20260911/snapback-b0489fd1e/snapback2/scripts/publish.mjs:1124)  
  Although stage-only returns before `npm view` or `npm publish`, earlier unqualified `npm install` calls can fetch TypeScript, React, Vite, and optional-package metadata from the configured registry on a cold cache.  
  **Minimal correction:** run both stage-only installation phases with npm offline mode and fail on a cache miss.

## Inspection and verification status

I read both complete patches first, then the specified rules/LLPs and relevant build, receipt, loader, Rust/rustls transport, publisher, shim, consumer, qualification, and resume code. The Rust-owned Linux fetch authority, foreign-artifact non-execution, platform identity checks, final-shim integrity binding, and Mac-specific source branches showed no additional introduced defect in static review.

I ran no commands that build or test code and did not use git metadata, remotes, the web, or other review output. Consequently I did not independently verify the reported results, full Linux execution, Mac regression, static-link/glibc observations, Ubuntu benchmark, or mandatory production/media/installed-consumer qualification. Those remain pending verification, not inherited product defects. The deliberately pending production dependency-pin integration is not treated as a finding.
