# Review of the Ibex 2 kernel work, `fdc20c2a6..fa706afa8` — OpenAI Codex family

**Reviewer family:** OpenAI Codex
**Provider / runtime:** codex-cli 0.150.1 / `gpt-5.6-sol`
**Model / effort:** requested `gpt-5.6-sol` / `xhigh`
**Date:** 2026-08-29
**Target:** commits `fdc20c2a6..fa706afa8` — `crates/ibex2`, `scripts/metrics.mjs`, judged against LLP 0067
**Method:** Headless `codex exec` in a detached worktree at `fa706afa8` with the engine artifacts linked in, workspace-write sandbox, network on for the second run
**Scope:** Code review. Priorities given: grant correctness, FFI soundness, spec conformance, tests that cannot fail their claims.

## What happened

**No report was produced.** Two launches — the first with the same brief
Grok received, the second reworded in defect-against-specification terms with
no attack vocabulary — both ran to completion of the review work (135,384 and
307,950 tokens) and were then terminated by the provider's content filter at
the moment of writing the report:

> ERROR: This content was flagged for possible cybersecurity risk. If this
> seems wrong, try rephrasing your request. To get authorized for security
> work, join the Trusted Access for Cyber program.

The reviewer's own interim message before the second termination: "I've
confirmed several specification failures with executable reproductions,
including three grant-boundary defects and two WHATWG mismatches."

This is recorded rather than retried a third time: a capability-model review
is, by its nature, a search for ways a module reaches what it should not, and
that is what the filter refuses to let the model say. LLP 0005's honesty rule
applies — the review was not fabricated, and its findings below are what its
fixtures show, not what it wrote.

## Findings, recovered from the reviewer's fixtures

The second run left its reproductions under `review-scratch/` in the worktree.
Each was re-run by the author, and each reproduced.

| # | Severity | Finding (from the fixture) | Status |
|---|---|---|---|
| 1 | HIGH | `fs-symlink`: a symlink inside a granted prefix reads bytes outside it (`allowed/link.txt -> outside.txt` under a grant on `allowed`) | **Fixed** (`117bce153`) — the request is admitted only if both its spelling and its realized path are covered, against the grant's spelling and realized prefix |
| 2 | MEDIUM | `workspace-grant`: an author's `[./packages/ui/]` directory section outranked an empty `[@w/ui]` package section for a workspace package | **Fixed** (`117bce153`) — bound packages are their own precedence level |
| 3 | MEDIUM | `case-manifest`: `[./LOCKED.js]` did not govern `./locked.js` on a case-insensitive filesystem, so the module inherited `[*]` | **Fixed** (`117bce153`) — sections are canonicalized at bind |
| 4 | LOW | `url-setters`: `host = 'x:80abc'` and `host = 'x:'` did not follow the port state; `protocol = 'http:garbage'` was a no-op | **Fixed** — leading digits, empty buffer leaves the port, scheme up to the first colon |
| 5 | LOW | `env-snapshot`: `process.env` was writable | **Fixed** earlier the same day (`ef35a2030`) — shared bindings are frozen |
| 6 | — | `harden-graph`: a walk of the intrinsic graph for open objects | Now a test, `every_object_reachable_from_the_global_bindings_is_frozen`, which passes after the symbol fix |

The fixtures are not preserved beyond this record; the tests that pin each
finding are named in the commits.
