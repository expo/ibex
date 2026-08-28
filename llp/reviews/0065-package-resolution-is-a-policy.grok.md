# Review of LLP 0065 and the package-resolution change — xAI Grok family

**Reviewer family:** xAI Grok
**Provider / runtime:** grok 1.0.5 (5115b46bc909) / `grok-4.6`
**Model / effort:** requested `grok-4.6` / `xhigh`
**Date:** 2026-08-28
**Target:** commit `4e4fff556` — `crates/ibex2/src/loader.rs`, `src/transport/darwin.rs`, `src/engine/darwin_http.mm`, LLP 0065
**Method:** Headless CLI session with repository access; reviewer ran its own probes against real temp directories on an APFS (case-insensitive) volume
**Scope:** Adversarial code review, not an LLP 0005 document round. Priorities given: containment, FFI soundness, resolution-policy correctness, test quality.

## Disposition

Every confirmed finding was **independently reproduced** before being acted on;
the probes are recorded in the commit that fixes them. Nothing was taken on the
reviewer's word, and nothing it confirmed turned out to be wrong.

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | HIGH | Relative resolution does not canonicalize; `read_to_string` follows a symlink, so an in-tree package can execute out-of-tree bytes | **Fixed** — both arms now go through `loader::contain` |
| 2 | HIGH | Grant identity is the specifier *spelling*; one file under two names is two grant sets, so a locked-down module inherits `[*]` under its other name. Also via case alias on macOS | **Fixed** — canonical identity; two regression tests |
| 3 | HIGH | Package resolution still cannot load Exact: root is `entry.parent()`, so a hoisted `node_modules` is above it | **Open** — LLP 0065 OQ4; found independently by the author before the review |
| 4 | MEDIUM | Shared ephemeral session keeps an in-memory cookie jar and URL cache; comments claimed neither. Cookies are domain-scoped where grants are origin-scoped | **Fixed** — cookies and cache disabled, asserted against the live configuration |
| 5 | MEDIUM | `full_path()` appends `?query`/`#fragment` to the filesystem path | **Fixed** — `path()`, with a regression test |
| 6 | HIGH | `CONDITIONS` is a *set* matched in package key order, not a preference order; a `node`-only package does not fall through to `default` | **Fixed in docs and tests** — behaviour was correct, both claims about it were false |
| 7 | MEDIUM | `.json` dropped from `extensions` | **Ticketed** — issues/20260828-json-modules-do-not-resolve.md |
| 8 | HIGH | The connection-reuse test measured the URL cache, not the pool; and a failed `send` was a pass | **Fixed** — asserts `NSURLSessionTaskMetrics.reusedConnection` directly |
| 9 | MEDIUM | Several tests could not fail the claim in their comment | **Fixed** — fixtures rewritten so they can |
| 10 | LOW | Stale comments describing the retracted `symlinks: false` policy | **Fixed** |

On FFI the reviewer confirmed the change **sound**: correct ARC `+1` handoff,
no retain cycle, and no send/Drop race — the worker's `Arc<RuntimeState>` keeps
the transport alive across the blocking call. It noted that `OnceLock<usize>`
launders pointer provenance to avoid an `unsafe impl Send + Sync`, which is
accurate: it is the same claim with the provenance erased, and it is kept
because `NSURLSession` is thread-safe and the handle is write-once.

It found **nothing at critical severity**, and said so plainly rather than
inflating: bare-specifier containment against parent `node_modules`, absolute
paths, and `exports` targets containing `..` were all genuinely enforced.

## What it got right that the author had not

The author's own pass had already found #3, the inert `symlinks: false` option,
and the eager-session boot regression. It had **not** found #1, #2, #4, #5, #6,
or #8 — including two confirmed capability bypasses and a security regression
introduced by the session change under review.

## The reviewer's summary judgement, quoted

> They keep enforcing **strings**, then talking as if they had enforced
> **files**. [...] Commit `4e4fff556` correctly retracted "`symlinks: false`
> weakens containment." It did not notice that containment was only ever applied
> to one of the two resolver arms, or that the grant map uses the arm's spelling
> as identity.

Accepted. `loader::contain` exists because of it, and LLP 0065 §4.1 states the
general form so the next path that produces a specifier has somewhere to look.
