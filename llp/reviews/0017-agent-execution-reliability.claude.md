# Review: LLP 0017 — Agent Execution Reliability Plan

**Reviewer family:** Claude (Anthropic)
**Provider / runtime:** Claude Code · model `claude-opus-4-8[1m]`
**Date:** 2026-07-05
**Redacted:** No — the review was performed entirely against local repo sources; no
document content was transmitted to any external provider.
**Method:** Direct provenance verification. Every `[observed]` citation was read
against its cited file and line range (`.githooks/post-checkout`,
`scripts/sync-agent-skills.sh`, `package.json`, the six generated-artifact paths,
and the live `origin` remote). This Claude session did **not** author the draft
(Author: *Charlie Cheever / Claude (pilot feedback) / Codex*), so it stands as one
independent family reviewer per
[LLP 0005 review process](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md).

## Overall assessment

**Revise and stay `Draft`.** This is a strong, well-scoped operational plan. It
turns a candid pilot retro into concrete, testable repo work, correctly ranks the
skill-sync hook as the P0 hazard, and grounds itself in prior LLPs (0005/0006/0012/
0015/0001) so the convenience commands it proposes don't violate the hermetic-default
invariant. Acceptance criteria are specific and mostly falsifiable, and the sequencing
is sane. The provenance discipline holds up: I re-read every cited file and the claims
are accurate.

The revisions worth making are all in service of the P0 item, where the plan describes
the hazard at the right altitude but stops one level short of the mechanism — and that
last level is where the regression test and the fix actually live. Everything below is
non-blocking for `Draft`, but items C-1 and C-2 would materially harden the plan.

## Strengths

- **§Constraints From Existing LLPs** is the best part of the doc. It pre-empts the
  obvious failure mode (a convenience `regenerate` command quietly becoming part of the
  default `cargo build`) by binding item 2 to LLP 0005/0006 up front. This is exactly
  the kind of cross-LLP grounding the corpus is for.
- **§Plan item 1** correctly identifies remote mutation in a shared `.git/config` as
  the highest-severity issue and orders the mitigations sensibly (invert the default →
  non-mutating relink → harden the script). Option 3's proposed guard — assert
  `git -C "$dir" rev-parse --show-toplevel` equals the source dir before any mutation —
  is precisely the right defense for the "git discovers a parent repo" class of bug.
- **Acceptance criteria are concrete.** Line 118 pins the exact expected remote
  (`https://github.com/ccheever/ibex.git`), which I verified is the live `origin`. That
  makes the item-1 regression test unambiguous to write.
- The plan resists over-reach: item 4 keeps shared `CARGO_TARGET_DIR` gated behind an
  explicit single-writer guarantee, and item 5 refuses to smuggle a landing-policy
  decision in as an implementation detail.

## Concerns

- **C-1 (medium) — "no-fetch" is not "no-mutate"; the plan should say so.**
  `scripts/sync-agent-skills.sh` already has a `--no-fetch` flag and an
  `IBEX_AGENT_SKILLS_NO_NETWORK=1` env var (lines 17-18, 37-39), which item 1 option 2
  ("restrict to a non-mutating local relink path: no fetch") does not mention. More
  importantly, the dangerous operation is **not** gated by fetch: `remote set-url`
  runs unconditionally at lines 86-89, *above* the `if [ "$fetch" -eq 1 ]` block.
  So the existing no-fetch mode still repoints the remote. The plan reads as if
  "no fetch" ≈ "safe"; it should state that the set-url is currently unconditional and
  that the relink path must explicitly skip it. **Resolves when:** option 2's text
  names `remote set-url` (line 88) as an operation to remove/guard, distinct from fetch.
- **C-2 (medium) — §Current Repo Surface describes the call surface but not the escape.**
  The section accurately lists what `ensure_repo` *can* do (set-url, fetch, switch,
  pull) but doesn't pin *how* those operations escaped `.agent-skill-sources/` and hit
  the Ibex repo. The pilot feedback names it: `git -C "$dir"` with `$dir` not itself a
  Git repo lets Git walk up to the enclosing Ibex worktree, so the set-url lands on
  Ibex's shared config. Without that mechanism written down, the item-1 acceptance
  test ("triggers checkout hooks, asserts origin unchanged") can pass against a
  configuration that never reproduced the bug. **Resolves when:** the plan states the
  upward-discovery mechanism and the regression test asserts it reproduces the trigger
  (e.g. a source dir that is absent or not a Git toplevel), not merely that a hook ran.
- **C-3 (low) — item 2's check mode is underspecified in a way that decides whether
  `check:drift` mutates the tree.** The item hedges "runs the same generators in check
  mode where a generator supports it; otherwise regenerates and fails if tracked outputs
  differ." None of the five scripts in `package.json:9-13` is asserted to have a check
  mode, so in practice `check:drift` may regenerate-and-diff for all of them — which
  writes to `vendored-generated/` as a side effect of a "check." For a command CI and a
  pre-push playbook run, that side effect matters. **Resolves when:** the plan states
  which generators get a real `--check` and confirms the diff path restores/leaves the
  tree clean (e.g. runs against a temp out-dir).
- **C-4 (low) — two regenerate paths that must agree, with no stated parity check.**
  The existing `refresh:vendored` (`package.json:14`) regenerates via a full
  `IBEX_REGENERATE_RUNTIME=1 … cargo build --features openssl-crypto` through `build.rs`;
  the proposed `regenerate:vendored` runs the five bun generators directly. The plan
  keeps both (item 2 acceptance, line 158-159) but doesn't assert they produce
  byte-identical `vendored-generated/` output. If they can diverge, agents now have two
  commands that disagree and a `check:drift` whose verdict depends on which one last ran.
  **Resolves when:** the plan states they must produce identical bytes (and ideally that
  `check:drift` is what enforces it), or documents the intended difference.

## Suggestions

- **Name the coupling between item 1 and item 5.** The whole plan exists because an
  automatic hook silently mutated a *shared* remote — and item 5 contemplates keeping
  *direct pushes to `main`*. Unconditional-remote-mutation + direct-to-main is exactly
  the pair that turned a papercut into a near-miss push to the wrong repo. The sequencing
  (P0 before P3) implies the dependency, but item 5's body should state that any
  direct-to-main option is contingent on item 1 having landed. The doc already gestures
  at this (line 221-222); making it a named precondition would close the loop.
- **Consider folding the two "already fixed for the run" mitigations into the doc as
  the current interim state.** `core.hooksPath` is presently pointed at an empty dir and
  playbooks use explicit URLs (I confirmed the former locally). A one-line "Interim
  state" note would keep the plan honest about what protection exists *today* vs. what
  the P0 fix makes durable.

## Open questions (beyond those already listed)

- Does `regenerate:vendored` (5 bun generators) produce the same bytes as
  `refresh:vendored` (build.rs path)? This is the load-bearing assumption behind having
  both. (→ C-4)
- Should `check:drift` be required to run without writing to the working tree, so it's
  safe to wire into CI and a pre-push hook without a dirty-tree race? (→ C-3)

## Recommended next step

**Revise and stay `Draft`**, applying C-1 through C-4 (all are code-grounded and
low-risk to incorporate). Then, if the author wants the formal loop for a plan of this
blast radius, **gather one non-Claude family review** — there's precedent in this corpus
(LLP 0013 carries both `openai` and `claude-fable` artifacts). A single Claude session
is not a substitute for a second family on the skill-sync hazard, which is a
shell/Git-semantics question where a different family may catch a different escape path.
