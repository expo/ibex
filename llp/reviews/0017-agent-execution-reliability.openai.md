# Review: LLP 0017 — Agent Execution Reliability Plan

**Reviewer family:** OpenAI
**Provider / runtime:** Codex · GPT-5
**Date:** 2026-07-05
**Redacted:** No — the review was performed against local repository sources in this checkout.
**Method:** Direct local review. I read the LLP 0017 draft, LLP 0000, the LLP 0005 review guide, the existing Claude-family review artifact, and the live repo surfaces cited by the plan (`.githooks/*`, `scripts/sync-agent-skills.sh`, `scripts/install-agent-skills.sh`, `package.json`, `vendored-generated/README.md`, LLP 0012, and LLP 0015). This Codex session did not author the draft, but the draft credits prior Codex involvement, so treat this as a fresh OpenAI-family pass rather than evidence that all drafting-family blind spots are exhausted.

## Overall assessment

Revise and stay `Draft`.

The plan is directionally right and already incorporates the most important Claude-family feedback: it distinguishes no-network from no-mutation, names generated-artifact drift as a first-class landing hazard, ties the direct-to-main decision to the hook fix, and keeps the hermetic build invariant intact. The P0/P1/P2/P3 sequencing is also sensible.

I found two remaining issues worth fixing before the author treats the draft as ready for implementation. One is a real operational gap: the install script currently configures `core.hooksPath` automatically, so a plan that inverts the hook default must also constrain the installer. The other is a precision issue in the bug-mechanism text: the current `sync-agent-skills.sh` clone branch means an absent `.agent-skill-sources/<name>` directory alone does not reach the dangerous `git -C "$dir" remote set-url` path. The upward-discovery hazard is still worth guarding against, but the regression test should reproduce a path that actually reaches the mutating update branch or should be described as a guard against malformed/aliased source checkouts.

## Strengths

- **§Constraints From Existing LLPs** correctly binds the new convenience commands to LLP 0005/0006/0012 instead of letting agent ergonomics weaken the hermetic default.
- **§Plan item 1** has the right priority. Hidden Git hook side effects plus shared worktree config are the highest-blast-radius failure mode in the draft.
- **§Plan item 2** is scoped well: a single regenerate command plus a non-mutating drift check is exactly the surface agents need, and preserving `refresh:vendored` avoids losing the build.rs-mediated path from LLP 0005.
- **§Plan item 5** now states the direct-to-main dependency explicitly, which closes the biggest policy loop from the pilot feedback.

## Concerns

- **C-1 (medium) — The installer can silently re-enable the hooks the plan wants to make opt-in.** `scripts/install-agent-skills.sh` runs `scripts/sync-agent-skills.sh` and then unconditionally sets `core.hooksPath .githooks` when the repo is a Git worktree (`scripts/install-agent-skills.sh:17,92-94`). If item 1 inverts the hook default but the installer still configures hooks without an explicit opt-in, a future "refresh my skills" command can put the checkout back into the hidden-hook regime. **Resolves when:** item 1 covers `install-agent-skills.sh` and says installer/update flows must not enable automatic hook sync unless the user explicitly opts in.
- **C-2 (medium) — The upward-discovery reproduction is overstated for the current script.** The draft says a fresh worktree with `.agent-skill-sources/` absent lets `git -C` escape upward. In the live script, `ensure_repo` checks `[ ! -d "$dir/.git" ]` first; if `$dir` is absent it runs `git clone ... "$dir"` and returns, and if `$dir` exists but is not a checkout it dies before running `git -C` (`scripts/sync-agent-skills.sh:76-83`). The dangerous `git -C "$dir" remote set-url` path is still insufficiently validated, especially for malformed, aliased, or wrong-identity source directories, but absence alone is not the current trigger. **Resolves when:** the mechanism text and acceptance criteria are narrowed to "before any update-path mutation, prove `$dir` is exactly the managed source checkout and not the Ibex repo or any outside worktree," without claiming that absence alone reaches `remote set-url`.
- **C-3 (low) — The safe-hook target state could be made mechanically testable.** The plan says hook-triggered sync cannot mutate unless opted in, but it does not say which command/test asserts the installer leaves `core.hooksPath` alone in non-opt-in mode. **Resolves when:** item 1 acceptance includes an install/update smoke that runs without the opt-in env var and verifies `core.hooksPath` is not changed to `.githooks`.

## Suggestions

- Add a `Revised` metadata line when applying this review, since the draft is changing substantively after review feedback.
- Replace the "fresh worktree with `.agent-skill-sources/` absent" acceptance language with two tests: one for normal fresh-worktree hook execution preserving `origin`, and one for a malformed or wrong-identity managed source path that proves the script refuses before `remote set-url`.
- Keep ENG-22986 focused on the P0 hook/install safety work unless Linear already has a broader breakdown. The drift-check and build-machine work are separable enough to track as follow-ups.

## Open questions

- Should `install-agent-skills.sh` stop configuring `core.hooksPath` entirely, or should it require an explicit flag such as `--enable-hooks`?
- Should the hardening test intentionally create a bogus `.agent-skill-sources/llp/.git` that points at the Ibex Git directory, or is a simpler wrong-identity checkout enough to prevent regressions?

## Recommended next step

Revise LLP 0017 to address C-1 through C-3, keep `Status: Draft`, and then decide whether to gather another fresh non-OpenAI/non-Claude review. For this plan's current blast radius, the existing Claude artifact plus this OpenAI artifact is a reasonable first formal loop, but the shell/Git failure mode is important enough that a second implementation-time review of the actual script patch would still be worthwhile.
