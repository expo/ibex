# LLP 0018: Agent Tooling Should Fail Loud, Not Silent-Green

**Type:** Plan
**Status:** Draft
**Systems:** Tooling, Build, Agent Skills, Developer Experience, CI
**Author:** Charlie Cheever / Claude (second-round pilot feedback)
**Date:** 2026-07-05
**Related:** LLP 0000; LLP 0005; LLP 0006 (fail-closed/loud principle); LLP 0015 (build machines); LLP 0017 (agent execution reliability); ENG-22986

## Summary

LLP 0017 landed the first round of agent-execution reliability infrastructure:
safe skill sync, a single regenerate/drift path, a portable timeout wrapper, and
a worktree artifact linker. A second round of pilot runs then hit a new class of
friction that 0017's code surface *introduced or left open*. The common thread is
sharper than any single script: **the tooling agents depend on can produce a
result that looks green but is wrong or empty** — a symlink step that links
nothing and exits 0, a test invocation that runs zero tests and exits 0, a build
that silently redoes ~40s of work because a cache was never wired up, a wrapper
that exists without the binary it wraps.

This plan turns that second round of feedback into repo-level work and names the
governing rule so future agent tooling is held to it: **an agent-facing command
must fail loud when its postcondition is not met, never exit 0 on a no-op the
caller expected to be an op.** LLP 0006 already states this posture for the
build (`missing artifacts fail the build loudly rather than silently
regenerating`); this plan extends it from the build to the agent tool surface.

## Motivation

The second-round pilot feedback surfaced four concrete frictions. Every one of
them is a *silent-green* failure: the failure mode is not a crash the agent can
see, but a success the agent can't distrust.

1. **`link-worktree-artifacts.sh` links into the wrong checkout, then reports
   success.** The script anchors its *destination* to its own file location
   (`repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"`
   `[observed]`, `scripts/link-worktree-artifacts.sh:16`) rather than to the
   worktree the agent is actually working in. The natural agent workflow is to
   `cd` into a fresh worktree and invoke the *warm primary's* copy of the script
   by path. When they do, `repo_root` resolves to the primary and the default
   source *also* resolves to the primary (`git worktree list` first entry,
   `:34`), so the source==dest guard trips (`:39-42`) — or, absent that guard,
   the loop links nothing and still prints `Done: 0 linked, N skipped` and exits
   0 (`:73`). Either way the fresh worktree gets no `ios/Frameworks`, and cargo
   dies much later on a missing Hermes framework, far from the real cause. The
   pilot reports every agent hit this.

2. **`cargo test --bin ibex <filter>` is a false-pass trap.** The bulk of the
   suite lives in the `ibex_runtime` **lib** crate (17 `mod tests` files under
   `src/` plus integration tests under `tests/`) `[observed]`
   (`Cargo.toml:9-15`). `--bin ibex` scopes to the binary target
   (`src/bin/ibex/`) only. An agent verifying a lib-crate fix with a filter that
   matches a lib test but scopes to `--bin ibex` runs **zero** matching tests —
   and `cargo test` exits 0 on zero tests. The agent reads green and lands an
   unverified change. The interim mitigation is a playbook rule forcing an
   explicit `--lib`/`--test` choice and an "N passed > 0" check; this plan makes
   that a tool, not a habit.

3. **Cold native builds re-do ~40s of CPU per worktree because no cache is wired
   up by default.** LLP 0017 §4 chose to *not* link `target/` across worktrees
   (concurrent Cargo writers contend/corrupt) and to prefer `sccache` plus an
   APFS `cp -c` clone of a warm `target/` as the fallback. Both are still
   un-bootstrapped: nothing wires the APFS clone into worktree setup, and
   `sccache` / `RUSTC_WRAPPER` is documented but not installed
   (`0017-agent-execution-reliability.plan.md:342-351`). The result is silent
   waste — correct output, duplicated cost, per worktree, every time.

4. **`with-timeout.sh` existed before the binary it wraps did.** The wrapper
   correctly errors with exit 127 when neither `timeout` nor `gtimeout` is
   present (`scripts/with-timeout.sh:24-33`) — the one item in this list that
   *does* fail loud — but the macOS build machine shipped without GNU coreutils,
   so the wrapper was dead on arrival until `brew install coreutils` was run.
   This is the mildest case (it fails closed), but it is the same shape: a tool
   whose precondition was never established.

Items 1 and 3 are follow-through on 0017 deliverables that shipped with a
silent-green edge; item 2 is new; item 4 is now operationally resolved and is
recorded here to close the loop and seed the bootstrap checklist.

## The governing rule

**Agent-facing tooling fails loud when its postcondition is unmet.** Concretely,
a command an agent uses to make a change happen or to verify one must not exit 0
when:

- it did nothing but the caller expected it to do something (0 symlinks, 0 tests,
  0 files regenerated) — unless "nothing to do" is explicitly the requested,
  already-satisfied state;
- it ran its inner commands successfully but the *postcondition* those commands
  were for is still false (script ran, but `ios/Frameworks` is still absent);
- it is a wrapper whose underlying binary is missing (already correct for
  `with-timeout.sh`; the standard to hold new wrappers to).

This is the same instinct as LLP 0006's "Hermetic by default, regeneration by
opt-in" — failing closed keeps "did this actually work?" an *observable*
property instead of a latent surprise. The agent context makes it sharper: an
agent cannot eyeball a terminal the way a human skimming for red can. A green
exit is load-bearing, so it must mean what it says.

## Constraints from existing LLPs

- **LLP 0017 §4** deliberately forbids a shared `CARGO_TARGET_DIR` across
  worktrees without a single-writer guarantee. Item 3 here must keep the APFS
  per-worktree clone and `sccache` as the sanctioned fast paths; it must not
  "fix" the cost by sharing one mutable `target/`.
- **LLP 0015** records the reachable build machines as an inventory, not a CI
  contract. Bootstrapping coreutils and `sccache` on them is operational setup;
  if these become persistent requirements, 0015 is updated (as 0017 §3 already
  notes).
- **LLP 0005 / LLP 0006** keep the default build hermetic and fail-loud. Nothing
  here may make a normal `cargo build` depend on bun/`node_modules`, and the
  fail-loud additions must not weaken the existing loud-on-missing-artifact
  behavior.

## Plan

### 1. Make `link-worktree-artifacts.sh` target the invoking worktree and fail loud on a no-op

The destination must be *where the agent is*, not *where the script file is*, so
that running the warm primary's copy from inside a fresh worktree links into the
fresh worktree.

- Resolve the **destination** worktree from the invocation, not from
  `BASH_SOURCE`: prefer `git -C "$PWD" rev-parse --show-toplevel`, falling back
  to `$PWD`, and accept an explicit `--dest DIR` argument for the case where the
  agent is not `cd`'d into the target. Keep `BASH_SOURCE`-relative resolution
  only for locating the *default warm source* (the primary), never the
  destination.
- Keep the source==dest guard, but reframe its message around the new model
  ("run from inside the worktree you want to populate, or pass --dest").
- **Fail loud on an empty result.** If zero artifacts were linked *and* the
  destination is missing an artifact the caller needs, exit nonzero. At minimum,
  a `--require ios/Frameworks,tools/hermes` mode (or a default required set)
  makes the script assert the postcondition — the artifacts exist at the
  destination after the run — rather than reporting `0 linked` as success.
- Update the script's own usage doc and every playbook that invokes it to the
  corrected invocation, since the current header example is what led agents to
  run it wrong (LLP 0017 §3 acceptance: playbooks use the wrapper correctly).

Acceptance criteria:

- Running the primary checkout's copy of the script from inside a fresh worktree
  links the artifacts into the **fresh worktree**, not the primary.
- A run that links nothing while a required artifact is still absent at the
  destination exits nonzero with a message naming the missing artifact.
- An idempotent re-run on an already-linked worktree still exits 0 (already in
  the desired state is not a silent no-op).
- A smoke test covers: fresh-worktree link-in via the primary's copy; the
  required-artifact-absent failure; the idempotent re-run.

### 2. Give agents a test entry point that cannot silently run zero tests

Replace the fragile "remember to pass `--lib` and eyeball the count" habit with a
wrapper that enforces both.

- Add `scripts/run-tests.sh` (name TBD) that drives `cargo test` with the correct
  default scope for this crate layout (lib + integration tests, not `--bin`
  alone), parses the `test result: ... N passed` lines, and **exits nonzero if
  the total tests run is zero** unless an explicit `--allow-zero` is passed (for
  the rare intentional case).
- The wrapper forwards a filter argument to the right scope so that
  `run-tests.sh deep_freeze` runs the lib tests matching `deep_freeze`, not a
  zero-test `--bin` scoping.
- Update the agent playbook so verification goes through the wrapper; keep the
  raw `cargo test` documented for humans who know the scoping.

Acceptance criteria:

- A filter that matches only lib tests runs them (nonzero count) instead of
  silently running zero.
- A run that matches zero tests exits nonzero by default.
- The wrapper's exit status is the real test outcome, not masked by the parsing
  step.

### 3. Wire up a native build cache by default, safely

Make the fast path the *default* path, without violating LLP 0017 §4's
single-writer rule.

- Bootstrap `sccache` on the reachable macOS/Linux build machines and export a
  documented `RUSTC_WRAPPER=sccache` + persistent `SCCACHE_DIR` in the agent run
  environment, so cross-worktree compilation is deduplicated at the compiler
  level (the write-safe way to share build work).
- Provide an opt-in `--clone-target` path in worktree setup (in
  `link-worktree-artifacts.sh` or a sibling `warm-worktree.sh`) that APFS
  `cp -c`-clones a warm `target/` into the new worktree as a *per-worktree*
  directory — never a shared symlink. Loudly refuse (or clearly warn) if the
  clone would collide with an existing `target/`.
- Document, in the playbook, that shared `CARGO_TARGET_DIR` remains unsafe under
  concurrent writers and is not the sanctioned path.

Acceptance criteria:

- A documented one-line bootstrap enables `sccache` on a build machine, and a
  second cold worktree build reuses cached compilation instead of redoing it.
- Worktree setup can produce a warm per-worktree `target/` clone without a
  shared mutable target dir.
- The playbook states which speedup is in effect and why shared targets are
  disallowed.

### 4. Establish a build-machine bootstrap checklist (and close the timeout gap)

The `with-timeout.sh` episode is the general case of "a tool whose precondition
was never established." Record the machine setup so a fresh build host is
provably ready, not discovered-broken mid-ticket.

- A single `scripts/check-build-machine.sh` (or a checklist section in the
  playbook) that verifies, and reports loudly on: `timeout`/`gtimeout` present
  (coreutils installed), `sccache` present and configured, git hooks in the
  LLP 0017 safe-by-default state, and any other agent-run precondition. It exits
  nonzero and lists the missing pieces with their install commands.
- Fold the already-completed `brew install coreutils` and the item-3 `sccache`
  bootstrap into this checklist so they are verifiable, not tribal.
- Update LLP 0015 if these become persistent per-machine requirements.

Acceptance criteria:

- Running one command on a build machine reports every unmet agent-run
  precondition with its fix, and exits nonzero if any is unmet.
- A wrapper script added in the future is expected to check its own binary's
  presence (the standard `with-timeout.sh` already meets).

### 5. Hold new agent tooling to the fail-loud rule

Make the governing rule a checklist item for future scripts, so this class does
not silently regrow.

- When adding or changing an agent-facing script, confirm: it exits nonzero on an
  expected-op no-op; it asserts its postcondition (the artifact exists, N tests
  ran, the file changed) rather than only that its inner commands returned 0;
  wrappers verify their dependencies.
- Prefer postcondition checks the agent can't skip (built into the script's exit
  status) over playbook prose the agent must remember.

## Sequencing

1. P1: fix `link-worktree-artifacts.sh` destination + no-op failure (item 1) —
   this blocked every pilot agent.
2. P1: add the fail-on-zero test wrapper (item 2) — it gates verification
   correctness for every native ticket.
3. P2: bootstrap `sccache` and the opt-in target clone (item 3).
4. P2: build-machine bootstrap checklist (item 4).
5. Ongoing: apply the fail-loud checklist to new tooling (item 5).

## Open questions

- Should items 1–4 be tracked under the existing ENG-22986 (0017's reliability
  set) or a new sibling issue in the **Exact** Linear project? Leaning toward a
  new issue that `Related`-links 0017's, since these are follow-ups to shipped
  code rather than the original scope.
- Should the fail-on-zero-tests wrapper (item 2) also become a CI gate, or stay
  an agent-side verification tool? CI already runs the full suite, so the value
  is mostly at agent verification time.
- Is `check-build-machine.sh` (item 4) better as a script or as a section of the
  agent playbook the agent runs first? A script is enforceable; prose is
  cheaper to keep current.
- Does the fail-loud rule (item 5) belong here as a Plan item or promoted into
  LLP 0006 as a standing principle for the agent tool surface? For now it lives
  here; if it proves durable, fold a one-line principle into 0006.
