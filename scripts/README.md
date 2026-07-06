# Agent build/verify tooling

The scripts here are the commands agents use to set up worktrees, build, and
**verify** changes. They follow one rule from
[LLP 0018](../llp/0018-agent-tooling-fail-loud.plan.md):

> **Agent-facing tooling fails loud when its postcondition is unmet.** A command
> an agent uses to make a change or verify one must not exit 0 when it did
> nothing the caller expected it to do (0 symlinks, 0 tests, 0 regenerations),
> when its postcondition is still false, or when a wrapper's binary is missing.

## The scripts

| Script | Use |
| --- | --- |
| `check-build-machine.sh` | Run first on a fresh host. Reports every unmet precondition (timeout binary, safe git hooks, cargo, sccache/bun) and exits nonzero if a required one is missing. |
| `warm-worktree.sh [--clone-target]` | Warm a fresh worktree: link the git-ignored artifacts, and optionally APFS-clone a per-worktree `target/`. |
| `link-worktree-artifacts.sh` | Link `ios/Frameworks` + `tools/hermes` (required) and `node_modules` (optional) from the warm primary **into the worktree you run it from**. Fails loud if a required artifact is still absent after linking. |
| `run-tests.sh [--scope lib\|bin\|test\|all]` | The verification entry point. Runs the **full** package test set by default and **exits nonzero if zero tests ran**. Also fails on stale vendored bytes. |
| `build-blocking.sh` | Run a long build/test in the foreground under a timeout, with a heartbeat. |
| `with-timeout.sh` | Portable `timeout`/`gtimeout` wrapper (exit 127 if neither is installed). |
| `check-generated-drift.sh` | Prove committed generated artifacts are current (land-time gate). |

## Verifying a change (item 2)

Use `run-tests.sh`, not a bare `cargo test`. A filtered `cargo test --bin ibex X`
or `cargo test --lib X` can match **zero** tests and still exit 0 — the tests are
split across the lib, the `ibex` binary target (`src/bin/ibex/`, ~63 tests), and
`tests/`. `run-tests.sh` defaults to the whole package and fails loud on a
zero-test run:

```sh
scripts/run-tests.sh deep_freeze        # every matching test, all targets
scripts/run-tests.sh --scope lib         # narrow deliberately, opt-in
```

It exports `IBEX_FAIL_ON_STALE_VENDORED=1`, so if you edited `src/builtins/*.js`
(or another generated source) without regenerating, the build fails instead of
testing the last-committed bytes. To iterate: `IBEX_REGENERATE_RUNTIME=1 cargo …`;
to commit: `bun run regenerate:vendored` + `bun run check:drift`.

## Long builds run in the foreground (item 6)

Do **not** background a multi-minute build and park on an event that may never
re-wake you. Run it on your own control flow:

```sh
scripts/build-blocking.sh --timeout 20m -- build
```

If you must background a build, poll its output/exit to completion rather than
waiting on an external notification.

## Landing onto a busy `main` (item 7)

`sccache` (see `check-build-machine.sh`) is the primary rebuild-cost reducer —
a post-rebase rebuild is mostly cache hits. It is the cost fix; do **not** buy
speed by skipping verification.

Minimum post-rebase verification policy — "no conflicts touching my files" is
NOT enough evidence the base change is irrelevant:

- **Always** re-run the directly affected test/build command and the drift check
  after any rebase.
- **Re-run the fuller native suite** when the rebase pulled in upstream changes
  (by merge-base path diff, not "did it conflict") to any of: `Cargo.toml`,
  `Cargo.lock`, `build.rs`, `vendored-generated/**` or other generated
  artifacts, scripts used by the workflow, shared native files (e.g.
  `hermes_runtime.cc`), or tests for the touched subsystem.
- Only when none of those were touched may you stop at the targeted re-run.

## Adding new agent-facing tooling (item 8 checklist)

Before landing a new or changed agent-facing script, confirm it:

- [ ] exits nonzero on an expected-op no-op (0 links / 0 tests / 0 files changed),
      unless "nothing to do" is explicitly the already-satisfied requested state;
- [ ] asserts its **postcondition** (the artifact exists, N tests ran, the file
      changed) — not merely that its inner commands returned 0;
- [ ] if it wraps a binary, checks that binary is present (as `with-timeout.sh`
      does);
- [ ] prefers a check built into its own exit status over playbook prose an agent
      must remember.
