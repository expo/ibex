# LLP 0017: Agent Execution Reliability Plan

**Type:** Plan
**Status:** Draft
**Systems:** Build, Tooling, Agent Skills, CI, Developer Experience
**Author:** Charlie Cheever / Claude (pilot feedback) / Codex
**Date:** 2026-07-05
**Revised:** 2026-07-05 (Claude and OpenAI review revisions: hook mutability, drift-check cleanliness, regenerate parity, installer hook opt-in, and source-repo validation); 2026-07-05 (P0/P1/P2 code items implemented — see §Implementation status)
**Related:** LLP 0000; LLP 0001; LLP 0005; LLP 0006; LLP 0012; LLP 0015; LLP 0018 (second-round fail-loud follow-ups); ENG-22986

## Summary

Recent agent pilot work proved that Ibex can be developed effectively from
fresh Git worktrees when the native build cache is warm, but it also exposed two
workflow hazards that can corrupt the repository state agents operate on:

- agent skill sync hooks can run as a hidden side effect of worktree creation,
  skill installation can silently enable those hooks, and the sync path can
  mutate Git remotes;
- committed generated artifacts are easy to drift because the regeneration
  surface is spread across several commands.

This plan turns that feedback into repo-level work: make agent worktree setup
safe by default, make generated artifact refresh and drift checking
single-command, make long builds bounded on the available machines, support a
shared Rust build cache path, and make the main-branch landing policy explicit.

## Motivation

The pilot feedback was mostly positive:

- An APFS clone of a warm `target/` directory made native work feasible: the
  feedback reports a roughly 17 GB copy-on-write clone in about 28 seconds and
  an incremental native end-to-end run around eight minutes.
- Native, JS-web, and JS-builtin paths were all exercised during the pilot.
- The agents recovered from a mispointed `origin` by pushing through explicit
  URLs.
- The playbook-file pattern kept prompts short enough that a single playbook
  update could improve multiple pilot agents.

The same run exposed friction worth fixing before scaling this workflow. The
highest-severity issue is the skill-sync hook because a wrong remote in a shared
worktree config can turn an ordinary `git push origin HEAD:main` into a push to
the wrong repository. The next most frequent issue is generated artifact drift:
JS source edits often require regenerated committed outputs, and concurrent
JS-web tickets conflict on `vendored-generated/embedded_runtime_bundle.js`.

## Constraints From Existing LLPs

- LLP 0005 keeps the default build hermetic for the generated JS layer. Any new
  regeneration or drift-check script must preserve the rule that normal
  `cargo build` does not require bun or `node_modules`.
- LLP 0006 frames regeneration as opt-in and loud on failure. Agent convenience
  commands should make the opt-in path easier, not make hidden generation part
  of the default build.
- LLP 0012 makes `runtime-identity.json` the authority for runtime identity, so
  drift checks must include its generated Rust and TypeScript bindings, not only
  `vendored-generated/`.
- LLP 0015 records manually reachable build machines but says they are not a CI
  contract. Installing utilities or caches on those machines is operational
  setup unless a later CI LLP promotes them to required runners.
- LLP 0001 owns the platform CI matrix. This plan may add a generated-artifact
  drift check to CI, but it does not replace the platform matrix.

## Current Repo Surface

The repository contains post-checkout, post-merge, and post-rewrite hooks that
run `scripts/sync-agent-skills.sh --quiet` unless
`IBEX_SKIP_AGENT_SKILLS_SYNC=1` is present. Those hooks run whenever a checkout's
`core.hooksPath` points at `.githooks` `[observed]`
(`.githooks/post-checkout:1-14`; `.githooks/post-merge:1-14`;
`.githooks/post-rewrite:1-14`). The sync script clones or updates upstream
skill repositories under `.agent-skill-sources`, repairs their `origin` URL,
fetches, switches, and pulls `[observed]`
(`scripts/sync-agent-skills.sh:68-101,135-136`).
`scripts/install-agent-skills.sh` runs that sync script and then configures the
checkout's `core.hooksPath` to `.githooks` automatically `[observed]`
(`scripts/install-agent-skills.sh:17,92-94`).

Three properties of that surface constrain the fix:

- The `remote set-url origin` call runs **unconditionally** at
  `scripts/sync-agent-skills.sh:86-89`, *above* the `if [ "$fetch" -eq 1 ]`
  block `[observed]`. The existing `--no-fetch` flag and
  `IBEX_AGENT_SKILLS_NO_NETWORK=1` env var (`:17-18,37-39`) suppress fetch/
  switch/pull but **not** the remote mutation, so "no network" is not "no
  mutate."
- The update path uses `git -C "$dir"` with `$dir` a source dir under
  `.agent-skill-sources/` `[observed]` (`:68-101`) but never proves that `$dir`
  is exactly the managed source checkout before mutating it. In the current
  script, an absent `$dir` takes the clone branch (`:76-83`) rather than the
  `remote set-url` branch `[observed]`; the remaining escape to close is a
  malformed, symlinked, worktree-indirected, or wrong-identity source checkout
  that lets the update path mutate a repository outside the intended managed
  source dir `[inferred]`.
- The installer can re-enable the hidden hook path after a manual skill refresh
  by setting `core.hooksPath` to `.githooks` `[observed]`
  (`scripts/install-agent-skills.sh:92-94`). Inverting the hook default is
  incomplete unless the installer honors the same opt-in rule.

The root package scripts expose the five relevant JS generation commands
individually: builtins, runtime bundle, capability bits, runtime identity, and
module manifest `[observed]` (`package.json:8-14`). The committed generated
snapshot under `vendored-generated/` contains the builtin manifest,
transformed builtin modules, and `embedded_runtime_bundle.js` `[observed]`
(`vendored-generated/README.md:11-35`). Runtime identity also has generated
Rust and TypeScript bindings outside `vendored-generated/` `[observed]`
(`runtime-identity.json`; `src/identity_generated.rs`;
`packages/ibex-runtime-js/src/identity.generated.ts`; LLP 0012).

## Plan

### 1. Make agent skill sync safe by default

This is the highest-priority item. Worktree creation and skill installation
must not mutate the Ibex remote, fetch from the network unexpectedly, enable
hidden sync hooks, or repair another checkout's repository identity.

Implementation options, in preferred order:

1. Invert the hook default. Hooks should no-op unless an explicit opt-in such as
   `IBEX_ENABLE_AGENT_SKILLS_SYNC=1` is present. Manual
   `scripts/sync-agent-skills.sh` and `scripts/install-agent-skills.sh` remain
   available for intentional refreshes, but the installer must not set
   `core.hooksPath=.githooks` unless the same opt-in is present or the user
   passes an explicit hook-enabling flag.
2. If automatic hooks remain, restrict them to a non-mutating local relink path:
   no fetch, no branch switching, and — critically — no `remote set-url`. Note
   that the existing `--no-fetch` / `IBEX_AGENT_SKILLS_NO_NETWORK=1` modes are
   insufficient here: they leave the unconditional `set-url` at
   `scripts/sync-agent-skills.sh:86-89` in place.
3. Harden `scripts/sync-agent-skills.sh` so every managed source repo is
   validated before mutation:
   - resolve real paths for `$repo_root`, `$sources_root`, and each source dir;
   - keep the absent-directory clone path separate from the update path, then
     verify the clone's toplevel before any later repair/update mutation;
   - assert `git -C "$dir" rev-parse --show-toplevel` is exactly the source
     dir before running any mutating Git command;
   - refuse to run if a source dir resolves to the Ibex worktree or to a Git
     file/worktree indirection outside `.agent-skill-sources`;
   - only repair `origin` after the repo identity is proven to be the managed
     upstream.

Acceptance criteria:

- `git worktree add` for Ibex cannot change `remote.origin.url` in the shared
  Ibex Git config.
- Running `scripts/install-agent-skills.sh` without explicit hook opt-in cannot
  change `core.hooksPath` to `.githooks` or otherwise enable automatic
  hook-triggered sync.
- Hook-triggered skill sync cannot fetch, switch branches, pull, or set remote
  URLs unless the user explicitly opted into that behavior.
- A regression test or shell smoke covers both relevant hook paths:
  - a fresh Ibex worktree with `.agent-skill-sources/` absent runs the hook path
    and asserts the original repo's `origin` remains
    `https://github.com/ccheever/ibex.git`;
  - a malformed or wrong-identity managed source path that could make
    `git -C "$dir"` resolve outside the intended source checkout is refused
    before `remote set-url`, fetch, switch, or pull can run.
- Agent playbooks use explicit repository URLs for pushes until this item is
  complete.

**Interim state (as of this draft):** the hook is disabled for pilot runs by
pointing `core.hooksPath` at an empty directory, and all agent playbooks push
through explicit URLs. That is a per-run mitigation, not the durable fix this
item delivers.

### 2. Add one regenerate command and one drift check

Agents should not need to remember which generated outputs correspond to a JS
change. Add a single repo command that updates all committed generated outputs
and a fast check that proves they are fresh.

Proposed command surface:

- `bun run regenerate:vendored` or `scripts/regenerate-vendored.sh`
  - runs `generate:capability-bits`;
  - runs `generate:identity`;
  - runs `generate:modules`;
  - runs `build:builtins`;
  - runs `build:runtime`.
- `bun run check:drift` or `scripts/check-generated-drift.sh`
  - runs the same generators in check mode where a generator supports it;
  - otherwise regenerates into a scratch location and diffs, so the check does
    not leave the working tree dirty (it must be safe to run in CI and as a
    pre-push step without a dirty-tree race);
  - prints the changed paths and the regenerate command to run.

`regenerate:vendored` (the five bun generators) and the existing
`refresh:vendored` (`package.json:14`, a full
`IBEX_REGENERATE_RUNTIME=1 … cargo build --features openssl-crypto` through
`build.rs`) must produce byte-identical `vendored-generated/` output. If they
can diverge, agents get two regenerate commands that disagree and a drift check
whose verdict depends on which one ran last; `check:drift` should be the thing
that enforces their equivalence.

The checked path set must include at least:

- `vendored-generated/builtin_manifest.generated.rs`;
- `vendored-generated/builtins/*.js`;
- `vendored-generated/embedded_runtime_bundle.js`;
- `packages/ibex-runtime-js/src/security/capability-bits.generated.ts`;
- `packages/ibex-runtime-js/src/identity.generated.ts`;
- `src/identity_generated.rs`;
- `runtime-identity.json` as an input authority, not a generated output.

Acceptance criteria:

- A JS-web, JS-builtin, capability-bit, or runtime-identity source change has
  one documented command to refresh all committed generated files.
- CI or the pre-push playbook runs `bun run check:drift` before landing.
- The drift check exits nonzero on stale generated files and does not require a
  native `cargo build`.
- The old `refresh:vendored` command remains available for the full
  `build.rs`-mediated refresh path described by LLP 0005.

### 3. Standardize timeout and directory setup on build machines

The pilot reported small environment mismatches: `timeout`/`gtimeout` was not
available, and some fresh worktrees lacked parent directories such as `ios/` and
`tools/` before scripts tried to place symlinks or artifacts under them.

Acceptance criteria:

- The macOS build machine has GNU coreutils installed, or the repo has a small
  timeout wrapper that uses `timeout` on Linux and `gtimeout` on macOS with a
  clear error if neither exists.
- Agent playbooks use the wrapper instead of spelling platform-specific timeout
  binaries directly.
- Setup scripts that create platform artifact symlinks run `mkdir -p` for
  required parents before linking.
- LLP 0015 is updated if these machines gain persistent bootstrap requirements
  beyond the current inventory role.

### 4. Support a shared Rust build cache path

The APFS clone of a warm `target/` directory is a good emergency speedup, but it
is still a per-worktree copy. The supported path should prefer a shared compiler
cache and keep target-directory sharing explicit because concurrent Cargo
writers can contend or corrupt build products.

Proposed direction:

- install and document `sccache` for the agent-reachable macOS/Linux machines;
- standardize `RUSTC_WRAPPER=sccache` and a persistent cache directory for
  agent runs;
- keep APFS-cloned `target/` directories as the fast local fallback;
- only allow a shared `CARGO_TARGET_DIR` when the workflow has an explicit lock
  or single-writer guarantee.

Acceptance criteria:

- A documented build-machine bootstrap command enables `sccache`.
- Native agent tickets can start from either `sccache` or an APFS-cloned warm
  target without re-discovering the setup.
- The playbook records when shared target directories are unsafe due to
  concurrent writers.

### 5. Decide direct-to-main vs PR landing

The pilot feedback says the current skill can push straight to `main`. That may
be acceptable for a trusted direct-landing workflow, but it should be a policy
rather than an accident.

This decision is gated on item 1. The near-miss was catastrophic precisely
because unconditional remote mutation met a direct-to-main push: an ordinary
`git push origin HEAD:main` would have gone to the wrong repository. Any option
that keeps direct-to-main is contingent on item 1 having landed (hence P0 before
P3 in the sequencing).

Options:

- Protect `main` and update agent playbooks or skills to push branches and open
  draft PRs.
- Keep direct fast-forward pushes, but require explicit push URLs, drift checks,
  and build/test evidence before landing.

Acceptance criteria:

- The repository has one documented default landing mode for agent work.
- If PR-only is chosen, branch protection rejects direct pushes to `main` and
  the agent playbook opens PRs.
- If direct-to-main remains allowed, the playbook forbids bare `git push origin`
  while the skill-sync hook fix is unresolved.

## Implementation status

Landed 2026-07-05. Items 1–4's code surface is implemented and tested; the
remaining work is operational (build-machine bootstrap) and one policy decision
(item 5).

**Item 1 — agent skill sync safe by default (P0): done.**

- The three Git hooks (`.githooks/post-checkout`, `post-merge`, `post-rewrite`)
  now no-op unless `IBEX_ENABLE_AGENT_SKILLS_SYNC=1`. Option 1 (invert the
  default) was chosen.
- `scripts/sync-agent-skills.sh` proves every managed source repo's identity
  before any mutating Git command. `assert_managed_source_repo` requires the
  source dir to resolve strictly under the managed sources root, to not be the
  Ibex repo root, to have a Git top-level equal to itself (defeats upward `.git`
  discovery), and to have both its git-dir and common-dir resolve inside itself
  (defeats a `.git`-file gitdir redirection at the Ibex repo). The clone path
  (absent dir) is now separate from the update path, and `remote set-url` runs
  only after identity proof and only in network mode — no-network is now truly
  read-only, closing the "no-fetch ≠ no-mutate" gap.
- `scripts/install-agent-skills.sh` no longer sets `core.hooksPath=.githooks`
  unless `--enable-hooks` is passed or `IBEX_ENABLE_AGENT_SKILLS_SYNC=1` is set.
- `scripts/agent-skills-safety.test.sh` is an offline smoke test covering all
  acceptance cases: hook no-op without opt-in; no-network sync leaves origin
  untouched; a non-repo managed source (upward-discovery escape) is refused; a
  gitdir-redirected managed source is refused; the installer leaves
  `core.hooksPath` unset without opt-in and sets it with `--enable-hooks`.
- With this landed, the interim mitigation (pointing `core.hooksPath` at an
  empty dir) is no longer required: `.githooks` is safe by default.

**Item 2 — one regenerate command and one drift check (P1): done.**

- `bun run regenerate:vendored` (`scripts/regenerate-vendored.sh`) runs the five
  generators in order. `bun run check:drift`
  (`scripts/check-generated-drift.sh`) verifies freshness without writing to the
  working tree: the three check-capable generators run with `--check`; the two
  bundle builders write to a scratch out-dir (last `--out`/`--out-dir` wins) and
  are diffed against the committed copies. Both scripts drive the package.json
  scripts as the single source of truth for flags.
- Verified: `check:drift` is clean on a clean tree with no tree mutation, and
  detects staleness on both the `--check` path and the builder-diff path.
- **C-4 / parity open question resolved:** running `regenerate:vendored` left
  the committed `vendored-generated/` and the runtime-identity bindings
  byte-identical (empty `git status`), i.e. the five bun generators produce the
  same bytes as the `build.rs`-mediated `refresh:vendored`. `check:drift` is the
  standing enforcement of that equivalence.

**Item 3 — parent directories and setup (P1): done.**

- The `build-hermes*.sh` scripts already `mkdir -p` their `ios/Frameworks` and
  `tools/hermes` parents. `scripts/link-worktree-artifacts.sh` operationalizes
  the fresh-worktree artifact linking from a warm primary checkout (symlinks
  `ios/Frameworks`, `tools/hermes`, `node_modules`, creating missing parents;
  idempotent; refuses to target the main worktree). It intentionally does not
  link `target/` (see item 4).

**Item 4 — timeout wrapper (P2): partially done.**

- `scripts/with-timeout.sh` wraps `timeout` (Linux) / `gtimeout` (macOS) with a
  clear error and exit 127 when neither exists. Confirmed firsthand that the
  current macOS build machine has **neither** binary installed, which is the
  friction the pilot hit.
- **Operational, not yet done:** install GNU coreutils on the macOS build
  machine (`brew install coreutils`) and bootstrap `sccache`
  (`RUSTC_WRAPPER=sccache` + a persistent cache dir). These are machine setup
  under LLP 0015's inventory role, not code in this repo. (coreutils since
  installed; `sccache` bootstrap and default cache wiring are now tracked by
  [LLP 0018](./0018-agent-tooling-fail-loud.plan.md) items 3–4.)

**Item 5 — direct-to-main vs PR landing (P3): decided.** The author chose to
**keep direct-to-main** (2026-07-05), now that item 1 removes the
unconditional-remote-mutation hazard that made it dangerous. Direct fast-forward
pushes to `main` remain allowed for agent work, subject to these guardrails,
which the agent playbook must enforce before landing:

- push through an **explicit repository URL**
  (`git push https://github.com/ccheever/ibex.git HEAD:main`), never a bare
  `git push origin` — a defense-in-depth habit even though item 1 makes a
  mispointed `origin` far less likely;
- `bun run check:drift` passes (no stale committed generated artifacts);
- build/test evidence for the change is captured before landing.

Branch protection on `main` is therefore **not** being enabled at this time.

## Sequencing

1. P0: fix or disable automatic skill sync from Git hooks and stop
   `install-agent-skills.sh` from silently re-enabling those hooks; keep
   explicit push URLs in all agent playbooks until this lands.
2. P1: add `regenerate:vendored` and `check:drift`; wire the drift check into
   the landing path.
3. P1: patch setup scripts for missing parent directories.
4. P2: install or wrap timeout support on build machines and update playbooks.
5. P2: document and bootstrap `sccache`; keep APFS target clones as fallback.
6. P3: decide and enforce the main-branch landing mode.

## Open Questions

- Is ENG-22986 scoped only to the skill-sync hook hazard, or should it track the
  whole P0/P1 agent reliability set?
- Should automatic skill sync ever run from Git hooks, or should all networked
  skill updates be explicit commands?
- ~~Should `scripts/install-agent-skills.sh` stop configuring `core.hooksPath`
  entirely, or should it require an explicit flag such as `--enable-hooks`?~~
  **Resolved (2026-07-05):** it requires `--enable-hooks` (or
  `IBEX_ENABLE_AGENT_SKILLS_SYNC=1`); default installs leave hooks unchanged.
- Should `check:drift` be a CI job, a pre-push playbook step, or both? (Still
  open; it is now safe for both since it does not write the working tree.)
- ~~Should branch protection be enabled now, or after the direct landing skill
  has a PR-based path?~~ **Resolved (2026-07-05): neither** — the author chose to
  keep direct-to-main with explicit-URL + drift-check + evidence guardrails
  (§Implementation status item 5), so branch protection stays off for now.
- ~~Does `regenerate:vendored` (five bun generators) produce byte-identical
  output to `refresh:vendored` (the `build.rs` path)?~~ **Resolved (2026-07-05):
  yes** — `regenerate:vendored` left the committed tree byte-identical. See
  §Implementation status.
- ~~Can `check:drift` run without writing to the working tree, so it is safe to
  wire into both CI and a pre-push hook without a dirty-tree race?~~ **Resolved
  (2026-07-05): yes** — `--check` mode plus scratch-out-dir builder diffs write
  nothing to tracked paths; verified clean `git status` after a run.
