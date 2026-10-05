# Agent Instructions

This repository contains Ibex 2 only. Its implementation is under
`crates/ibex2/` and `crates/ibex2-sqlite/`; do not introduce Ibex 1 runtime,
patched-Hermes, SFE, mobile-app, or package-monorepo machinery.

## Linked Literate Programming

- Read [LLP 0000](./llp/0000-ibex.explainer.md) and the governing LLPs before
  substantial changes.
- LLP files use `NNNN-slug.type.md`; dotted numbers are sub-LLPs and numbers
  are never reused.
- `llp/current/` and `llp/foundation/` contain only relative links to local LLP
  documents. `current` is the working set; `foundation` is the active kernel.
- Keep the standard metadata fields (`Type`, `Status`, `Systems`, `Author`,
  `Date`) and preserve review artifacts under `llp/reviews/`.
- Use `@ref LLP NNNN#section` for local load-bearing decisions. Cross-repo
  references must be stable URLs. Run `./ref-check` after editing references.

## Agent skills

Run `scripts/install-agent-skills.sh` to install the Git-backed LLP and
cdcstack skills, or `scripts/sync-agent-skills.sh` to refresh them. Do not edit
generated entries under `skills/` directly. The adopted `caps.mjs`,
`issue.mjs`, and issue conventions remain documented under `scripts/` and
`docs/issues.md`.

## Working here

- Keep Rust behavior and its LLP updates in the same commit.
- Prefer filesystem issues under `issues/`; resolved issues move to
  `issues/closed/` with their resolution recorded.
- Ibex 2 links only vanilla Hermes. The platform build scripts install into
  `Frameworks-vanilla` or `tools/hermes-vanilla` paths.
- Run focused tests, workspace clippy, and `./ref-check` before landing.
- Workspace clippy is `cargo clippy --workspace --all-targets --all-features
  --exclude hermes-lean-sys -- -D warnings` plus `cargo clippy -p hermes-lean-sys
  --all-targets --features link -- -D warnings`. hermes-lean-sys's `link` and
  `link-lean` are mutually exclusive, so `--all-features` can't apply to it. The
  lean-VM proof is `crates/ibex2-lean-embedding` (its own workspace). `link-lean`
  needs a receipted install, so a receipt-free repository layout refuses it: use
  the pinned bundle (remove the repository layout) or a receipted
  `HERMES_LEAN_SYS_DIR`.
