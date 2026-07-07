# LLP 0015: Available Build Machines

**Type:** Guide
**Status:** Draft
**Systems:** Build, Tooling, Windows, macOS, Linux, Developer Experience
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-05
**Revised:** 2026-07-06 (recorded Unix build-host bootstrap expectations and current macOS coreutils verification)
**Related:** LLP 0000, LLP 0001, LLP 0005, LLP 0017, LLP 0018

## Summary

Ibex development sometimes needs real target machines instead of local
cross-compilation or generic CI runners. This guide records the current
agent-reachable build machines for ad hoc Windows, macOS, and Linux work.

This inventory is copied from Exact LLP 0302 by direction from the project
owner; Ibex can use the same three machines for builds if target-specific work
ever needs them.

## Machines

| Target | SSH command | Use for |
|---|---|---|
| Windows | `ssh CCHEE@100.85.26.90` | Windows builds, host checks, and target-specific investigation |
| macOS Mac Mini | `ssh ccheever@100.85.133.74` | macOS builds, Apple host checks, and target-specific investigation |
| Linux | `ssh ccheever@100.65.137.99` | Linux builds, CLI/runtime checks, and target-specific investigation |

## Usage

- Use these machines when a task needs OS-specific build, runtime, or smoke
  validation that cannot be reproduced on the current development host.
- Prefer documenting the exact commands and results in the issue, PR, or LLP
  that depends on the machine-specific evidence.
- Treat the IP addresses as operational inventory for agent and developer work,
  not as a public product surface or permanent API.
- Do not store new secrets, credentials, or long-lived tokens on these machines
  as part of a build unless the owning workflow explicitly requires it.

## Relationship To Ibex Build Docs

LLP 0001 records the desired target-platform and CI matrix for Ibex, and
LLP 0005 records the hermetic-default build pipeline. This guide is narrower:
it documents manually reachable machines that agents or contributors may use
for target-specific investigation when local builds or generic runners are not
enough.

The machines listed here are not currently part of an Ibex CI contract. If one
becomes a self-hosted runner or a required release builder, update this guide
and the relevant build or CI LLP in the same change.

## Bootstrap Expectations

For Unix-like agent build hosts, run `scripts/check-build-machine.sh` before
depending on the host for Ibex work. It is the repo-local readiness contract for
the operational prerequisites introduced by LLP 0017 and LLP 0018.

Required setup checked by that script includes:

- a GNU timeout binary reachable through `scripts/with-timeout.sh` (`timeout` on
  Linux; Homebrew `coreutils`, which provides `gtimeout`, on macOS);
- the LLP 0017 safe Git hook configuration;
- `cargo`.

Recommended setup checked by that script includes `sccache` with
`RUSTC_WRAPPER=sccache` and a persistent `SCCACHE_DIR`, plus `bun` for
regenerating vendored artifacts.

As of 2026-07-06, the current macOS development host used for this Codex run has
Homebrew `coreutils` 9.11 installed, with both `/opt/homebrew/bin/timeout` and
`/opt/homebrew/bin/gtimeout` available. Treat that as verified for this host,
not as proof that every listed remote machine is bootstrapped; run the check
script on each host before relying on it.

## Open Questions

- Should these machines get stable Tailscale DNS names or repo-local aliases so
  future docs do not need to pin raw `100.x` addresses?
- Should any machine become a self-hosted runner, or should they remain manual
  SSH infrastructure for target-specific investigation?
