# LLP 0040: How Exact and Snapback Consume Ibex

**Type:** Decision
**Status:** Draft
**Systems:** Build, Release, CapSec, Product
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-27
**Related:** LLP 0039 (secure/insecure modes — the intra-repo mode-divergence
risk this document generalizes across repos); LLP 0000 (Ibex); Exact's
LLP 0180 (Ibex extracted to its own repository, consumed as a submodule);
snapback `issues/20260727-vendor-ibex-advance-blocked-on-compat-abi.md` (the
motivating failure)

## Context

Ibex was extracted from the `exact` monorepo into its own repository
(`expo/ibex`, formerly `ccheever/ibex`) and is consumed by two downstream
projects, both as git submodules at `vendor/ibex`:

- **Exact** pins commits on (or near) ibex `main`.
- **Snapback** pinned the tip of `eng-25006-snapback-compat` — an ibex side
  branch carrying six commits that were never merged to `main`, including
  three `ex_hermes_*` ABI symbols that exist nowhere else
  (`ex_hermes_create_no_eval`, `ex_hermes_watch_time_limit`,
  `ex_hermes_unwatch_time_limit`).

On 2026-07-27 that arrangement produced its characteristic failure, in an
unusually clean form. Snapback's own verification had discovered a macOS
`SIGSEGV` in ibex's native-fetch completion (a JSI owner destroyed off the
Hermes thread). The fix landed on ibex `main` (`e523475f`). Snapback could
not take it: its compat branch base had fallen **890 commits** behind, the
compat commits touch the same engine files the fix rewrote, and the missing
compat ABI does not link against current `main`. The consumer that found the
crash is the one consumer structurally unable to receive the fix — and it
keeps shipping the crash until someone performs a porting job that now
requires engine-level judgment.

Three costs of consumer compat branches, all of which compound with time:

1. **Fixes cannot flow.** Every `main` improvement — including security
   fixes — is inaccessible until someone re-cuts the branch. The cost of the
   re-cut grows superlinearly, because ibex's engine files are hot: the
   longer the wait, the more the fork conflicts.
2. **Unreviewed surface.** Ibex `main` puts every ABI symbol, environment
   read, and global through a fail-closed review chain (reviewed host-ABI
   rows, coverage classification, generated registry/contract, `check:drift`).
   A side branch bypasses all of it. Three ABI symbols existed for months
   with none of the discipline the rest of the surface gets — on the
   security-focused runtime, for a consumer whose interest in ibex is
   precisely its security properties.
3. **Consumer divergence.** With Exact near `main` and Snapback on an old
   fork, the two flagship consumers exercise different engines. Bugs
   reproduce in one and not the other; matrix findings (the SIGSEGV came out
   of the Exact-side Partitime matrix) don't transfer. This is LLP 0039's
   two-track rot argument, replayed across repositories: a track nobody
   advances silently decays.

## Decision

**Consumers pin ibex `main`-lineage commits. Consumer-needed capability
lands in ibex `main`, through ibex's normal review discipline, before a
consumer depends on it. Long-lived consumer compat branches are
prohibited.**

Concretely:

1. **Pin discipline.** `vendor/ibex` in Exact and Snapback points at a
   commit reachable from ibex `main` — never at a side branch. When both
   consumers can, they should pin the *same* commit, so matrix findings
   transfer and one advance serves both.
2. **Upstream-first.** When a consumer needs behavior ibex lacks, the
   feature is proposed and landed in ibex `main` (feature-gated if it is
   consumer-specific), with its capsec rows, conformance coverage, and docs.
   The consumer advances its pin to consume it. "It's faster to patch our
   copy" is how `eng-25006-snapback-compat` happened.
3. **Bounded integration branches.** A short-lived ibex branch is fine while
   a consumer integration is being worked out, with two hard requirements:
   an ibex issue exists naming what must be upstreamed, and the branch dies
   at the next consumer pin advance — it is never itself a pin target for
   longer than one advance cycle. A branch someone is afraid to delete is a
   fork.
4. **Advance cadence.** Consumers advance their pin (a) promptly when ibex
   lands a fix for a defect that consumer reported or is exposed to —
   security fixes are not optional; and (b) routinely otherwise, at least
   every few weeks, so no advance is ever big enough to require archaeology.
   An advance that breaks the consumer produces an ibex issue (or fix) the
   same day, while the delta is one pin, not 890 commits.
5. **Breakage flows back as issues.** When an advance breaks a consumer, the
   consumer files the break against ibex (repo-scoped `issues/`, or Linear
   for cross-repo coordination per both repos' conventions) rather than
   absorbing it into a local patch. Ibex treats consumer breakage from a
   `main` advance as its bug or its deliberate, documented migration.

### What consumers must absorb, knowingly

Tracking `main` means tracking ibex's deliberate inversions and churn:

- `insecure` is default-on for now (LLP 0039); consumers building secure
  configurations use `--no-default-features --features standard,...`.
- Toolchain pins move (`rust-toolchain.toml` 1.97.0 as of this writing);
  consumers keep their pinned channel equal to ibex's, and an advance that
  moves the toolchain moves the consumer's too, in the same change.
- Framework/build artifacts (`ios/Frameworks`, `tools/hermes`) follow the
  receipt discipline; consumers rebuild or re-link per ibex's scripts rather
  than caching artifacts across advances.

## Remediation of the current state

1. **Audit `eng-25006-snapback-compat` against current `main`** (six
   commits). Expect part of it to be obsolete: `main` now has structural
   lockdown that tames `eval`/`Function` (LLP 0013 Mechanism 1), watchdog
   heartbeat ABI, and `tls-client-identity-openssl` PEM/PKCS#8 decoders.
2. **Upstream the remainder** to ibex `main` as reviewed surfaces (the
   likely survivors are the eval time-limit semantics, if the watchdog ABI
   doesn't already express them, and whatever of ENG-25006's fetch-cleanup
   semantics the owner-race rework didn't subsume).
3. **Advance Snapback's pin to `main`** (the prepared, unpushed branch
   `chore/advance-vendor-ibex-jsi-owner-fix` in snapback already carries the
   submodule bump and toolchain move) and rerun the verification that
   exposed the SIGSEGV — the still-owed follow-up from
   `issues/closed/20260726-native-fetch-jsi-last-owner-race.md`.
4. **Delete `eng-25006-snapback-compat`.**
5. **Advance Exact's pin** (at `1407af0e` as of this writing) at its next
   convenient window; Exact needs no compat reconciliation.

## Alternatives considered

- **Per-consumer compat branches (status quo).** Rejected; the Context
  section is the argument. Its one advantage — the consumer never has to
  react to upstream churn — is exactly the mechanism by which it rots.
- **Vendored source copies (no submodule).** Strictly worse: same divergence
  dynamics, plus no provenance and no cheap diffing.
- **Published crate releases (cargo registry).** Attractive eventually, but
  premature: ibex's consumers need engine artifacts and scripts, not just
  Rust code, and the release ceremony would slow the fix-flow this decision
  exists to speed up. Tagged release pins can layer on top of this decision
  later without changing it; the pin-`main`-lineage rule already permits
  pinning a tag.

## Consequences

- Snapback takes a one-time reconciliation cost now (the audit/upstream
  work) in exchange for never doing 890-commit archaeology again.
- Ibex accepts consumer-motivated surface into `main` and the review load
  that carries; in exchange it stops accruing invisible, unreviewed forks.
- Both consumers stay on one engine lineage, so a finding in either one's
  verification is a finding about the engine both ship.
