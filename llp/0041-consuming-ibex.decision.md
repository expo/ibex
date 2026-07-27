# LLP 0041: How Exact and Snapback Consume Ibex

**Type:** Decision
**Status:** Review
**Systems:** Build, Release, CapSec, Product
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-27
**Revised:** 2026-07-27 (round-2 delta review: step 0 corrected — the pin IS
advertised on origin, incidentally, by the Hermes artifact-cache tag
`hermes-ac8c6e6c80ec-bcd8ab683229`, and the step now replaces incidental
with obligation-bearing retention; the six-commit set fixed as
`accb686f..bfbc6133`; pin age defined (pinned commit's committer date) and
the 30-day bound justified as a backstop; rule 6 named as ibex's pin
discovery channel; Exact's pin SHA refreshed; lineage-transfer consequence
scoped to synchronized pins; Related pointer marked provisional)
**Revised:** 2026-07-27 (round-1 dual-family review: SIGSEGV provenance
corrected; compat-branch age and retrofit stated honestly with exact refs
and SHAs; integration-branch exception narrowed to ephemeral test-only use;
CI reachability/pin-age check and 30-day cadence decided; remediation
re-anchored on the archive tip `bfbc6133`, ref-retention step 0 added,
existing cherry-picks credited; consumer-side adoption record required)
**Related:** LLP 0039 (secure/insecure modes — the intra-repo mode-divergence
risk this document generalizes across repos); LLP 0000 (Ibex); Exact's
LLP 0180 (Ibex extracted to its own repository, consumed as a submodule);
snapback `issues/20260727-vendor-ibex-advance-blocked-on-compat-abi.md` (the
motivating failure; provisional — on snapback's unpushed
`chore/advance-vendor-ibex-jsi-owner-fix` branch until remediation step 3
lands it)

## Context

Ibex was extracted from the `exact` monorepo into its own repository
(`expo/ibex`, formerly `ccheever/ibex`) and is consumed by two downstream
projects, both as git submodules at `vendor/ibex`:

- **Exact** pins commits on (or near) ibex `main`.
- **Snapback** pinned `bfbc6133` — the tip of an ibex side branch (the
  branch refs survive only locally, as `archive/eng-25006-snapback-compat`
  and the live `eng-25006-snapback-compat`, which ends two commits earlier
  at `b129c8e0`; on `origin` the commit is advertised only incidentally, by
  the Hermes artifact-cache release tag
  `hermes-ac8c6e6c80ec-bcd8ab683229`) carrying six commits
  (`accb686f..bfbc6133`), dated 2026-07-12..18, never merged to `main`:
  ENG-24340 eval time limits, ENG-24383 TLS PEM parsing, two ENG-25006 fetch
  keepalive/cleanup fixes, async-continuation authentication, and principal
  sentinels. They include three `ex_hermes_*` ABI symbols
  (`ex_hermes_create_no_eval`, `ex_hermes_watch_time_limit`,
  `ex_hermes_unwatch_time_limit`) that exist on no reviewed `main`-lineage
  commit — only on that branch and a couple of unmerged local salvage
  branches.

On 2026-07-27 that arrangement produced its characteristic failure, in an
unusually clean form. Snapback's own verification had discovered a macOS
`SIGSEGV` in ibex's native-fetch completion (a JSI owner destroyed off the
Hermes thread). The fix landed on ibex `main` (`e523475f`). Snapback could
not take it: its compat branch base had fallen **~890 commits** behind, the
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
2. **Surface outside the producer's continuously integrated lineage.** Ibex
   `main` puts every ABI symbol, environment read, and global through a
   fail-closed review chain (reviewed host-ABI rows, coverage
   classification, generated registry/contract, `check:drift`) — and then
   keeps re-verifying it on every subsequent `main` change. The compat
   branch's tip did retrofit much of that ceremony (header docs, coverage
   rows, regenerated manifests), so the defect is not that the ceremony
   never ran; it is that the surface lives outside the lineage where the
   chain keeps running. In the roughly two weeks the branch existed, `main`
   moved ~890 commits — including a capsec-registry redesign and the
   fetch-path rework — and none of that re-verification ever saw the compat
   surface. A retrofit ages from the moment it lands; only `main` residency
   keeps review current.
3. **Consumer divergence.** With Exact near `main` and Snapback on an old
   fork, the two flagship consumers exercise different engines. Bugs
   reproduce in one and not the other, and a fix verified against one
   consumer's engine says nothing about the other's. The SIGSEGV fix itself
   is the example: it was developed and verified against `main`'s fetch
   path, which by then shared little with the compat branch's. This is
   LLP 0039's two-track rot argument, replayed across repositories: a track
   nobody advances silently decays.

## Decision

**Consumers pin ibex `main`-lineage commits. Consumer-needed capability
lands in ibex `main`, through ibex's normal review discipline, before a
consumer depends on it. Long-lived consumer compat branches are
prohibited.**

Concretely:

1. **Pin discipline.** Every `vendor/ibex` pin that is *committed* on a
   consumer branch that ships, merges, or is shared with other people or
   agents points at a commit reachable from ibex `main`. When both
   consumers can, they should pin the *same* commit, so verification
   findings transfer and one advance serves both.
2. **Upstream-first.** When a consumer needs behavior ibex lacks, the
   feature is proposed and landed in ibex `main` (feature-gated if it is
   consumer-specific), with its capsec rows, conformance coverage, and docs.
   The consumer advances its pin to consume it. "It's faster to patch our
   copy" is how `eng-25006-snapback-compat` happened.
3. **Ephemeral integration only.** While a consumer integration is being
   worked out, a local or CI checkout may *test against* an ibex work
   branch. That branch never becomes a committed consumer pin (rule 1); an
   ibex issue exists naming what must be upstreamed; and the branch is
   deleted when the upstreamed capability lands on `main`. A branch someone
   is afraid to delete is a fork.
4. **Advance cadence.** Consumers advance their pin (a) promptly when ibex
   lands a fix for a defect that consumer reported or is exposed to —
   security fixes are not optional; and (b) routinely otherwise: a pin more
   than **30 days** old is overdue. Pin age is measured from the pinned
   ibex commit's committer date — checkable from the SHA alone. Thirty days
   is a deliberately generous backstop, not the expected rhythm: rule 4(a)
   is what keeps drift small (the motivating fork accrued ~890 commits in
   two weeks, so no calendar bound alone can), and the bound is a starting
   value the rule-6 check can tighten as advances get cheaper. Small
   frequent advances keep any single advance from ever requiring
   archaeology. An advance that breaks the consumer produces an ibex issue
   (or fix) the same day, while the delta is one pin, not 890 commits.
5. **Breakage flows back as issues.** When an advance breaks a consumer, the
   consumer files the break against ibex (repo-scoped `issues/`, or Linear
   for cross-repo coordination per both repos' conventions) rather than
   absorbing it into a local patch. Ibex treats consumer breakage from a
   `main` advance as its bug or its deliberate, documented migration.
6. **The rules are checked, not remembered.** Each consumer's CI verifies
   that the committed `vendor/ibex` SHA is reachable from ibex `main` and
   alarms when the pin's age exceeds the rule-4 bound; ibex keeps every
   commit a consumer currently pins reachable from an advertised ref until
   the consumer has moved off it — and the consumer-side check (with its
   adoption record, rule 7) is also the channel through which ibex learns
   what the live pins are. The motivating failure accrued silently for
   ~890 commits; a policy against silent drift that relies on memory would
   reproduce it. The check's existence, the reachability predicate, and the
   30-day bound are decided here; its venue and alerting mechanics are
   implementation-phase.
7. **Consumers record adoption.** Each consumer repository records its
   adoption of this policy in its own corpus (a short mirroring decision or
   pointer document), so the consumer's agents and CI encounter the
   obligation where they work; this document is the normative text.

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

0. **Make the pinned commit's retention deliberate.** The only `origin` ref
   advertising Snapback's pin `bfbc6133` today is the Hermes artifact-cache
   release tag `hermes-ac8c6e6c80ec-bcd8ab683229` — incidental retention: a
   tag that exists to host build assets, subject to artifact-cache GC and
   release re-cuts, signaling nothing about intent to keep the commit.
   Replace it with obligation-bearing retention: push an explicit archive
   ref (or tag) for `bfbc6133` to `origin`, and drop no ref advertising the
   commit until step 3 completes.
1. **Audit the six compat commits `accb686f..bfbc6133`** (the *archive* tip —
   the live branch is two commits short, missing the continuation-auth and
   principal-sentinel work) against current `main`. Expect part to be
   obsolete: `main` now has structural lockdown that tames `eval`/`Function`
   (LLP 0013 Mechanism 1), watchdog heartbeat ABI, and
   `tls-client-identity-openssl` PEM/PKCS#8 decoders. Start from the
   existing partial cherry-picks of the ENG-24340 time-limit work
   (`57b4fb5e`; `d93d3620` on the local salvage branch) rather than redoing
   them.
2. **Upstream the remainder** to ibex `main` as reviewed surfaces (the
   likely survivors are the eval time-limit semantics, if the watchdog ABI
   doesn't already express them, and whatever of ENG-25006's fetch-cleanup
   semantics the owner-race rework didn't subsume).
3. **Advance Snapback's pin to `main`** (the prepared, unpushed branch
   `chore/advance-vendor-ibex-jsi-owner-fix` in snapback already carries the
   submodule bump and toolchain move) and rerun the verification that
   exposed the SIGSEGV — the still-owed follow-up from
   `issues/closed/20260726-native-fetch-jsi-last-owner-race.md`.
4. **Retire the compat refs** — delete the live branch and the archive
   ref/tag — only after every commit in `accb686f..bfbc6133` has a recorded
   disposition (upstreamed, subsumed by `main`, or dropped with a reason)
   and step 3 has landed.
5. **Advance Exact's pin** (a `main`-lineage commit; `002ba828` on Exact's
   `origin/main` as of this writing) at its next convenient window; Exact
   needs no compat reconciliation.

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
- Both consumers stay on one engine lineage, which makes findings
  transferable and fixes directly consumable; a finding in one consumer's
  verification is a finding about the exact engine the other ships only
  when their pins are synchronized (rule 1 encourages, but does not
  require, that).
