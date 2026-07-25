# LLP 0039: Secure and Insecure Modes

**Type:** Decision
**Status:** Draft
**Systems:** Runtime, CapSec, Build, Product
**Author:** Charlie Cheever / Claude
**Date:** 2026-07-24
**Revised:** 2026-07-24 (ENG-25424 closes prepared-graph backing-path disclosure and removes the secure-gate test exclusion; promotion-facing CapSec executors now explicitly disable Cargo defaults so conformance cannot inherit the insecure mode)
**Related:** LLP 0021 (target advertisement + conformance report); LLP 0036 (advertisement completion); LLP 0038 (unadvertised dev arming, insecure build)

## Context

Ibex's security model is real and largely built — a typed capability decision
engine, per-package frame attribution, a virtual filesystem mount, and a
fail-closed arming ceremony. What is *not* finished is the target advertisement
pipeline that lets an ordinary build arm at all (LLP 0036 measures the remainder:
~22k unresolved rows, no cheap bulk win). Finishing it is months of work, not
days.

Until then a default build cannot run a single line of JavaScript. That is a
correct fail-closed posture and a useless developer experience, and the second
fact was blocking work on everything else in the runtime.

The security model is also still being *built*, which means it breaks things for
reasons that are bugs rather than policy. Every hour spent discovering that a
refusal came from an unfinished migration rather than a real capability decision
is an hour not spent on either the runtime or the security model.

## Decision

Maintain **two supported modes for the foreseeable future**, and treat this as a
durable product posture rather than a temporary hack.

| position | today | after LLP 0036 |
|---|---|---|
| **secure** | `--no-default-features --features standard,unadvertised-dev-arming` | default build |
| **insecure** | **the default build** | `--features insecure` |

`insecure` is **not** scheduled for deletion. `unadvertised-dev-arming` is
scaffolding and disappears when the default build can arm from a real
conformance report; at that point the split becomes exactly *default* versus
*insecure*, which is one switch with two positions.

This supersedes the removal condition in LLP 0038, which assumed both features
were transitional.

Mechanically the modes are described in
[LLP 0038](./0038-unadvertised-dev-arming.decision.md); this document records
*why the split exists* and *when it stops being acceptable*.

## The default is insecure, for now

`insecure` is in Cargo's **default** feature set. A default build therefore has
no sandbox.

This inverts the usual and correct convention — secure by default — and it is
done deliberately, because the alternative is worse in the current state of the
project: secure mode cannot arm without a target advertisement (LLP 0036), so a
"secure by default" build does not run at all. A default that refuses to execute
JavaScript is not a safe default; it is an unusable one, and it pushes every
developer onto an explicit flag they will then never turn off.

A secure build is correspondingly explicit:

    cargo build --bin ibex --no-default-features \
        --features standard,unadvertised-dev-arming

The `standard` feature exists only so that invocation does not have to re-list
the ordinary runtime features (`module-runner`, `tls-client-identity-openssl`)
by hand.

**This is the most reversible part of this decision and the first thing to
revisit.** The default should flip back to secure as soon as secure mode is
dependable — before Ibex runs any third-party code, and well before anything
ships. Until then the inverted default is a bet that the project is still
entirely internal.

## Why this is acceptable right now

The threat a capability sandbox principally defends against is **code you did
not write**. Ibex today is developed internally, runs first-party code, and does
not pull packages from npm. Under those conditions the sandbox is protecting
first-party code from itself, which is worth much less than it will be later.

Accepting that trade is a deliberate, informed choice, not an oversight. It is
recorded here so that it stays deliberate.

## When this stops being acceptable

The reasoning above rests on assumptions that will expire. Any of the following
invalidates it and requires re-evaluating this decision — not merely noting it:

1. **Running third-party code.** Installing an npm dependency and executing it
   under `insecure` removes the only thing making the trade sound. This is the
   likeliest trip-wire because it can happen casually, in a single command.
2. **Running code from outside the team** — a bug reproduction, a gist, a
   customer sample, an AI-generated snippet from an untrusted source.
3. **Anything user-facing.** A build that reaches a user, a demo machine, or a
   published artifact must never be `insecure`.
4. **Agent-driven execution.** Coding agents (including the one that wrote this)
   run code in this repository. An agent running arbitrary or generated code
   under an `insecure` build has the same exposure as item 2, with more volume
   and less human review per execution.
5. **CI producing artifacts.** A release pipeline that inherits `insecure`
   ships a runtime with no sandbox.

None of these are hypothetical-only; items 1 and 4 are the ones to actually
watch, because both are one careless command away.

## Secure mode must stay exercised

The security risk of this split is low today. The **engineering** risk is not,
and it is the thing this decision must actively defend against.

If all day-to-day development happens in `insecure`, nothing exercises the
secure path. Secure mode then rots silently: breakage accumulates, is discovered
late, and is attributed to whichever change is being made at the time rather
than the one that caused it. "We will care about security later" degrades into
"secure mode has not worked for months and nobody knows which commit did it."

Flipping the default made this concrete immediately. Five lib tests assert
*armed refusal* semantics that an `insecure` build deliberately does not have,
so they are gated `#[cfg(not(feature = "insecure"))]` and no longer run in a
default `cargo test`. That is correct scoping — the assertions are meaningless
in a build with no sandbox — but it means the default test run is now blind to
exactly the behaviour this project most needs to keep working. Running the suite
in secure mode is what closes that gap, and it is no longer optional bookkeeping.

This is the failure mode of every two-track system where one track is optional.
Mitigations, in rough priority:

1. **CI runs the suite in secure mode.** Implemented as
   `scripts/check-secure-mode.sh` (`bun run check:secure-mode`), wired into the
   CapSec macOS job, which already has a patched Hermes available. This is the
   single most valuable guard, because it converts silent rot into a failing
   build attributable to a commit.
2. **The same script asserts enforcement behaviourally**, not just that tests
   pass: a project read must succeed while reads, writes, and spawns outside
   the project must be *refused*. This is the check unit tests are least likely
   to cover and it is the one that matters most — a secure mode that compiles
   and passes its assertions while authorizing everything would look healthy
   right up until it shipped. The probe was validated against an `insecure`
   binary and correctly reports `BAD(permitted)`, so it can actually fail.
3. **When a capability refusal blocks work, prefer fixing the grant over
   switching to `insecure`.** Reaching for `insecure` is correct when the
   refusal is a bug in an unfinished mechanism; it is a mistake when the
   refusal is legitimate and the real fix is a policy or ceiling change.

The secure-mode script has no test exclusions. The former ENG-25424 exclusion
was removed after prepared graphs stopped projecting private backing paths into
Hermes source labels, `import.meta`, stack traces, and source maps. Its
regression also retains the independent fail-closed boundary for authored
call-time dynamic imports: until the runtime owns an in-drive activation
capability, the prepared linker refuses that graph rather than eagerly
authorizing a dead branch.

Promotion-facing CapSec execution is part of this guard, not an exception to
it. Every generated fixture, adapter, public-surface, callback, startup,
closed-surface, target-absence, and inherited-intrinsic Cargo command must use
`--no-default-features` and explicitly select
`standard,capsec-conformance-observer,openssl-crypto`. The command stored in a
recipe or evidence plan is itself security-relevant evidence. It must never
inherit Cargo's default feature set, because the default currently includes
`insecure` and deliberately bypasses the production decision plane.
The physical portable-promotion build follows the same rule: its checked
all-target executable-set vector includes `--no-default-features`, and the
source-derived active feature closure rejects both `default` and `insecure`.
The workflow must byte-for-byte spell that checked vector before any selected
test executable can produce promotion evidence.

## Preventing an accidental ship

A banner is a good reminder and a weak guarantee — it is observed by humans at
runtime, not by pipelines at build time. A stronger guard is a build-time
refusal, for example rejecting `insecure` in release builds or in CI release
jobs.

This is deliberately **not** implemented yet, because a release-profile
`insecure` build is legitimately useful for local performance work, and a naive
`compile_error!` on `--release` would block it. The guard should key on
publication (release pipeline, artifact upload), not on optimization level.
Until it exists, item 3 and item 5 above rest on discipline alone.

## Consequences

- Ibex is usable locally today, and work on the runtime is not gated on the
  security model being finished.
- Security work proceeds on its own schedule, against a mode that CI keeps
  honest, rather than under pressure to unblock everyone else.
- The project accepts, explicitly, that `insecure` builds have the ambient
  authority of the invoking user, and that the assumptions justifying this are
  written down and expire. Since 2026-07-24 that includes the inherited host
  environment: insecure `process.env` projects it (LLP 0038 §"Fully open
  mode"), while every secure mode keeps the authenticated empty base.
- This document should be revisited the first time Ibex executes code it did not
  author — that event, not a date, is the trigger.
