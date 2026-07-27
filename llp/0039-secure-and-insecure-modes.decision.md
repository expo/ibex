# LLP 0039: Secure and Insecure Modes

**Type:** Decision
**Status:** Draft
**Systems:** Runtime, CapSec, Build, Product
**Author:** Charlie Cheever / Claude
**Date:** 2026-07-24
**Revised:** 2026-07-27 (document the authenticated, release-only iOS
Simulator performance observer and its non-product boundary)
**Revised:** 2026-07-25 (the default feature set is secure and fail-closed; unadvertised development arming and no-sandbox execution are explicit compile-time choices; invocation-time ESM import and CommonJS require now cover source and prepared targets)
**Revised:** 2026-07-24 (the secure prepared/live-graph path now defers ESM and CommonJS `import()` discovery until an exact reached site; synchronous authored CommonJS `require()` retains the no-probe refusal)
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
| **secure production posture** | **the default build; refuses without an advertisement** | default build |
| **secure development posture** | `--features unadvertised-dev-arming` | removed |
| **insecure** | `--features insecure` | `--features insecure` |

`insecure` is **not** scheduled for deletion, but it is never implicit.
`unadvertised-dev-arming` is scaffolding and disappears when the default build
can arm from a real conformance report; at that point the split becomes exactly
*default* versus *insecure*, which is one explicit switch with two positions.

This supersedes the removal condition in LLP 0038, which assumed both features
were transitional.

Mechanically the modes are described in
[LLP 0038](./0038-unadvertised-dev-arming.decision.md); this document records
*why the split exists* and *when it stops being acceptable*.

## The default is secure and fail-closed

`insecure` is absent from Cargo's **default** feature set. A default build has
the complete sandbox and target-advertisement ceremony. While LLP 0036 has no
promoted target, that build refuses before project code instead of silently
executing with ambient authority.

The repository briefly inverted this convention on 2026-07-24 to unblock
development while major secure-path mechanisms were unfinished. That trade is
no longer justified: the secure gate has no exclusions, invocation-time ESM
and CommonJS activation covers source and prepared targets, and agent-driven
execution is already one of this document's explicit trip-wires. Developer
convenience remains available through named compile-time choices rather than
an ambient default.

A secure development build that bypasses only target advertisement is:

    cargo build --bin ibex --no-default-features \
        --features standard,unadvertised-dev-arming

The `standard` feature exists only so that invocation does not have to re-list
the ordinary runtime features (`module-runner`, `tls-client-identity-openssl`)
by hand. A no-sandbox build requires the separately named `insecure` feature
and retains its red banner.

## Why explicit insecure mode remains

The threat a capability sandbox principally defends against is **code you did
not write**. There are still legitimate local compatibility and performance
investigations that need the historical ambient behavior. Keeping that posture
as an explicit compile-time feature makes those investigations possible
without making every ordinary build inherit the same authority.

## When this stops being acceptable

Choosing the explicit insecure posture rests on assumptions that will expire.
Any of the following invalidates that choice and requires re-evaluating it —
not merely noting it:

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

The no-sandbox mode is explicit, but the **engineering** risk of two paths
remains and this decision must actively defend against it.

If all day-to-day development happens in `insecure`, nothing exercises the
secure path. Secure mode then rots silently: breakage accumulates, is discovered
late, and is attributed to whichever change is being made at the time rather
than the one that caused it. "We will care about security later" degrades into
"secure mode has not worked for months and nobody knows which commit did it."

Tests scoped away from `insecure` now run in an ordinary default suite. The
separate secure-mode gate remains necessary because it also compiles the
unadvertised development posture and executes behavioral denial probes.

The same scoping now covers the `--bin ibex` armed/capsec conformance batches
(2026-07-27, after forty of them spent days failing confusingly on
insecure-default observer builds and were briefly misdiagnosed as engine
drift): every observer test that asserts secure-armed semantics carries
`#[cfg(not(feature = "insecure"))]`, so a default build simply does not
contain them. The suite they belong to runs on an explicit secure build —
`scripts/run-tests.sh --secure --features capsec-conformance-observer
--scope bin -- --test-threads=1` (the `--secure` flag supplies
`--no-default-features --features standard,...`; serial because the batches
share process-global environment variables). The full story is in
`issues/closed/20260727-armed-observer-suite-needs-secure-build.md`.

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
call-time module work: ESM and CommonJS `import()` retain only exact deferred
site declarations and cannot resolve, acquire, or read a target carrier before
the site is reached. Authored CommonJS `require()` uses the narrower in-drive
capability, and both import forms can select deterministic invocation-time
prepared carriers only after the exact source receipt exists.

Promotion-facing CapSec execution is part of this guard, not an exception to
it. Every generated fixture, adapter, public-surface, callback, startup,
closed-surface, target-absence, and inherited-intrinsic Cargo command must use
`--no-default-features` and explicitly select
`standard,capsec-conformance-observer,openssl-crypto`. The command stored in a
recipe or evidence plan is itself security-relevant evidence. It keeps spelling
the exact secure feature closure rather than inheriting Cargo defaults, so a
future default-feature change cannot silently alter promotion authority.
The physical portable-promotion build follows the same rule: its checked
all-target executable-set vector includes `--no-default-features`, and the
source-derived active feature closure rejects both `default` and `insecure`.
The workflow must byte-for-byte spell that checked vector before any selected
test executable can produce promotion evidence.

## Simulator-only performance observer

The `capsec-simulator-performance-observer` Cargo feature is a narrow
measurement carrier for a consumer-owned native performance lane. It is not a
third product mode and is never a default feature. The crate refuses to compile
it in debug builds or for anything except an iOS Simulator target.

The carrier preserves ordinary ABI behavior while substituting only the
ratified report target cells and root-loopback fetch used by the measurement
fixture. Before either substitution is accepted, the armed runtime authenticates
the loaded Hermes image and verifies the secure posture. It emits explicit
markers for authenticated substitution, loopback substitution, posture
verification, runtime creation, and carrier dispatch so the consumer receipt
can fail closed if any stage is absent. The observer does not advertise an
ordinary target complete, weaken the default runtime, or authorize a production
artifact.

Consumer evidence may use this feature only in an explicitly feature-bound
Release simulator build governed by that consumer's own ratified observer and
invalidation amendments. Ordinary iOS products retain the normal build surface,
and publication pipelines must not enable the feature.

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

- Ibex is usable locally through the explicitly selected secure-development or
  insecure posture; an ordinary build keeps the production fail-closed claim.
- Security work proceeds on its own schedule, against a mode that CI keeps
  honest, rather than under pressure to unblock everyone else.
- The project accepts, explicitly, that `insecure` builds have the ambient
  authority of the invoking user, and that the assumptions justifying this are
  written down and expire. Since 2026-07-24 that includes the inherited host
  environment: insecure `process.env` projects it (LLP 0038 §"Fully open
  mode"), while every secure mode keeps the authenticated empty base.
- This document should be revisited the first time Ibex executes code it did not
  author — that event, not a date, is the trigger.
