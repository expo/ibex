# LLP 0039: Secure and Insecure Modes

**Type:** Decision
**Status:** Accepted
**Systems:** Runtime, CapSec, Build, Product
**Author:** Charlie Cheever / Claude
**Date:** 2026-07-24
**Revised:** 2026-08-02 (LLP 0047 author ratification retains ambient
compatibility as the standalone v1 default and closes the copied-recipient
disclosure gap with authenticated first-position `--ibex-info`, which reports
posture/backend/CapSec facts after admission and before application evaluation.)
**Revised:** 2026-08-01 (implementation checkpoint: a catalog-pinned V2
ambient standalone artifact now exists and runs authored code after relocation;
the foreign-code trigger remains tied to actually embedding/executing code Ibex
did not author, while this document's advance re-evaluation already governs
that planned use)
**Revised:** 2026-08-01 (round-3 delta review, **applied after the round budget
closed and therefore NOT re-reviewed**: trip-wire 5 states why it stays keyed
to the Cargo feature rather than generalizing like wires 1-4)
**Revised:** 2026-08-01 (round-2 delta review: the enforcement-off distinction
is restated at its true strength — an ordinary build has no runtime-selectable
enforcement-off route, not literal absence of enforcement-off code; the
foreign-code trigger is recorded as committed-to by a reviewed design rather
than already fired, since no ambient artifact can exist yet)
**Revised:** 2026-08-01 (round-1 dual review: the acceptability trip-wires now
cover *both* enforcement-off surfaces rather than only the `insecure` Cargo
feature, since LLP 0047's ambient path reaches ambient authority through a
supported default route; trip-wire 3 is restated over surfaces Ibex actually
controls; the accidental-ship guard distinguishes the defect it refuses from
the product it permits; the foreign-code trigger is recorded as fired
deliberately rather than left ambiguous; stale unresolved-row figures and an
inverted `cfg` explanation corrected)
**Revised:** 2026-08-01 (LLP 0047 adds a scoped standalone-executable product
posture: the general Ibex CLI remains secure by default, while a compiled
application defaults to an explicitly documented ambient compatibility boot
and can monotonically opt into fail-closed CapSec in the same artifact)
**Revised:** 2026-07-27 (document the authenticated, release-only iOS
Simulator performance observer and its non-product boundary)
**Revised:** 2026-07-25 (the default feature set is secure and fail-closed; unadvertised development arming and no-sandbox execution are explicit compile-time choices; invocation-time ESM import and CommonJS require now cover source and prepared targets)
**Revised:** 2026-07-24 (the secure prepared/live-graph path now defers ESM and CommonJS `import()` discovery until an exact reached site; synchronous authored CommonJS `require()` retains the no-probe refusal)
**Revised:** 2026-07-24 (ENG-25424 closes prepared-graph backing-path disclosure and removes the secure-gate test exclusion; promotion-facing CapSec executors now explicitly disable Cargo defaults so conformance cannot inherit the insecure mode)
**Related:** LLP 0021 (target advertisement + conformance report); LLP 0036 (advertisement completion); LLP 0038 (unadvertised dev arming, insecure build); LLP 0047 (standalone executable dual-mode finish line)

## Context

Ibex's security model is real and largely built — a typed capability decision
engine, per-package frame attribution, a virtual filesystem mount, and a
fail-closed arming ceremony. What is *not* finished is the target advertisement
pipeline that lets an ordinary build arm at all (LLP 0036 measures the
remainder; as of 2026-07-27 it reports ~17.2k unresolved rows per tuple, and
LLP 0021's 2026-07-28 accounting reports 16,628 — down from the ~22k this
document originally cited, with no cheap bulk win found). Finishing it is
months of work, not days.

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

LLP 0047 adds one deliberately scoped product exception. A standalone
application produced by `ibex compile` contains an **ambient compatibility**
boot path and a CapSec boot path in the same file. The standalone application
defaults to ambient compatibility, accepts a monotonic CapSec selector, and
reserves a separate non-evaluating information selector; the general `ibex`
CLI, its Cargo defaults, and its publication
posture remain secure and fail-closed. “Ambient compatibility” is named
separately from the `insecure` Cargo feature because it is a supported compiled
application contract, not a development build accidentally published. The
distinction is mechanical, not just nominal: `insecure` is a compile-time
choice that selects an enforcement-off host construction and permissive gates
for the entire binary, whereas ambient compatibility is a runtime posture
selected within a binary that retains a reachable armed path. Stated precisely,
because an earlier wording overclaimed it: the property an ordinary build has
is **no runtime-selectable enforcement-off route**, not the literal absence of
enforcement-off code — the armed constructor is compiled unconditionally, and
`insecure` selects a different one. **A release stub must never be built with
`insecure`** — its enforcement path has to be present, because the same
artifact must be able to arm when the CapSec selector is given. Ambient boot
keeps package/envelope integrity checks and does not permit runtime module
discovery outside the embedded graph.

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

There are now **two** enforcement-off surfaces, and the trip-wires below cover
both. Until 2026-08-01 there was only one — the `insecure` Cargo feature — and
the wires were written to key on it. LLP 0047 adds a second: a compiled
standalone application's ambient path, which reaches the same ambient authority
through a supported, default, zero-feature-flag route. A wire that names only
the Cargo feature would leave the newer and more likely surface uncovered, so
the wires are stated over *enforcement-off execution* generally — except wire
5, which stays feature-specific for the reason given there.

Any of the following invalidates the choice and requires re-evaluating it —
not merely noting it:

1. **Running third-party code.** Installing an npm dependency and executing it
   under `insecure`, *or embedding it in an ambient standalone executable*,
   removes the only thing making the trade sound. LLP 0047 concedes the point
   directly ("bundling third-party or generated code does not become safe
   because it is embedded in one file"); this document records that the
   concession is a live trip-wire, not a caveat. Likeliest wire on both
   surfaces, because both are a single command.
2. **Running code from outside the team** — a bug reproduction, a gist, a
   customer sample, an AI-generated snippet from an untrusted source — under
   either surface.
3. **Anything user-facing outside LLP 0047's compiled-application contract.**
   The general Ibex CLI, a demo runtime, or another published artifact must
   never carry the development `insecure` feature. A standalone application may
   use LLP 0047's ambient default only when the surfaces **Ibex actually
   controls** disclose the absent sandbox: `ibex compile`'s help and
   first-compile notice, `inspect-executable`, the standalone guide, and
   release metadata. An earlier wording also demanded it of the application's
   own help — which Ibex cannot deliver. LLP 0047 now reserves exact
   first-position `--ibex-info`, so a copied executable itself can disclose the
   authenticated posture, backend inventory, and CapSec availability without
   evaluating its application. Removing or weakening that surface reopens and
   fails this wire.
4. **Agent-driven execution.** Coding agents (including the one that wrote this)
   run code in this repository. An agent running arbitrary or generated code
   under an `insecure` build has the same exposure as item 2, with more volume
   and less human review per execution. The same applies verbatim to an agent
   compiling and running ambient standalone executables, which is a plausible
   near-term use of the very feature LLP 0047 ships.
5. **CI producing artifacts.** A release pipeline that inherits `insecure`
   ships a runtime with no sandbox. This wire stays keyed to the Cargo feature
   deliberately: a posture-general version would fire on every sanctioned
   item-3 ambient release, which is designed behavior, and a wire that fires
   on the intended product stops being a signal. Distinct from, and not
   excused by, deliberately shipping ambient standalone artifacts under item 3.

None of these are hypothetical-only; items 1 and 4 are the ones to actually
watch, because both are one careless command away on either surface.

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
`#[cfg(not(feature = "insecure"))]`. That gate excludes them from an
`insecure` build — it does not exclude them from a default one, since
`insecure` is not a default feature. What keeps them out of an ordinary
default run is the separate `capsec-conformance-observer` feature they also
require. An earlier wording stated the implication backwards. The suite they
belong to runs on an explicit secure build —
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

**This section is about *accidental* shipping, and LLP 0047 makes one form of
enforcement-off shipping deliberate.** The two must not be conflated, and the
guard must distinguish them rather than treat every enforcement-off artifact as
a mistake:

- An `ibex` CLI, demo, or pipeline artifact built with `insecure` is always a
  defect. That is what the guard should refuse.
- A standalone executable whose *default runtime posture* is ambient is the
  reviewed product contract. It is built **without** `insecure` — its
  enforcement path is present and reachable via the CapSec selector — so a
  guard keyed on the Cargo feature correctly permits it without a carve-out.

That is a convenient property, not a lucky one: keying the guard on the
compile-time feature rather than on observed runtime posture is what lets the
same rule refuse the mistake and permit the product. It does mean the guard
provides no protection at all against the ambient default being wrong as a
*product decision* — that risk is governed by trip-wire 3 and LLP 0047's
register, not by a build-time check.

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
  author — that event, not a date, is the trigger. **As of LLP 0047 a reviewed
  design commits to firing it.** The standalone mechanism now exists: a
  catalog-pinned producer has built and run an authored ambient fixture from
  a relocated, source-free executable. That evidence does not by itself prove
  the narrower foreign-code event occurred. An ambient standalone executable
  embedding npm dependencies would be exactly "Ibex executing code it did not
  author with ambient authority," and LLP 0047 schedules precisely that as
  designed, reviewed behavior rather than the accident this trigger was meant
  to catch. This revision is that re-evaluation, made in advance. What remains
  live is every *undeliberate* instance — the general CLI, an agent, a demo, or
  CI reaching ambient authority over foreign code without a reviewed contract
  saying it may. Each such instance still requires re-evaluating this decision
  rather than noting it.
