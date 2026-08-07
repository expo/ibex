# LLP 0031: Ibex 0.2 Native Platform Matrix

**Type:** Decision
**Status:** Accepted
**Systems:** Build, Engine, Runtime, CI
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-18
**Revised:** 2026-08-05 (author acceptance recorded after implementation and
the LLP 0047 standalone-release scope reconciliation)
**Revised:** 2026-08-01 (LLP 0047 scopes the SFE release coupling below: the
standalone executable's ambient path ships without a verified CapSec
advertisement, while 0.2 source execution keeps the coupling unchanged)
**Related:** LLP 0001 (target-platform ambition and CI); LLP 0026 (native module runner); LLP 0028 (legacy-window retirement); LLP 0029 (single-file executable targets); LLP 0030 (diagnostic audit admission); LLP 0047 (standalone executable finish line; scopes the SFE coupling)

## Context

Closing the 0.1 compatibility window makes platform support an execution and
security decision, not only a build-matrix preference. A tuple without the
patched native module runner, matching Hermes artifacts, and verified CapSec
evidence cannot silently retain the compatibility evaluator for source,
runtime TypeScript, audit, or diagnostic execution.

The repository has complete native-runner and single-file-executable work for
`aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`. Windows x64 and macOS
x64 remain product-relevant, especially to Snapback, but do not yet have the
same verified artifact and conformance chain. LLP 0028 requires an explicit
0.2 disposition before the legacy window closes.

## Options considered

1. Advertise every aspirational LLP 0001 tuple and accept partial evidence.
   This would turn a product goal into an unsupported security claim.
2. Keep the compatibility evaluator on unverified tuples. This would preserve
   surface compatibility while defeating the Oxc-only 0.2 contract and its
   single transform-identity domain.
3. Advertise only evidence-complete native tuples and fail closed elsewhere,
   promoting more tuples only after their exact evidence gates pass.

## Decision

Ibex 0.2's native source/module execution matrix is:

| Tuple | 0.2 disposition | Required release evidence |
| --- | --- | --- |
| `aarch64-apple-darwin` | intended advertised native target | matching patched Hermes bundle, native module-runner corpus, complete verified CapSec target advertisement |
| `x86_64-unknown-linux-gnu` | intended advertised native target; compiled baseline `linux-glibc-2.35-x86-64-v1` | matching static patched Hermes bundle, ELF dependency/ISA audit, native module-runner corpus, complete verified CapSec target advertisement |
| Windows, macOS x64, and every other tuple | unsupported for 0.2 source/module execution until independently promoted | exact matching artifacts plus the same native-runner and CapSec gates; product demand alone is not evidence |

“Intended advertised” does not bypass production posture. If either selected
tuple lacks a verified CapSec advertisement at release time, 0.2 waits; code or
CI configuration must not fabricate or infer promotion from the tuple list.

On an unadvertised tuple, file execution, runtime TypeScript/JSX, source audit,
and source diagnostics that require evaluation return a stable
target-unavailable refusal. They do not select SWC, the compatibility
evaluator, an ambient Hermes build, or an unverified prepared carrier.
Non-evaluating inspection remains available where its own format parser is
supported and must report the absent execution advertisement honestly.

Single-file executable catalog population follows the same two tuples.
Windows and macOS x64 may be pulled forward by a later author decision when
Snapback needs them, but that changes scheduling only; it does not relax any
promotion gate.

**Scoped 2026-08-01 by LLP 0047.** The advertisement requirement above, and
the release coupling in Consequences, govern **0.2 source execution** — `ibex
run`, eval, REPL, runtime TypeScript, audit, and diagnostics — unchanged. They
no longer gate the standalone executable, which under LLP 0047 ships one
artifact with an ambient-compatibility default that makes no capability claim
and an explicitly selected, fail-closed CapSec path. A standalone v1 may
therefore release with zero verified advertisements; the first successful
CapSec launch is a v1.1 milestone. Two consequences of the surrounding text
are scoped accordingly: SFE catalog population still follows these two tuples,
and there is still exactly one catalog entry per target serving one dual-mode
artifact — but "complete verified CapSec target advertisement" is no longer
among the evidence required to populate that entry. Advertisement now gates
claiming the artifact's optional CapSec mode *works* on a tuple, not whether
the tuple may be cataloged at all. The unadvertised-tuple
refusal language above ("do not select ... an ambient Hermes build, or an
unverified prepared carrier") continues to bind source execution and does not
forbid ambient compiled boot, which selects neither an ambient engine build
nor an unverified carrier — every carrier it evaluates is envelope-admitted
and digest-bound exactly as on the CapSec path.

## Consequences

- LLP 0028 may close the compatibility window without implying support on
  every platform named by LLP 0001's longer-term ambition.
- Runtime TypeScript remains a first-class 0.2 capability on the two selected
  tuples and an explicit incompatibility elsewhere.
- CI derives required native execution rows from this decision and keeps other
  tuples visible as unsupported/known-red rather than silently passing them.
- Release scheduling for **0.2 source execution** is coupled to verified CapSec
  advertisements for both selected tuples. Missing evidence holds that release.
  Per LLP 0047 this coupling does not extend to the standalone executable's
  ambient path (see the scoping note above).
- Adding Windows, macOS x64, another architecture, or another Linux baseline is
  a monotonic matrix expansion with its own artifacts and evidence, not a
  compatibility-mode exception.

## Follow-up

1. Reconcile LLP 0001 and LLP 0026 so their broad platform language points to
   this 0.2 matrix for native source execution.
2. Make the window-close and SFE CI matrices consume the selected tuples from
   one generated authority.
3. Archive the verified target reports before changing either tuple from
   intended to advertised in generated CapSec artifacts.
