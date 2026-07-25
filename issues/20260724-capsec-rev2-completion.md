# Complete CapSec revision 2 and critical security features

**Status:** In Progress
**Severity:** P1
**Systems:** Security, Policy, Runtime, Engine, Host ABI, Module Loader, Build, CLI, CI
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-24
**Related:** LLP 0013, LLP 0014, LLP 0016, LLP 0021, LLP 0023, LLP 0039

Complete the CapSec revision-2 program defined by LLP 0021, prioritizing
security-critical enforcement gaps over catalog-only cleanup while retaining
the plan's exact-target conformance and legacy-retirement completion gates.
Work happens on branch `codex/capsec-rev2-completion` in the dedicated
`ibex-capsec-rev2` worktree. Because other work is landing concurrently, the
branch must regularly reconcile with the moving `main` branch at clean
milestones.

## Completion evidence

The authoritative completion audit is LLP 0021's eight completion criteria,
not the absence of TODOs or a narrow passing test. For every criterion, record
the current proving artifact or the remaining contradiction here before this
ticket closes.

## Milestone log

### 2026-07-24 — resumed and established an isolated completion worktree

- Created `/Users/ccheever/projects/ibex-capsec-rev2` on
  `codex/capsec-rev2-completion` from `main` at `86df42ba`.
- Read the root LLP and used `llp-orient` to identify LLP 0021 as the canonical
  revision-2 program, with LLP 0013/0014/0023/0039 as governing siblings.
- Confirmed the typed semantics, canonical-policy v2, arming ABI v2, legacy
  retirement map, and secure-mode rot guard exist.
- Confirmed completion is not yet proved: LLP 0021 remains Draft, the latest
  recorded exact-target report is intentionally incomplete, and multiple
  filesystem, network, audit-admission, bootstrap-floor, target-promotion, and
  legacy-window items remain open.
- Initial estimate: **45% complete for the full LLP 0021 completion contract;
  roughly 70% complete for the security-critical runtime mechanism set.**
  The difference is dominated by exact-target physical conformance,
  advertisements, residual public-surface evidence, and legacy-plane/window
  retirement.

### 2026-07-24 — closed prepared-graph backing-path disclosure (ENG-25424)

- Removed physical source paths from the canonical prepared-graph index. This
  brings the Rust publisher back into agreement with the existing strict v1/v2
  schemas, which already disallowed the extra `path` field.
- Carried the Host-authenticated VFS `SourceLabel` and virtual path through
  source and prepared graphs into native Hermes metadata. File modules expose
  only `file:///project/...` and `/project/...`; builtins expose no virtual
  filesystem path.
- Extended the regression to assert that neither native execution inputs nor
  serialized prepared artifacts contain the private fixture root.
- The newly reachable tail of that regression exposed a second trust-boundary
  defect: an attacker could replace executable carrier bytes and recompute the
  carrier manifest/index digests self-consistently. Writable-cache admission
  now reconstructs the deterministic per-principal publication from the
  independently authenticated inline graph and requires exact manifest,
  carrier-byte, record-artifact, entry, and carrier-index equality. The forged
  cache is refused even when every attacker-controlled digest agrees.
- Preserved the separate production refusal for authored call-time dynamic
  imports. Candidate tables exist, but eager link-time authorization is not a
  substitute for LLP 0026's invocation-time activation; the regression now
  proves this graph remains closed until that capability exists.
- Removed the only test exclusion from `scripts/check-secure-mode.sh` and
  reconciled LLP 0039's description of the gate.
- Test environment note: the isolated worktree does not contain the untracked
  Hermes framework/compiler cache. Tests use explicit read-only paths into the
  primary checkout's `ios/Frameworks` and `tools/hermes` artifacts. The
  catalog-compiler real-HBC test now honors the standard `HERMESC` override so
  the no-exclusions gate works in isolated worktrees and fleet checkouts.
- Verification: `./ref-check` passes (37 LLPs, 2,016 checked refs); the complete
  secure-mode gate passes with 629 library tests passed, 3 hosted/diagnostic
  tests intentionally ignored, and the behavioral denial smoke reporting every
  expected boundary as enforced.
- Estimate after this milestone: **47% complete for the full LLP 0021
  completion contract; roughly 74% complete for the security-critical runtime
  mechanism set.**

### 2026-07-24 — wired cold dependency reads through CapSec graph receipts

- Split production native-graph metadata resolution from executable-source
  acquisition. An authored dependency now yields an exact target identity
  before its source bytes can be read.
- The graph authorizer validates the exact request, target, resolution kind,
  conditions, attributes, principals, snapshot generations, and graph
  generation before entering the Host source-acquisition closure.
- Cold reads finalize their digest-bound `SourceAcquisition` receipt from the
  authenticated bytes and revalidate that receipt before releasing the loaded
  module to the producer. Receipts remain retained for the graph lifetime.
- The six-record source/prepared regression retains five dependency-access
  receipts; the entry is governed by its separate authenticated launch request.
  A denied-edge fixture proves the source closure is never entered.
- Scope remains honest: cache-hit and prepared-carrier reads are not yet wired
  through their corresponding access receipts, although the prepared cache now
  has exact deterministic byte equality from the prior milestone.
- Estimate after this milestone: **49% complete for the full LLP 0021
  completion contract; roughly 76% complete for the security-critical runtime
  mechanism set.**

## Current hard parts

- Exact-target completion is deliberately all-or-nothing. Existing evidence
  must not be promoted from partial or diagnostic runs.
- The production surface is large; generated residual counts must be reduced
  through real source-bound executions or honest closure, never hand-labelled
  as passing.
- `main` is moving as old worktrees are landed, so generated CapSec artifacts
  and source-review identities can rotate during this effort.
- The default build is intentionally insecure per LLP 0039 while the secure
  feature is separately guarded; LLP 0021's original plain-execution wording
  needs a completion interpretation consistent with that later decision.
- Native dynamic-import candidate tables are implemented, but production
  linkers deliberately refuse all authored call-time edges because the runtime
  lacks a private invocation-time CapSec activation capability. The filesystem
  issue claiming this runtime work complete is stale relative to the later
  security guard and LLP 0026's call-time contract.
- The root/bootstrap mechanism seals correctly, but both builders still emit an
  empty `bootstrapAuthorityFloor`. Current bootstrap host inputs are
  authenticated projections consumed under the transparent runtime principal,
  so there is no evidenced root effect from which to derive a nonempty floor.
  Populating one by guess would add authority rather than close a gap. This
  needs either a named root-attributed bootstrap operation or a revised
  requirement before the requested real retained-callback fixture is honest.

## Next milestone

Audit the current secure-mode and generated-registry gates, then close the
highest-priority live enforcement gap that can be proved on the current
macOS/arm64 target. Reconcile `main` before committing.
