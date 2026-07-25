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
  primary checkout's `ios/Frameworks` artifacts. Fleet validation stages the
  compiler at its standard repository-relative test path; making the test read
  a new process environment variable would itself add an unclassified startup
  surface to the generated CapSec registry.
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

### 2026-07-24 — reconciled the target-advertisement program from moving main

- Observed `main` advance from `86df42ba` to `f85443a3` while the source-access
  slice was in progress. Checkpointed the slice and rebased both security
  milestones cleanly onto the new tip.
- The landed LLP 0036/0037 program closes producer attestation, accepts the six
  gate-1 residual output rows by author decision, and reclassifies 3,727
  internal-invariant recipes under a separately auditable
  `internally-verified` disposition.
- No target is advertised yet. On Apple, gate 2 still has 18,266 reachable
  unresolved recipe rows after the reclassification (2,592 fully executable
  in the measured catalog); the new plan correctly frames the remainder as
  thousands of distinct public invocation shapes, not a cheap bulk-labeling
  exercise.
- Current rebased commits are `72a3b154` (prepared publication) and `d8380b9b`
  (source acquisition) on `codex/capsec-rev2-completion`.
- Reconciled estimate: **52% complete for the full LLP 0021 completion
  contract; roughly 76% complete for the security-critical runtime mechanism
  set.** The full-contract increase reflects landed promotion machinery and
  governed recipe-family authoring, not target promotion.

### 2026-07-24 — fleet-validated the rebased security milestones

- Staged the rebased worktree plus the exact Hermes framework/compiler inputs
  on the M4 fleet host (`100.106.94.95`). The advertised M5 host
  (`100.88.75.121`) currently refuses its documented SSH key, so it could not
  be used.
- The first M4 run found two diagnostic subprocess-transpiler failures because
  that host's `node` resolves to a deliberately non-invocable Volta shim. After
  placing the host's real Bun binary first in `PATH`, both race tests passed.
- The complete secure-mode gate then passed on the rebased source: 629 library
  tests passed, 3 hosted/diagnostic tests remained intentionally ignored, and
  the project-read/outside-read/outside-write/spawn/environment behavioral
  probes all reported the expected enforced outcomes.

### 2026-07-24 — receipt-gated prepared dependency carriers

- A retained `SourceAcquisition` receipt can now continue only into a
  `PreparedCarrierRead` for the same exact target and source integrity. The new
  receipt additionally binds the deterministic carrier digest, graph
  generation, snapshot digest, and all authority generations.
- Prepared dependency manifest/payload bytes are read only inside the
  revalidated carrier receipt closure, and the prepared graph retains the new
  receipt for its lifetime. A mismatch refuses before the access closure is
  entered.
- A carrier with no dependency receipt is admissible only if it contains the
  launch entry. That is not treated as an import edge: production prepared
  selection already follows the exact structured entry-request join.
- Armed transpilation is fresh and in-memory, so there is no persistent
  transpile-cache hit requiring a `CacheRead` receipt. The operation remains in
  the closed graph algebra for any future cache-bearing path.
- Verification: the focused prepared-cache regression passed on the M4,
  including forged-publication refusal and the retained carrier-receipt count.
  The M4's 228 GiB temporary volume then reached 100% while rebuilding the
  complete native archive; its exact 7.0 GiB disposable worktree `target/` was
  removed, restoring that space. The final local secure-mode gate passed with
  630 library tests, 3 intentional ignores, and every behavioral denial probe
  enforced. The generated CapSec registry check and `ref-check` also pass.
- Current estimate: **53% complete for the full LLP 0021 completion contract;
  roughly 78% complete for the security-critical runtime mechanism set.**

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

Run the focused prepared-carrier regression and full secure gate for the new
receipt continuation, reconcile moving `main`, then select the next proved
enforcement gap. Dynamic call-time activation and bootstrap-floor authorship
remain blocked on the named design/runtime capabilities above rather than safe
local substitutions.
