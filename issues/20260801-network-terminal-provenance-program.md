# Network terminal-provenance program (LLP 0045 → 0046) — umbrella

**Status:** Open — rescoped
**Severity:** P2
**Systems:** Security, Conformance, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-01
**Revised:** 2026-08-01 (LLP 0045 executed and superseded)
**Related:** LLP 0046 (what the measurement found — **read this first**);
LLP 0045 (the superseded plan); LLP 0044 §9 (origin measurement);
issues/20260728-capsec-public-surface-evidence-backlog.md

## Status change

LLP 0045 was executed on 2026-08-01. Every work stream was measured against
source and the running walker; **seven of eight yield figures were wrong, five
collapsing to zero**. The plan is superseded by LLP 0046, which records the
measurement.

The **problem is still real** — network cells genuinely cannot be certified by
probe authoring alone. What changed is its size and shape.

## Corrected scope

Of the 338 asserted Lane B cells: **127 capability-bearing** (floor 81), 112
network-by-origin *policy*, 90 seeding defects, 9 unconditional throws. A
further 42 are exact export aliases of other counted cells (296 unique).

## Work breakdown (rescoped)

**Blocked on an author decision — the highest-leverage question in the program:**

- [ ] **Origin policy (112 cells).** Is touching a socket-derived message
      network-attributed by origin (`retainedNetworkOriginEffectSpec`)? This one
      decision moves the scope between **127 and 239**. Not a bug fix; a policy
      call. LLP 0046 §6.

**Prerequisite, not parallel cleanup** — certifying a mis-seeded cell would
certify a claim that is false about the source:

- [x] Fix `builtinExportClassification`: member carve-outs *before* the
      receiver-class prefixes, exact-string member sets — **landed 2026-08-06**
      (LLP 0049 Phase 0). Caveat recorded in the allow-list note: the LLP 0046
      `K-cell-verdicts.tsv` could not be found, so membership was re-derived
      from `src/builtins` at HEAD with a conservative any-doubt-stays-seeded
      rule; measured movement 82 cells (vs the 90 the 2026-08-01 measurement
      predicted — surface growth since then accounts for part of the gap).
      Deliberately-left-seeded residuals are enumerated in
      `llp/evidence/0049-allow-list-phase0-seeding.json`.
- [x] New `unsupported-throwing-stub` disposition — **landed 2026-08-06** as a
      non-capability rationale id in `capsec/registry/policy-rules.json` (8
      cells at HEAD, not 9: the four http2 producers, the two `.pipe` stubs,
      the two ws `_handle` accessors; each keeps an authorable
      observe-the-throw obligation, nothing retired; closed vocabularies
      untouched).
- [x] Withdraw the `node_http2` effect assertions — **landed 2026-08-06**, all
      three sites (connect, performServerHandshake, and the class prefix), not
      just the one the original note pinned.
- [x] De-duplicate the alias cells — **landed 2026-08-06** via a reviewed
      exact-export-alias table + fail-closed join (59 cells at HEAD — net 50,
      ws 9 — vs the 42 the 2026-08-01 measurement counted; surface growth).
      Obligations attach to the canonical cell; alias edgeIds stay covered on
      the shared fixtures.
- [ ] Re-measure, then author the successor plan — organized by **analyzer
      capability**, not by ambiguity-string bucket. *(Partially discharged
      2026-08-06: post-seeding network accounting is measured — 507
      network-asserting cells, network Lane B 284 → 216 — but the successor
      plan still MUST NOT be authored until the origin-policy decision above
      is made; that decision is deliberately NOT part of LLP 0049's Phase 0
      packet.)*

**Landed 2026-08-05:**

- [x] **Normalized the four hook aliases + hardened every hook install.** The
      two `http.js` aliases plus the `net.js` and `dgram.js` aliases now use the
      walker's existing `const _x = globalThis.__exact*Owner` form. The POSIX
      net install (`hermes_runtime_net.cc:967-970`), HTTP install
      (`hermes_runtime_http.cc:347-350`), and Windows shim
      (`hermes_runtime_platform_windows.cc:2870-2873`) seal the installed host
      function non-writable and non-configurable before returning. Fresh Apple
      and Windows recipe catalogs both moved network Lane B **338 → 292:
      exactly 46 cells cleared**, matching the estimate. In total, **104 unique
      network cells** had route-evidence changes (1,126 scenario recipes / 3,408
      gated route-and-residual entries); the other 58 gained or changed
      provenance without leaving Lane B. The focused P2 ticket is closed under
      `issues/closed/20260801-net-owner-hook-lazily-captured-after-user-code.md`.
- [x] **Callback-argument attribution** (`walkDirectFunctionBody`,
      capsec-surface-inventory.mjs, landed 2026-08-05). The original **11-cell
      network Lane B** estimate reproduced exactly and all 11 now have a
      terminal. Measuring the outside-Lane-B class at the same time found and
      corrected **9 network misattributions** (**20 network cells total**).
      Repository-wide, 46 misattributions were corrected and 15 zero-terminal
      cells gained terminals (13 carried and cleared formal Lane B); 0 recorded
      terminals were removed. `unresolved-call:setTimeout` remains unadmitted.
      See issues/closed/20260801-conformance-misattributed-terminals-outside-lane-b.md.

Nothing remains under "ready to staff now" — both measured, independent items
above have landed.

**Landed 2026-08-01:**

- [x] Duplicate-definition source hygiene (`oncreate` rename + 3 dead-assignment
      deletions in http.js). 13 ambiguity entries retired, 5 previously-masked
      entries surfaced, **net −8, 0 cells cleared**. Open question 7 answered.
- [x] `scripts/llp0045-route-evidence-diff.mjs` — LLP 0045 §3's paired
      allow-list acceptance gate, executable, with 14 tests
      (`bun run test:llp0045-route-evidence-gate`).

## Explicitly NOT this program's work

- **Step 1 de-virtualization.** The eligible set is 5 slots / 31 call sites, all
  `HttpRequestParser` internals, and **no Lane B cell's route mentions any of
  them**. Register items 1 and 5 govern a transform nothing routes through.
- **Qualified-member resolution.** 113 pure cells → 0 Lane B yield, ceiling 6.
  107 are property reads and EventEmitter projections with no route to prove.
- **The 33 `empty-no-mechanism` cells.** 0 capability-bearing; they close via the
  seeding fix, not via analysis. Count them separately — nothing became provable.

## Spun out

- issues/closed/20260801-builtin-commonjs-require-activation-refused.md — the
  entire CommonJS builtin surface was broken on `main`; only `path` loaded.
- issues/20260801-net-owner-hook-lazily-captured-after-user-code.md (P2)
- issues/closed/20260801-lockdown-tostring-override-blocks-builtins.md (resolved)
- issues/20260801-readline-interface-prefix-seeds-stdio-effect.md
- issues/closed/20260801-conformance-misattributed-terminals-outside-lane-b.md

**Done when:** the successor plan authored in LLP 0046 §6's sequence passes its
own exit gate. This ticket tracks the rescope; the original "373 → ~0" metric is
void — both the numerator and the denominator were wrong.
