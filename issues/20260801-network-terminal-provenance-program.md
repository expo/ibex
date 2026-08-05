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

- [ ] Fix `builtinExportClassification` (capsec-coverage-model.mjs:8788): member
      carve-outs *before* the receiver-class prefixes, following the existing
      :9207/:9216/:9219 pattern. Prefer exact-string member sets over widened
      regexes — a widened regex silently absorbs future members, which is how
      this arose.
- [ ] New `unsupported-throwing-stub` disposition for the 9 refusal cells —
      `pure-in-memory-compute` is the wrong rationale for a throw.
- [ ] Withdraw the `node_http2` effect assertion: 18/18 cells mis-seeded, 0
      capability-bearing, every producer throws (http2.js:250/254/258/262). The
      model asserts an effect the implementation does not have.
- [ ] De-duplicate the 42 alias cells (`net.Stream.*` ≡ `net.Socket.*`
      net.js:4623; `ws.Server*` ≡ `ws.WebSocketServer*` ws.js:1185-1186).
- [ ] Re-measure, then author the successor plan — organized by **analyzer
      capability**, not by ambiguity-string bucket.

**Ready to staff now — measured, cheap, independent of the above:**

- [ ] **Normalize the four hook aliases + harden the hook install.** 4 JS lines
      (`const _x = globalThis.__exactNetOwner`, which the walker resolves today
      unchanged) + 3 C++ lines (`writable:false, configurable:false` at
      hermes_runtime_net.cc:967, hermes_runtime_http.cc:347, and the Windows
      shim). **46 cells.** The two halves must land together: normalization
      alone makes the analyzer credit a terminal the runtime does not guarantee.
      See issues/20260801-net-owner-hook-lazily-captured-after-user-code.md.
- [x] **Callback-argument attribution** (`walkDirectFunctionBody`,
      capsec-surface-inventory.mjs, landed 2026-08-05). The original **11-cell
      network Lane B** estimate reproduced exactly and all 11 now have a
      terminal. Measuring the outside-Lane-B class at the same time found and
      corrected **9 network misattributions** (**20 network cells total**).
      Repository-wide, 46 misattributions were corrected and 15 zero-terminal
      cells gained terminals (13 carried and cleared formal Lane B); 0 recorded
      terminals were removed. `unresolved-call:setTimeout` remains unadmitted.
      See issues/closed/20260801-conformance-misattributed-terminals-outside-lane-b.md.

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
