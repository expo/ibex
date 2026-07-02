# Review: LLP 0013 — Per-Package Capability Enforcement via Hardened Compartments

**Reviewer family:** Claude (Anthropic)
**Provider / runtime:** Claude Code · model `claude-fable-5`
**Date:** 2026-07-02
**Redacted:** No — performed entirely against local repo sources and the local
Hermes build checkout; nothing transmitted to an external provider.
**Independence:** **Not independent.** This session's family (and largely this
session) authored the draft. Under the LLP 0005 honesty rules this artifact is
an **author-side deep revision pass**, not an independent family review — it
does not count toward a multi-family loop. The independent review on file is
`0013-per-package-capability-compartments.openai.md` (Codex/GPT-5, 2026-07-02).
**Method:** Full re-read of the assembled document; re-verification of
`[observed]` citations (all previously checked in-session, two re-checked
below); disposition of every concern in the OpenAI review; fresh adversarial
pass over the design for gaps neither the draft nor that review named.

## Overall assessment

Revise in place and stay `Draft` — which this pass did. The draft's shape
survived review intact (threat model split, three mechanisms, phasing, fork
discipline, re-derivation posture). What needed fixing was seams: Phase 1's
security story was under-specified in exactly the places a hostile package
would probe (dynamic code, `this`-escapes, the real-global surface), one
internal contradiction had crept in during the decision edits, and one
citation was wrong.

## Disposition of the OpenAI review (C1–C6)

- **C1 (High, eval/Function containment in Phase 1) — accepted.** Mechanism 1
  now specifies evaluator taming as load-bearing (prototype-walk reachability
  of `%Function%` et al.); Mechanism 2 enumerates the three escape channels
  (free identifiers, `this`-escapes, dynamic evaluators) with their closures;
  Phase 1 gains an explicit dynamic-code deliverable; Resolved question 5 now
  states the vendored `ses` subset includes taming; Resolved question 2 gains
  the reject-vs-compiler-hook clarification the review asked about.
- **C2 (High, frame-accuracy promised early) — accepted.** New
  security-claims-by-phase table at the top of the Plan; Phase 1 attribution
  re-worded to best-effort, transform-derived, explicitly forgeable; Phase 2
  is now "the first phase entitled to claim frame-accurate attribution," with
  the callback/prototype/promise/native/host-callable test list; acceptance
  criteria tag frame-accuracy as Phase 2+.
- **C3 (High, real-global inventory) — accepted.** Phase 0 begins the
  inventory (citing the lazy `__exactEnsure*` installers,
  `src/engine/hermes_runtime.cc:1056-1074`, which conflict with sealing the
  true global and move to eager-install-then-seal); Phase 1 completes the
  classification (removed / hidden / endowed-attenuated / retained-inert);
  "recover the real global" is a named red-team case; the `__exact*` family
  is explicitly a subset of the checklist.
- **C4 (Medium, name-only principals) — accepted as a refinement.** Resolved
  question 1 keeps the author's name-keyed decision but now separates policy
  **selector** (name) from runtime **principal** (name + resolved locator),
  with audit logs emitting both; Design §Policy gains a concrete two-version
  policy sketch.
- **C5 (Medium, hermes: citation reproducibility) — accepted.** The citation
  convention now names the materialization commands, the cache path, and the
  resolved commit (`ac8c6e6c80ec5fc22da39a77379ffb2fdbdde138`, HEAD of
  `origin/260318099.0.0-stable`, verified this pass).
- **C6 (Low, acceptance criteria mixing) — accepted.** Acceptance criteria
  split into "For accepting this RFC" vs "Feature / phase exit criteria,"
  with the two-pin-bump item tagged as Phase 3/4 operational readiness.
- **Suggestions — all taken**: claims-by-phase table; named red-team cases
  ("recover the real global," "dynamic-code escape," plus this pass's
  "sloppy-`this` escape"); `child_process`→`process:spawn` and
  `Capability`≡`Strict` moved from Phase 4 to Phase 0 as audit-data-quality
  defects; the two-version/alias policy example.
- **Surfaced questions — answered in place**: static-transform rejection vs
  compiler hook (Resolved question 2 clarification); acting-principal
  visibility in deputy flows (added to Open question 3's lean); would-deny
  audit semantics (Phase 1 now states would-deny is logged while the
  operation proceeds).

## Findings from this pass (not in the OpenAI review)

- **A1 — Goals §5 contradicted Resolved question 6.** "The fork is opt-in
  after evidence" survived from the pre-decision draft while §6 green-lit all
  phases. Fixed: kill criteria are the only aborts.
- **A2 — Sloppy-mode `this`-escape was unaddressed.**
  `(function(){return this})()` yields the real global in sloppy code — the
  standard UMD idiom, so it is pervasive, not exotic. Fixed: strict-mode
  emission in Mechanism 2 with the compat fallout routed to the Phase 1
  corpus, and a named red-team case.
- **A3 — Attribution granularity assumed evaluation units align with
  packages.** A single bundled HBC file is one `RuntimeModule`, collapsing
  all packages into one principal. Fixed: Mechanism 3 now requires
  per-package module units (also the natural `Domain`-per-package structure
  for Phase 3) or a build-time function-range → package table; Phase 2 owns
  the choice.
- **A4 — The import graph was missing as a policy surface.** Builtins are
  reachable via `require('node:fs')`; endowment policy alone does not contain
  a package that can import builtins freely. Fixed: Design §Policy now
  governs three surfaces (host capabilities, endowments, import graph), with
  loader-enforced builtin/dependency restrictions.
- **A5 — Runtime-internal JS was not named as a principal.** The
  `ibex-runtime-js` security layer exports mutable toggles
  (`enableTestMode`, `disableStrictMode` — `Capabilities.ts:246-333`);
  importable from package code they would be a self-disarm switch. Fixed:
  internal modules are a trusted principal, unimportable from package
  compartments; toggles compiled out or unreachable in production.
- **A6 — Shared mutable module exports (exports pollution) was an
  unacknowledged residual.** Fixed: named in the threat model's accepted
  residuals with new Open question 9 (freeze-on-load as per-package policy,
  default off, corpus-measured).
- **A7 — Stale citation.** `src/host/abi.rs:586-599` pointed at fs-metadata
  code; `ex_host_install` is at `abi.rs:657-659` (verified). Fixed in 0013,
  and the same staleness fixed in LLP 0006 (`586-592` → `657-659`;
  `597-599` → `664-666` for `ex_host_is_allow_all`).
- **A8 — Stale Phase 0 task.** "Decide package identity" survived from
  before the question was resolved; now "validate the decision against real
  graphs."

## Verification notes

Re-checked this pass: `ex_host_install` (`src/host/abi.rs:657-659`),
`ex_host_is_allow_all` (`abi.rs:664-666`), the lazy `__exactEnsure*` pattern
(`src/engine/hermes_runtime.cc:1056-1074`), and the Hermes checkout identity
(commit above). All other `[observed]` citations were verified earlier in the
authoring session against the same tree state. External `[inferred]` claims
(SES/Endo semantics, LavaMoat granularity, MetaMask–Hermes history, JEP 411,
Node policy removal) were **not** re-fetched; they remain marked as external
inference in the document.

## Residual concerns for the next (independent) reviewer

- Whether `ses` lockdown actually completes on the pinned Hermes is the
  single biggest unknown; everything in Phases 1–3 assumes Phase 0 clears it.
- The strict-mode-emission compat bet (A2) is asserted, not measured; the
  Phase 1 corpus must actually quantify it.
- The claims-by-phase table's Phase 1 row ("reachability containment, no
  enforcement claims") is doing a lot of work — an independent reader should
  attack that row specifically.
