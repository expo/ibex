# Complete the residual CapSec public-surface evidence catalog

**Status:** Open
**Severity:** P2
**Systems:** Security, Conformance, CI
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-28
**Related:** LLP 0021; issues/20260717-sfe-capsec-advertisement.md;
LLP 0044 (Draft, 2026-07-31 — proposes collapsing this backlog's cost via
scoped advertisement + obligation-vocabulary audits + the mechanized
family loop; if accepted, this ticket's "each shipped target's required
rows" criterion binds to the declared v1.1 scope)

## Problem

The security-critical CapSec rev2 implementation is complete, but neither
candidate target has a complete public-surface conformance catalog. The final
bounded catalogs at revision 2 acceptance are:

- Apple
  `sha256-GHlqGTU7b020Cp107EbGh4TShEtB_kOoRz5R1pDtYEo`: 23,598 required,
  3,928 fully executable, 3,042 internally verified, 16,628 unresolved.
- Windows
  `sha256-FAud-eHXcShfXTx3wsnucQFaQ96H2khcNzhxUqxbwzU`: 23,257 required,
  3,564 fully executable, 3,028 internally verified, 16,665 unresolved.

Advertisements correctly remain empty. These residual rows are conformance
and evidence uncertainty, not proof of a runtime bypass and not permission to
claim either target. This ticket is deliberately separate from the completed
security-implementation tranche so catalog work converges through prioritized,
reviewable batches rather than open-ended discovery.

## Priority and scope

P2. Prefer rows that are target-applicable, source-inventoried, and close a
release-relevant claim. Evidence-quality improvements and speculative
hardening stay behind those rows unless a concrete exploitable flaw is found.
Do not promote labels, generic failed imports, or one target's evidence as
another target's proof.

**Measured 2026-07-31 (LLP 0044 §9):** the day-one scope measurement
found the certifiable cheap scope is **fs+env+process** (457/513 cells
clean, 3,256 authorable rows across 424 surfaces in 64 template classes);
`network` is 64% poisoned by no-terminal rows and needs its own program.
If LLP 0044 is accepted, prioritize the fs+env+process rows first.

**Progress 2026-08-05 — direct armed environment write:** a fresh
`aarch64-apple-darwin` catalog at
`sha256-FNMK1tLlsukgqktcaro3d9yASLSAWPFUfb0Uxj4CoOE` measured **610**
fs+env+process cells, **536 clean / 74 poisoned**, with **3,927** clean
unresolved authorable rows across **491 surfaces in 81 template classes**.
The day-one estimate has therefore drifted by **+671 rows, +67 surfaces, and
+17 classes**; use the live denominator rather than continuing to quote
3,256/64 as current.

This tranche closed the whole
`surface.native.op × [env:write]` template class: all five direct
`native-op:__exactSetEnv` fixtures (allow, deny, malformed-adapter,
missing-attribution-adapter, and wrong-principal-adapter) now carry one exact
principal-overlay name/value recipe and passed source-bound physical execution.
The five receipts share source-descriptor digest
`sha256-NWtFz7qLMhddu-59NMebwbquc-lEXdXCpow3KV4_vgs`, were executed from
derived five-row catalog
`sha256-Z25MqQOYrlDrW0nKS4KPR_4RyiRTiHzYDUutvnemuQc`, and bind mapped engine
`sha256-fD3RqCwynBh9V5OQcdv_uPpplRhVmjIBnxcHekQTv7Y`; both native evidence
partitions passed. The regenerated full catalog is
`sha256--gN43pJfa74lwK2EVtpq24AHsS0zelI_jUkKHslH3ic`: **3,922 rows across
490 surfaces in 80 classes remain**. This is **5/3,927 rows and 1/81 whole
classes closed** against the live pre-change worklist; the historical
3,256/64 denominator is retained only as provenance.

**Model concern found, not fixed here:** the separate clean
`surface.host.abi × [env:write]` class for `ex_host_env_ambient_set` contains
five rows, but its source is the compile-time `insecure` ambient projection.
In the secure conformance profile the projection is inactive and the ABI
returns `-1` before mutation without a typed environment decision. Treat those
rows as a seeding/disposition review prerequisite, not an authoring target;
this tranche deliberately did not manufacture receipts for the asserted
effect. This is an explicit release constraint until the model is corrected.

**Progress 2026-08-06 — LLP 0049 Phase 2 calibration tranche.** Two template
classes closed to the full §6 gate standard (both diff gates exit 0 in strict
mode, both batches physically green on the bound engine):
`surface.native.op × [env:read]` — the whole class, 6 rows on
`__exactGetAllEnv`'s nonempty logical branch, one seeded principal-overlay
name disclosed on allow and skipped on the denial-return deny — and the two
direct-list cells of `surface.native.op × [fs:list]`, 10 rows on
`__exactAccess` and `__exactOpendir`. Catalog
`sha256-C4T2GOmlKtNepQb5tBc5gulZ9MVwVsGJf5mwqyYzmhw` →
`sha256-SsTA9juFohEIIckHaQ0q_LRxlH1C9CcfhzlAnWtRYBs`; the live worklist moved
**3,927 → 3,911 rows, 491 → 488 surfaces, 80 → 79 template classes** with
**zero** in-scope inventory growth in the interval. Full metrics and the
cost-model findings: `llp/evidence/0049-calibration-tranche-report.json`.

**Model concern found, not fixed (second of this family):** two in-scope
native-op cells carry an `effects` classification with declared typed stages
over a **legacy** authorization path that emits no typed decision at all —
`__exactWhich` (`checkCapability("process:spawn")`, host `getenv("PATH")`,
raw `access`/`realpath`) and `__exactHandleReadFileSync`
(`ex_host_handle_check` plus a direct `ifstream`, bypassing the armed VFS).
Filed as `issues/20260806-exactwhich-declares-typed-effects-it-never-emits.md`;
`surface.native.op × [env:read, fs:list]` cannot reach zero unresolved until
it is resolved.

**Sequencing (2026-07-29, LLP 0029 §7 register item 4):** v1 ships
fail-closed with empty advertisements; this backlog now converges toward a
**single-tuple v1.1 advertisement** (leading candidate on current
verified-row volume: `aarch64-apple-darwin`). Prioritize that tuple's
target-applicable rows until its report passes complete; the other
candidate target's catalog completion follows in a later milestone rather
than being worked in parallel.

## Done when

- each shipped target's required public-surface rows have source-bound physical
  receipts or an explicit non-applicable/unsupported disposition;
- the full generated and physical validation gates pass on the exact engine
  artifacts named by the reports;
- target advertisements are generated only from complete passing reports; and
- remaining unsupported product surfaces are stated as release constraints,
  not hidden by aggregate coverage counts.

## 2026-08-06 — ambient env:write ruling (LLP 0049 §4.2 packet)

Author ruling: `ex_host_env_ambient_set` (`surface.host.abi × env:write`,
sourced from the compile-time `insecure` ambient projection, inactive in
the secure profile — ABI returns −1 with no typed decision) is
**target-inapplicable in the secure profile**. Its rows classify as
inapplicable under the secure feature vector with a **generated release
constraint**, not as unresolved obligations. Implementation of the
classification lands with the Phase 1/Phase 2 work it gates; recorded in
LLP 0044 §7 (2026-08-06 resolution record) and LLP 0049 §10.
