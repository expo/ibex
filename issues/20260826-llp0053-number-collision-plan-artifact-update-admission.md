# LLP 0053 is claimed by two different documents

**Opened:** 2026-08-26 (by the Exact LLP 0506 D1(d) burn-down lane, auditing
Exact LLP 0504 §3 row 54c).
**Status:** Open
**Owner:** unassigned (ibex LLP numbering / the `agent/update-admission-llp` lane)

## The collision

Two different documents carry ibex LLP number **0053**:

| Where | File | Title |
| --- | --- | --- |
| `origin/main` | `llp/0053-carrier-bearing-ingress-coordination.rfc.md` | Carrier-Bearing Ingress Coordination (Exact 0510 Carrier Arc — Asks I1–I4) |
| `origin/agent/update-admission-llp` (tip `69f139837`, contains `62e8ae6aa`) | `llp/0053-plan-artifact-update-admission.rfc.md` | Plan-Artifact Update Admission |

Verified 2026-08-26 against `expo/ibex` by `git ls-remote` and
`git ls-tree -r 62e8ae6aa llp/`. Both files exist; neither knows about the
other. The branch document was written first and never merged; main
subsequently allocated 0053 to the carrier-coordination RFC.

**Next free number on main is 0057** (main carries 0001–0056).

## Why this is urgent even though nothing is broken yet

Exact's ticket `issues/20260821-eplan-ota-armed-snapshot-confirmation.md`
records the commissioning of the update-admission LLP and says, verbatim:

> This ticket closes when ibex 0053 is accepted and row 54c is flipped.

Read on main today, **that instruction points at the wrong document.** Anyone
following it would flip Exact LLP 0504 §3 row 54c — the `.eplan` OTA
admission gap that gates LLP 0553's L-E lane and D6 — on a carrier-ingress
coordination RFC that has nothing to do with plan-artifact update admission.
A warning has been added to the Exact-side ticket in the meantime; this ticket
is the actual repair.

## What the branch document is

`PlanUpdateUnitV1` (eplan plus digest-enumerated companions, full-set-only at
v1); a seven-check ordered fail-closed admission predicate (presenter
authority → signed TLV envelope per ibex 0052 → digest closure → format
window → 0541 edition compatibility → min-runtime plus strict epoch
monotonicity → generation-fenced activation via `ArmedSnapshot`); 13 typed
refusal codes; host-ABI-only presentation; retain-until-healthy rollback with
revert-as-re-arm. RFC, Draft r2.

## Doing it

Renumber the **branch** document (main's 0053 has dependents and stays), per
LLP 0001 Numbering: `llp/0053-plan-artifact-update-admission.rfc.md` →
`llp/0057-plan-artifact-update-admission.rfc.md`, updating self-references
and any `Related:` lines that cite it. Then update the two Exact-side
pointers: `issues/20260821-eplan-ota-armed-snapshot-confirmation.md` and
Exact LLP 0504 §3 row 54c.

Deliberately **not** done by the finding lane: this is a rename on another
lane's unmerged branch in another repository, and picking which document keeps
0053 is the numbering owner's call even though LLP 0001 makes the mechanics
obvious.
