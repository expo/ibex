# LLP 0056 §10 defect: no dev-unarmed grant authority — #34 unimplementable without inventing security semantics

**Status:** Closed
**Resolution:** Resolved (2026-08-24 — LLP 0056 Amendment A2)
**Severity:** P1 (blocks the LLP 0056 legs 2/3 admission driver — 0413.001 §6 "no composition admits" stays in force)
**Systems:** Module Loader, Security, Conformance
**Author:** Claude (Fable 5), verifying the codex gpt-5.6-sol implementation lane's stop-rule report
**Date:** 2026-08-24
**Related:** llp/0056-package-aware-composition-admission.spec.md §5 step 6, §10, §4.7; Exact LLP 0413.001 r7 §3.3/§4.1 row 34; `src/module_loader/security.rs` (`GraphImportPolicy`), `crates/capsec-semantics/src/arming.rs:723` (`authenticates_module_edge`)

## Blocking defect (verified against the trees)

§5 step 6 requires the driver to run the §10 defining-principal
authorization and refuse denials as #34 `cross-principal-denied`; §10
says "v1 defines a dev-unarmed `GraphImportPolicy` ... its inputs are the
admitted records' `definingPrincipal` fields, the declaration, and the
composition's committed facts" and requires each external edge crossing
defining principals to "be authorized by the policy" (fixture F: origin
principal "lacks the grant" for the target's principal). But:

- the only landed grant relation is the ArmedSnapshot's per-edge
  `module_edges` allowlist (arming.rs:723) — host-supplied via the armed
  snapshot document, unavailable by construction in the mandatory
  dev-unarmed posture (step 0 unconditionally excludes an armed Host);
- neither channel (§3.2 digest-only commitment, §3.3 expectations) nor
  the envelope carries grant rows — `policyDigest` authenticates an
  identity only, and the landed O-1 envelope authority marks it a
  dark-only placeholder (O-4);
- the committed facts (declaration, union table, boundary inventories,
  alias table) cannot separate granted from ungranted crossings: by the
  time #34 runs, #29/#31/#32 have already verified every external edge
  IS committed, so "committed = granted" makes #34 unreachable.

Every candidate implementation therefore invents a rule: allow-all
(kills #34 and fixture F), deny-all-crossing (a real policy choice the
spec never states), equal-principals-only, or consulting the armed
snapshot (violates the exclusion). Per the implementation mandate this
is a STOP-AND-REPORT, not an agent decision.

## Resolution options (author decision required — 0056 amendment)

1. **v1 denies every external edge that crosses defining principals**
   (recommended): fail-closed, zero new channels/schema, #34 reachable
   (fixture F = any crafted crossing), monotonically relaxable later by
   a real grant mechanism landing with O-4/armed. Requires: §10 bullet 2
   restated as the explicit deny rule; fixture-F wording updated
   ("lacks the grant" → "no v1 grant exists"); a compatibility note that
   v1 external references between Root-principal records do not cross
   and are unaffected (equal principals never consult the policy —
   `ModuleGraphAuthorizer` gates on `importer != imported`).
2. A verifier-supplied grant/policy document (or loaded-policy handle)
   bound to `policyDigest` — the real mechanism, but it belongs with the
   O-4 real-policy work, adds a channel + O-1 schema rows, and changes
   §3.3/§3.4 surfaces.
3. A deterministic grant relation defined entirely from committed facts,
   with the exact positive/negative rule stated — no existing committed
   fact can carry it without becoming option 1's document in envelope
   clothing.

## Secondary friction (same amendment can carry it)

§4.7 names `resolverInventoryDigest` (§3.3) as "the explicit verifier
input" to alias import-site verification, but the O-3 algorithm as
pinned (O-1 `preimages.json` at Exact `c30edd547`) computes the
import-site inventory digest solely over sorted unique
`{importer, specifier}` rows — no operation consumes
`resolverInventoryDigest`, and the word does not appear in the preimage
authority. Either the preimage gains the binding row or the spec states
where the comparison actually happens (e.g. an explicit step-2b/step-3
equality against an envelope-committed value); today a conforming
implementation cannot claim to consume that input.

## Lane state at stop

Slice-2 milestones 1–4 (envelope/package decode + bounds, carrier v3 +
`prepared-package` identity + candidate-table v2, `admit_package_v1`
extraction, inert package-admission scaffolding) are landed and
gate-green; they are stable under all three resolution options. The
step-ordered driver, steps 2–7, fixture families B/C/F-i, covering map,
and legs-3 work are stopped pending the amendment. Full detail:
the lane's `.l23/BLOCKED.md` / `.l23/slice2-report.md` (session
scratch), summarized here.

## Resolution (2026-08-24)

Charlie Cheever approved both halves ("sure amend it", relayed via
session exact-b7, on the recommendation of the legs-2/3 lane + exact-9e
+ exact-b7's independent read): **option 1 — v1 DENY-ALL-CROSSING** for
§10 (every external edge crossing defining principals refuses #34; equal
principals never consult the policy; no v1 grant exists; relaxation is a
future O-4/armed amendment), and the §4.7 `resolverInventoryDigest`
phantom-input claim is DELETED with the field marked RESERVED on the
wire (the lane's delegated call: the pinned O-3 preimage and vector
corpus stay untouched; the field is mandatory in the landed O-1 schema;
inventing a comparison target would be new normative surface).
Amendment A2 landed on the spec with both edits verified OUTSIDE the
§6.2 lockstep row bytes (row #34's predicate text unchanged). Driver
work (steps 2-7, leg 3, fixture families) resumed at the amendment.
