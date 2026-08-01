# Reviews — LLP 0045 (Claude (Fable 5) family)

## Round 1 — 2026-08-01

- **Family:** Claude (Fable 5)
- **Provider/runtime:** fresh general-purpose subagent via Claude Code Agent tool (independent context; the authoring session did not write this review)
- **Date:** 2026-08-01
- **Redacted:** no (public-repo content only)
- **Method:** full-repo read-only capsule (git ls-files snapshot), round-1
  brief `llp0045-brief-r1.md`; document revision under review `db4e17800132`
- **Status:** RECEIVED 2026-08-01 — body below, recorded verbatim.

### Review body (verbatim)

**Verdict:** NOT READY

**Strengths**

- The core diagnosis is honest and verified: the Summary's "correct, not conservative" framing holds — `src/builtins/http.js` contains zero `Object.freeze` calls (verified by count), the typeof-guarded alias shape exists exactly as quoted (`http.js:63,67`, `net.js:222`, `dgram.js:11`), and the walker (`routeForCallable`, `capsec-surface-inventory.mjs:4485`) genuinely cannot resolve those shapes today (its `terminalAliases` pass at 4392-4406 accepts only `const` declarations with direct terminal-reference initializers).
- Evidence-bar discipline is real, not decorative: the Non-goals and step-0 review gating (register item 2) keep LLP 0044 §3 Lane B / §6 intact — no dynamic witnessing enters through either step, and step 3 requires explicit per-cell dispositions for residue.
- Register discipline: the de-patching consequence is stated plainly in the body and surfaced as an owner decision (item 1) rather than buried; sequencing (item 3) matches LLP 0044 §9 option (a); estimates are labeled estimates with the step-0 gate producing the first measured revision.
- The re-derivable counts I could check are accurate: 373/580 = 64% (scope-measurement evidence `perSeedFamilyPoison.network`), http.js 117 `this._x()` sites of 196 total `this.method()` sites, net.js 20 sites / 14 definitions — all exact matches.
- The scope boundary is clean: "makes network *authorable*, not *certified*" (Step 3) prevents this plan from silently absorbing Lane A work.

**Concerns**

1. **MATERIAL — The step-0 expectation for dns/tls is contradicted by the source.** The plan's gate expectation ("dns and tls clear entirely or nearly so") and the "may halve the program" framing assume the dns/tls `unresolved-call` poison is alias-shaped. It is not: `dns.js` and `tls.js` contain **no function-valued hook aliases at all** — only boolean feature flags (`_hasDnsResolve = typeof __exactDnsResolve === 'function'`, dns.js:3,106-112) with hook calls made directly. Their unresolved identifier calls are callback parameters (`callback` x34 in dns.js), promise-executor bindings (`reject`, `resolvePromise`), and `setTimeout`/`clearTimeout` (16-20 each per module) — and async terminals sit inside `.then(function(json){...})` closures (dns.js:74, 915) that `walkDirectFunctionBody` never attributes (nested functions skipped at inventory line 3880). The SSA-alias rule resolves none of these shapes, and step 2's fallback for dns/tls residue is the de-virtualization pattern, which also doesn't apply to dns's function-based, callback-driven code. Resolve: re-derive the per-name `unresolved-call` breakdown for the dns/tls poisoned rows from the catalog before asserting the expected delta; if it confirms this reading, either add the actual clearing mechanism (nested-closure attribution, or reshaping to direct-call sites — each its own reviewed analyzer/code change) or drop the halving expectation.
2. **MATERIAL — A third poison mechanism is measured but unaddressed.** The Summary asserts the routes are dynamic "in two distinct ways," yet the plan's own table lists `cross-source-export-projection` at 370 row-occurrences among the poisoned rows. The inventory emits these rows with empty `terminals` by construction (e.g. the dns.promises projection, `capsec-surface-inventory.mjs:15316-15322`), so they carry `no-static-enforcement-terminal` and neither step 0 (alias resolution) nor steps 1-2 (de-virtualization) can touch them. The step-3 target "373 -> ~0" is unreachable by the named mechanisms for those cells. Resolve: quantify how many cells the 370 occurrences span, and either add a projection-joining step (with review gating) or scope those cells out explicitly with a named disposition.
3. **MATERIAL — Step 1's de-patching account omits legitimate internal polymorphism.** http.js's underscore internals are deliberately virtual: `_implicitHeader` x3 (OutgoingMessage/ServerResponse/ClientRequest), `_read` x3, and `_send`, `_renderHeaders`, `_dump`, `_flushManualData`, `_scheduleManualReadable`, `_emitManualEnd`, `_emitHttpClose`, `_pushBodyChunk` x2 each — these names are among the most frequent `this._x()` sites. Naive `this._x()` -> `_x(self)` inside a shared base method either binds the wrong implementation for subclass instances or, if each body becomes a same-named free function, trips `routeForCallable`'s multiple-definition refusal (line 4494) and creates a *new* ambiguity. Cross-module virtual contracts exist too: `_read` is invoked by the stream machinery in `stream.js` via prototype dispatch, and `https.js:93` extends `http.Agent`. "Thin wrapper preserves the method surface, internal routing becomes non-patchable" is therefore not a complete account of the observable change — some hops cannot be de-virtualized without a semantics change, not merely a patching change. Resolve: add an explicit rule (e.g. de-virtualize only hops monomorphic on the route's class; name-mangle per class; state the treatment of framework-virtual methods and subclass chains), and reflect this bound in register item 1's wording.
4. **MATERIAL — The retention claim is false as stated.** "The counts above are retained in the LLP 0044 evidence files" — neither `0044-scope-measurement-09e6aece....json` nor `0044-batch-timing-501504f6....json` contains the per-module poisoned-cell table, the ambiguity-kind counts (3,226 / 75 / 370), or the call-site counts; they retain only the aggregate 373/580 and per-family poison rates. This breaks the re-derivability standard LLP 0044 §1 itself sets ("re-derivable from retained artifacts rather than from prose") and which this plan inherits. Additionally, "62 prototype-internal method definitions" does not match a straightforward count (61 `X.prototype._y =` matches, two of which are `__proto__` assignments), and no counting method is stated. Resolve: retain the aggregation as an LLP 0045 evidence file with its derivation command, or reword to "re-derivable via the recipe below" and pin each count's method.
5. **MATERIAL — The SSA rule's stated conditions are not the complete soundness conditions register item 2 presents them as.** (a) No direct-`eval`/`with` exclusion: "no other write to `_x` exists anywhere in the module" is not statically decidable if the module contains direct eval. (b) `<inert>` is undefined: if an alternate branch is callable (a JS fallback), resolving the call to the hook alone silently drops a real route — inert must be pinned to a provably non-callable constant (it is `null` in all four current sites, but the rule must say so). (c) The mechanism is mischaracterized: with `var _x = cond ? hook : null`, `_x` lands in `declaredIdentifiers` (inventory 4152-4155), not `assignedIdentifiers` — the refusal is `unresolved-call` via no callable definition, not "assignment is mutation"; the rule's security review needs the true mechanism. (d) "Assigned exactly once" requires a declarator-*counting* pass; the existing name-keyed sets record presence, not multiplicity, so the rule as written does not match what the current data structures support without new machinery (fine, but should be said — the flat, non-scope-aware sets also mean the implementation must be name-keyed-conservative, which is stronger than the binding-level prose). Resolve: restate the conditions with (a)-(d) closed before register item 2 is put to the owner.
6. **MINOR — Bootstrap-timing trust is implicit.** Alias capture reads the global hook twice (typeof + capture); the rule inherits the same capture-before-user-code / sealed-globals assumption as today's direct terminal references, but the rule text should state it explicitly since it is the assumption the whole resolution rests on.
7. **MINOR — Step-1/step-0 coupling.** "Normalized to whatever shape step 0's accepted rule resolves" leaves step 1's normalization target undefined if register item 2 rejects or narrows the rule; state the fallback (e.g. bare capture with separate guard statement, which today's `terminalReference` could accept with a `const`).
8. **MINOR — Register completeness.** If concern 1 holds, clearing dns/tls needs an analyzer widening beyond the SSA rule (closure attribution) — a second widening decision the register does not currently anticipate; add a placeholder or state that any further widening re-enters item 2's review path.

**Suggestions**

- Publish the re-derived per-module x per-ambiguity-name matrix (not just kind) as the plan's own evidence file; concern 1 would have been visible in it immediately.
- Consider whether `setTimeout`/`setImmediate`/`setInterval` should become reviewed-closed globals in route analysis — the inventory already has `reviewedClosedGlobalCallValue` (line 8397-8404) for another purpose; extending it to `routeForCallable` may clear a large slice of tls/dns `unresolved-call` cheaply, under the same review gate as the SSA rule.
- For step 1, name the transform's collision rule up front (`_clientRequestSend(self)`-style per-class free functions) so the pattern-proving iteration doesn't discover it mid-flight.
- Cross-reference issues/20260801-network-terminal-provenance-program.md's "117 / 62" figures to whatever counting method the revised plan pins (concern 4).

**Open questions**

- What is the actual per-name `unresolved-call` distribution on the dns/tls poisoned rows in catalog `sha256-XcvN5FFF...`? (The catalog is not in the capsule; this decides concern 1.)
- How many of the 373 poisoned cells are cross-source-export-projection cells (dns.promises, https re-exports), and under which module label does the table count them?
- Do ws/http2 subclass http/net classes in ways that put shared virtual internals on capability paths (constraining step 2 the same way concern 3 constrains step 1)?
- Is the walker's flat, non-scope-aware identifier model itself in scope for step 0, or is the SSA rule to be layered on it as-is? The answer changes the review surface of register item 2.

**Recommended next step:** Revise and re-review. Before the revision: re-derive the dns/tls per-name breakdown and the projection-cell count from the catalog and let those numbers rewrite the step-0 gate expectation and the step list (concerns 1-2); add the polymorphism rule to step 1 (concern 3); fix the retention claim (concern 4); close the SSA-rule condition gaps (concern 5). Register items 1-3 should go to the owner only after the revision, since items 1 and 2 currently describe an incomplete transform and an incomplete rule.

## Round 2 (delta) — 2026-08-01

- **Method:** delta round against revision `071214db0606` (revised from
  `db4e17800132`); brief `llp0045-brief-r2.md` with the delta
  enumeration; round-1 artifacts and the new mechanism-matrix evidence in
  the capsule; same family/runtime as round 1.
- **Status:** RECEIVED 2026-08-01 — body below, recorded verbatim.

### Round-2 review body (verbatim)

**Verdict:** NOT READY

**Delta assessment**

1. **Measured taxonomy replaced — PARTIALLY RESOLVED.** The matrix is real, retained, and digest-true (file sha256 matches its name; catalog digest matches; pure-cell column 113/39/17/33/32 and every per-module count verified, buckets sum to 338) — but the table's "cells touching" column (164 / ~154 / ~130) contradicts the evidence file's own `cellsTouchingMechanism` (155 / 142 / 106); see Concern 1.
2. **Denominators corrected — RESOLVED.** 580/373/338/35 all verified against the 0044 scope-measurement (`perSeedFamilyPoison.network` = 580/373) and the matrix (`laneCellCounts` B:338 C:35, `unionBCD` 373); Step 3's metric is now 338 → ~0; Lane C scoped out via register item 6.
3. **Halving claim withdrawn — RESOLVED.** Evidence confirms node.dns = 32 projection-only cells and node.tls = 30 qualified-member-miss-only cells; source confirms dns.js uses boolean flags + direct hook calls (dns.js:3,74,89,915) and tls inherits via `Object.setPrototypeOf` at tls.js:2885/3678; the withdrawal is stated in §1 and the Revised header.
4. **Step 1 re-founded — RESOLVED.** The hazard is exactly as stated: `this.createConnection(options, oncreate)` at http.js:5909, overridden at https.js:97 to reach `tls.connect`. The three-class scheme, per-class mangled free functions (matching `routeForCallable`'s unqualified multiple-definition refusal, inventory:4494), and compat-tests-before-approval are all in the text; the class-3 polymorphic list matches source (`_implicitHeader` ×3, `_read` ×3, the ×2 set all verified).
5. **Step 0 respecified — RESOLVED.** Binding-aware framing, accepted/rejected grammar with enumerated inert alternatives (all four real sites use `null`, within the enumerated set), all write forms, module-level `eval`/`with` rejection, the schema extension (verified: `enforcementRouteEvidence` today is flat terminals/paths/ambiguousCallees, inventory:15316-15322), and the native-hook immutability invariant are present. The four callable aliases verified exactly (http.js:63,67; net.js:222; dgram.js:11). One dangling reference ("open question 1") — Concern 3.
6. **Step 2 added — RESOLVED.** All four uncovered mechanisms have named work; the projection-join target matches the inventory's by-construction empty-terminal emission; the nested-function skip in `walkDirectFunctionBody` verified (inventory ~3880).
7. **Acceptance criteria — RESOLVED.** §3 contains all six obligations and explicitly rejects the falling count, matching Codex C6's resolve list nearly item for item.
8. **Estimates withdrawn — RESOLVED.** §4 withholds a number until the step-0 gate and step-2 diagnosis, states the coupling (https→http, tls→net, dns.promises→dns).
9. **Register 3 → 7 — RESOLVED.** Items 4–7 present as described; mode policy has the three named options with (a) recommended; further widenings re-enter item 2's review path (closes Fable C8).
10. **Counting methods pinned — PARTIALLY RESOLVED.** 117, 196, and 20 reproduce exactly under the pinned queries. The prototype-assignment query does not: `rg -c '\.prototype\._[A-Za-z0-9_]+\s*='` on http.js returns **62**, not the "corrected" 61 — see Concern 2.

**Concerns**

1. **IN-DELTA, MATERIAL — The "cells touching" column contradicts the plan's own retained evidence.** §1 states qualified-member-miss 164 touching, dynamic-dispatch ~154, unresolved-ident ~130; the cited artifact's `cellsTouchingMechanism` (and independent recomputation from its `bucketCells`) gives 155, 142, 106. The wrong figure is load-bearing: §2 step 2 repeats "113 pure / 164 touching" and §4 sizes "the largest single lever" as "164 cells touching". This is precisely the prose-vs-artifact divergence round 1 rated MATERIAL (Fable C4), recurring inside the fix for it. The strategic conclusion survives (155 is still the largest mechanism), so the fix is narrow. Resolve: recompute the column from the artifact (155/142/106) in all three places — or, if 164/~154/~130 came from a different derivation, retain that derivation in the evidence file and reconcile the two.
2. **IN-DELTA, MINOR — The pinned prototype-assignment count does not reproduce, and the correction's explanation is wrong.** The pinned query yields 62 matching lines (including 2 `.prototype.__proto__ =` assignments; 49 unique underscore names). The doc's "61" appears copied from the round-1 Fable review rather than re-run, and "conflated assignment sites with unique names" is false — unique names are 49, not 61/62. Resolve: rerun the pinned query and state 62 lines / 2 `__proto__` / 49 unique names (or refine the query to exclude `__proto__` and pin that).
3. **IN-DELTA, MINOR — Dangling cross-reference.** Step 0 says "open question 1", but the document has no Open Questions section. Resolve: add the section or inline the lazy-builtin-loading verification obligation where it is referenced.
4. **IN-DELTA, MINOR — Class-1 membership is tested in-tree only.** "No subclass override anywhere in-tree" cannot bound out-of-tree subclasses that override underscore internals; de-virtualizing then silently ignores their overrides — a stronger break than the "code patching underscore internals" wording in register item 1, and it slightly undercuts register 5(a)'s "by construction not a compat surface". Resolve: state explicitly that class-1 acceptance includes out-of-tree underscore-override breakage, in register item 1/5 wording.
5. **IN-DELTA, MINOR — Register item 7's normalization option has an unstated semantic wrinkle.** Rewriting `var _x = typeof __exactHook === 'function' ? __exactHook : null` to a bare `const _x = __exactHook` the walker already resolves changes absent-hook behavior: the bare reference throws ReferenceError at module evaluation if the global is not installed, where the `typeof` guard is safe. Whether the hooks are unconditionally installed in both modes decides if normalization is even semantics-preserving. Resolve: name this as a spike-measurement criterion under item 7.
6. **PRE-EXISTING, MINOR — "Overwhelmingly inherited" for qualified-member-miss is asserted beyond the retained evidence.** The artifact's keyFindings pin inheritance only for tls's 30 cells; the http/net qualified-member-miss cells (49 + 28 pure) are not decomposed by name, yet step 2 ranks inherited-member resolution "likely the highest-value analyzer item" partly on this. Resolve: retain the per-name qualified-miss breakdown (or hedge the ranking until step 2's diagnosis) — this is the same visibility gap that hid round 1's dns/tls error.

**Suggestions**

- Add `cellsTouchingMechanism` provenance to the doc table caption ("touching = cell's bucket contains the mechanism, from `bucketCells`") so the column is mechanically checkable against the artifact.
- Step 2's inherited-member resolution should pre-state its own soundness conditions in the plan (child-shadowing check; whether the resolved parent slot's patchability needs the same immutability argument step 1 makes for class-1 slots) so register item 2's future review has a starting spec.
- When fixing Concern 2, cross-update the umbrella issue if it carries the 61/62 figure.

**Open questions**

- What derivation produced 164/~154/~130? If it was an earlier matrix run against a different catalog, the evidence file and the doc disagree about which run is "this plan's measured basis."
- Are the `__exact*` network hooks installed (as immutable data properties) in insecure mode as well, or only under secure arming? This decides both Concern 5 and the mode-policy analysis in register item 5.
- For step 2's inheritance resolution: when the child module later assigns the same member name on its own prototype, does the planned "statically-established inheritance" rule detect the shadow, or is that left to the future review?

**Recommended next step:** Revise narrowly — Concerns 1–3 are mechanical fixes (recompute two number sets from the retained artifact, repair one dangling reference), Concerns 4–5 are wording additions to register items 1/5/7. The program structure, taxonomy, hazard analysis, acceptance criteria, and register are now coherent and verified against source and evidence; nothing structural needs another full round. After that revision, this reviewer's remaining concerns would be MINOR only, and register items 1–7 can go to the owner.

## Round 3 (delta) — 2026-08-01

- **Method:** delta round against revision `584983599f19` (revised from
  `071214db0606`); brief `llp0045-brief-r3.md`; rounds 1-2 artifacts, the
  regenerated evidence, and the new generator script in the capsule; same
  family/runtime as round 1.
- **Status:** LAUNCHED — review body appended below only if actually received.
