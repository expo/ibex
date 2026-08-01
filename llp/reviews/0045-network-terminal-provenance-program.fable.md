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
- **Status:** RECEIVED 2026-08-01 — body below, recorded verbatim (full text in the session transcript; key findings preserved).

### Round-3 review body (verbatim)

**Verdict:** `NOT READY`

Delta assessment: 1 PARTIALLY RESOLVED (artifact real and digest-true, every §1 summary recomputes; but invariants overstated, catch-all in `mechanismOf`, `moduleOf` positional heuristic, no row identities/spans) · 2 PARTIALLY RESOLVED (155/142/106, per-module rows, counting method all reproduce; Summary still says "five", the 60/49 pair mixes populations, `unresolved-ident` gloss mismatches the artifact) · 3 PARTIALLY RESOLVED (closed — around zero of the four sites) · 4 PARTIALLY RESOLVED (asymmetric across fields) · 5 PARTIALLY RESOLVED (P1/P2/P3 clean; register item 4 still "Class-2" and now under-scoped) · 6 PARTIALLY RESOLVED (hedge correct; `bare-callee-miss` disposition wrong) · 7 PARTIALLY RESOLVED (item 7 still lacks the normalization criterion; "throws"/"ReferenceError" appear nowhere) · 8 RESOLVED.

**Concerns**

1. **IN-DELTA, MATERIAL — The closed step-0 grammar admits none of the four hook aliases, and the document still claims it admits all four.** All four sites are `var`, not `const` (http.js:63,67; net.js:222; dgram.js:11 — `rg '(var|let|const)\s+_\w+\s*=\s*typeof\s+__exact\w*\s*==='` returns exactly those four, all `var`; no `const`-declared `__exact*` alias exists in the network builtins). Separately the use-site whitelist rejects every real use: the sites read the alias in truthiness position — `if (!_httpOwnerHost || _httpOwnerHost(...))` (http.js:483), `_httpNetOwnerHost ? _httpNetOwnerHost('new') : null` (http.js:276,448), `if (state.ownerStamp != null && _netOwnerHost)` (net.js:287), `var ownerStamp = _netOwnerHost ? _netOwnerHost('new') : null` (net.js:403). Net effect: step 0's yield on today's source is **0 cells**, not four. That decides register item 7 without a spike — if normalization is a precondition rather than an alternative, the widening has no marginal yield.
2. **IN-DELTA, MATERIAL — `bare-callee-miss` is misdiagnosed; it is the walker's multiple-definition marker, not preserved-dynamic slots.** Bare unqualified names come from `capsec-surface-inventory.mjs:4494-4498` (`definitions.length > 1 ? [name] : …`), bare *qualified* names from `:4538` (inside `directAmbiguities`, reached only for a qualified name with >1 definition). `oncreate` (10 of 13 cells) is a local callback **declared twice** — `function oncreate` at http.js:4015 and 5877. `IncomingMessage.pause`/`_read`/`resume` each have **two prototype assignments**: a guarded fallback at http.js:2707/2710/2713 and a later unconditional assignment at 2805/2807/2811, the second of which is dead for `pause`. These 13 cells are therefore the *cheapest* mechanism in the matrix — resolvable by renaming one `oncreate` and collapsing three dead fallback assignments — and the plan classifies them as irreducible residue. Same failure the generator was built to prevent, one layer up: named from the raw string's *shape* rather than traced to the *emitting code*.
3. **IN-DELTA, MATERIAL — The Summary contradicts §1 on the central count.** "five measured ways, not two" vs "The six mechanisms". Third consecutive round in which prose disagrees with its own measured basis, in the first paragraph a reader trusts.
4. **IN-DELTA, MINOR — The generator's three numeric invariants are tautological and cannot fail.** `cellRows` is built from the same iteration that populates `laneCells.B`; `bucketSum` is a tally over `cellRows`; `cellsTouching` is re-checked over the same array with `mechanisms` from a `Set`. Only the `mechanismOf` throw is a live check. Add a falsifiable invariant (independent second pass over `residualReasons`) or downgrade the claim.
5. **IN-DELTA, MINOR — The paired allow-list is asymmetric and would fail step 1 the way additive-only failed step 2.** Step 1's extraction rewrites route *path strings* on cells whose terminals and ambiguities are unchanged; those are path removals — neither allow-listable (only ambiguity removals are) nor byte-equivalent. Make pairing symmetric over terminals, paths, and ambiguities, additions and removals alike.
6. **IN-DELTA, MINOR — `moduleOf` mislabels the module axis.** A fixed positional slice with no validation: `ws.server`/`ws.websocket`/`ws.websocketserver`/`ws.createwebsocketstream` are four *exports* of one module presented as four modules; "node.dns 32" is entirely `node.dns.promises` exports.
7. **IN-DELTA, MINOR — "60 callable assignments across 49 unique names" mixes populations.** 49 includes `__proto__`; the 60 callable assignments span 48 names.
8. **IN-DELTA, MINOR — The `unresolved-ident` gloss does not match the retained distribution.** No promise bindings at all; omits `require` (6), `buffer` (8), `AbortController` (4), `fetch` (4), `StringDecoder` (2), `atob` (2), `createConnection` (10). Buries the actionable fact: `setTimeout` alone touches **64** of 106 cells, `clearTimeout` 7 more — which sizes step 2's timer lever, the one §4 leaves unsized.
9. **IN-DELTA, MINOR — Register item 4 retains the retired nominal class and is under-scoped.** Titled "Class-2 extension points" after the scheme was replaced; the residue is P1-yes **or** P2-non-none.
10. **IN-DELTA, MINOR — §4 sizes a "lever" with touching counts.** No cell clears until every mechanism it touches is resolved; qualified-member resolution alone clears at most the 113 pure cells (+14, +21, +7 jointly per `bucketCells`).
11. **PRE-EXISTING, MINOR — "The walker's refusal is correct, not conservative" is now partly contradicted by the plan's own matrix.** 13 cells are duplicate-name artifacts, 33 undiagnosed, and `require`/`StringDecoder`/`AbortController` misses look like analyzer gaps.

**Suggestions:** emit `fixtureId` lists and source spans; add a `zero-mechanism` entry to `pureCells`; tighten `mechanismOf`'s regex fallback (it is structurally the renamed "other" bucket) by enumerating the two known emission sites; note in the generator header that `dynamic-callable-alternative:`, `shadowed:`, `computed-terminal:`, `dynamic-terminal-receiver:`, `dynamic-constructor:`, `unresolved-required-export:` all exist and would correctly throw; wire the generator to a `package.json` script.

**Open questions:** is step 0 still a live step, or has it collapsed into "normalize four declarations and ~12 use sites"? · are the three `IncomingMessage.prototype.*` guarded fallbacks (http.js:2707-2715) dead code? · is `unresolved-call:createConnection` (10 cells) the imported `net.createConnection`, and does step 2's projection/require work cover it or is it a fifth uncounted lever? · do the 33 `empty-no-mechanism` cells get their Lane B tag from something other than route evidence?

**Recommended next step:** Revise, then one more narrow delta round. Concerns 3, 7, 9 are one-line edits. Concern 1 is a paragraph plus a reframing of register item 7 — as written, step 0's measured yield is zero and normalization is a precondition rather than an alternative, so item 7 should not go to the owner in its current form. Concern 2 requires re-glossing the sixth mechanism against the emitting code and moving 13 cells out of register item 4's residue. Concerns 4-6, 8, 10 are generator/prose hardening that can land in the same pass. The program structure, denominators, hazard analysis, orthogonal slot properties, acceptance-gate direction, and Open Questions are sound and independently verified; nothing structural is in question.

## Round 4 (narrow delta) — 2026-08-01

- **Method:** narrow delta round against revision `76b043c8ab74` (revised from
  `584983599f19`); brief `llp0045-brief-r4.md`; rounds 1-3 artifacts,
  regenerated evidence, and hardened generator in the capsule; same
  family/runtime as round 1.
- **Status:** LAUNCHED — review body appended below only if actually received.

## Round 5 (fixed-text confirmation) — 2026-08-01

- **Method:** confirmation pass against revision `e971c91ab230`; brief
  `llp0045-brief-r5.md`; same family/runtime as round 1.
- **Status:** RECEIVED 2026-08-01 — body below, recorded verbatim.

### Round-5 confirmation body (verbatim)

**Verdict:** `NOT READY`

**Confirmation:** 1 CONFIRMED (substance; see Concern 1 on the stated *reason*) · 2 CONFIRMED with a wrong breakdown (Concern 2) · 3 CONFIRMED (§5 item 7, not changelog-only) · 4 CONFIRMED (one editorial defect, Concern 4) · 5 CONFIRMED with an inaccurate label (Concern 3) · 6 CONFIRMED (per-prefix counts sum to 338) · 7 CONFIRMED · 8 CONFIRMED (1-8, halves merged, all in-text references resolve).

**Concerns**

1. **The `pause` justification is wrong in the default profile.** The doc asserts "the live 2713 fallback makes that guard false". `http.js:11` requires `node:stream`, which resolves in the default builtin set; `Readable.prototype.pause` exists (`stream.js:2153`), `Readable.prototype.on` exists (`:2163`) so `_IncomingMessageBase` is `Readable.prototype`, and therefore the `typeof … !== 'function'` guard at 2712 is **false** — 2713 does not execute. 2804 is falsified by the *inherited* `pause`, not by 2713. 2713 is live only in a stream-less profile (the `try/catch` at http.js:11 anticipates one). The conclusion is unaffected — 2805 is dead in **both** profiles, and the three planned deletions (2707, 2710, 2805) are safe in both — but the document states a profile-dependent premise as proof, at the one point it claims proof, for the second round running.
2. **The 12-cell breakdown contradicts the retained artifact.** §4 says the other 12 "carry dynamic-dispatch (5) or dynamic-dispatch+qualified-member-miss (7)". The artifact's `bucketCells` gives `duplicate-definition+dynamic-dispatch+unresolved-ident` = 5 and `duplicate-definition+dynamic-dispatch+qualified-member-miss+unresolved-ident` = 7 — **all 12 also carry `unresolved-ident`**. Dropping it understates joint clearance in the very sentence enforcing "a cell clears only when every mechanism it touches is resolved".
3. **"top 10 of 17 raws" is not what the gloss lists.** It names 13 raws, and `StringDecoder`/`atob` (2 each) are not in the top 10 — they tie with `_httpDefineOwnedProperty`, `assertOwner`, `callback` at 2, which are omitted.
4. **Editorial:** §5 item 4 carries a stray "`, ;`" — deletion residue.
5. **Minor tension:** §1 still says the generator "throws on any unrecognized ambiguity shape rather than absorbing it into a catch-all", while the generator now documents that a bare-name ambiguity from a new emission site *would* be absorbed.

**Recommended next step:** Apply the four one-clause corrections (Concerns 1-4) plus the optional §1 hedge — no structural change, and no further review round is warranted: each fix is mechanically checkable. Register items 1-7 are ready for the owner once the text is corrected; the program structure, denominators, hazard analysis, acceptance gate, and open questions are sound and independently verified.

## Close-out ledger — 2026-08-01

- **Terminal state: converged after 5 rounds.** Round 5 (fable): confirmed all 8 edits in substance; 5 one-clause corrections applied in the same revision.
  Final reviewed text: revision `e971c91ab230` plus the five round-5
  corrections; the corrected revision is labeled in the document header
  and is **UNREVIEWED** beyond the round-5 confirmation, per the loop's
  honesty rule.
- Round history: r1 dual NOT READY (Fable 5 MATERIAL / Codex 7) → r2
  dual NOT READY (1 / 3) → r3 dual NOT READY (3 / 2) → r4 NOT READY
  (Fable 3 MATERIAL / Codex 2 MINOR) → r5 Codex READY, Fable
  confirmation with editorial corrections.
- What the loop changed, beyond wording: the TLS-bypass hazard
  (`http.Agent.createSocket` → `this.createConnection`, overridden by
  `https.Agent` to reach `tls.connect`) re-founded step 1 on virtual-slot
  properties; the step-0 grammar was found to admit **zero** of the four
  real alias sites (all `var`, all used in truthiness position),
  reframing register item 7 as the live decision; the sixth mechanism
  was retraced three times before landing on the walker's
  duplicate-definition marker; denominators corrected to 338 Lane B; the
  "additive-only" acceptance gate was found to forbid step 2's own work;
  and the evidence artifact was replaced by a checked generator after the
  hand-rolled one contradicted itself.
- The author decides status. Both reviewers' terminal recommendation:
  register items 1-7 are ready to go to the owner; step 0 is
  decision-free and can start any time; step 1 waits on items 1 and 5.
  This ledger proposes that transition; it does not apply it.
