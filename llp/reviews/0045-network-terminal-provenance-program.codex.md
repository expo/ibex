# Reviews — LLP 0045 (OpenAI Codex (gpt-5.6-sol) family)

## Round 1 — 2026-08-01

- **Family:** OpenAI Codex (gpt-5.6-sol)
- **Provider/runtime:** `codex exec` CLI 0.146.0, `-c model_reasoning_effort="high"`, `--sandbox read-only`, `--skip-git-repo-check`
- **Date:** 2026-08-01
- **Redacted:** no (public-repo content only)
- **Method:** full-repo read-only capsule (git ls-files snapshot), round-1
  brief `llp0045-brief-r1.md`; document revision under review `db4e17800132`
- **Status:** RECEIVED 2026-08-01 — body below, recorded verbatim.

### Review body (verbatim)

**Verdict:** `NOT READY`.

## Strengths

- The **Summary**, **Step 3**, and **Non-goals** correctly distinguish “Lane A-authorable” from “certified” and explicitly reject dynamic route witnessing, consistent with LLP 0044 §§3 and 6.
- **Step 0** retains the existing refusal when the proposed rule cannot prove an alias and requires measurement before broader transformation.
- **Step 1** at least acknowledges that de-patching is observable, and the **author-decision register** exposes it instead of disguising it as a refactor.
- **Step 3** requires explicit dispositions for residue and security review of changed enforcement paths.

## Concerns

1. **MATERIAL — Step 0 is not a sound, implementable SSA rule as specified.**

   The current walker is spelling-based, not binding-aware:

   - `declaredIdentifiers` merges declarations from every lexical scope.
   - `assignedIdentifiers` records only `AssignmentExpression` with an identifier LHS. It misses destructuring targets, `UpdateExpression`, `for-in`/`for-of` targets, catch bindings, and other binding/write forms.
   - `terminalAliases` is keyed only by identifier text.
   - `staticEnforcementCall` does not resolve the binding at the call site.

   This already produces false terminals. Both of these are currently classified as direct calls to `__exactReadFile`:

   ```js
   const hook = __exactReadFile;
   function f(hook) { return hook(); }
   ```

   ```js
   const hook = __exactReadFile;
   function f() {
     let hook = user;
     return hook();
   }
   ```

   The plan excludes parameters but does not clearly exclude all nested redeclarations, catch bindings, destructuring, `with`, or direct `eval`. The proposed escape conditions also cannot be implemented from the three existing sets. Conversely, a closure merely capturing an immutable binding is not mutation; the plan conflates binding mutation, value escape, and native-authority leakage.

   **Resolve by:** specifying a lexical binding-resolution algorithm and an exhaustive accepted/rejected AST grammar. Reject direct `eval`, `with`, duplicate/shadowing bindings, unsupported write targets, and pre-initialization execution unless separately proved. Add adversarial tests for every binding and write form. Do not widen the current spelling-based alias map.

2. **MATERIAL — The conditional alias has no defined route-evidence semantics.**

   `enforcementRouteEvidence` currently records flat `terminals`, `paths`, and `ambiguousCallees`; it has no conditional-route representation. “Records the guard as a conditional shape” is therefore not an implementation specification.

   The accepted initializer also reads the hook twice:

   ```js
   typeof __exactHook === 'function' ? __exactHook : null
   ```

   If hook identity is not guaranteed by an authenticated, immutable global descriptor during module evaluation, an accessor can return different values. Merely matching the `__exact*` name is not proof of native identity. The inert alternative must also remain a real no-terminal branch rather than allowing a possible terminal to erase Lane B.

   **Resolve by:** defining the evidence schema for both alternatives, the target predicate that selects them, the exact inert expressions allowed, and the native-hook installation/sealing invariant. Prefer a single-read immutable capture where possible.

3. **MATERIAL — The measured problem statement conflates 373 poisoned cells with 338 Lane B cells.**

   Regeneration produces:

   - 580 network cells;
   - 373 poisoned cells total;
   - 338 with `no-static-enforcement-terminal`;
   - 35 with `native-public-source-invocation-unavailable`.

   The per-module table sums to 338, not 373. The remaining 35 are native/global Fetch, WebSocket, Bun/Exact, and executor surfaces that Steps 0–2 do not address. Consequently, the **Step 3** target `373 → ~0` cannot follow from this plan.

   The ambiguity characterization is also wrong:

   - `dynamic-call-receiver`: 4,632 occurrences, so `unresolved-call` at 3,226 does not “dominate.”
   - DNS’s 32 cells are entirely 370 `cross-source-export-projection:dns.promises:*` occurrences, not `unresolved-call`.
   - TLS’s 30 cells are 360 unresolved projections such as `TLSSocket.addListener`, `allowHalfOpen`, and inherited properties—not hook aliases.

   Source agrees: `dns.js` uses boolean feature flags and direct native calls; TLS uses direct native calls and inherits from `net.Socket`. Neither contains the assigned callable aliases Step 0 targets. There are only four matching callable aliases across these builtins: two in HTTP, one in net, and one in dgram.

   The cited LLP 0044 evidence JSON retains only aggregate network poison, not the module/ambiguity table.

   **Resolve by:** retaining a digest-bound per-cell/per-module analysis artifact; relabeling the table as the 338 Lane B cells; correcting the ambiguity claims; adding explicit work for DNS cross-source projection, TLS inherited projections, and the 35 Lane C cells—or changing the success metric to Lane B `338 → ~0`.

4. **MATERIAL — Step 1’s behavioral account omits legitimate virtual extension points.**

   Thin wrappers preserve property names, not semantics. Extraction changes subclass overrides, instance overrides, `super` chains, accessors/proxies, method identity, `.name`, `.length`, `.toString()`, stack shape, and instrumentation.

   There is a concrete correctness hazard: `https.Agent` extends `http.Agent` and overrides `createConnection` to call `tls.connect`. `http.Agent.createSocket` deliberately dispatches through `this.createConnection`. Devirtualizing that hop would bypass HTTPS’s TLS transport. `options.createConnection` is another intentional extension point. Similarly, HTTP accepts socket-like objects, HTTP/2 delegates to supplied stream objects, and TLS inherits behavior from `net.Socket`. These are not all hostile prototype patches or underscore internals.

   **Resolve by:** inventorying every proposed virtual slot and classifying it as security-private, documented/compat extension point, or cross-module inheritance. Preserve intentional dispatch. Add subclass, `super`, custom-agent, custom-socket, HTTPS, TLS/net inheritance, ws, and HTTP/2 compatibility tests before approving the extraction pattern.

5. **MATERIAL — Applying de-patching in both modes is asserted, not decided.**

   LLP 0039 retains insecure mode partly for compatibility investigations. In insecure mode, de-patching has little enforcement benefit but can remove Node-compatible extensibility. “Mode-divergent routing would be worse” does not analyze that tradeoff, and register item 1 offers no alternatives.

   **Resolve by:** escalating a named decision with at least:

   - shared behavior that devirtualizes only genuinely private enforcement slots;
   - secure-only de-patching with explicit divergence tests and maintenance cost;
   - a documented shared compatibility break.

   The first is preferable if the slots can be classified correctly.

6. **MATERIAL — The review gates do not preserve LLP 0044’s evidence bar strongly enough.**

   “Security review” plus a falling poisoned-cell count is not an acceptance criterion for an analyzer widening. A bug that suppresses ambiguity or records a merely possible terminal would also make the count fall. Step 1 similarly needs proof that each new direct edge corresponds to the runtime path, not simply a catalog delta.

   **Resolve by:** requiring:

   - an allow-listed route-evidence diff with source spans and initializer/terminal identity;
   - adversarial negative fixtures for binding, mutation, shadowing, `eval`, `with`, escape, and conditional fallback;
   - a proof that no unrelated ambiguity disappears;
   - secure and insecure behavioral differential tests;
   - retained digest-bound inventory/catalog outputs;
   - separate review of every intentionally preserved dynamic extension point.

   Executed behavior may validate semantics, but it must not manufacture route provenance.

7. **MATERIAL — Sequencing and estimates rest on the false Step-0 yield model.**

   Step 0 cannot clear DNS or TLS and therefore cannot plausibly “halve the program” for the reason given. A binding-aware analyzer and conditional evidence-schema extension are not a one-day spike. The remaining streams are coupled: HTTPS depends on HTTP, TLS on net, and DNS promises on DNS projection logic.

   **Resolve by:** begin with a retained per-cell first-missing-link decomposition, then split the work into distinct analyzer, cross-source projection, inheritance, private-slot extraction, and Lane C programs. Re-estimate after those categories and compatibility extension points are measured.

8. **MINOR — Some call-site measurements are reproducible, but their labels are imprecise.**

   The 117/196 HTTP and 20 net `this._x()` call-site counts reproduce. “Across 62 prototype-internal method definitions” does not: 62 appears to count unique `Constructor.prototype._name` references, while the source has fewer function assignments. This matters when the number is used as an edit estimate.

   **Resolve by:** define the counting query and distinguish call sites, distinct callees, enclosing definitions, and prototype definitions.

## Suggestions

- Rename Step 0 to “lexically bound immutable terminal capture” unless it actually constructs SSA/binding information.
- Prefer narrow source normalization for the four real hook aliases over a general analyzer widening unless measurement shows broader value.
- Make the per-cell causal manifest a checked evidence artifact so future estimates do not depend on unreproduced prose.
- Separate deliberate Node extension points from incidental underscore methods in the plan and register.

## Open questions

- Are all native hook globals authenticated immutable data properties before any builtin can evaluate, including lazy builtin loading?
- Is the intended success denominator 338 Lane B cells or all 373 poisoned cells?
- Which program owns the 35 Lane C native/global surfaces?
- Which HTTP/net/TLS virtual methods are compatibility contracts, and which are genuinely private?
- Does the author intend DNS and TLS to be solved by new cross-source/inheritance analysis not currently described?

## Recommended next step

Revise and re-review. Escalate two named decisions before implementation: **virtual extension-point and mode policy**, and **whether LLP 0045 owns only the 338 Lane B cells or all 373 poisoned network cells**. The revised plan needs a binding-aware Step-0 specification and retained corrected measurement evidence.

## Round 2 (delta) — 2026-08-01

- **Method:** delta round against revision `071214db0606` (revised from
  `db4e17800132`); brief `llp0045-brief-r2.md` with the delta
  enumeration; round-1 artifacts and the new mechanism-matrix evidence in
  the capsule; same family/runtime as round 1.
- **Status:** RECEIVED 2026-08-01 — body below, recorded verbatim.

### Round-2 review body (verbatim)

**Verdict:** `NOT READY`

## Delta assessment

1. **PARTIALLY RESOLVED** — The two-mechanism account was replaced, but the new matrix contradicts the document and contains an omitted sixth bucket.
2. **RESOLVED** — The evidence supports 338 Lane B cells, 35 Lane C cells, and 373 in their union; the scope and success denominator are corrected.
3. **RESOLVED** — The dns/tls Step-0 claim is withdrawn; source confirms dns projection and TLS/net prototype inheritance.
4. **RESOLVED** — The TLS-bypass hazard now governs the transform, intentional dispatch is preserved, names are class-mangled, and compatibility tests gate approval.
5. **PARTIALLY RESOLVED** — Binding awareness and most rejected forms are specified, but the accepted grammar still has soundness and lifecycle gaps.
6. **PARTIALLY RESOLVED** — Step 2 covers four major categories, but it omits the evidence artifact’s 13-cell `other` mechanism.
7. **PARTIALLY RESOLVED** — The evidence gates are substantially stronger, but “additive-only” contradicts the intended ambiguity resolution.
8. **RESOLVED** — Unsupported schedule estimates are withdrawn and stream coupling is explicit.
9. **RESOLVED** — The register contains all seven promised decisions, though the mode alternatives need sharper separation.
10. **PARTIALLY RESOLVED** — Methods are pinned, but the corrected 61-assignment claim is still false under the stated query.

## Concerns

1. **IN-DELTA — MATERIAL:** The measured taxonomy is internally false.

   The retained JSON reports:

   - qualified-member-miss: **155 touching**, not 164;
   - dynamic-dispatch: **142 touching**, not ~154;
   - unresolved-ident: **106 touching**, not ~130;
   - `other`: **1 pure / 13 touching**, omitted entirely from the claimed five-mechanism taxonomy.

   The artifact even contradicts itself: `cellsTouchingMechanism.qualified-member-miss` says 155 while `keyFindings` says 164. Its `derivation` field is prose, not the promised regeneration command, and it contains no per-cell identities, row identities, source spans, or underlying ambiguity names. Consequently, neither the causal classification nor the claim that Step 2 covers the residual can be audited. The unhandled `other` cells also make 338 → ~0 unsupported.

   **Resolve:** Regenerate a mechanically checked artifact containing every Lane B cell, contributing rows, raw `ambiguousCallees`, bucket decisions, source identities, and an executable command/script. Derive summaries from those rows, reject summary inconsistencies, name the `other` mechanism, and give it a step or explicit disposition.

2. **PRE-EXISTING — MATERIAL:** Step 0 still lacks a closed soundness specification.

   Round 1 explicitly required treatment of pre-initialization execution. The revision still permits `var`/`let` without proving that every credited call occurs after initialization, including immediate module execution and CommonJS-cycle exposure. It also calls `undefined` a provably non-callable literal, although `undefined` is an identifier and can be shadowed. Finally, acceptance requires rejection of “escaped mutable capture,” but the accepted/rejected grammar defines no escape or use-site rule.

   **Resolve:** Either accept only `const` plus a proven post-initialization lifecycle, or specify and prove the initialization/dominance rule for `var`/`let`. Admit `undefined` only when lexical resolution proves the intrinsic binding—or allow only `null`. Define the permitted alias uses and exact escape predicate. Also require the initializer’s `__exactHook` reference itself to resolve to the authenticated native global.

3. **IN-DELTA — MATERIAL:** The acceptance criterion is incompatible with the intended analyzer changes.

   Step 2’s inheritance and projection resolutions should remove related ambiguity entries such as `unresolved-call:Type.member`. Section 3 nevertheless says the diff is “additive-only.” Taken literally, valid Step-2 changes cannot pass; taken loosely, the gate does not define which removals are permitted.

   **Resolve:** Require allow-listed terminal/path additions and allow-listed ambiguity removals, paired by cell, source span, and resolution proof. All unlisted fields and ambiguities must remain byte-equivalent.

4. **IN-DELTA — MINOR:** The three virtual-slot classes are not actually exclusive, and the mode options overlap.

   `createConnection` is explicitly a documented extension point—class 2—but is also a cross-module overridden virtual slot, matching class 3’s wording. Likewise, option (a) already acknowledges a shared compatibility break for prototype patching, making its distinction from option (c), “shared with a documented compatibility break,” unclear.

   **Resolve:** Define classification precedence or use orthogonal axes: documented contract, runtime polymorphism source, and de-virtualization eligibility. State exactly what additional behavior option (c) changes beyond option (a).

5. **IN-DELTA — MINOR:** The pinned prototype-assignment count does not reproduce.

   The exact stated query:

   ```sh
   rg -c '\.prototype\._[A-Za-z0-9_]+\s*=' src/builtins/http.js
   ```

   returns **62**, not 61. Two matches are `prototype.__proto__` assignments, leaving 60 callable method assignments if those are excluded. Neither interpretation yields 61.

   **Resolve:** Report 62 regex-matched assignment lines or use a narrower query and report 60 callable function assignments.

## Suggestions

- Remove approximations from §1 when the retained artifact purports to provide exact cell counts.
- Make the mechanism-matrix generator a checked script with schema invariants: bucket sum equals 338, touching counts recompute from raw cells, and no unrecognized mechanism is silently omitted.
- Prefer normalizing the four aliases unless the corrected matrix demonstrates broader value from a general analyzer widening.
- Express virtual-slot analysis as properties rather than three overloaded nominal classes.

## Open questions

- What raw ambiguity values produced the 13 `other` cells?
- Are all four native hooks immutable authenticated data properties before every possible lazy builtin evaluation?
- Can CommonJS cycles expose a callable export before a permitted `var`/`let` alias initializes?
- What exact class-2 residue is expected at Step 3, and how will `~0` distinguish approved residue from unfinished work?

## Recommended next step

Revise and run another delta review. First regenerate the mechanism evidence from the bound catalog and reconcile every count; then close Step 0’s initialization/use grammar and replace the impossible additive-only gate. Do not begin implementation or put the analyzer-widening decision to the owner before those changes.

## Round 3 (delta) — 2026-08-01

- **Method:** delta round against revision `584983599f19` (revised from
  `071214db0606`); brief `llp0045-brief-r3.md`; rounds 1-2 artifacts, the
  regenerated evidence, and the new generator script in the capsule; same
  family/runtime as round 1.
- **Status:** RECEIVED 2026-08-01 — body below, recorded verbatim.

### Round-3 review body (verbatim)

**Verdict:** NOT READY

## Delta assessment

1. **RESOLVED** — The artifact hash matches its filename; it contains 338 unique Lane B cells, and bucket, touching, module, and raw-ambiguity summaries independently recompute correctly.
2. **PARTIALLY RESOLVED** — Numeric and assignment figures are corrected, but the causal interpretation of `bare-callee-miss` is wrong and the “pure cells” caption is false.
3. **PARTIALLY RESOLVED** — `const`, `null`, native identity, writes, `eval`, and `with` are closed, but the use/escape rule rejects the four intended sites and leaves “escaping function” undefined.
4. **RESOLVED** — Additions and removals are individually paired and allow-listed; everything unlisted must remain byte-equivalent.
5. **PARTIALLY RESOLVED** — P1/P2/P3 are orthogonal, but register item 4 still uses the retired “Class-2” taxonomy.
6. **PARTIALLY RESOLVED** — The inherited-share hedge and soundness conditions are present, but the estimates section still calls all 155 cells a single lever, and most `bare-callee-miss` cells have the wrong disposition.
7. **PARTIALLY RESOLVED** — Out-of-tree breakage and distinct mode options are present; the promised absent-hook normalization criterion is still missing from item 7.
8. **RESOLVED** — The Open Questions section exists and covers all five promised subjects.

## Concerns

1. **IN-DELTA — MATERIAL:** Step 0’s supposedly closed use grammar does not admit the four aliases it is meant to analyze.

   Every alias is used outside callee or `typeof` position: `_httpOwnerHost` appears in `!alias` guards; the other three appear in `alias && …` or `alias ? … : …` tests. They are also captured by exported/prototype functions, yet “closed over by an escaping function” is rejected without defining what makes a function escape. Consequently, the analyzer-widening branch has zero clearly eligible real sites, contradicting “four callable hook aliases matching this shape.” Define the accepted boolean-test forms and a mechanical closure-escape predicate, or state that Step 0 necessarily rewrites all four initializers and uses.

2. **IN-DELTA — MATERIAL:** `bare-callee-miss` is routed to the wrong remedy.

   The artifact reports `oncreate` in 10 of the 13 touching cells. Source shows `oncreate` is a local nested callback in `ClientRequest`/`Agent` code, not a documented or framework-virtual slot. Only the three `IncomingMessage.*` entries fit the preserved-dynamic account. Sending all 13 cells to register item 4 risks approving an analyzer/local-callback deficiency as irreducible extension-point residue. Split `oncreate` into local/nested-function attribution and retain only `IncomingMessage.*` under preserved dynamic dispatch.

3. **PRE-EXISTING — MINOR:** Register item 7 still lacks the promised normalization-semantics criterion.

   Open question 2 says hook installation “decides” normalization, but neither it nor item 7 states why: bare `const _x = __exactHook` throws when the global is absent, whereas the current `typeof` guard is safe. State explicitly that normalization is semantics-preserving only if authenticated hooks are unconditionally installed before evaluation in both modes.

4. **PRE-EXISTING — MINOR:** The qualified-member sizing remains internally inconsistent.

   Step 2 correctly says only TLS’s 30 inherited cells are proven and calls the expected yield a hypothesis. Section 4 nevertheless says qualified-member resolution is “the largest single lever” at 155 cells. That is the mechanism’s touching count, not the proven yield of the proposed inheritance resolver.

5. **PRE-EXISTING — MINOR:** Register item 4 still says “Class-2 extension points,” despite the claimed removal of all nominal class references. Rename it in P1/P2 terms.

6. **IN-DELTA — MINOR:** The matrix caption says “Pure cells sum to 338.” They do not: the artifact has 202 single-mechanism cells, 33 empty cells, and 103 multi-mechanism cells. Reword this as “single/empty buckets plus multi-mechanism buckets sum to 338.”

## Suggestions

- Emit contributing `fixtureId` values, not only `rowCount`, to make each cell’s aggregation independently traceable.
- Use the same mechanism key in prose and JSON (`projection` versus `cross-source-export-projection`).
- Add positive fixtures for every admitted Step-0 use form, alongside the existing negative-fixture requirement.

## Open questions

- Are truthiness tests such as `if (_x)`, `_x && …`, and `_x ? … : …` intended to be accepted?
- Does “escaping function” conservatively include every function assigned to an exported prototype?
- Should `oncreate` be handled by nested/local-function attribution even when it is also passed through the documented `createConnection` dispatch boundary?

## Recommended next step

Revise narrowly and run another delta review. Close Step 0 with an implementable use/escape grammar and split the `bare-callee-miss` disposition before implementation or owner approval. The evidence machinery and numeric corrections themselves are now sound.

## Round 4 (narrow delta) — 2026-08-01

- **Method:** narrow delta round against revision `76b043c8ab74` (revised from
  `584983599f19`); brief `llp0045-brief-r4.md`; rounds 1-3 artifacts,
  regenerated evidence, and hardened generator in the capsule; same
  family/runtime as round 1.
- **Status:** RECEIVED 2026-08-01 — body below, recorded verbatim.

### Round-4 review body (verbatim)

- **Verdict:** `NOT READY`

- **Delta assessment**
  1. **PARTIALLY RESOLVED** — `duplicate-definition` is correctly traced and routed, but the `IncomingMessage.pause` dead-code description is inverted.
  2. **RESOLVED** — Boolean tests, `var`-with-dominance, the mechanical escape rule, and the zero-yield fallback decision are present.
  3. **RESOLVED** — The Summary says six and appropriately qualifies the mixed causes.
  4. **RESOLVED** — The stated identifier counts recompute from the artifact.
  5. **RESOLVED** — Pairing is symmetric across terminals, paths, and ambiguities, for additions and removals.
  6. **PARTIALLY RESOLVED** — The 113 pure plus 14/21/7 joint qualified-member figures recompute, but 13 duplicate-definition *touching* cells are still called a lever size.
  7. **PARTIALLY RESOLVED** — Register item 4 is correctly rescoped; item 7 still does not state the promised ReferenceError semantics.
  8. **RESOLVED** — 62 matches, two `__proto__`, 60 callable assignments, and 48 callable names recompute.
  9. **RESOLVED** — The generator has the independent pass, `fixtureIds`, documented emission shapes, `modulePrefix`, and `zero-mechanism`; the artifact hash and 338 unique rows verify.
  10. **PARTIALLY RESOLVED** — All four questions were added, but the dead-fallback question embeds the same inverted `pause` claim.

- **Concerns**
  1. **IN-DELTA, MINOR — The promised ReferenceError criterion is absent.** Register item 7 and Open Question 2 say hook installation decides normalization, but never state why: replacing the guarded initializer with `const _x = __exactHook` throws `ReferenceError` during module evaluation when the global is absent, whereas `typeof` is safe. The only `ReferenceError` occurrence is in the revision history.
  2. **IN-DELTA, MINOR — Duplicate-definition cleanup is still misdescribed and mis-sized.** The assignment at `http.js:2805` is guarded by line 2804; the earlier `pause` fallback prevents that later branch, so the later assignment—not the fallback—is dead. Separately, the artifact has 13 duplicate-definition-touching cells but only one pure cell; the other 12 retain additional mechanisms. Calling all 13 a “lever” and saying the three fallback deletions “clear 3 cells” repeats the touching-versus-clearance error.

- **Recommended next step.** Make two surgical edits: add the explicit absent-hook/ReferenceError condition to register item 7, and correct the `pause` dead-code direction plus distinguish 13 ambiguity removals from one independently cleared cell. Then run one final narrow verification; no structural revision is needed.
