# LLP 0045: Network Terminal-Provenance Program

**Type:** Plan
**Status:** Superseded by [LLP 0046](./0046-network-terminal-provenance-measurement.research.md)
**Systems:** Security, Conformance, Runtime
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-01

> **Superseded 2026-08-01, by execution.** Every work stream below was measured
> against source and the running walker. **Seven of eight yield figures were
> wrong, five collapsing to zero**, and the two flagship streams — step 1's
> de-virtualization and step 2's qualified-member resolution — clear **no cells
> at all**. The cause is structural: §1 buckets cells by the *text of the
> ambiguity string the walker emitted* and derives the work breakdown from those
> buckets, but the strings are emission artifacts, not mechanisms. Separately,
> the 338 denominator was never capability-audited: **127 cells are
> capability-bearing** (floor 81), 112 are network-by-origin policy, 90 are
> seeding defects, 9 are unconditional throws, and 42 are exact aliases of other
> counted cells.
>
> **Do not staff any step below, and do not decide the §5 register against it** —
> register item 1 governs a transform no Lane B cell's route passes through, and
> item 7's fork has no live branch. Read LLP 0046 first; it records what the
> measurement found, what survives (the problem statement, §3's acceptance
> discipline, the mechanism-matrix generator, the TLS-bypass hazard), and why the
> successor plan is deliberately not yet authored.
>
> Retained unedited below as the authored record — its §1 counts all reproduce
> exactly, and the review history is why the errors were findable.
**Revised:** 2026-08-01f (round-5 confirmation — Codex **READY** (all 8
edits confirmed, zero concerns), Fable confirmed all 8 in substance with
five one-clause corrections, now applied: the `pause` dead-code
*justification* was profile-dependent (`IncomingMessage` inherits
`pause` from `Readable.prototype`, stream.js:2153, so the 2712 guard is
false and 2713 never runs in the default profile) — the conclusion holds
in both profiles and now says why; the 12 non-pure duplicate-definition
cells all carry `unresolved-ident`, which §4 had dropped; the
`unresolved-ident` gloss is relabelled 13-of-17; a stray deletion
residue and a §1 over-claim about the generator's catch-all are fixed.
No structural change; both families state no further round is warranted.
Review artifacts: llp/reviews/0045-*.{fable,codex}.md rounds 1-5)
**Revised:** 2026-08-01e (round-4 narrow delta — Fable 3 MATERIAL, Codex
2 MINOR, converging on the same two items, all fixed. **The
`IncomingMessage` dead-code direction was inverted** in the previous
revision at the one point it claimed proof: `_read` (2707 fallback vs
2811 unconditional) and `resume` (2710 vs 2807) have dead *fallbacks*,
but `pause`'s second assignment at **2805** is guarded by 2804 and the
live 2713 fallback makes that guard false — so 2805 is the dead one.
Corrected in the table, step 2, and open question 7. **The
duplicate-definition work is re-sized honestly**: cheapest in *effort*
(one rename, three deletions) but standalone *yield of 1 cell* — only
one of its 13 touching cells is pure; the other 12 need the analyzer
work anyway. It removes 13 ambiguity entries but is not a lever, and
§4's own rule against sizing with touching counts now applies to it too.
Register item 7 finally **states the ReferenceError fact in the body**
(third round asked): normalization throws at module evaluation when the
global is absent where `typeof` is safe, so it is semantics-preserving
only if hooks are unconditionally installed in both modes. Also: item 4
excludes the duplicate-definition *marker*, not the cells (12 of 13 carry
other mechanisms that may legitimately be residue); the
`unresolved-ident` gloss is marked top-10-of-17 and notes the fourth hook
alias; the per-module axis is relabelled a module.export prefix with the
`ws.*`/`dns.promises` caveat inline; the projection row names its JSON
key; open questions renumbered and the two 33-cell halves merged; the
generator states that its bare-name test is a regex, not an enumeration.
Review artifacts: llp/reviews/0045-*.{fable,codex}.md rounds 1-4)
**Revised:** 2026-08-01d (round-3 dual-review revision, both families NOT
READY — Codex 2 MATERIAL, Fable 3 MATERIAL + 8 MINOR, all addressed.
**Fable's tracing superseded the earlier diagnosis of the sixth
mechanism**: it is the walker's *duplicate-definition marker*
(`definitions.length > 1`), not preserved-dynamic slots (first draft) and
not a nested-callback attribution gap (second draft) — `oncreate` is
declared twice and each `IncomingMessage.*` member has a guarded fallback
plus a later unconditional assignment, making these 13 cells the
**cheapest** work in the program rather than irreducible residue. Renamed
`duplicate-definition` and routed to source hygiene, done first. Also:
the Summary's "five ways" corrected to six and qualified (the refusal is
sound in every case, but its causes are mixed and only some need source
change); `unresolved-ident` re-glossed with its measured distribution,
surfacing the timer lever (`setTimeout` touches 64 of 106 cells); the
acceptance gate's pairing made symmetric across terminals, paths, and
ambiguities (step 1 rewrites path strings, which an ambiguity-only
allow-list would have failed); §4 stops using touching counts as lever
sizes and quotes joint clearance; register item 4 rescoped to the P1/P2
union and explicitly excluding the duplicate-definition cells; item 7
states the ReferenceError semantics; 60 assignments across 48 names; the
generator hardened (independent second-pass invariant, per-cell
`fixtureIds`, strict shape enumeration, `modulePrefix` axis honesty) and
its over-claimed invariants downgraded; four open questions added.
Earlier in this round, Codex established that **the step-0 grammar as drafted admitted zero of the four
real alias sites** — every one is `var` (not `const`) and every one is
used in truthiness tests, not pure callee position — so the grammar now
accepts boolean-test use positions and `var`-with-dominance, states a
*mechanical* escape predicate (a read inside a nested/exported function
is not escape), and records the finding: if either allowance fails
review, the analyzer branch has no eligible sites and source
normalization (register item 7) becomes the decision rather than an
alternative. The `bare-callee-miss` bucket is **split by cause**:
`oncreate` (10 of 13 cells) is a local nested callback declared inside
`ClientRequest`/`Agent` bodies — an analyzer attribution gap routed to
step 2, not irreducible extension-point residue as previously claimed —
leaving only the three `IncomingMessage.*` cells preserved-dynamic. Also:
the "pure cells sum to 338" caption is corrected (202 single / 33 empty /
103 multi), register item 4 drops the retired class naming, §4 stops
calling 155 touching cells a lever size, item 7 states why it is a real
fork, positive step-0 fixtures are required alongside negative ones, and
open question 6 asks whether `oncreate` attribution survives the
`createConnection` boundary. Review artifacts:
llp/reviews/0045-*.{fable,codex}.md rounds 1-3)
**Revised:** 2026-08-01b (round-2 dual-review revision — Fable 1 MATERIAL
(prose contradicted the retained artifact), Codex 3 MATERIAL. The
mechanism evidence is **regenerated by a checked generator**
(`scripts/llp0045-mechanism-matrix.mjs`) that emits one row per Lane B
cell and derives every summary from those rows in the same run, asserting
bucket-sum, touching-recompute, and no-unrecognized-shape invariants; the
first hand-rolled artifact was self-contradictory (164 vs 155) and hid a
sixth mechanism, now named `bare-callee-miss` (13 cells: `oncreate` and
`IncomingMessage.*` — the preserved-dynamic slots surfacing as
ambiguity). Corrected figures: touching 155/142/106, six mechanisms,
62 matched lines / 2 `__proto__` / 60 callable assignments / 49 unique
names. Step 0's grammar is closed: `const`-only (no `var`/`let`
lifecycle proof), `null`-only inert, hook-identity resolution required,
an explicit use-site/escape predicate, `eval`/`with` module rejection.
The "additive-only" acceptance gate is replaced with paired allow-lists
for additions *and* removals — step 2's resolutions legitimately retire
ambiguity entries, so additive-only forbade the work it gated. The three
virtual-slot classes become three orthogonal properties (documented
contract / polymorphism source / derived eligibility) after review found
`createConnection` matched two classes. Register items 1/5/7 gain
out-of-tree override breakage, three genuinely distinct mode options, and
the normalization-semantics criterion; an Open Questions section is added.
Review artifacts: llp/reviews/0045-*.{fable,codex}.md rounds 1-2)
**Revised:** 2026-08-01 (round-1 dual-review revision, both families NOT
READY — Fable 5 MATERIAL / Codex 7 MATERIAL, strongly convergent. The
two-mechanism story is replaced by a **measured mechanism matrix**
retained as evidence: the step-0 alias rule clears neither dns (100%
cross-source projection) nor tls (100% inherited-member miss), so the
"may halve the program" claim is withdrawn; denominators corrected to
**338 Lane B** cells (373 was Lane B∪C∪D) with the 35 Lane C cells
scoped out; step 1 is re-founded on a virtual-slot classification after
review found a **TLS-bypass hazard** — `http.Agent.createSocket`
dispatches `this.createConnection`, which `https.Agent` overrides to
reach `tls.connect`, so de-virtualizing it would silently bypass TLS;
step 0 is respecified as a binding-aware capture rule with an explicit
rejected-grammar and adversarial fixtures, since the current walker is
spelling-based; acceptance criteria now require an allow-listed
route-evidence diff rather than a falling residual count; the register
grows from three to seven items including mode policy and scope
ownership. Review artifacts: llp/reviews/0045-*.{fable,codex}.md round 1)
**Related:** LLP 0044 §9 (the measurement that scoped this program; this
is the "Lane B terminal-provenance program" it defers network to);
LLP 0036 (advertisement completion plan); LLP 0021 (conformance program);
LLP 0037 (D1–D4 attribution rulings); LLP 0039 (secure/insecure modes —
register item 5); LLP 0004 (module loading and builtins);
issues/20260801-network-terminal-provenance-program.md (umbrella ticket);
llp/evidence/0045-mechanism-matrix-9665228aa5d1db0078b967cb78f4c7c993f715437a7cc33b30e938b06a412646.json
(this plan's measured basis, regenerated by the checked generator
`scripts/llp0045-mechanism-matrix.mjs`);
llp/evidence/0044-scope-measurement-09e6aeceb938aa0a945f5f94c2901dfcc84c66ed509d986f32d05f284dfaea18.json

## Summary

LLP 0044 §9 measured that most `network`-family coverage cells cannot be
certified by any amount of probe authoring: their rows carry
`no-static-enforcement-terminal` — the static builtin call-graph walker
finds **no path from the public surface to any typed enforcement gate**.
Without a source-derived terminal there is nothing to validate an
observed run against, and accepting the run alone would be the dynamic
route witnessing LLP 0044 §6 rejects.

The walker's refusal is **correct, not conservative**: the routes
genuinely are dynamic **where the walker's refusal reflects real
dynamism** — but the measured matrix (§1) names **six** mechanisms, and
some of them are not dynamism at all: 13 cells are duplicate-definition
artifacts, 33 are undiagnosed, and several unresolved identifiers
(`require`, `StringDecoder`, `AbortController`) look like analyzer gaps.
So the honest statement is: the refusal is *sound* in every case, but its
*causes* are mixed, and only some need source change. This plan's job is to make each
mechanism's routes statically provable — an enforcement-hardening change
in its own right — so network's cells become Lane A-authorable. It does
**not** author network probes, certify anything, or change HTTP
behavior semantics.

## 1. Measured problem shape

Catalog `sha256-XcvN5FFF…` (`aarch64-apple-darwin`, 2026-07-31). Every figure below is
recomputed from the retained artifact
`llp/evidence/0045-mechanism-matrix-9665228a….json`, which carries **one
row per Lane B cell** (edge id, module, bucket, mechanisms, raw
`ambiguousCallees`, row count) with every summary derived from those rows
in the same run. Regenerate with
`node scripts/llp0045-mechanism-matrix.mjs <catalog.json>`; the generator
re-derives the Lane B cell set in an **independent second pass** and
fails on disagreement, throws on any unrecognized *prefixed* ambiguity shape rather than
absorbing it into a catch-all (its bare-name test is a regex, so a
bare-name ambiguity from a new emission site would be absorbed — the
generator says so, and a new catalog must be re-verified), and carries per-cell `fixtureIds` so
each row is traceable. (Its other numeric assertions are derived from the
same rows they check and are regression guards, not proofs — the
auditability comes from the retained rows.)
The first hand-rolled version of this analysis was self-contradictory and
omitted a mechanism; that is why the generator exists.

**Denominators (corrected).** 580 seed-pure network cells; **373**
poisoned across Lane B∪C∪D; **338** carry Lane B
(`no-static-enforcement-terminal`) — this plan's denominator; **35**
carry only Lane C (`native-public-source-invocation-unavailable`:
native/global Fetch, WebSocket, Bun/Exact, executor surfaces) and are
**out of scope** (register item 6).

**The six mechanisms** (per cell, by the union of its rows'
`route.ambiguousCallees`; a cell may touch several):

| mechanism | pure cells | cells touching | what it is |
| --- | ---: | ---: | --- |
| qualified-member-miss | 113 | 155 | `unresolved-call:Type.member` — a member of a type the walker cannot resolve, including **inherited** members (tls's `TLSSocket` inherits `net.Socket` via `Object.setPrototypeOf`, tls.js:2885/3678) |
| dynamic-dispatch | 39 | 142 | `dynamic-call-receiver` / `computed-call` / `dynamic-call-target` — method calls on mutable receivers (the `this._x()` family) |
| unresolved-ident | 17 | 106 | bare `unresolved-call:name`. Measured distribution: **`setTimeout` 64 cells** and `clearTimeout` 7 (the timer lever, §2), three hook aliases 29/27/16 (`_dgramOwnerHost`, the fourth, touches 1), `createConnection` 10, `buffer` 8, `require` 6, `AbortController`/`fetch` 4 each, `StringDecoder`/`atob` 2 each — 13 of 17 raws (the 4 omitted each touch 1-2 cells); the artifact has the full set |
| empty-no-mechanism | 33 | 33 | **undiagnosed**: routes recorded neither terminals nor any ambiguity (28 http, 5 http2) |
| projection (`cross-source-export-projection`) | 32 | 32 | re-export layers emitted with empty `terminals` by construction (all of dns, via `dns.promises`) |
| duplicate-definition | 1 | 13 | the walker's **multiple-definition marker** (`definitions.length > 1`, capsec-surface-inventory.mjs:4494-4498 unqualified / :4538 qualified) — *not* a dynamism shape. `oncreate` (10 cells) is declared twice (http.js:4015, 5877); `IncomingMessage._read`/`resume`/`pause` each have a guarded fallback (http.js:2707/2710/2713) **and** a second assignment (2811/2807/2805) — for `_read`/`resume` the second is unconditional so the *fallback* is dead; for `pause` the second sits inside `if (!…pause)` (2804) and `pause` is callable on the chain either way, so the *second* is dead. Cheapest in effort, but see §4 on yield |

("Cells touching" counts every cell whose bucket contains the mechanism;
a cell with several mechanisms is counted in each, so the column does not
sum to 338. The artifact's `bucketCells` partitions all 338: 202
single-mechanism cells, 33 empty-mechanism cells, and 103
multi-mechanism cells.)

**Per module.export prefix** (Lane B cells; the axis is a positional
prefix of the edge id, not a module — `ws.*` rows are four exports of the
single `ws.js`, and `node.dns` rows are all `dns.promises` exports):
node.http 162, node.net 78, node.dns 32,
node.tls 30, node.http2 18, ws.server/websocket/websocketserver 4 each, https 4,
dgram 1, ws.createwebsocketstream 1 — summing to 338.
Decisively: **dns is 100% projection and tls is 100% qualified-member-miss**;
neither is touched by the hook-alias rule, and the earlier claim that
step 0 would clear them (and "halve the program") is **withdrawn**.

**Call-site counts** for the de-virtualization candidates, with the
counting method pinned: `rg -c 'this\._[A-Za-z0-9_]+\('` gives
`src/builtins/http.js` **117** internal call sites (196 for all
`this.method(`), `net.js` **20**. `rg -c '\.prototype\._[A-Za-z0-9_]+\s*='`
gives **62** matching lines in http.js, of which 2 are
`.prototype.__proto__ =` assignments, leaving **60** callable
prototype-method assignments across **48** unique underscore names (49 counting `__proto__`, which is not one of them). (The
earlier "62 definitions" and its "61" correction were both wrong; each
figure here names its query and what it counts.)

## 2. The plan

### Step 0 — Binding-aware immutable terminal capture (spike + review)

*(Renamed from "SSA-alias": the walker is spelling-based, not
binding-aware, so this step must build binding information rather than
extend an identifier map.)*

Today's walker merges declarations across scopes (`declaredIdentifiers`),
records only `AssignmentExpression`-with-identifier-LHS writes, and keys
alias resolution by identifier text. Review demonstrated this is already
unsound in principle for shadowed names, so the step must **first** make
resolution binding-aware, then permit exactly one new resolution:

A call through identifier `_x` resolves to native hook `__exactHook` iff,
under lexical binding resolution at the call site, `_x` resolves to a
module-top-level binding that satisfies **all** of:

- **Declaration form.** `const` at module top level is accepted. `var`
  and `let` are accepted **only** with a proven post-initialization
  dominance argument (hoisting and CommonJS-cycle exposure can otherwise
  let a credited call run before initialization) — and, per the finding
  below, all four real sites today are `var`, so this is not a
  hypothetical branch.
- **Never re-declared or shadowed** on any path to the call site
  (binding-resolved, not name-matched).
- **Initializer is one of exactly two forms:** `= __exactHook`, or the
  guarded `typeof __exactHook === 'function' ? __exactHook : null` —
  where the inert alternative is the **literal `null` only**.
  `undefined` is *not* accepted: it is an identifier and can be shadowed,
  so it is not provably non-callable. A callable fallback keeps today's
  refusal, since resolving to the hook would erase a real alternative
  route.
- **The initializer's `__exactHook` reference itself resolves to the
  authenticated native global** — not merely a name matching `__exact*`.
  Name-shape matching is not proof of native identity.
- **No write of any form** anywhere in the module: assignment, compound
  assignment, update expression, destructuring target, `for-in`/`for-of`
  target, or catch binding.
- **Use rule.** Accepted use positions are: (i) callee of a call
  expression; (ii) the operand of the alias's own `typeof` guard; and
  (iii) **boolean tests of the alias's presence** — `if (_x)`,
  `_x && …`, `!_x`, `_x ? … : …`, and equality against `null`. Position
  (iii) is required, not optional: see the finding below. A boolean test
  cannot invoke or leak the value, so it does not widen what a call can
  reach.
- **Escape predicate (mechanical).** The alias escapes — and the
  refusal stands — if it appears in any *other* position: as a call
  argument, in an object/array literal or property assignment, as a
  return value, or as an operand of any expression not listed above.
  Being *read* inside a nested or exported function body is **not**
  escape (the binding is immutable and the read is one of the accepted
  positions); this must be stated mechanically because "closed over by
  an escaping function" is not a decidable predicate as written.
- **Module contains no direct `eval` and no `with`** — both make the
  "no other write" and escape claims undecidable. Module-level rejection.

**Finding that reshapes this step (round-3 review).** Measured against
the four real sites — `_httpOwnerHost`/`_httpNetOwnerHost` (http.js:63,67),
`_netOwnerHost` (net.js:222), `_dgramOwnerHost` (dgram.js:11) — an
earlier, stricter draft of this grammar admitted **none of them**, on two
independent counts: every site is declared `var`, and every site is used
in truthiness tests (`state.ownerStamp != null && _netOwnerHost`,
`_httpNetOwnerHost ? _httpNetOwnerHost('new') : null`, `!_netOwnerHost`)
rather than purely in callee position. The grammar above admits them by
accepting boolean-test positions and `var`-with-dominance. **If either
allowance fails review**, step 0's analyzer branch has zero eligible
sites in practice, and the only remaining path is source normalization
(register item 7) — which would then be the decision, not an
alternative. This is why item 7 is a real fork rather than a
preference.

Two further obligations the review surfaced: the guarded form reads the
global twice, so resolution depends on native hooks being authenticated,
immutable data properties installed before any builtin evaluates
(**state this invariant and verify it**, including under lazy builtin
loading — open question 1); and the conditional shape needs a **defined
representation in `enforcementRouteEvidence`**, which today carries only
flat `terminals`/`paths`/`ambiguousCallees` (schema extension, reviewed
with the rule).

Only **four** callable hook aliases matching this shape exist across the
network builtins (two http, one net, one dgram). Register item 7 asks
whether that yield justifies an analyzer widening at all, or whether
normalizing four source sites to a shape today's walker already accepts
is the better trade.

**Gate:** an allow-listed route-evidence diff (below), not a falling
count.

### Step 1 — Virtual-slot classification, then bounded extraction

**The hazard that re-founds this step.** `http.Agent.createSocket`
dispatches `this.createConnection(options, oncreate)` (http.js:5909) and
`https.Agent` **overrides that slot** to route through `tls.connect`
(https.js:97). De-virtualizing it would silently **bypass TLS for every
HTTPS request**. `options.createConnection`, caller-supplied
socket-likes, HTTP/2's supplied stream objects, and `TLSSocket`'s
inheritance from `net.Socket` are the same shape: intentional dispatch,
not patchable internals.

So extraction is gated on a **complete inventory of every virtual slot on
a capability route**, each described by three *orthogonal properties*
rather than one nominal class (review found the earlier three classes
overlapped: `createConnection` is both a documented contract and a
cross-module overridden slot):

- **P1 — documented contract?** Is the slot a published/compat extension
  point (`createConnection`, `options.*` hooks, caller-supplied
  socket-likes and stream-likes)?
- **P2 — polymorphism source:** none observed; in-tree subclass or
  cross-module dispatch (`_read` via stream machinery, `https.Agent`
  over `http.Agent`); or caller-supplied object.
- **P3 — de-virtualization eligibility**, which is *derived*, not
  asserted: eligible **iff P1 is "no" and P2 is "none"**. Everything
  else is preserved as dynamic.

The eligible set (P1 no, P2 none) is what the rest of this step calls
**security-private**. Preserved-dynamic slots split by *why*: documented
contracts (P1 yes) and framework/inheritance polymorphism (P2 non-none,
e.g. `_implicitHeader` ×3, `_read` ×3, plus `_send`, `_renderHeaders`,
`_dump`, `_flushManualData`, `_scheduleManualReadable`, `_emitManualEnd`,
`_emitHttpClose`, `_pushBodyChunk`). Their routes need a different
mechanism — a declared, authenticated dispatch contract — or an explicit
residual disposition (register item 4). (The duplicate-definition
*marker* is not part of this residue — see §2 step 2 — though 12 of those
13 cells carry other mechanisms that may be.)

Transform rule for the eligible (security-private) set: `this._x()` → a **per-class** module-local
function with a mangled name (`_clientRequestQueueStreamingBody(self)`),
because same-named free functions would trip the walker's
multiple-definition refusal and manufacture *new* ambiguity. The
prototype method is retained as a thin wrapper delegating to it.

Consequence, stated plainly: for eligible slots, internal capability
routing no longer flows through a patchable prototype slot. This is
hardening — an enforcement route reroutable by prototype writes is a
vulnerability shape — but it is an observable change for code patching
underscore internals, and it changes method identity/`.name`/`.length`/
stack shape for the extracted bodies. Register item 1.

**Compatibility obligation:** subclass, `super`, custom-agent,
custom-socket, HTTPS-through-Agent, TLS/net inheritance, ws, and HTTP/2
delegation tests must exist and pass **before** the pattern is approved,
not after.

### Step 2 — The mechanisms step 1 does not address

Each is separate work with its own review, not a variation of step 1:

- **Cross-source export projection (32 cells, all dns).** Join the
  projection to the projected module's routes so `dns.promises.resolve4`
  inherits `dns.resolve4`'s terminals, with the join authenticated
  (both sides source-bound, no re-export laundering). Analyzer work.
- **Qualified-member resolution (113 pure / 155 touching cells).** Teach the walker prototype-chain resolution
  for statically-established inheritance (`Object.setPrototypeOf` at
  module top level with both sides in-inventory). This is the largest mechanism by cell count. Its inherited-member share
  is *proven* only for tls's 30 cells; the http/net qualified-miss cells
  are not yet decomposed by name, so "highest-value analyzer item" is a
  hypothesis this step's diagnosis must confirm before it is staffed.
  Soundness conditions to pre-state for its review: child-shadowing
  detection when the child prototype later assigns the same member, and
  whether a resolved parent slot needs the same immutability argument
  eligible-set extraction makes.
- **Undiagnosed empty-mechanism cells (33).** Diagnose before planning:
  routes recorded neither terminals nor ambiguity, so the cause is
  unknown and may be an inventory defect rather than a source shape.
- **Duplicate definitions (13 cells) — source hygiene, do first.**
  Traced to the emitting code, these are not dynamism and not residue:
  the walker refuses because the source declares the callee more than
  once. `oncreate` is declared twice (http.js:4015, 5877) — rename one.
  `IncomingMessage._read`/`resume`/`pause` each carry two assignments;
  which one is dead differs per member: `_read` (2707 fallback vs 2811
  unconditional) and `resume` (2710 vs 2807 unconditional) have dead
  *fallbacks*; `pause`'s second assignment at 2805 is inside
  `if (!IncomingMessage.prototype.pause)` (2804), and `pause` is already
  callable on the prototype chain by then — inherited from
  `Readable.prototype` (stream.js:2153) in the default profile, or
  supplied by the 2713 fallback in a stream-less one (http.js:11 wraps
  the `node:stream` require in try/catch for exactly that case) — so
  **2805** is dead in **both** profiles. Collapse each
  in its own direction. This is the **cheapest work in effort** — a
  rename and three deletions — and worth doing first, but see §4: its
  standalone yield is 1 cell.
  Two earlier drafts mis-routed these cells — once to extension-point
  residue, once to a nested-callback attribution gap — because the
  mechanism was named from the raw string's shape instead of traced to
  the code that emits it.
- **Callback/promise/timer identifiers.** Consider admitting reviewed
  intrinsic timers (`setTimeout`/`setImmediate`) as non-terminal calls
  and attributing terminals inside `.then`/callback closures
  (`walkDirectFunctionBody` skips nested functions today). Both are
  analyzer widenings and re-enter register item 2's review path.

### Step 3 — Verification and hand-off

Success metric: **Lane B network cells 338 → ~0**, with every irreducible
cell carrying an explicit named disposition (preserved documented extension points are
expected to be a real, honest residue). The 35 Lane C cells are out of
scope. Then network enters the ordinary LLP 0036 step-2 / LLP 0044 Lane A
authoring program — finishing this plan makes network *authorable*, not
*certified*.

## 3. Acceptance criteria (what "the count fell" is not)

A falling residual count is not evidence: a bug that suppresses ambiguity
or records a merely-possible terminal also makes it fall. Every step
lands only with:

- an **allow-listed route-evidence diff**: each newly-resolved route
  named, with source spans and initializer/terminal identity, reviewed
  row by row;
- **paired allow-lists, not "additive-only".** Step 2's resolutions
  legitimately *remove* ambiguity entries (an inherited-member or
  projection resolution retires the `unresolved-call:Type.member` it
  explains), so an additive-only rule would forbid the work it is meant
  to gate. The gate is instead: every terminal/path **addition** and
  every ambiguity **removal** is individually allow-listed — and the
  pairing is **symmetric across all three route-evidence fields**
  (terminals, paths, ambiguities), additions and removals alike. Step 1's
  extraction rewrites *path strings* on cells whose terminals and
  ambiguities are unchanged; an ambiguity-only allow-list would fail that
  legitimate work exactly as "additive-only" failed step 2's. Each listed
  change is paired by cell, source span, and its resolution proof; every
  unlisted field, cell, path, and ambiguity entry must remain
  byte-equivalent against the prior inventory. An unexplained removal
  fails the gate exactly as an unexplained addition does;
- **positive fixtures for every admitted step-0 use form** (callee
  position, own-`typeof` guard, each accepted boolean test) proving it
  resolves, alongside **adversarial negative fixtures** for every
  binding, write, and use form the grammar rejects (shadowing, destructuring, update expressions,
  catch bindings, `eval`, `with`, callable fallback, escaped mutable
  capture) — each must still refuse;
- secure **and** insecure behavioral differential tests for any extracted
  route (register item 5);
- retained digest-bound inventory/catalog outputs per iteration; and
- separate review of every intentionally preserved dynamic extension
  point (P1-yes or P2-non-none), since those are the routes that stay unproven.

Executed behavior may validate semantics; it must never manufacture route
provenance.

## 4. Estimates

Deliberately **not restated as a single number** until the step-0 gate
and the step-2 diagnosis report: review established that the earlier
two-week estimate rested on the withdrawn step-0 yield model, and that
the streams are coupled (https depends on http, tls on net, dns.promises
on dns). What can be said now: **touching counts are not lever sizes** — a cell clears only when
*every* mechanism it touches is resolved. Qualified-member resolution
alone clears at most its 113 pure cells; its other 42 touching cells
clear only jointly (14 with dynamic-dispatch, 21 with
dynamic-dispatch+unresolved-ident, 7 with three others), per the
artifact's `bucketCells`. And of those 113, only tls's 30 are *proven*
inherited. The duplicate-definition work is the cheapest in
*effort* (one rename, three deletions) but its standalone *yield* is
**1 cell** — only one of its 13 touching cells is pure; the other 12 also
carry `unresolved-ident` — 5 as duplicate-definition+dynamic-dispatch+
unresolved-ident and 7 with qualified-member-miss on top — so they clear
only once that analyzer *and* timer/identifier work lands. It still removes 13
ambiguity entries, which is worth doing early, but it is not a lever.
Likewise the timer admission would touch 64 `setTimeout` cells and clear
only those whose other mechanisms also resolve; the four hook
aliases are a small lever; and http.js's 117 call sites are bounded by
the eligible (P1-no/P2-none) subset, which the step-1 inventory sizes. Re-estimate at the
first gate.

## 5. Author-decision register

1. **De-patching eligible (security-private) slots** (blocks step 1):
   accept that internal capability routing on those slots stops flowing
   through patchable prototype slots, with thin wrappers preserving the
   method surface and the identity/`.name`/`.length`/stack changes noted.
   Eligibility is tested **in-tree**, so acceptance explicitly includes
   breaking *out-of-tree* subclasses that override those underscore
   internals: their overrides would be silently bypassed on internal
   routes. Recommended: yes, bounded to the eligible set.
2. **The binding-aware capture rule** (blocks trusting step-0 output):
   the accepted/rejected grammar above, reviewed as a widening of what
   static analysis accepts. Any *further* widening in step 2
   (projection join, inheritance resolution, closure attribution, timer
   admission) re-enters this item's review path as its own decision.
3. **Sequencing** (blocks staffing): recommended to run beside, not
   blocking, the LLP 0044 fs+env+process v1.1 push.
4. **Preserved-dynamic residue** (every slot with P1-yes **or**
   P2-non-none — the union of the old classes 2 and 3; the duplicate-definition
   **marker** is excluded as source hygiene, but a cell that also carries
   a preserved-dynamic mechanism still belongs here — 12 of the 13 do;
   blocks step 3's exit): accept that
   documented dynamic dispatch stays dynamic and its cells remain an
   honest, dispositioned residue — or fund a declared authenticated
   dispatch contract to prove them.
5. **Mode policy** (blocks step 1's scope; LLP 0039). The options differ
   in *which* slots may be de-virtualized and *where*:
   (a) **shared, eligible-set only** — de-virtualize only P1-no/P2-none
   slots, in both modes; the compatibility cost is exactly the
   out-of-tree underscore-override breakage named in item 1.
   Recommended.
   (b) **secure-only** — same slot set, secure mode only; adds permanent
   mode-divergent routing, divergence tests, and the LLP 0039
   mode-divergence risk, for no enforcement gain in insecure mode.
   (c) **shared, extended beyond the eligible set** — additionally
   de-virtualize some P1-yes/P2-non-none slots, accepting a documented
   break of published extension points (this is strictly more than (a):
   it breaks *documented* contracts, not just underscore internals).
   The earlier plan asserted (a) without analysis; this is the decision.
6. **Scope ownership** (blocks the success metric): confirm LLP 0045
   owns the 338 Lane B cells and that the 35 Lane C native/global
   surfaces belong to a separate program.
7. **Analyzer widening vs source normalization for the four hook
   aliases** (blocks step 0's shape). **The deciding fact:** normalizing
   to a bare `const _x = __exactHook` **throws a ReferenceError during
   module evaluation** if the global is absent, where today's
   `typeof __exactHook === 'function' ? … : null` is safe — so
   normalization is semantics-preserving **only if** the authenticated
   hooks are unconditionally installed before builtin evaluation in
   *both* modes (open question 2). Options: a general binding-aware rule
   (broader, more review surface) vs normalizing four source sites into
   the `const` form today's walker already resolves (narrow, no analyzer
   trust change). Recommended: measure both at the spike, prefer
   normalization if the yield is only those four.

## 6. Non-goals

- No rewrite of HTTP/net behavior semantics; the transform is
  route-shape-preserving with the documented eligible-slot patching exception.
- No de-virtualization of documented extension points or
  framework-virtual methods — the TLS-bypass hazard is why.
- No dynamic route witnessing, no evidence-bar change, no adapter
  credit: Lane B rows clear only because source provenance now supplies
  their terminals.
- No network probe authoring, no advertisement, no scope change: this
  plan ends where Lane A begins.
- Lane C's 35 native/global cells are not this program's work.

## 7. Open questions

1. Are the `__exact*` network hooks installed as authenticated, immutable
   data properties **before every possible builtin evaluation**,
   including lazy builtin loading? Step 0's resolution rests on this.
2. Are those hooks installed unconditionally in **insecure** mode as
   well as secure? With register item 7's ReferenceError fact, this
   decides whether normalization is even available.
3. The 33 `empty-no-mechanism` cells record neither terminals nor
   ambiguity — so what source pattern produces them, **and** where does
   their Lane B tag come from if not route evidence? (One question, two
   halves; step 2 diagnoses before planning.)
4. What class of residue is expected at step 3, and how does the metric
   distinguish *approved* residue (preserved-dynamic slots, register
   item 4) from *unfinished* work? "~0" is not a criterion until that
   split is named.
5. For step 2's qualified-member resolution: when a child prototype
   later assigns the same member name, does the inheritance rule detect
   the shadow, or is that deferred to its own review?
6. Should `oncreate` be attributed as a local nested callback even
   though it is also handed across the documented `createConnection`
   dispatch boundary — i.e. does attribution stop at the boundary?
7. Confirmed dead assignments to delete: `_read`'s 2707 fallback (2811
   is unconditional) and `resume`'s 2710 fallback (2807 is
   unconditional); `pause`'s **2805** (guarded by 2804, false in both profiles: `pause` is
   inherited from `Readable.prototype` when `node:stream` loads, and
   supplied by the 2713 fallback when it does not). Is there any load-bearing reason these
   were written defensively that this reading misses?
8. Is `unresolved-call:createConnection` (10 cells) the imported
   `net.createConnection` — i.e. covered by step 2's projection/require
   work — or a further uncounted lever?
