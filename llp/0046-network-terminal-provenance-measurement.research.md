# LLP 0046: What the Network Terminal-Provenance Measurement Actually Found

**Type:** Research
**Status:** Draft
**Systems:** Security, Conformance, Runtime
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-01
**Related:** LLP 0045 (the plan this supersedes — read its §1 for the taxonomy
that failed); LLP 0044 §9 (the measurement that scoped both); LLP 0037
(D1–D4 attribution rulings); LLP 0039 (secure/insecure modes);
issues/20260801-network-terminal-provenance-program.md (umbrella);
issues/20260801-net-owner-hook-lazily-captured-after-user-code.md;
llp/evidence/0045-mechanism-matrix-9665228aa5d1db0078b967cb78f4c7c993f715437a7cc33b30e938b06a412646.json

## Summary

LLP 0045 planned six work streams to make 338 network Lane B cells statically
provable. Executing it measured every stream against source and the running
walker. **Seven of eight yield figures were wrong, five of them by collapsing to
zero**, and the two flagship streams — step 1's de-virtualization and step 2's
qualified-member resolution — clear **no cells at all**.

The cause is structural, not arithmetic. LLP 0045 §1 bucketed cells by the
**text of the ambiguity string the walker emitted**, and derived its work
breakdown from those buckets. The strings are emission artifacts, not
mechanisms: `cross-source-export-projection` is a placeholder masking five
unrelated shapes, `empty-no-mechanism` has at least two causes,
`qualified-member-miss` decomposes into eleven causes of which inheritance is
third. Five work streams were therefore sized against labels that do not
correspond to causes.

Worse, **the denominator was never capability-audited**. Of the 338 seeded
cells, **127 are capability-bearing** (floor 81); 112 are network-by-origin
*policy*, 90 are seeding defects, and 9 are unconditional throws. A further 42
are exact export aliases of other counted cells.

LLP 0045's problem statement survives, its evidence discipline survives, and two
cheap real levers were found that it treated as marginal. Its taxonomy,
work breakdown, estimates, and most of its decision register do not.

**This document records the measurement. It deliberately does not author a
successor plan** — see §6: the denominator is not stable until the seeding
defects are fixed, and planning against a number that is about to move by 60%
is the error that produced LLP 0045.

## 1. Method

Ten parallel investigations against catalog `sha256-XcvN5FFF…`
(`aarch64-apple-darwin`, baseline revision `e276d4ec` of `src/builtins/http.js`),
each required to derive every figure from a command it ran and to cite
`file:line` for every source claim. Where a claim was load-bearing it was
re-verified independently; where two investigations disagreed, the disagreement
is recorded in §5 rather than resolved by preference.

Two results were checked by an adversarial verifier tasked to refute them. It
refuted two *consequences* (see §3.4) and confirmed the rest.

## 2. The corrected denominator

Every cell of the 338 carries a verdict with a `file:line` citation
(`K-cell-verdicts.tsv`; 338/338 asserted, `edgeId`→export join exact, 0
unresolved).

| category | n | meaning |
| --- | ---: | --- |
| **CAP** | **127** | genuinely capability-bearing — the real program |
| **ORIGIN-POLICY** | 112 | in-memory, seeded by `retainedNetworkOriginEffectSpec`. Network-by-origin is a **policy** call, not a defect |
| **PURE** | 90 | in-memory, seeded by a non-origin receiver-class catch-all. Mis-seeded |
| **STUB** | 9 | unconditionally throws. Mis-seeded, and the model has no disposition for a refusal |

- **Scope if the origin policy stands: 239.** 99 cells (29%) drop out as defects.
- **Scope if origin is re-derived from source: 127** — 38% of the asserted 338.
- **Floor 81**: 46 CAPs are deliberate conservative defaults (`.connection`/
  `.socket` getters returning a live socket; `net.Socket.{on,addListener,
  prependListener,pipe}` reaching `resume()`→`_startPolling`→`__exactTcpRead`,
  net.js:3425/3433/3441/3613→2379).
- **Separate inflation:** 42 cells are exact export aliases — `net.Stream.*` ≡
  `net.Socket.*` (net.js:4623 `Stream: Socket,`), `ws.Server*` ≡
  `ws.WebSocketServer*` (ws.js:1185-1186). De-duplicated: **296 cells / 112 CAP.**

### Where the seeding bug lives

`builtinExportClassification` (capsec-coverage-model.mjs:8788) assigns capability
by **receiver-class prefix**, not by member: `/^clientrequest(?:\.|$)/` →
`network:connect`, and ten siblings. The model's own
`nonCapabilitySpec("pure-in-memory-compute")` escape hatch (:9268, :9321) exists
but is keyed on the whole export id **and ordered after the class catch-alls**,
so a `ClientRequest.*` member can never reach it. The correct pattern — member
carve-outs placed *before* the prefix — already exists three lines away at
:9207/:9216/:9219.

By spec: `optionalNetworkEffectSpec` 122 cells → 72 PURE + 2 STUB (**61%
wrong**); flat effect specs 34 → 18 PURE + 5 STUB;
`retainedNetworkOriginEffectSpec` 152 → 112 in-memory by construction (policy);
DNS resolver 28 → 28 CAP.

### node_http2 is 18/18 mis-seeded, 0 CAP

Every producer throws — `createServer` http2.js:250, `createSecureServer` :254,
`connect` :258, `performServerHandshake` :262. `Http2ServerRequest` (:347) and
`Http2ServerResponse` (:392) are field-initialising constructors whose
`this.stream` is caller-supplied; nothing in `src/` outside http2.js references
them. The 16 members are header-map operations. Yet
`/^(?:http2serverrequest|http2serverresponse)(?:\.|$)/` seeds an
**unconditional** `effectSpec(["network:listen"])` (:9311). This is a second,
distinct defect: **the model asserts an effect the implementation does not
have.**

### Is the shape systemic? No — one non-network instance

The `/^receiverclass(?:\.|$)/ → effect spec` shape occurs at exactly 12 sites;
11 are network. The twelfth is `node_readline`: `/^interface(?:\.|$)/ →
readlineOperationEffectSpec()` (:9587), seeding a `stdio` effect on all 51
`Interface.*` surfaces including pure ones (`_wordLeftIndex` readline.js:849,
`getPrompt` :1372, `_pushUndoSnapshot` :759). By contrast `node_fs` (:8975–9080),
`exact_process`, `node_child_process`, `exact_sqlite`, and `exact_crypto` all
**enumerate members** — fs tests `/^readstream\.(?:_read|open)$/`, not a prefix.
A bounded ticket for `node_readline` is warranted; a cross-family audit is not.

## 3. Every stream, measured

| stream | LLP 0045's framing | measured Lane B yield |
| --- | --- | ---: |
| Step 1 de-virtualization | 117 call sites; blocks on register item 1 | **0** |
| qualified-member-miss | "the largest mechanism by cell count" | **0** (ceiling 6) |
| empty-no-mechanism | 33 undiagnosed | **0** — not capability-bearing |
| duplicate-definition | "cheapest work in the program" | **0** (net −8 entries) |
| timer admission | 64-cell lever | **0 — and falsifies 6 cells** |
| projection | 32 cells, "100% pure" | **1** |
| step-0 hook aliases | marginal 4-site fork | **46** |
| callback attribution | a sub-bullet of step 2 | **+11**, with real hardening |

### 3.1 Step 1 clears zero cells

The eligible set (P1-no, P2-none) is **5 slots / 31 call sites** — 26% of
http.js's 117, all of them `HttpRequestParser` internals (unexported,
unadvertised). `capsec/generated/surface-inventory.md` carries **66 of 76**
underscore slots as advertised `builtin:export:` entries with declared effects:
**67 of 76 are P1-yes.**

Decisive: **no Lane B cell's route evidence mentions `HttpRequestParser` or any
of the five eligible slots.** Measured over the baseline catalog — 0 of 338.

So register item 1 — the plan's largest decision, the out-of-tree-subclass
breakage it asks the author to accept, and the mode-policy fork in item 5 —
governs a transform that no Lane B cell's route passes through.

Three further findings from that inventory: item **5(c)** is refuted by
evidence (17 uncounted `TLSSocket`-over-`net.Socket` cross-capability dispatch
sites, three inside underscore methods, exactly where 5(c) reaches); the
extraction pattern **already exists in-tree** as six reviewed `*Owned`
module-local captures (net.js:2257/3206/3451-3453, dgram.js:526/855,
http.js:9602), and it works on P1-yes slots, which the plan's extraction cannot;
and §2 step 1's compatibility precondition **is not met** — subclass, `super`,
and HTTP/2 delegation have **zero** test coverage today.

Every pinned count in LLP 0045 §1 reproduces exactly (117/20/196/62→60/48, and
every line number). The counting was careful; the interpretation was not.

### 3.2 qualified-member-miss yields zero, and §1's tls gloss is inverted

113 pure cells decompose into **eleven** causes, of which inheritance is third
(11 cells). All 11 resolvable parent slots have `terminals: []` — resolution
swaps an ambiguity label and never adds a terminal. Ceiling for the whole
mechanism is **6 cells**, and those 6 reach `__exactTlsOwnerToken('assert', …)`,
an ownership assertion that is arguably not the typed gate Lane B wants, so it
may be 0.

**LLP 0045 §1 has tls backwards.** It glosses tls's 30 cells as inherited-member
misses. The chain exists (tls.js:3678) but **none of the 30 resolve through
it**: 16 constructor-time own properties (tls.js:2824-2865), 6 prototype
accessors, 5 computed-loop writes (tls.js:3452-3464), 3 non-function RHS —
16+6+5+3 = 30. tls is **0% inherited**, not 100%. tls.js:184-191 documents that
those own properties exist precisely to *defeat* the inherited `net.Socket`
accessors. This was the one part §4 called *proven*.

**A second TLS-shaped hazard, on the analyzer side.** `TLSSocket.prototype
.addListener = TLSSocket.prototype.on` (tls.js:3397) invisibly shadows
`Socket.prototype.addListener` (net.js:3433), whose body calls
`_assertNetSocketOwner`. Resolving inheritance would credit net's route **and
its owner assertion** when tls's `on` is what actually runs — manufactured route
provenance in the precise sense LLP 0045 §3 forbids. Structurally identical to
the `createConnection` TLS-bypass that re-founded step 1, but reached by
*proving* rather than by transforming.

107 of the 113 are property reads and EventEmitter projections with no
capability route to prove. They are a scope question, not analyzer work.

### 3.3 Timer admission is negative-valued

Admitting `setTimeout`/`setImmediate` as non-terminal clears **0** Lane B cells
and turns **6** into routes recording neither terminals nor ambiguities — routes
that claim to have been fully analyzed and to contain no gate. Three
demonstrably contain one.

`walkDirectFunctionBody` (capsec-surface-inventory.mjs:3873) never walks a
function passed as an argument, so `unresolved-call:setTimeout` is the **only
marker** that a route defers into unanalyzed code. Removing the marker removes
the evidence of the gap. Real terminals live in those callbacks: `ws.js:948`
`setTimeout(acceptLoop, 0)` where `acceptLoop` calls `__exactTcpAccept`;
`net.js:2727` `setTimeout(function(){ … __exactUnixConnect(…) }, 0)`, sibling
`__exactTcpConnect` at :2814.

**The consequence reaches outside this plan's scope.** `net.Socket.connect`'s
recorded route today is:

```
terminalObservedKey: builtin:export:node_net:Socket.connect
alternatives:        ["native-op:__exactTcpClose"]      <- the cleanup path
residualReasons:     ambiguous-static-enforcement-route,
                     public-surface-invocation-not-authored
```

The connect syscall is invisible; the only terminal recorded is the socket
*close*. Note the absent residual: `no-static-enforcement-terminal`. **This cell
is not in Lane B.** It reads as a cell that has a static enforcement terminal —
it just has the wrong one. LLP 0045 is scoped to the walker's honest refusals
while a class of confident **misattributions** goes uncounted.

The constructive half: callback-argument attribution — the thing timer admission
would have destroyed the evidence for — gains **11 Lane B cells a real terminal
with 0 going silent**, surfacing `__exactTcpAccept`, `__exactTcpRead`,
`__exactUdpRecv`, and `__exactUnixConnect` routes invisible today. This is
genuine enforcement hardening and the highest-value analyzer item found.

### 3.4 Step 0: the premise is false, the fix is four lines

LLP 0045 §2 step 0 requires the `__exact*` hooks to be "authenticated, immutable
data properties installed before any builtin evaluates," and says to state and
verify that invariant. Verified — it does not hold. Both hooks are installed
with a plain JSI `setProperty` (`hermes_runtime_net.cc:967`,
`hermes_runtime_http.cc:347`) — writable, enumerable, configurable. No
hardening pass exists; lockdown's freeze roots are intrinsics only and
`globalThis` is not among them.

**Confirmed empirically** once a require blocker was cleared (§4): a sentinel
installed by root code before `require('net')` fires — `SENTINEL FIRED new` then
105 `assert` calls; dgram 9; http 10. The accessor variant works, with read #1
answering the `typeof` guard and read #2 supplying the captured value: the
guarded ternary is two distinct global reads that **can be made to disagree**.
So `net.js:219-221`'s comment — "Capture the native owner boundary before
application code can replace the writable global binding" — is false.

**Blast radius, honestly: not a privilege escalation.** With the preflight fully
neutralized, `new net.Socket({fd:3})` constructs but the handle is inert —
`__exactTcpWrite` → `invalid handle`, `__exactTcpConnect` → `Permission denied`.
`requireSocketHandle` (hermes_runtime_net.cc:783) independently checks the
runtime nonce, the owning principal, and typed-lease reauth. http.js:59-62's
claim that payload-bearing hosts retain their own native checks is **accurate**.
What is lost is the **cross-package integrity** check: `net.js` is one shared
instance, so a root replacement strips the per-socket owner binding for every
principal. Filed P2, not P1.

Two consequences the adversarial verifier **refuted**, recorded here because
they were briefed as findings:
- The `__exactHttpOwner` lazy-install gap is **not live**. An eager-install seal
  (`hermes_runtime.cc:6402-6415`) calls every `__exactEnsure*` and deletes it,
  gated on `structural_lockdown`, set only by `ex_hermes_create_no_eval`, which
  the CLI never uses. The hook is installed before any builtin evaluates in every
  real `ibex` process.
- **Package code cannot mount the replacement.** `makeCompartment`
  (hermes_runtime.cc:4132) withholds every `__exact*`/`__ibex*` name and lands
  writes on a package-local target. Exposure is first-party/root code only.
  (Established by static reading; a policy-admitted fixture could not be run —
  recorded as a gap in the ticket rather than asserted.)

**The fix is not an analyzer.** The walker's `terminalAliases`
(capsec-surface-inventory.mjs:4392-4406) requires `const` plus a bare `__exact*`
identifier or a member expression on a global alias. A `ConditionalExpression`
returns `null`, so today's guarded ternary can never resolve — `var` or `const`.
But this resolves **today, unchanged**:

```js
const _netOwnerHost = globalThis.__exactNetOwner;
```

Measured by edit → regenerate → restore, one variant at a time:

| variant | Lane B | cleared |
| --- | ---: | ---: |
| control (`var` + ternary) | 338 | 0 |
| `const` + ternary | 338 | **0** |
| `const _x = __exactNetOwner` | **322** | 16 |
| `const _x = globalThis.__exactNetOwner` | **322** | **16** |

Zero route-evidence differences across all 1086 `node.net` fixtures; confirmed
cross-module on dgram.js. The `globalThis.` form is the one to take: a property
read yields `undefined` rather than throwing, and **no alias is ever compared
against `null`/`undefined` at any of its 11 use sites**, so it is
behavior-identical. That dissolves register item 7's ReferenceError objection and
removes the dependency on open question 2.

**Four source lines, 46 cells.** The analyzer alternative was costed at ~220-260
lines, seven consumers whose conservative over-approximation must each be
re-proved, a `var`-dominance dataflow proof with no CFG, and a route-evidence
schema extension touching 6 modules, 4 test files, a Rust assertion and the §3
gate — for the identical 46 cells.

**But normalization alone is not correct.** It makes the walker credit
`globalThis.__exactNetOwner` as an authenticated native terminal, which §3.4
just showed the runtime does not guarantee. The two must land together:

- **4 JS lines** — normalize the aliases → 46 cells
- **3 C++ lines** — install both hooks `writable:false, configurable:false`
  → makes the credited terminal actually authentic

Neither half is correct alone. `zlib.js:285` is the only bare `= __exact*` alias
in `src/builtins/` — the shape already exists in-tree, in the one file register
item 7 never mentions. `_wsGlobal` (http.js:9856) is a fifth alias-shaped site
the plan does not count.

### 3.5 projection: 32 → 1

`dns-promises.js` is a pure re-export, but the re-export ends at the **object**;
the 32 members are built inside `dns.js`. Only one is an alias of a `dns.*`
export (`getServers`, dns.js:1193). The rest: 1 overwritten alias, 5 inline
promise wrappers, 11 promisify-factory products, 14 computed dispatches through
`Resolver.prototype[method].apply`. `dns.promises.resolve4` — **the plan's own
worked example** — is a promisify wrapper whose route is not `dns.resolve4`'s.

The laundering witness is in-tree: `promises.Resolver` is `PromiseResolver`, not
`Resolver`, so a name-keyed join would produce the right terminals *by luck*
while attributing a path naming a function the export isn't.

Note the tension with §2: the denominator audit finds projection **32/32 CAP** —
these are real capability surfaces. Both hold. The cells are genuine; the
*mechanism label* was a placeholder masking five shapes, so the analyzer work
was mis-specified even though the cells are in scope.

### 3.6 duplicate-definition: 0 cells, and resolving ambiguity can add ambiguity

Landed and verified: 23597 recipes indexed, **0 terminal and 0 path changes
anywhere**, 325/338 cells byte-identical. The 13 ambiguity entries retire as
predicted, but the one "pure" cell does **not** clear — its surviving callee is
`function() { return this; }`, a body with zero call expressions, so it still
records no terminal. It moved `duplicate-definition` → `empty-no-mechanism`
(33→34).

**The hazard worth keeping:** the walker's duplicate branch early-returns without
walking the callee body, so removing the duplicate makes it descend and surface
dynamism the duplicate was **masking** — 5 new entries on 3 `Agent` cells. Net
is **−8 distinct entries, not −13**. A one-directional acceptance gate would have
booked this as a clean win.

Open question 7 is answered, with a cause: `git show 9e9418d2^` shows the
fallback block is the **newer** code (2026-03-13). The `if (!…pause)` guard *was*
load-bearing before that commit — the only `pause` source in a stream-less
profile — and 9e9418d2 superseded it without removing it. A defensive remnant,
not a guard for an unmodelled profile.

### 3.7 empty-no-mechanism: not a defect, and confirmed three ways

The walker resolved all 33 routes completely (`routesLen=1`, `definitions=1`).
The bodies are pure in-memory accessors, throwing stubs, and field-initialising
constructors. They reach no gate because they have no capability to reach one
with. Three independent investigations converged on CAP=0 for this bucket, from
three different directions — a direct AST audit, the qualified-member trace
(which found three of the 33 as parent slots it was following), and the
denominator audit.

## 4. Findings outside LLP 0045's scope

**A severe pre-existing regression on `main`.** `authorize_reachable_operations`
(src/module_loader/graph.rs) demanded a graph target for every builtin CommonJS
edge **without the bootstrap-internal skip its two sibling functions already
apply**. `fs.js` names `internal/fs/utils`, and `assert → fs` puts that in the
closure of nearly everything, so `ERR_MODULE_LINK: has no authenticated target`
broke **the entire CommonJS builtin surface** — `path` was the only module that
loaded. Fixed (the fix restores a skip; no authority is widened). Ticket closed:
`issues/closed/20260801-builtin-commonjs-require-activation-refused.md`.

**A new P1**, surfaced by that fix: `require('buffer')`/`os`/`string_decoder`
pass activation but fail evaluation with `Cannot assign to read-only property
'toString'` — lockdown's `enableOverride` repair covers only the error
intrinsics. `issues/closed/20260801-lockdown-tostring-override-blocks-builtins.md`.

**A test-infrastructure gotcha:** `node_net_builtins` and the
`host-http-server` suites both bind loopback ports and **cannot run in
parallel** — a false 4/4 failure that reads as a regression.

**A measured instance of the walker's spelling-based analysis.** Intrinsic
bindings are keyed by identifier *text* across the whole module
(capsec-surface-inventory.mjs:4354-4370), so `var value = String(…)` in one
function silently suppresses `value.join(sep)` in an unrelated one 1900 lines
away. Ten cells depend on it; the conclusions happen to be correct, guarded by
`Array.isArray`, but the reasoning is not. This is LLP 0045 step 0's
"spelling-based, not binding-aware" claim, now measured on a concrete site.

## 5. Recorded disagreement

One investigation reported that 16 of the 33 `empty-no-mechanism` cells are
unwalked-callback routes rather than mis-seeded. Two others contradict it, and
the contradicting evidence is stronger: a direct Babel parse of all 33 bodies
measured `nestedFns=0, callsInNested=0`, and the signal came from a probe its own
author described as crude ("adds every Identifier argument"), which would
generate exactly that noise. **Resolved against the callback hypothesis**, but
recorded because the resolution is by weight of evidence, not proof.

## 6. What replaces LLP 0045 — and why not yet

**Do not author the successor plan against the 338.** The denominator moves by
29–62% the moment the seeding defects are fixed, and planning against a number
about to move is the error that produced LLP 0045. The sequence is:

1. **Fix the seeding** (`builtinExportClassification`): member carve-outs before
   the class prefixes, a new `unsupported-throwing-stub` disposition for the 9
   refusals, and the `node_http2` effect assertion withdrawn. Prefer exact-string
   member sets over widened regexes — a widened regex silently absorbs future
   members, which is how this arose. This is a **prerequisite, not a parallel
   cleanup**: certifying `TLSSocket.alpnProtocol` as `network:connect|listen`
   would certify a claim that is false about the source.
2. **Decide the origin policy** (112 cells): is touching a socket-derived message
   network-attributed by origin? That single decision moves the scope between 127
   and 239. It is the author's call and it is the highest-leverage question in
   the program.
3. **De-duplicate the 42 alias cells.**
4. **Re-measure**, then plan — organized by **analyzer capability**, not by
   ambiguity-string bucket.

Two items need not wait, because they are measured, cheap, and independent:

- **Normalize the four aliases + harden the hook install** — 4 JS lines + 3 C++
  lines, 46 cells, with the provenance claim made sound by the pairing.
- **Callback-argument attribution** — 11 cells and genuine hardening, and it must
  land *before* any timer admission, which is negative-valued without it.

And one item belongs to whoever owns conformance evidence generally, not to this
program: **`net.Socket.connect` records the wrong terminal.** Cells outside Lane
B may carry confident misattributions, and nothing currently measures that class.

## 7. What survives from LLP 0045

- **The problem statement.** Network cells genuinely cannot be certified by probe
  authoring alone; LLP 0044 §9's measurement stands.
- **§3's acceptance discipline**, which earned its keep: the paired allow-list
  caught an ambiguity *increase* hidden inside an ambiguity-removing change. It
  is now executable as `scripts/llp0045-route-evidence-diff.mjs` with 14 tests,
  including the case where a residual reason vanishes with no matching route
  change.
- **The mechanism-matrix generator**, which is why the figures above could be
  recomputed at all.
- **The TLS-bypass hazard** (http.js:5854 → `this.createConnection` →
  https.js:97 → `tls.connect`) — real, CAP, and now joined by the analyzer-side
  `TLSSocket.addListener` shadow in §3.2.

## 8. Process finding

Five rounds of dual-model review converged to dual-READY on LLP 0045. Neither of
the two errors that collapsed it survived first contact with **running the
walker** and **reading the C++**. The loop was optimizing internal consistency;
the empirical foundations were never checked.

The plan had also already learned the exact lesson that would have caught this.
Its round-3 revision retraced `bare-callee-miss` to the duplicate-definition
marker and recorded: *name a mechanism from the code that emits it, never from
the label's shape.* §1's projection row was never re-derived that way. **The
corpus contained its own refutation.**

Recommendation: a "converged" verdict on a document whose load-bearing claims are
empirical should not be reported without a pass that executes them. Cheap here —
the full catalog regen is ~11 seconds.
