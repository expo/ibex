# LLP 0016: The Capability-Security Architecture — Review and Assessment

**Type:** Research
**Status:** Draft
**Systems:** Engine, Host ABI, Module Loader, Runtime, Build
**Author:** Charlie Cheever / Claude (Fable)
**Date:** 2026-07-05
**Revised:** 2026-07-09 (marked W4(a)/R4 enforce-without-lockdown warning as implemented; W4(b)/R3 advisory-enforce startup behavior remains implemented in code and CI)
**Related:** LLP 0013 (the compartments RFC this reviews); LLP 0014 (grant
authoring); LLP 0006 (design principles); LLP 0002 (host ABI); LLP 0004
(module loading); LLP 0012 (runtime identity)

> **Reassessment (2026-07-11):** LLP 0021 resolves the assessment's
> permissive-default, optional-lockdown, advisory-attribution, string-policy,
> and durable-audit findings for the advertised `aarch64-apple-darwin`
> profile. Production now arms an immutable typed snapshot and refuses other
> targets or incomplete prerequisites. Historical findings below remain useful
> provenance, but their old flags and downgrade procedures are not current
> operator guidance.

## Summary and verdict

This document is an architectural review of Ibex's capability-security
system ("capsec") — the layered design built by LLP 0013 (hardened
compartments, frame attribution, policy enforcement) and LLP 0014
(import-site grants, the generated policy artifact) on top of the
instance-isolation substrate the runtime always had. It explains the system
as a whole, positions it against prior art, evaluates the tradeoffs it
chose, names the weak points and differentiated strengths, and ends with
recommendations.

The verdict, stated up front `[assessment]`:

**The design is sound, honest, and genuinely differentiated; the evidence is
younger than the mechanism.** The two foundational bets — compartments in a
single realm rather than realm/isolate boundaries, and a generated,
declared, drift-checked policy rather than a hand-written or usage-inferred
one — are the right bets, and no shipping JavaScript runtime offers what
this system offers on paper: per-package, default-deny capability
enforcement with engine-derived attribution at a native host boundary.
The threat-model honesty (supply-chain integrity, not sandbox) is unusually
disciplined and should be defended as a feature.

The system's soundness rests on three load-bearing properties: unforgeable
attribution (including across async boundaries), a closed global inventory,
and a frozen shared surface. Of these, **async attribution is the most
fragile by construction** — it has been secured channel-by-channel (Promise
queue, timer queues, host-callback re-entry) rather than by a structural
chokepoint, and every future deferred-execution surface re-opens the
question. The **frozen shared surface is compat-gated and currently
opt-in** even under enforce mode. And the **ecosystem-compatibility
evidence** that would justify enforce-by-default — the Phase 1 compat
corpus on real Exact/Snapback graphs — has not yet run. The largest risks
are therefore operational, not conceptual: fork upkeep, compat breakage,
configuration states that look stronger than they are, and human
rubber-stamping in the policy-review loop.

Recommendation in one line: **stop expanding mechanism; start consolidating
structure and gathering evidence.** Details in §Recommendations.

## Scope and method

Reviewed: the full LLP corpus (0000–0015), the LLP 0013/0014 review
artifacts under `llp/reviews/`, the carried Hermes patch stack
(`patches/hermes/0001–0008` + README), and targeted reads of the host,
loader, CLI-runtime, and worklet sources to confirm current defaults. This
is a review of the **architecture and the system-design choices**. It is
explicitly *not* an implementation vulnerability hunt — three adversarial
implementation reviews have already run and their fixes are recorded in
LLP 0013's revision log; re-litigating that layer here would duplicate
them.

Provenance discipline, extending LLP 0000's: `[observed]` claims are
verified against this tree or its LLP corpus; `[inferred: external]` claims
about other systems come from general knowledge, not fetched sources;
`[assessment]` marks the author's judgment — the substance of this
document — and should be argued with, not cited as fact.

## The system in one pass

Ibex is the Hermes-based JS/TS runtime under Exact and Snapback. Its
security posture matters more than a typical runtime's because its
consumers run **code the app author did not write**: third-party Exact
experiences, npm dependency graphs, and — increasingly — agent-generated
code (LLP 0013 §Motivation). The architecture answers with concentric
layers, each with a stated job:

```
OS permission layer (prompts, entitlements)        — embedder + OS
  └─ Process / runtime-instance isolation           — trust domains
       └─ Per-package compartments in one instance  — supply-chain containment
            └─ Object-capability discipline          — delegation between packages
```

### Layer 1: instances for trust domains

Genuinely hostile code gets its own runtime instance with its own
`HostConfig`; policy lives in Rust behind the C ABI, outside the JS
reachability graph (`src/host/capability.rs`; LLP 0002) `[observed]`. The
recent **restricted worklet runtime** is this layer at its purest: a second
Hermes instance created bare — no module loader, no network, no timers, a
fully enumerated global surface of five or so functions, and an async-only
escape hatch to the app runtime (`src/engine/hermes_runtime_worklet.cc`)
`[observed]`. Subtractive construction ("never installed") rather than
additive restriction is the strongest isolation primitive in the codebase,
and it is cheap here because the embedding ABI is narrow (LLP 0002).

### Layer 2: compartments for the dependency graph

Inside an instance, LLP 0013 makes the **package** the unit of enforcement,
via three mechanisms `[observed]` (LLP 0013 §Design):

1. **Lockdown** — freeze the shared intrinsics graph after bootstrap
   repairs; tame the intrinsic evaluators (`Function`, generator/async
   constructors, indirect `eval`). Two implementations: the vendored SES
   walk, and a native transitive deep-freeze (`__exactDeepFreeze`,
   patch 0006).
2. **Per-package compartment globals** — each package resolves bare globals
   and `globalThis` against a private global holding exactly its policy's
   endowments; intrinsics stay shared (and frozen) so cross-package object
   flow, classes, and `instanceof` keep working. Two implementations of one
   semantics: a build-time free-global rewrite in the owned bundler
   pipeline (LLP 0007), and engine-native per-`Domain` global resolution
   (patch 0004), which also closes the sloppy-`this` UMD escape and binds
   `eval`/`Function`-produced code to the caller's compartment
   (patch 0006).
3. **Frame-derived attribution** — host-boundary checks identify the caller
   from the executing bytecode frame (`CodeBlock → RuntimeModule/Domain →
   package principal`), which JS cannot forge. Trusted runtime deputies
   carry a reserved principal (`0xFFFFFFFF`) the walk skips; a stack with
   no user frame yields a sentinel (`0xFFFFFFFE`) that **fails closed**;
   schedule-time principal capture covers the Promise queue (patch 0008)
   and the embedder-owned timer/microtask queues (ENG-22759/22761).

### The policy plane

Policy governs three surfaces (LLP 0013 §Policy): host capabilities (a
canonical manifest of 56 capability bits in a u64), endowed globals, and
the import graph (builtins + package edges, gated in the loader before the
module cache). Modes are permissive / audit / enforce; under enforce the
first-party root principal and the module loader are trusted (unless the
policy declares a dynamic-permissions ceiling), so the gates bite
*dependencies* — which is the threat model. Enforce and audit auto-enable
per-package bundle chunking so a bundled dependency actually gets its own
principal (`enable_isolation_prerequisites`, `src/bin/ibex/runtime.rs`)
`[observed]`; lockdown remains opt-in (`--lockdown`) because intrinsics
freezing is the top compat risk (LLP 0013 Risks §1) `[observed]`.

### The authoring plane (LLP 0014)

The app's policy file is **generated, never hand-maintained**: root-principal
code declares grants at its import sites using standard import-attribute
grammar —

```js
import img from "image-lib" with { grants: "fs:read:/app/images" };
```

— and a build-time static analysis compiles those declarations, the
request/delegation cascade (`ibex` manifests in packages are *requests*;
`effective(dep via pkg) = delegates(pkg → dep) ∩ effective(pkg)`; union
across importers), and each package's *observed* builtin imports into a
reproducible artifact with per-entry provenance, committed like a lockfile
and drift-checked in CI, with capability **expansions** reported as the
review tripwire `[observed]` (LLP 0014). Grant syntax inside `node_modules`
is inert — stripped and reported as a supply-chain signal. Grants are
declared, not inferred from usage, so a hijacked release needing new
ambient authority fails closed until the app author edits their own import
site.

### Delegation and the dynamic layer

Passed **authority-bearing handles** are the primary delegation mechanism:
an endowed attenuator carries its grant fixed at creation; handle-mediated
host operations check *possession*, not calling-frame identity; handles
re-attenuate (`.scoped()`) and revoke with a cascade through everything
derived from them `[observed]` (LLP 0013 §Delegation; `src/host/handles.rs`).
The ambient cascade is the coarse fallback for packages whose APIs don't
take handles. User-facing dynamic permissions sit above: tri-state grant
status, async acquisition in the attenuator with a synchronous boundary
check, the static artifact as the **ceiling** that prompts can never
exceed, and revocation cascading into live handles.

### The fork discipline

The engine work is carried as a pin plus an ordered eight-patch series with
a patch-shape taxonomy (additive files / insertion points / surgical
semantic changes, the last budgeted at single-digit sites — currently five)
`[observed]` (LLP 0013 §Upstream tracking; `patches/hermes/README.md`).
Canary CI applies the stack to newer upstream; the stated recovery from a
major upstream refactor is **re-derivation from the spec and conformance
suite, not archaeology**. Unpatched engines still build: a probe
(`build.rs:1081`) falls back to the legacy thread-local attribution
`[observed]` — a compatibility affordance with a security implication
addressed in §Weak points.

## Prior art and positioning

The design descends from a well-documented lineage and is candid about it.
What follows places Ibex in that lineage and against its live alternatives
`[inferred: external]` throughout, `[assessment]` where judged.

### The family tree

The object-capability tradition (Dennis & Van Horn; KeyKOS/EROS/seL4 at the
OS layer; E and its descendants at the language layer; CHERI in hardware)
contributes the core discipline: authority as reachable references, no
ambient authority, attenuation and revocation as first-class moves. Google
Caja brought it to JavaScript and lost to maintenance economics; its
successor — Agoric's SES / Endo / "Hardened JavaScript," with `lockdown()`
and `Compartment` — is the direct ancestor of Mechanisms 1–2 and runs in
production today (Agoric's chain; MetaMask Snaps executes third-party code
in SES compartments). MetaMask's **LavaMoat** is the closest production
analog to the whole system: per-package SES compartments wired by bundler
plugins, plus a generated per-package policy over globals, builtins, and
packages.

The identity/ACL tradition contributes the cautionary tales: Java's
SecurityManager (stack-inspection permissions, `doPrivileged`, hand-written
policy files nobody maintained — deprecated by JEP 411 after two decades),
browser CSP header rot, and Node's removed per-module policy mechanism.
LLP 0013/0014 cite all three as negative constraints, and the design
visibly routes around each: stack intersection is opt-in per capability
class rather than the default; delegation rides possession-checked handles
rather than stack walks; the policy file is generated with co-location and
GC rather than hand-authored.

### Against the live alternatives

| System | Granularity | Enforcement point | Attribution | Policy authoring | Delegation | Ecosystem posture |
|---|---|---|---|---|---|---|
| **Ibex capsec** | package (name@version principals) | engine + native host boundary | frame-derived + schedule-time capture | generated from declared import-site grants; drift-checked | attenuated revocable handles; request cascade | npm-compatible; shared frozen intrinsics |
| SES / Endo | compartment | userland reachability | none (pure ocap) | manual endowments | passed references | strict-mode subset of JS |
| LavaMoat | package | userland reachability | none | **inferred** from usage (`lavamoat generate`) + overrides | passed references | npm-compatible + repairs corpus |
| Moddable XS | compartment | engine (native SES) | n/a (mostly single-tenant) | manifest | references | embedded JS subset |
| Node.js | **process** | host (syscall layer) | none below process | CLI flags | none | full |
| Deno | **process** | host | none below process | flags + runtime prompts | none | full |
| Bun | none | — | — | — | — | full |
| Cloudflare Workers | isolate/tenant | V8 isolate + bindings | per-isolate | bindings config | bindings-as-endowments | Workers subset |
| Java SecurityManager | protection domain | VM stack inspection | stack walk (default) | hand-written files | `doPrivileged` | full (deprecated, JEP 411) |
| WASI / components | component | import-only linkage | n/a (no ambient) | world/wit declarations | explicit imports | clean slate; no npm |

Three contrasts carry most of the information `[assessment]`:

- **Versus Node/Deno permissions:** those are *instance*-granularity — one
  grant set for the whole process, so a malicious transitive dependency is
  indistinguishable from the app. That is precisely the layer Ibex already
  had (instance isolation, `HostConfig`) before LLP 0013. The entire point
  of this system is the layer below, which neither Node nor Deno attempts.
- **Versus LavaMoat:** the two deep differences are (a) **enforcement
  depth** — LavaMoat's containment is userland reachability only; there is
  no native boundary at which a forged or laundered access could be caught,
  and no attribution for audit. Ibex adds engine-truth attribution and a
  default-deny native host boundary behind the reachability layer. And (b)
  **policy direction** — `lavamoat generate` infers policy from what
  package code *does*, so a malicious update's new behavior gets
  rubber-stamped into the regenerated policy unless a human reads the
  diff; Ibex's grants are *declared* by root code and fail closed, with
  inference deliberately confined to the request side and the (mitigated,
  tripwired) builtins axis (LLP 0014 §Declared, not inferred). Ibex is,
  fairly stated, LavaMoat's design with the two pieces LavaMoat cannot
  build without owning an engine and a runtime — plus a better authoring
  story.
- **Versus the realm/isolate school** (ShadowRealm, isolated-vm, Workers;
  and the failures: vm2's escape history, Figma's abandonment of same-realm
  plugin sandboxing for an interpreter-in-interpreter): realm boundaries
  are the right tool for *trust domains* and the wrong tool for a
  *dependency graph*, because the isolation boundary is exactly the thing
  that breaks shared live objects, classes, and `instanceof` across
  packages. Ibex agrees, keeps realms at layer 1 (instances, worklets), and
  uses same-realm compartments at layer 2. vm2's history is the strongest
  external evidence for LLP 0013's refusal to build enforcement out of
  userland membranes over shared mutable intrinsics.

WASI/components deserve one more sentence: they are the clean-slate
endpoint of this design space — no ambient authority at all, capabilities
as typed imports — and they achieve it by giving up the npm ecosystem
entirely. Ibex's bet is the exact complement: preserve npm object flow and
retrofit containment. Both are coherent; they serve different code.

One terminology hazard worth recording: SpiderMonkey "compartments" (heap
partitions with cross-compartment wrappers) and Java's "capability"-flavored
vocabulary both collide with the Hardened-JS senses used here. This corpus
uses the Hardened-JS senses exclusively.

### What is genuinely novel here

`[assessment]` Three things, in descending order of novelty:

1. **Import-site grants compiled to a provenance-carrying artifact.**
   Repurposing standard import-attribute grammar as the grant-authoring
   surface — with union-across-sites semantics, entry-scoped analysis,
   co-location GC (delete the import, the grant disappears), inert-in-
   package-code hygiene, and expansion-tripwired CI drift-checking — has no
   direct precedent I know of. It attacks the *economics* of policy
   maintenance, which is the layer where SecurityManager, CSP, and Node
   policies actually died.
2. **Frame-derived package attribution feeding a native default-deny host
   boundary.** Engines have per-realm security (browser chrome/content);
   runtimes have process permissions; nobody ships bytecode-provenance
   package identity at a host ABI. The deputy-transparency rule (reserved
   runtime principal) and the fail-closed no-user-frame sentinel are the
   non-obvious parts that make it usable.
3. **Version-distinguished principals under name-keyed policy** — selector
   vs locator, separate compartments/chunks per `name@version` — is a small
   design but resolves an ambiguity most prior art leaves unstated.

## The bets and their tradeoffs

Each major decision, with what it buys, what it costs, and a judgment.
All `[assessment]` except where cited.

**B1 — Package granularity** (not module, not process). Buys: matches the
attacker's unit (the published package), matches how humans author policy,
cuts compartment count ~10× vs per-module. Costs: intra-package
compromise is invisible (one poisoned file in a large package inherits the
package's whole grant set); vendored/inlined code dissolves into its host
package. Verdict: right default; the escape hatch (LLP 0013 Open Q4) is
correctly parked until a concrete case appears.

**B2 — Compartments in one realm, not realms/isolates.** Buys: npm
semantics survive — live objects, classes, `instanceof` flow across
packages; adoption cost stays plausible. Costs: the shared surface must be
*perfectly* frozen for the model to hold, which makes lockdown completeness
load-bearing and drags in the compat risk (B9); CJS export objects remain a
shared mutable channel (accepted residual, Open Q9). Verdict: correct, and
the strongest-evidenced choice in the design — the alternative has failed
publicly and repeatedly (vm2; Figma; ShadowRealm's callable-only boundary).

**B3 — Hybrid authority model: reachability × identity × possession.**
This is the deepest and least-conventional choice. Pure ocap says identity
is irrelevant — authority is what you can reach. Pure ACL says authority is
who you are. Ibex runs three planes at once: endowments govern what a
package can *reach*; frame-keyed checks govern what its *frames* may do
ambient-ly; possession-checked handles govern what it was *handed*. Buys:
ambient-authority npm code runs (it expects `require('fs')` to work);
attribution produces an audit trail pure ocap cannot; handles keep
delegation expressive where identity checks would strangle it (the
SecurityManager failure mode, explicitly dodged — LLP 0013 §Delegation).
Costs: two authority semantics to reason about; and the identity plane
resurrects the confused-deputy problem that pure ocap defines away — which
is exactly where the post-landing hardening history concentrated (detached
deputies, async laundering, patches 0007/0008, ENG-22759). Verdict: the
hybrid is justified by the ecosystem constraint, but it must be understood
as buying compatibility and auditability *at the price of a permanent
deputy-boundary maintenance obligation*. §Weak points returns to this.

**B4 — Engine-native via a carried patch stack** (vs userland-only, vs
upstream-first). Buys: attribution becomes engine truth rather than
transform artifact; sloppy-`this` and `eval` close natively; unbundled and
dynamically-loaded code is covered without a rewrite; measured steady-state
overhead ≈0% behind a hot-path guard `[observed]`
(`benches/compartment_overhead.rs`; LLP 0013 Goals §3). Costs: a fork is a
standing tax and a bus-factor risk; Static Hermes may reshape the
interpreter under it; held pins lag upstream security fixes. The
discipline — class taxonomy with a Class C budget of single digits
(currently five sites), canary CI, spec-plus-suite as the re-derivation
asset — is the best available shape for this liability, modeled on
Electron's at small scale. Verdict: justified *because* the patch stack is
small and the fallback (drop Class C, keep A/B, retreat to the userland
implementation) is real; the discipline must be treated as normative, not
aspirational.

**B5 — Declared, generated, drift-checked policy** (vs inferred, vs
hand-written). Buys: fail-closed under malicious updates; provenance per
entry; co-location GC; the reviewable diff lands in the PR that motivated
it. Costs: authoring friction at adoption (the first artifact is a wall of
grants); and the builtins axis *is* observed rather than declared — a
deliberate purity crack, mitigated by the fact that loading a builtin is
not exercising a capability and by expansion tripwires `[observed]`
(LLP 0014 §Declared, not inferred). Verdict: the strongest part of the
system. The residual risk is human: tripwires only work if expansions are
actually reviewed (see R5).

**B6 — Union-monotone grant composition.** Buys: import sites compose
without coordination; adding a site never breaks another. Costs: one
generous site grants the package for *all* its callers — per-edge precision
exists only on the handle channel; `also:` exceptions are app-wide ambient
authority whose edge-association is provenance, not enforcement (the spec
says so honestly — LLP 0014 §Honesty requirement). Verdict: the only
coherent semantics given one-compartment-per-package; the honesty rule must
follow the feature into user-facing docs.

**B7 — Trust the root principal under enforce.** Buys: enforce mode is
runnable without the app self-granting; matches the threat model (the gate
is for dependencies). Costs: everything that *launders into* root
attribution becomes ungated — which is why the no-user-frame sentinel, the
internal-bytecode runtime-principal stamp, and the schedule-time captures
had to exist. Verdict: right call, but it converts async-attribution
soundness from "nice property" into the load-bearing wall of enforce mode.

**B8 — Fail-closed posture at ambiguity.** Malformed committed policy fails
the run rather than degrading to permissive; no-user-frame fails closed;
`IBEX_ENDOW` is dropped under enforce/audit rather than merged; computed
import specifiers get a quarantine principal `[observed]`. Verdict:
consistently right, and consistently applied — this is the posture that
distinguishes a security system from a linter.

**B9 — Honest claims: "supply-chain integrity," not "sandbox."** The threat
model is normative for marketing; deputy-by-design, deliberate authority
passing, exports pollution, engine bugs, and side channels are documented
residuals; claim ceilings are stated per phase `[observed]` (LLP 0013
§Threat model, §Plan). Verdict: rare and valuable. The system's credibility
budget lives here; spend it nowhere.

## Weak points and biggest risks

Ranked by expected damage `[assessment]` throughout.

**W1 — The compat bet is unproven where it counts.** Lockdown + strict-mode
emission + tamed evaluators against the long tail of npm is the RFC's own
top risk, with kill criteria — and the Phase 1 compat corpus on real
Exact/Snapback graphs has not yet run. Everything user-visible (when
enforce can default on, whether lockdown can converge with enforce, how big
the repairs corpus gets) is downstream of this measurement. LavaMoat's
years of repairs work suggest the tail is real. Until the corpus runs, the
system is validated against red-team fixtures, not against the ecosystem
it must contain.

**W2 — Async attribution is secured per-channel, not structurally.** The
history is the argument: the Promise-queue capture (patch 0008), the
host-timer-queue capture (ENG-22759), the native-callback principal stamps
(ENG-22761), each closing the same *shape* of hole — a deputy detached
across a deferral boundary loses its scheduler's identity — on a different
queue. The invariant "every deferred-execution channel captures the
scheduling principal" is currently enforced by reviewer memory. Two new
deferral surfaces already exist (`__hostCallAsync` completions; the worklet
`scheduleOnAppRuntime` channel), and nothing structural forces them through
a capturing chokepoint. This is the most likely source of the next
enforcement hole, and it is fixable architecturally (R2).

**W3 — TCB breadth, especially the trusted-deputy JS layer.** The
enforcement story points at the Rust host, but the trusted computing base
is wider: the patched engine, the C++ bridge, the bootstrap/module-loader
JS, every builtin running under the runtime principal, and — for enforce
claims — the build-time generator and bundler that author the policy and
the chunks. The deputy JS layer is the soft spot: it processes
attacker-influenced arguments while being transparent to attribution, so a
logic bug there converts to authority without any forgery. Lockdown
protects deputies from prototype pollution — but lockdown is opt-in (W4).
The mitigation direction (validate at native choke points; keep deputy JS
thin) is already the codebase's instinct; it should become stated policy
(R6).

**W4 — Configuration states that look stronger than they are.** Two today:
(a) *enforce without lockdown* — the default — leaves shared intrinsics
mutable. Frame attribution means a prototype patch cannot *impersonate*
anyone (the patch body's frames are its author's), but it can still
corrupt data flowing through other packages' operations, capture secrets
into closures, and tamper with a granted package's behavior — integrity
attacks the mode's name does not advertise. (b) *enforce on an unpatched
engine* — the build probe silently falls back to thread-local attribution
`[observed]` (`build.rs:1081`), i.e. to the forgeable mechanism the RFC
exists to replace, with no runtime signal that the guarantee degraded.
Frame accuracy is demonstrated on macOS; the other platforms inherit
whatever their framework build contains. A mode named "enforce" should
either mean one thing or say loudly which thing it currently means (R3).

**Implementation note (2026-07-07; revised 2026-07-09):** W4(b)'s startup behavior has landed:
Enforce now fails closed when hard attribution prerequisites are missing unless
the operator passes `--capsec-allow-advisory`; Audit emits the same readiness
report without blocking. W4(a)'s interim disclosure has also landed: enforce
without lockdown now warns that shared intrinsics remain mutable and
intrinsic-integrity attacks between packages are not defended. The remaining
lockdown-convergence question is separate.

**W5 — Fork sustainability under upstream drift.** Static Hermes is the
named unknown; the re-derivation posture is the right hedge but has never
been exercised, and the pin-bump runbook has not yet run against two real
upstream releases (an explicit acceptance criterion still open). A held pin
also means upstream security fixes arrive on Ibex's schedule, not the
CVE's. None of this is mismanaged — it is simply the part of the system
whose cost curve is set by someone else (R9).

**W6 — Human factors in the policy loop.** Expansion tripwires assume
someone reads the diff; `also:` exceptions can accrete into exactly the
hodgepodge the design exists to prevent; union semantics mean the least
careful import site sets the package's grant. The design gives reviewers
the right artifacts; it cannot make them look. Cheap structural help
exists: class-sensitive approval gates on dangerous expansions
(`process:spawn`, `fs:write`, `env:read:*`, `network:*`) are LLP 0014
Open Q2 and should stop being open (R5).

**W7 — Accepted residuals worth re-stating, so acceptance stays a
decision rather than a habit.** (a) *Exports pollution* (Open Q9): with
intrinsics frozen, shared mutable CJS export objects are the remaining
cross-package mutation channel; the import fence narrows who can reach a
given module's exports, but popular utility packages are reachable from
everywhere. The freeze-on-load experiment should ride the compat corpus
(R7). (b) *Self-reported version in the principal locator*: documented as
not a trust boundary `[observed]` (LLP 0013 Resolved Q1) — but note the
interaction with version pins: a policy that narrows `pkg@1.2.3` while
leaving the bare `pkg` entry broader can be escaped by a forged version
string. Lockfile integrity hashes as locators close this (R8).
(c) *Install-time scripts*: npm lifecycle scripts run before any Ibex
policy exists and are simply outside this system's reach; no corpus
document currently says so out loud. One paragraph in the threat model
would prevent a category error by future readers (R10). (d) The
path-normalization check-vs-syscall TOCTOU note stands as recorded
`[observed]` (LLP 0013 §Implementation status).

## Differentiated strengths

`[assessment]` throughout, with the evidence noted.

**S1 — Position: the only runtime attempting this layer.** Process-level
permission models (Node, Deno) cannot see packages; userland compartment
systems (LavaMoat) cannot see the host boundary or produce unforgeable
attribution; engine-native SES (XS) serves single-tenant embedded targets.
Owning the engine pin, the bundler, the loader, and the host
simultaneously is the structural asset none of those projects has, and
this design is what that asset is *for*. If the compat bet lands, Exact
and Snapback get a real product property: third-party and agent-written
code with an enforced, reviewable, per-package authority envelope.

**S2 — The authoring economics.** The generated artifact — provenance per
entry, expansions as tripwires, co-location GC, entry scoping keeping test
grants out of production policy — is the first policy surface in this
lineage designed around the observation that *maintenance economics, not
mechanism, is where these systems die*. It is the part of the design most
worth publicizing and the part most likely to be imitated.

**S3 — Honesty as architecture.** Claim ceilings per phase; a threat model
normative for marketing; `[observed]`/`[inferred]` provenance discipline in
the corpus; adversarial reviews checked into the repo; fixes that
downgrade claims when they must. This is institutional strength — it makes
the system's statements cheap to trust and its regressions loud.

**S4 — The delegation model.** Authority-bearing revocable handles with
re-attenuation, possession-checked at the boundary, with the cascade for
ambient fallback and stack-intersection strictly opt-in — this threads the
needle between SecurityManager's identity-check-everything (which killed
delegation) and pure ocap's no-ambient-anything (which npm cannot run).
The revocation cascade and ceiling principle unify static policy, dynamic
prompts, and handles under one monotone rule: *the artifact is the
ceiling; everything dynamic moves the floor.*

**S5 — Fail-closed reflexes and the conformance suite as the durable
asset.** The red-team suite (impersonation, laundering, detached deputies,
symlink escapes, chunked and unbundled variants, permissive controls) is
what makes the fork re-derivable and the claims falsifiable. The
spec-is-the-asset stance is the correct insurance policy for a small team
carrying an engine patch stack.

**S6 — Right-sized layering.** Instances for hostility, compartments for
supply chain, OS intersection above, and the worklet runtime demonstrating
that when a surface *can* be subtractive, the codebase builds it
subtractive. No layer is asked to do another layer's job, and the
documents say which questions each layer answers.

## Overall assessment

`[assessment]` The architecture is very good — coherent top to bottom,
honest about what it is, and differentiated in ways that matter to its
actual consumers. Against the design's own stated goals (LLP 0013 §Goals)
the mechanism work is essentially complete and demonstrated on macOS; what
separates it from "the security story Exact/Snapback can lean on in
public" is not design but evidence and consolidation:

- **Design maturity: high.** The bets are right, the residuals are
  documented decisions, negative precedents were actually metabolized
  (SecurityManager, vm2, CSP rot, LavaMoat's inference) rather than cited
  as decoration.
- **Mechanism maturity: high, with one structural debt** — per-channel
  async capture (W2) — and one advertised-vs-actual gap in mode semantics
  (W4).
- **Evidence maturity: low.** Compat corpus unrun; perf/memory sweep on
  real apps pending; runbook unexercised; single-platform demonstration of
  frame accuracy.
- **The gravest failure mode is not a breach; it is erosion** — the RFC
  itself names it: compat pain and fork drag pushing the system into
  permanently-permissive machinery that *documents* containment rather
  than providing it. The revisit-trigger discipline (Open Q8) is the right
  antidote and should be armed with a real metric now.

What would change this assessment: a compat-corpus failure rate that
forces per-package repairs at LavaMoat-or-worse scale (would demote
lockdown to a niche mode and cap the system at attribution + import
fencing + host gates — still valuable, but a different product claim); a
second family of deputy-laundering holes appearing *after* a scheduling
chokepoint lands (would indicate the hybrid model's deputy boundary is
deeper than an engineering obligation); or two consecutive pin bumps
blowing the budget (would trigger the documented Class C retreat).

## Recommendations

Ordered by leverage; R1–R3 are the ones I would fund before any new
mechanism `[assessment]`.

- **R1 — Run the compat corpus now.** Audit-mode runs over the top real
  Exact and Snapback graphs, plus a top-N npm package battery under
  `--lockdown`, publishing repair-rate and would-deny metrics. Every open
  strategic question (enforce defaults, lockdown convergence, freeze-on-
  load, repairs investment) is priced by this number. *(LLP 0013 Phase 1
  exit criteria, unmet.)*
- **R2 — Make deferred-execution capture structural.** One host-side
  scheduling primitive that captures the scheduling principal, through
  which every deferral channel must pass — Promise jobs already covered in
  the VM, timers/nextTick/setImmediate host-side, plus `__hostCallAsync`
  completions and worklet `scheduleOnAppRuntime` from day one — enforced by
  a conformance enumerator that fails when a queue exists without capture,
  and a review rule that new queues use the primitive. Converts W2 from
  recurring vulnerability class to closed design.
- **R3 — Make the mode mean the guarantee.** At startup under
  enforce/audit, emit a security report: attribution source (frame vs
  thread-local), lockdown state, chunking state, policy hash and mode
  provenance. Enforce on an engine without frame attribution should fail
  to start absent an explicit `--capsec-allow-advisory`. Publish a
  per-platform claim-ceiling table (macOS: Phase 2+; others: as built)
  and keep it current. This is the cheapest insurance against the
  overclaiming risk the RFC ranks third. **Status (2026-07-07): implemented
  for readiness fail-closed/advisory reporting and enforced in the
  compartment-conformance CI job with `IBEX_REQUIRE_FRAME_ATTRIBUTION=1`; a
  published per-platform claim-ceiling table remains open.**
- **R4 — Plan the enforce ⇒ lockdown convergence.** If R1's numbers allow,
  enforce should eventually imply lockdown (with per-package repairs); in
  the interim, an enforce-without-lockdown run should say what it does not
  defend (intrinsic-integrity attacks between packages). **Status
  (2026-07-09): implemented for startup/readiness warning; enforce-to-lockdown
  convergence remains open.**
- **R5 — Land class-sensitive expansion gates** (LLP 0014 Open Q2):
  expansions touching `process:spawn`, `fs:write`, `env:read:*`, or
  `network:*` require a distinct approval (CODEOWNERS on the artifact).
  Cheap, and it converts W6's rubber-stamp risk into structured review.
- **R6 — Treat the deputy layer as TCB, in writing.** Inventory every
  module running under the runtime principal; state the rule that
  validation happens at native choke points; add deputy-surface fuzzing to
  CI. A short Principles-type LLP would fix the policy.
- **R7 — Run the exports-freeze experiment** (Open Q9) inside R1's corpus:
  freeze-on-load per package, default off, measure breakage; consider
  default-on for leaf packages if the numbers are clean.
- **R8 — Strengthen the principal locator**: adopt lockfile integrity
  (hash) as the locator component where available, closing the
  forged-version-escapes-a-pin residual and making audit identities
  tamper-evident.
- **R9 — Exercise the fork machinery on schedule, not on need**: run the
  pin-bump runbook against the next two upstream stables (the open
  acceptance criterion), and open the upstreaming conversation for the
  attribution/lockdown primitives while MetaMask's interest gives the
  proposal allies. Every upstreamed piece deletes a carried patch.
- **R10 — Close the documentation seams**: state the install-script
  boundary in the threat model; add a capability-classification step to
  the review checklist for every new host surface (the worklet runtime and
  `__hostCallAsync` are the precedents — both arrived after the manifest
  was authored); and once R1–R3 land, take LLP 0013/0014 through the
  formal review loop toward `Status: Accepted`, since the implementation
  now substantially exists.

## References

- LLP 0013 (RFC: per-package capability compartments — mechanism detail,
  threat model, phase plan, implementation status); LLP 0014 (spec:
  import-site grants, generated artifact); LLP 0006 (principles);
  LLP 0002 (host ABI); LLP 0004 (loader); LLP 0007 (bundler pipeline);
  LLP 0005 (hermetic build).
- Review artifacts: `llp/reviews/0013-per-package-capability-compartments.openai.md`;
  `llp/reviews/0013-per-package-capability-compartments.claude-fable.md`.
- Carried engine patches: `patches/hermes/0001–0008` + `patches/hermes/README.md`.
- External `[inferred]`: Agoric SES/Endo/Hardened JavaScript; MetaMask
  LavaMoat and Snaps; Moddable XS; Google Caja (retired); TC39 ShadowRealm
  and import-attributes proposals; Node.js permission model and removed
  policy mechanism; Deno permissions; Bun; Cloudflare Workers; Java
  SecurityManager / JEP 411; vm2 escape history; Figma plugin-sandbox
  history; WASI preview 2 / component model; KeyKOS/EROS/seL4; E and the
  object-capability literature; CHERI; OpenBSD `pledge`/`unveil`; FreeBSD
  Capsicum; supply-chain tooling (Socket, npm provenance/sigstore, OpenSSF
  Scorecard) as complementary detection layers.
