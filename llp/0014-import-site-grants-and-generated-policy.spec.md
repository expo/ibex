# LLP 0014: Import-Site Capability Grants and the Generated Policy Artifact

**Type:** Spec
**Status:** Draft
**Systems:** Build, Module Loader, Runtime, CLI
**Author:** Charlie Cheever / Claude (Fable)
**Date:** 2026-07-02
**Revised:** 2026-07-18 (the aggregate generated-drift gate validates every
checked policy lockfile so registry digest rotations cannot strand stale review
artifacts); 2026-07-18 (checked portable policy examples pin their authenticated source trees and rendered artifacts to LF across Git checkout platforms); 2026-07-18 (Snapback's 0.2 requirement activates computed imports: the generator joins reviewed manifest declarations to producer-owned `ibex:site` correspondence rows and authenticates the exact materialized sidecars); 2026-07-17 (canonical policy v2 binds graph, entry, deployment profile, normalized root ceiling, and closed computed-candidate materialization for LLP 0028/0029); 2026-07-15 (LLP 0026 adoption defines the bounded initialization-triggering authority carried by an authorized import edge); 2026-07-11 (ENG-24147 typed authoring and canonical policy generation); 2026-07-12 (ENG-24239/24247/24251 registry-bound policy ingress, selector constraints, and semantic drift classification)
**Related:** LLP 0013 (compartments/capability enforcement — this spec defines its grant-authoring surface); LLP 0007 (bundler pipeline the generator rides); LLP 0004 (package manifests); LLP 0026 (module-runner initialization authority)

> **Current implementation (2026-07-17):** authoring produces the versioned,
> digest-bound canonical typed policy defined by LLP 0021. References below to
> the unversioned `PolicyFile`, permissive execution, environment endowments,
> or audit/enforce mode selection describe the superseded rollout and must not
> be used as current CLI or deployment guidance. Production accepts only
> `purpose: production`, `mode: enforce`; audit is the separate foreground
> `ibex capsec audit` workflow.

## Summary

The app's capability policy is **generated, not hand-authored**. First-party
code declares grants at its import sites; a build-time static analysis over
the entry point's module graph compiles those declarations — together with
the LLP 0013 request/delegation cascade — into a single resolved policy
artifact with per-entry provenance. The artifact is committed and
drift-checked like a lockfile; the import sites are inputs, the artifact is
the record.

Two properties motivate the design (author decision, 2026-07-02):

1. **Union semantics.** A package needs a permission slip from *somewhere*,
   not from every office: if two sites import the same package and only one
   grants a capability, the package holds it. Under per-package principals
   this is the only coherent semantics — one package, one compartment, one
   ambient grant set — and it is the monotone one: adding an import site can
   widen but never break another consumer, so sites compose without
   coordination.
2. **Co-location.** Hand-maintained policy files rot at scale into a
   hodgepodge nobody dares prune (IAM policies, CSP headers, Android
   manifests). Putting the grant on the import links authority to the code
   that motivates it: delete the import and the grant garbage-collects out
   of the regenerated artifact. Nobody manages the policy file by hand.

## The grant channel

The permission-slip model needs one addendum to be sound: **the office
issuing the slip must itself be authorized to issue slips.** If grant
declarations were honored wherever they appear, a compromised package would
self-issue its permissions by annotating its own imports, and the
supply-chain containment story would collapse.

Normative rule, restating LLP 0013 §Delegation for this surface:

- **Root-principal code** (first-party / workspace code — LLP 0013 Resolved
  questions §1) is the **only grant channel**. Grant attributes are honored
  solely in modules that belong to the trusted root principal.
- The same syntax anywhere else (any `node_modules` module) is **never a
  grant**. The generator strips it, ignores it for policy purposes, and
  reports it as a supply-chain signal (a package trying to self-grant is
  worth surfacing loudly). Packages express needs through the *request*
  channel — the `ibex` manifest field (LLP 0013 §Delegation and authority
  flow) — which grants nothing by itself.

There is exactly one slip-issuing office: the app author's own code,
expressed through their own reviewed source. Everything else is a request
desk.

## Grant syntax

Grants are **import attributes with string values** — standard
ECMAScript grammar (attribute values must be string literals), parsed by the
stock toolchain, no custom syntax:

```js
import img from "image-lib" with {
  grants: "fs:read:/app/images, fs:write:/app/images",
  builtins: "node:fs, node:path",
};

import fetchLib from "node-fetch" with {
  grants: "network:fetch",   // endows `fetch` via the derivation table below
};

import steal from "evil-pkg";  // no attributes — package gets an empty grant set
```

Recognized attribute keys, all optional, all comma-separated string lists
unless noted:

| Key | Meaning |
|---|---|
| `grants` | Host capabilities granted to the imported package's principal (LLP 0013 Policy surface 1). |
| `endow` | Globals endowed on the package's compartment global (surface 2), in addition to derived ones. |
| `builtins` | Builtin modules the package may import (surface 3). |
| `also` | Co-located transitive exceptions — see below. Entry grammar: `pkg => cap, cap; pkg2 => cap`. |

Rules, all normative:

- **Statically evaluable, fail closed.** Attribute values are string
  literals by grammar; a grant list that fails to parse is a generation
  *error*, not a skipped entry. Dynamic `import()` with a computed
  specifier contributes nothing (the runtime already quarantines it —
  LLP 0013 Resolved questions §2).
- **Declarative build input, not a runtime act.** Grants are resolved at
  generation time, before any code runs; import order can never change
  effective policy. (The imperative counterpart is the dynamic layer,
  below.) The bundler strips grant attributes before the engine ever sees
  them; they have no runtime representation.
- **Union across sites.** The effective root grant for a package is the
  union of all its import-site grants in root-principal code, across the
  analyzed graph. Removing one site removes only what no other site still
  grants.
- **Entry-scoped.** Generation walks one entry point's module graph — the
  same graph the bundler builds (LLP 0007). Grants in code not reachable
  from the entry do not exist in that entry's artifact; test entries get
  their own artifact, so test-only grants cannot leak into production
  policy, and dead code's grants disappear with it.
- **Selector, not binding.** A grant attaches to the resolved package
  selector (name — LLP 0013 Resolved questions §1), not the import binding.
  Re-exporting a binding moves no authority.
- **ESM only, for now.** CommonJS `require()` has no attribute grammar;
  root code that wants to grant uses an ESM import site. (A pragma-comment
  form for CJS is a possible extension; not scheduled.)

## Declared, not inferred

LavaMoat's `generate` infers policy from what package code *does*; this
spec generates **host-capability grants** from what root code *declares*.
The difference is the failure mode under a malicious update: usage-inference
rubber-stamps new behavior into the regenerated policy unless a human reads
the diff, whereas declared grants fail closed — the compromised version's
new *ambient* reach (a granted capability) is denied until the app author
edits their own import site. Inference remains useful on the *request* side
(proposing `ibex` manifests for unannotated packages, LLP 0013
Open/Resolved question 11); it is never a **grant** source.

The **import fence** (`builtins`) is the one surface synthesized from the
static module graph rather than declared (ENG-22683): the alternative —
requiring the app author to hand-enumerate every builtin each transitive
dependency imports — reproduces exactly the hand-maintained-hodgepodge this
spec exists to avoid, and denies `util`/`events`/`stream` under enforce
until annotated. This does not reopen the inference failure mode: unlike a
capability grant, a synthesized allowlist entry only permits *loading* a
module — the dangerous operation is still gated by the (declared)
capability system — and a hijacked release that adds a builtin import
surfaces as a `--check` **expansion** review tripwire, so the new reach is
never rubber-stamped silently. Computed/obfuscated specifiers contribute
nothing and are denied at runtime.

### Import-edge initialization authority

An authorized import edge carries one bounded authority beyond mere namespace
reachability: it may trigger the target module's once-per-execution-generation
initialization at the target's own authenticated principal and grants. This is
not a host-capability grant to the importer and does not let the importer
select, borrow, amplify, or suppress the target's authority. It only lets the
importer choose when a cold, already-authorized edge causes the target's
ordinary module initialization; subsequent imports reuse the record.

The policy generator therefore treats review of an import edge as review of
that trigger. The edge must still pass the immutable armed import graph, and
the target's effects remain bounded by its own policy and compartment. A
minimal-authority importer triggering a privileged target and an attempted
sticky-error poisoning import are required adversarial fixtures under
LLP 0026. Calls made after initialization retain the ordinary full live-chain
deputy intersection; this exception does not become ambient delegation.

## Transitive grants and co-located exceptions

Import-site grants reach **direct** imports only, and most packages in a
real graph are transitive. The composition is:

1. Import-site grants define the **root grants** for directly-imported
   packages.
2. The LLP 0013 delegation cascade computes ambient authority for the rest:
   `effective(dep via pkg) = delegates(pkg → dep) ∩ effective(pkg)`, with
   per-package `ibex` manifests (shipped or inferred) as intersected
   requests and union across incoming edges.
3. Passed attenuated handles remain the primary, per-edge-precise
   delegation mechanism at runtime (LLP 0013 §Delegation); the cascade is
   the coarse ambient fallback for packages whose APIs don't accept
   handles.

For the stubborn case — a deep dependency that needs ambient authority
where intermediates neither take handles nor delegate sensibly — the
escape hatch is an `also:` exception **co-located with the import edge
that motivates it**, not a naked overlay entry:

```js
import img from "image-lib" with {
  grants: "fs:read:/app/images",
  also: "tmp-file-helper => fs:read:/app/images",
};
```

The exception generates into the artifact with provenance pointing at this
site and garbage-collects when the import goes away — the same co-location
property as ordinary grants, preserved for the exceptional path.

**Honesty requirement.** Under per-package principals with union
semantics, an `also:` grant is app-wide ambient authority for the named
package; its association with the importing edge is provenance and GC
linkage, **not** enforcement. "tmp-file-helper has fs only while image-lib
is on the stack" is exactly LLP 0013 Phase 5 stack-intersection
(`deputyClasses`), which composes with this surface but is opt-in per
capability class. Docs and tooling must not imply containment the default
mode does not provide.

## Surface derivation

Policy governs three surfaces (LLP 0013 §Policy); a grant string names a
host capability, but a usable policy usually needs the other two surfaces
to agree (a package granted `network:fetch` with no `fetch` endowment
cannot function). The generator derives the obvious **endowment** companions
from the capability class; explicit `endow:` attributes extend the derived
set:

| Capability class | Derived endowments |
|---|---|
| `network:fetch*`, `network:*` | `fetch`, `XMLHttpRequest`, `WebSocket` |
| `process:*` | `process` |
| `fs:*` | — |

The **builtins** surface is *not* derived from the capability class (a
partial class-derived list is enforced strictly and wrongly denies every
other builtin a package legitimately imports — ENG-22633). Instead the
generator **observes** each package's static builtin imports from the
module graph and emits exactly that allowlist (LavaMoat-style), plus any
explicit `builtins:` attributes (ENG-22683). A package that imports no
builtin gets `builtins: []` — deny-all, the containment statement — and one
that imports `os` gets `builtins: ["node:os"]`; a builtin reached through a
computed specifier the generator cannot see is denied at runtime (fail
closed). The derivation table and the builtin classifier both live in one
place (`packages/ibex-devtools/src/scripts/import-grants.mjs`).

The classifier (`builtinSpecifierOf`) is also the single source of truth for
"is this specifier a builtin, not a package": `packageNameOfSpecifier` delegates
to it, so a bare builtin (`fs`), a `node:`/`exact:`/`bun:` alias, or a builtin
subpath is never modeled as a package selector or dependency edge (ENG-22699),
and the `exact:`/`bun:` alias namespaces are observed and emitted verbatim so
the generated allowlist matches how the runtime gates them (ENG-22697). It must
cover every root the runtime gates (`RUNTIME_GATED_NODE_BUILTINS` in the
generated builtin manifest) — a drift guard in `import-grants.test.mjs` asserts
this.

## The generated artifact

The artifact is the canonical `ibex/capsec-policy/2` review policy. The trusted
arming step consumes it; the legacy `PolicyFile` is not a production-policy
form. ESM authors encode a JSON array of typed selectors in the string-valued
`authorities` import attribute. CommonJS authors use a JSON-only second
argument, `require("pkg", {"authorities":[...]})`. Both forms are stripped
before execution. Legacy colon-delimited `grants` and `also` strings are
rejected at the canonical boundary rather than copied or silently omitted.

```jsonc
{
  "policySchema": "ibex/capsec-policy/2",
  "capsVocab": "ibex/capsec/1",
  "semanticCore": "capsec/semantics/1",
  "vocabDigest": "sha256-...",
  "registryDigest": "sha256-...",
  "policyDigest": "sha256-...",
  "purpose": "production",
  "mode": "enforce",
  "graphIdentity": "sha256-...",
  "entryIdentity": {
    "root": "project",
    "components": [{ "encoding": "utf8", "value": "src" },
      { "encoding": "utf8", "value": "app.mjs" }],
    "sourceIntegrity": "sha256-..."
  },
  "targetProfile": { "kind": "source", "profile": "portable-v1" },
  "mountProfile": "project-v1",
  "rootCeiling": [],
  "computedCandidates": {
    "schema": "ibex/computed-candidate-manifest/1",
    "declarations": [],
    "packageClosureOptIns": [],
    "materializedSites": []
  },
  "principals": [{
    "principal": { "kind": "package", "name": "image-lib",
      "integrity": "sha256-...", "locator": "image-lib@2.4.1" },
    "floor": [{ "authority": { "cap": "fs:read", "resource": {
      "kind": "path-tree", "path": { "root": "project", "components": [] }
    }}, "provenance": [{ "kind": "import-site", "source": "app.js:1" }] }],
    "denials": [], "escalationCeiling": [],
    "imports": { "builtins": ["node:fs"], "packages": [] },
    "endowments": []
  }]
}
```

Normative properties:

- **One authenticated graph and entry.** `graphIdentity` is the
  `ibex/authenticated-graph-snapshot/1` digest of the canonical projection over
  the entry identity, source-integrity-bearing module nodes, integrity-bound
  package principals, typed package edges, and materialized computed-candidate
  sets. `entryIdentity` is a normalized project-relative `PathComponent` path
  plus source integrity. Both fields participate in `policyDigest`; a policy
  cannot be reused for another graph or entry merely because its package rows
  happen to look alike. Checked `portable-v1` examples pin every tracked source
  and rendered policy artifact to LF through `.gitattributes`; otherwise Git's
  Windows checkout conversion would change the authenticated graph bytes and
  make one committed review artifact platform-dependent.
- **One deployment profile.** `targetProfile` is tagged as either source
  (`portable-v1`) or compiled (`sfe-v1` plus a normalized target triple), and
  `mountProfile` is `project-v1` or `compiled-app-work-v1`. The pair is part of
  the reviewed digest. Default artifact names include entry, target profile,
  target triple when present, and mount profile; an explicit `--out` remains
  available for checked-in compatibility examples.
- **The root ceiling is explicit.** `rootCeiling` is the normalized,
  provenance-carrying authority declaration authored at
  `package.json#ibex.rootAuthorityCeiling`. An absent declaration is the empty
  ceiling; deployment code does not infer ambient authority from the host.
- **Computed resolution is closed.** Root `package.json` declares stable
  requester/label sites with explicit specifiers and/or exact package locators
  under `ibex.computedCandidates.sites`. A locator may contribute its package
  closure only when that exact package manifest opts in with
  `ibex.computedCandidateClosure: true`. The generator records the opt-in with
  provenance and materializes the complete per-site candidate set. Every
  declaration has exactly one materialized row, every declared explicit
  specifier is present, and undeclared/open filesystem discovery is forbidden.
  The Oxc producer is the only parser and assigns the site ordinal, stable
  source-authored `ibex:site` label, and original-source span. Policy
  generation consumes that correspondence through the authenticated graph
  snapshot; it does not parse source to rediscover or renumber sites. The
  resulting `ibex/computed-candidates/1` table binds requester/source integrity,
  transform-fingerprint domain, generation, attributes, exact spellings, and
  resolved target identities. Adding a candidate is therefore an explicit
  authority-relevant policy diff.
- **Every integrity-bound package in the analyzed graph appears**, granted or not, and
  every entry carries an explicit `builtins` list (`[]` when the package
  imports no builtin). The runtime reads an *absent* `builtins` as
  "unrestricted on the import axis", so the generator never omits it —
  absence is reserved for hand-authored policies (ENG-22683). A
  builtins-only entry (`{ "builtins": [] }`) is therefore the containment
  statement "this package holds nothing ambient and may import no builtin";
  a package missing from the artifact is a generation bug, not a default.
- **Every granted capability carries provenance**: the root site
  (`file:line`) that issued it, or the delegation chain that cascaded it.
  Every entry answers "why is this here" by construction.
- **Reproducible.** Same tree, same artifact, byte for byte — no
  timestamps, no absolute paths, sorted keys.
- **Committed and drift-checked.** The artifact is checked in like a
  lockfile. `generate-policy.mjs --check` regenerates and fails CI on any
  difference, reporting typed authority **expansions** separately from
  narrowings, mixed changes, semantic vocabulary changes, and graph/package
  identity changes separately. Package/builtin imports, endowments, denial
  removal, root or package ceiling widening, and computed-candidate additions
  participate in authority expansion classification rather than being
  mislabeled as structural drift. Provenance-only changes remain loud diffs.
  The aggregate `bun run check:drift` gate invokes this check for every
  committed example, so a registry digest rotation and its policy lockfiles
  cannot validate independently.

## Dynamic grants and the static ceiling

A separate, later layer may grant at runtime — dynamic
`import(spec, { with: { permissions } })`, post-import grant calls, or
user-facing permission prompts (LLP 0013 §Interaction with user-facing
dynamic permissions). Two rules bind that layer to this artifact:

1. **The artifact is the ceiling.** Runtime grants may instantiate or
   attenuate within the statically generated envelope, never exceed it —
   otherwise the artifact stops being the thing you read to answer "can
   left-pad ever reach the network". This extends the ceiling principle
   LLP 0013 already states for OS prompts ("the static policy is the
   ceiling; prompts move the floor") and for dynamic import (effective =
   caller-authority ∩ requested). A site that intends runtime widening
   declares the *potential* statically so the worst case stays in the
   artifact.
2. **Post-import grant is disfavored.** Granting to an already-instantiated
   package compartment retroactively amplifies every importer (the
   bundle-cache cross-contamination fix was this hazard's build-time
   shadow). Passed attenuated handles — already the primary delegation
   mechanism — cover runtime delegation without mutating ambient state.

**Extent-scoped delegation (considered, deferred).** A React-context-style
dynamic form — `withFs(handle, () => codec.decode(buf))`, authority scoped
to a call extent — offers least-authority in time, but is the Java
`doPrivileged` shape (JEP 411 is LLP 0013's cautionary reference):
everything executing inside the extent inherits the authority, including
callbacks passed in from elsewhere — a confused-deputy channel by
construction. It would also make async-context attribution (LLP 0013 Open
question 3) load-bearing for grants, not just audit. A frame-scoped
variant (context visible only to a named package's frames within the
extent, via Mechanism 3 attribution) could close the callback leak; parked
as research until a real graph demands what the static cascade and handles
cannot express. Note the static cascade already *is* the context analog
over the dependency tree: provider = delegating importer, consumers = its
subtree, resolved at build time.

## Toolchain integration

- `packages/ibex-devtools/src/scripts/import-grants.mjs` — parse/strip
  grant attributes; capability set algebra (union, intersection with path
  narrowing); the delegation-cascade fixpoint; the surface derivation
  table.
- `packages/ibex-devtools/src/scripts/generate-policy.mjs` — drives the
  same Rolldown resolution the bundle uses (LLP 0007), collects
  root-principal grants and package-level edges, reads `ibex` request
  manifests, resolves the cascade, emits the artifact. `--check` is the CI
  drift gate.
- The bundler pipeline strips grant attributes unconditionally
  (`createImportGrantsPlugin` in `transforms.mjs`), so grant-annotated
  source is runnable in every mode and the engine never sees the syntax.
- `ibex policy generate|check` — CLI plumbing over the generator (same
  spawn path as the bundler).
- Enforcement of the artifact is LLP 0013's machinery unchanged:
  `CapabilityManager::apply_policy` for host capabilities and the import
  graph; compartment endowments via the registry (the runtime composes
  endowment wiring from `packages.*.endow` at boot).

## Residual risks

- **Name-keyed grants survive version bumps.** A hijacked release of a
  package that already held `network:fetch` still holds it; nothing at
  this layer stops capability abuse *within* the granted envelope. The
  containment win is that ambient authority never grows silently. (Version
  pins as opt-in tightening — LLP 0013 Resolved questions §1.)
- **Union coarseness.** One importer's grant empowers the package for all
  its callers, including untrusted ones (deputy-by-design residual,
  LLP 0013 Threat model). Per-edge precision belongs to the handle
  channel; Phase 5 stack-intersection is the opt-in hardening.
- **The cascade trusts the app's review of the artifact diff**, not the
  packages: a compromised intermediate can delegate generously, but never
  more than the app granted its subtree.

## Open questions

1. **CJS grant surface.** Pragma comment on `require()` lines, or leave
   CJS root code grant-less (author in ESM)? *Lean:* leave it; root code
   is ESM-first and one syntax keeps the analyzer honest.
2. **Expansion gate mechanics.** Is `--check`'s expansion/shrinkage split
   enough, or should capability-class-sensitive expansions (anything
   gaining `process:spawn`, `fs:write`) require a distinct CI approval
   (CODEOWNERS on the artifact)? *Lean:* start with `--check` + review of
   the committed diff; add gates when a real repo's traffic justifies
   them.
3. **Request inference tooling** (shared with LLP 0013 question 11): when
   packages ship no `ibex` manifest, generate proposed requests from
   static analysis of the package source, surfaced as artifact diffs.
   Inference proposes; it never grants.

## Implementation status

First implementation landed with this spec (2026-07-02), branch
`llp-0013-compartments`. Anchors below are the stable `@ref LLP 0014#…`
targets.

#### Parse and strip

`import-grants.mjs`: `parseImportGrants` (Rolldown/Oxc import-attributes;
fail-closed errors for malformed grant strings), `stripGrantAttributes`
(removes recognized keys, drops emptied `with` clauses),
`createImportGrantsPlugin` (always-on bundler strip — wired into
`createSharedBundlerPlugins` in `transforms.mjs`).

#### Set algebra and cascade

`import-grants.mjs`: `capabilityUnion` / `capabilityIntersect`
(class:param model; parameter intersection picks the narrower path,
`/**`-style prefixes) and `resolveCascade` (monotone fixpoint of root
grants ∪ per-edge `delegates ∩ effective`).

#### Generator

`generate-policy.mjs`: Rolldown-driven graph walk; grants honored only for
root-principal modules; grant attributes found in `node_modules` are
stripped, ignored, and reported; `ibex` manifests read from each reachable
package's `package.json`; artifact emitted with provenance and sorted
keys; `--check` compares normalized JSON and reports expansions vs
shrinkage distinctly.

#### Runtime and CLI

`ibex policy generate|check` (`PolicyCommands` in `src/bin/ibex/cli.rs`,
dispatched to `run_policy_command` in `src/bin/ibex/runtime.rs`)
spawns the generator with the bundler's runner-resolution plumbing. At
boot, `packages.*.endow` from the loaded policy composes into the
compartment registry's endowment map (`src/bin/ibex/runtime.rs`), so the
artifact drives Mechanism 2 end-to-end. Under enforce/audit the artifact is
the **sole** endowment source: an ambient `IBEX_ENDOW` (operator- or
wrapper-set) is dropped rather than merged, so it cannot widen a package's
globals past the reviewed artifact (`--allow-env-endowments` is the
development escape hatch; a dropped value is reported on stderr). Permissive
keeps the ambient override for dev ergonomics. (ENG-22684 — this closes the
prior "explicit env keeps precedence" behavior, which pre-dated the
enforce-mode threat framing.) The artifact is also the security
**mode** source: when no explicit `--capsec` is passed, the policy's `mode`
field (`enforce`/`audit`/`permissive`) sets the runtime `SecurityMode`
(`load_policy_file` → `resolve_security_mode` → `build_host_config`), so a
generated artifact that declares `mode: "enforce"` enforces without a
redundant flag; `--allow-all` is the explicit permissive escape. (First-party
root and the module loader are trusted under enforce so the app runs without
self-granting — see LLP 0013 §Mechanism 3.) The CLI parses the artifact
exactly once per startup (`load_policy_file`) and threads the parsed
`PolicyFile` through mode resolution, capsec readiness, endowment
composition, and `HostConfig.policy` into `Host::new` — one consistent
snapshot rather than four independent reads of a file that could change
between them (ENG-22644).

#### Conformance

`import-grants.test.mjs` (bun) covers parse/strip/union/intersect/cascade and
the fail-closed cases. LLP 0021 replaced this document's string-policy artifact
and legacy end-to-end runner with strict typed policy ingress, authenticated
package-graph arming, and loaded-engine callback/conformance tests. The checked
case-by-case retirement join is
`tests/fixtures/capsec-rev2/llp0013-retirement-map.json`; the surviving
`tests/llp0013_compartments.rs` target guards stale-policy refusal and the two
non-policy runtime regressions that still require the diagnostic executable.

## References

- LLP 0013 §Delegation and authority flow (requests vs grants, the
  cascade, union across importers); §Policy (three surfaces); §Interaction
  with user-facing dynamic permissions (ceiling principle); Resolved
  questions §1 (selector/principal), §2 (dynamic-code quarantine).
- LLP 0007 (the bundler pipeline the generator and strip plugin ride);
  LLP 0004 (package manifest pipeline that carries `ibex` requests).
- External `[inferred]`: MetaMask LavaMoat (`lavamoat generate` — the
  inferred-from-usage contrast); TC39 import attributes (stage 4 grammar:
  string-literal values); Agoric SES/Endo (attenuation discipline);
  Java JEP 411 via LLP 0013 (extent-scoped authority cautionary tale).
