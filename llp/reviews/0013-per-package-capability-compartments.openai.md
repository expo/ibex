# Review: LLP 0013 - Per-Package Capability Enforcement via Hardened Compartments

**Reviewer family:** OpenAI
**Provider / runtime:** Codex CLI · model GPT-5
**Date:** 2026-07-02
**Redacted:** No - the review was performed entirely against local repo sources; no
document content was transmitted to an external provider.
**Method:** Direct RFC review plus targeted local provenance verification against
the cited Ibex files. External projects and the transient Hermes source checkout
were not fetched in this pass. This Codex session did **not** author the draft
(Author: *Charlie Cheever / Claude (Fable)*), so it stands as one independent
family review per the LLP 0005 review process.

## Overall assessment

**Revise and stay `Draft`.** The RFC identifies the real unsoundness in the
current per-module capability layer and chooses the right broad shape:
instance isolation for hostile code, package compartments for supply-chain
containment, frozen shared intrinsics, and engine-derived attribution before
enforcement claims.

The current-state claims I checked are mostly accurate: capability checks still
flow through a numeric `g_active_module_id` (`src/engine/hermes_runtime.cc:172`;
`src/engine/hermes_runtime_internal.h:168-179`), JS can reach
`__exactSetActiveModuleId` and `__exactGrantCapability`
(`src/engine/hermes_runtime.cc:962-979`;
`src/engine/hermes_runtime_crypto.cc:4653-4670`;
`packages/ibex-runtime-js/src/bootstrap.ts:1061-1069`), process checks use
`child_process` while the canonical bit table has `process:spawn` instead
(`src/engine/hermes_runtime_process.cc:105,236,390,814`;
`src/host/capability_bits.rs:13-70`), and `Capability` / `Strict` share the same
effective default-deny branch (`src/host/capability.rs:100-129`).

The draft should not be accepted yet because several security-critical semantics
are still too loose for a plan that will eventually produce enforce mode.
Most are fixable by tightening Phase 0-2 deliverables and acceptance criteria.

## Strengths

- **Threat model** - The RFC uses the honest term "supply-chain integrity" and
  explicitly excludes hostile-code sandboxing, engine bugs, side channels,
  deliberate authority passing, and deputy-by-design APIs. That boundary is the
  right product and security framing.
- **Current state** - The local mechanism audit is valuable and substantially
  matches source. In particular, the writable module-id attribution and global
  grant/setter hooks are real enforcement breaks, not just hardening concerns.
- **Phasing** - Shipping "hide/remove `__exact*` escape hatches" first is a good
  standalone defect fix. The conformance/red-team suite as the durable asset is
  also the right way to make a Hermes patch stack survivable.
- **Fork discipline** - Classifying carried patches by shape and treating the
  conformance suite as the oracle gives future maintainers a concrete rebase
  contract instead of a vague "small fork" promise.

## Concerns

### C1 (High) - Phase 1 needs explicit `eval` / `Function` containment

The design section correctly says `eval` and `Function` must bind generated code
to the caller's compartment or be tamed off per policy. The Phase 1 plan,
however, only names a build-time free-global rewrite, endowments, and SES
lockdown. That is not enough for audit/enforce confidence on stock Hermes:
dynamic code can bypass a static free-global transform unless the transform also
tames `eval`, `Function`, indirect eval, and any loader path that compiles source
after package attribution is known.

This matters before the Hermes fork. Phase 1 is supposed to produce the
conformance suite and a real audit-mode rollout against Exact/Snapback graphs.
If dynamic-code semantics are deferred until Phase 3, the Phase 1 suite may pass
against a model that does not actually represent the eventual enforcement
boundary, and audit logs can miss dynamic-code escapes.

**Resolution:** add a Phase 1 deliverable for dynamic-code handling: either deny
or tame `eval` / `Function` by default under compartment mode, define indirect
eval behavior, cover dynamic import and runtime-transformed sources, and add
red-team tests showing dynamic code cannot recover the real global or a more
privileged endowment.

### C2 (High) - "Frame-accurate" audit is promised before frame attribution exists

Phase 1 advertises "frame-accurate-as-available attribution" with no fork, while
the design's unforgeable attribution mechanism requires Hermes frame data in
Phase 2. The current stock-Hermes path cannot make host-boundary attribution
sound: C++ checks use `g_active_module_id` today
(`src/engine/hermes_runtime_internal.h:168-179`), and JS controls the loader-side
setter (`src/engine/bootstrap/module-loader.js:4223-4230`). A transformed
package label or JS stack parse can be useful audit evidence, but it is not
security-grade attribution.

The draft partly knows this, but the wording blurs "best effort audit labels"
and "frame-accurate audit logs." The acceptance criteria require frame-accurate
logs under forgery attempts without saying this is impossible until Phase 2
lands.

**Resolution:** split the claim. Phase 1 should produce best-effort,
transform-derived audit attribution with explicit known-forgeability. Phase 2
should be the first phase allowed to claim frame-accurate audit or enforce-mode
attribution, with tests for callbacks, prototype patches, promise jobs, native
frames, and host-created callables.

### C3 (High) - The real-global surface needs a complete Phase 1 inventory

The RFC says Phase 0 hides/removes the `__exact*` escape hatches, but the runtime
installs many powerful host functions on the shared real global during bootstrap
(`__exactGetAllEnv`, module resolution, fetch/fs/process/crypto helpers, etc.).
A per-package free-global rewrite can prevent bare `process` or `fetch` access,
but it does not by itself prove that package code cannot reach the actual
Hermes global object through `globalThis`, dynamic code, callable `this`, CJS
wrapper behavior, host-created functions, or reflective references captured
before lockdown.

Because Phase 1 is deliberately the no-fork supply-chain value phase, this
inventory is not optional. If any host bridge remains reachable on the real
global, the package compartment model becomes an advisory transform rather than
a containment boundary.

**Resolution:** add a Phase 0/1 checklist that enumerates every installed native
global, classifies it as removed, hidden behind an attenuator, endowed into a
package global, or retained as inert, and adds red-team tests for recovering the
real global. The `__exact*` family should be a subset of this checklist, not the
whole checklist.

### C4 (Medium) - Package identity keyed only by name is under-specified

Resolved question 1 says policy is keyed by package name, while coexisting
`name@version` instances get separate compartment globals and version pins are
only opt-in tightening. That may be ergonomic, but it leaves an important
security ambiguity: when two physical packages share a name, which grants apply
to which compartment, and how does an audit log distinguish them by lockfile
locator/path/integrity?

For supply-chain containment, "name" is a human policy label, not a sufficient
runtime principal. Package aliases, nested `node_modules`, pnpm-style layouts,
workspace packages, vendored code, and duplicate versions all need stable
resolved identities even if the policy UI defaults to names.

**Resolution:** separate policy selectors from runtime principals. The runtime
principal should include at least package name plus resolved locator
(version/path/lockfile identity as available), while policy can provide
name-wide selectors. Audit logs should emit both the human name and the resolved
principal.

### C5 (Medium) - Hermes source citations are not reproducible from the repo

The citation convention says `hermes:` paths were verified against the local
build checkout. In this repository checkout, the committed tree contains Hermes
headers/frameworks/binaries but not the source files cited by the RFC; the build
scripts clone Hermes into cache/temp locations (`scripts/build-hermes.sh:207-229`;
`scripts/build-hermes-macos.sh:84-87`). That is workable, but the review reader
cannot reproduce `hermes:` line citations from the committed tree alone.

**Resolution:** add a short reproducibility note to the citation convention:
the exact command/path used to materialize the source checkout, the commit SHA
or branch resolved from `260318099.0.0-stable`, and whether reviewers should use
`scripts/build-hermes.sh`, a documented cache path, or `git clone` directly.

### C6 (Low) - Acceptance criteria mix RFC acceptance with implementation exit

Several acceptance criteria are implementation-level and expensive, especially
"pin-bump runbook executed on >=2 real upstream releases." That is a good
criterion before declaring the engine fork operational, but it is not a
criterion for accepting the design RFC or even for starting Phase 0/1.

**Resolution:** split "RFC acceptance criteria" from "feature/phase exit
criteria." Keep the two real pin bumps as a Phase 3/4 operational-readiness
gate, not as an acceptance requirement for the RFC itself.

## Suggestions

- Add an explicit "security claim by phase" table. For each phase, state whether
  the system provides advisory audit only, best-effort audit, sound attribution,
  or enforceable package containment.
- Add "recover the real global" and "dynamic code escape" to the red-team suite
  by name. Those are the shortest paths from a transformed compartment model
  back to ambient authority.
- Treat the existing `child_process` capability mismatch and `Capability` ==
  `Strict` collapse as Phase 0 defects if they affect audit results; otherwise
  Phase 1 audit data may be polluted by known naming/mode bugs.
- Add a small policy example with two versions of the same package and a package
  alias. That will force the package-principal model to become concrete.

## Open questions surfaced

- In Phase 1, is the static transform allowed to reject packages that use
  dynamic code, or must it support them via a runtime compiler hook?
- What is the exact authority of first-party/workspace code when it imports a
  third-party package that returns a function later called from first-party code?
  The RFC's deputy-by-design section allows this, but audit logs should make the
  acting principal obvious.
- Does audit mode intentionally log would-deny decisions while still allowing the
  operation, or does it only log checks made by already-attenuated/endowed
  objects? The difference matters for building a compat corpus.

## Recommended next step

Revise LLP 0013 in place for C1-C6 and keep `Status: Draft`. After the security
claim-by-phase table and Phase 1 dynamic-code/global-recovery semantics are
tightened, route the revised draft to at least one non-OpenAI, non-Claude review
if the author wants a stronger multi-family loop before acceptance.
