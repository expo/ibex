# Audit graph admission

**Type:** Spec
**Status:** Draft
**Systems:** Security, Module Loader, Runtime, CI
**Author:** Codex, directed by Charlie Cheever
**Date:** 2026-07-17
**Revised:** 2026-07-18 (round-1 Fable review: foreground-vs-armed audit
separated; complete diagnostic decision context and protected baseline added;
builtin/candidate rules, byte retention, evidence overflow, verified-target
gating, and inline-only v1 admission specified; round-1 re-review returned
READY after four non-architectural wording fixes)
**Related:** LLP 0013 (diagnostic audit semantics); LLP 0021 (typed decisions and evidence); LLP 0026 (native module runner); LLP 0027 (module artifacts and carriers); LLP 0028 (Oxc-only retirement, audit-admission gate); LLP 0031 (0.2 native platform matrix)

## Summary

This Spec defines how the explicitly diagnostic `ibex capsec audit` workflow
may construct and execute a native Oxc module graph without an
`ArmedSnapshot`. Audit source execution uses a distinct, non-authorizing
`ForegroundAuditGraphSnapshotV1`; it never fabricates, weakens, or reuses a
production armed snapshot.

The snapshot authenticates graph identity, source and package provenance, and
the producer inputs needed by LLP 0027. It contains **no authority rows** and
cannot be passed to production arming or production artifact admission. Host
effects still use LLP 0021's `DiagnosticAudit` workflow: only a genuine
`missing-authority` result may proceed as would-deny. Identity, containment,
wire-format, target, and engine failures remain hard refusals.

This contract keeps source audit available after LLP 0028 retires the
compatibility evaluator. If the implementation cannot satisfy every hard
fence here, the required fallback is to refuse audit source entries; it must
not silently select the old evaluator or mint an `ArmedSnapshot`.

## Motivation

The production module runner currently starts from
`current_module_runner_snapshot()`, which returns only an `ArmedSnapshot`.
Foreground audit deliberately constructs `Host::new(SecurityMode::Audit)` and
accepts no durable policy, so it has no armed snapshot and therefore remains
on the compatibility evaluator. Deleting that evaluator without a separate
contract would either delete source audit accidentally or tempt the runtime to
manufacture production-looking authority from diagnostic state.

Audit needs two properties that are easy to conflate:

1. trustworthy graph and code identity, so observations belong to the module
   and package actually executed; and
2. non-blocking missing-authority decisions, so the audit can report what an
   enforce run would deny.

Property 2 does not weaken property 1. Audit may relax only the final
missing-authority stratum already named by LLP 0021. It cannot relax path
containment, package ownership, source integrity, parser diagnostics, carrier
identity, or engine compatibility.

## 1. Workflow and type separation

The implementation introduces an opaque `ForegroundAuditGraphSnapshotV1`
handle. Its name is intentionally disjoint from the historical
`ArmedSnapshot.workflow = "diagnostic-audit"` schema arm.
Its wire projection is:

```text
ibex/diagnostic-graph-snapshot/1 {
  workflow                 = "foreground-source-audit"
  runNonce                 // fresh, unguessable, process-local
  target                   // exact OS/arch + native-runner ABI
  root                     // retained root directory object identity
  entry                    // canonical SourceId
  graphIdentity            // authenticated-graph-snapshot/1 digest
  producerBinaryDigest
  transformFingerprintDigest
  nodes[]                  // SourceId, source integrity, object identity
  packages[]               // exact package locator/integrity/root identity
  edges[]                  // requester, typed resolution kind, attributes, target
}
```

The wire form is evidence, not a credential. The live handle additionally
retains the opened root/source/package objects from which the projection was
derived. It has no `authorities`, `denials`, ceilings, bootstrap floor,
protected-artifact grants, target-cell promotions, or policy digest.

The Rust types enforce the separation:

- `Host::new_armed`, `ArmedSnapshot`, production `ArtifactAdmissionV1`, and
  production prepared-cache publication do not accept a diagnostic handle;
- the audit graph builder accepts only a diagnostic handle and returns
  `DiagnosticSourceModuleGraphV1`, not `SourceModuleGraphV1`;
- the native linker may consume either graph only through a sealed enum whose
  audit arm installs `Workflow::DiagnosticAudit` and whose production arm
  installs `Workflow::ProductionEnforce`;
- no conversion exists from diagnostic to armed/production types.

The existing armed `diagnostic-audit` schema value is not a foreground CLI
path: `ibex capsec audit` rejects every durable policy input, and no new code
may arm that schema arm. It remains decode-only for historical contract
artifacts until the next armed-snapshot schema major removes it. The
`contract-fixture` workflow is likewise schema-only and never enters either
linker arm. LLP 0021 is revised with the same distinction.

### Diagnostic decision context

The live graph handle owns a separate immutable
`ForegroundAuditDecisionContextV1`; it is not an incomplete
`ArmedExecutionContext`. Every production decision input has this explicit
diagnostic disposition:

| Production input/stratum | Foreground audit input |
| --- | --- |
| vocabulary and registry digests | exact compiled digests; mismatch hard-refuses |
| policy digest | `foreground-audit-baseline/1` digest over the canonical dispositions in this table and the protected-object set, excluding this digest slot itself; never a canonical-policy digest |
| armed-snapshot digest | absent by type; evidence carries the foreground graph and baseline digests instead |
| target/engine/profile validity | same verified target advertisement and loaded-engine identity check as production |
| static floors, authored denials, escalation/root ceilings | empty; their policy-dependent strata are vacuous, not passed |
| registry hard closures and malformed/containment/attribution strata | unchanged and blocking |
| protected objects | host-derived mandatory baseline below; unchanged and blocking |
| bootstrap floor | absent; the audit graph is captured before application evaluation and gains no bootstrap authority |
| generations | fresh run-local generation, pinned into the graph, factories, decisions, and receipt |
| run/channel nonces | fresh process-local values; never serialized as reusable credentials |

The mandatory protected baseline covers the Ibex executable and loaded engine,
captured project/package/source objects, production and diagnostic cache trees,
the selected report/receipt destination, and any loaded canonical policy or
artifact files visible to the process. Writes, renames, links, replacement,
or deletion against this set hard-refuse even though an ordinary missing
filesystem grant would proceed as would-deny. The report destination is opened
and retained by the host before application code; application code never owns
its descriptor. This prevents audited code from poisoning the evidence or any
cache used by a later run.

Operator-facing output must state that foreground audit executes the effects
it reports: auditing untrusted code is running untrusted code. The workflow is
diagnostic, not a sandbox.

Serialization round trips never recreate the live handle. A new audit run
must recapture and reauthenticate the graph.

## 2. Capture and identity derivation

Audit capture begins only after CLI parsing has established the explicit
`capsec audit <entry>` workflow and validated that no durable policy input was
supplied.

1. Open and retain the project root and entry without following a replaceable
   pathname after capture. The entry must be contained by the retained root.
2. Derive the root principal from the captured root identity. The caller may
   not supply a principal or serialized `SourceId`.
3. Resolve every static edge with the ordinary typed resolver and the same
   condition/attribute inputs as production. Resolution may read only local
   captured filesystem objects and the compiled builtin manifest. A typed
   builtin edge enters the diagnostic graph so audit can observe it; its
   import-axis decision is emitted at link/evaluation and may proceed only as
   a final missing-authority would-deny. Registry-closed builtins and malformed
   edges remain hard refusals.
4. Derive package principals from exact name/version/integrity/root-object
   provenance. Workspace first-party files retain the governing LLP 0013 root
   disposition. A source cannot select its own package principal.
5. Open each source once, derive integrity from those bytes, and retain the
   bytes plus the opened object handle through evaluation. Transform,
   admission, and evaluation consume only those captured bytes; no later stage
   re-reads a pathname. If a platform cannot retain the handle, every re-open
   must re-check both native object identity and content integrity before use.
   Unix device/inode and Windows volume/file identity are host-local facts and
   do not enter the portable graph digest.
6. Derive `SourceId` with LLP 0027's canonical algorithm. `File` identities
   owned by root or exact package principals and compiled `Builtin` identities
   are admitted. Caller-authored `Synthetic` identities and any future
   generated identity without a separately specified diagnostic producer are
   refused.
7. Construct `ibex/authenticated-graph-snapshot/1` from the resulting entry,
   nodes, packages, and typed edges. Its digest is the diagnostic graph
   identity used by artifacts and receipts.
8. Treat root-manifest `ibex.computedCandidates.sites` declarations as captured
   graph-authoring input, not durable policy. Join them to producer sites and
   resolve their local exact candidates under the same capture fences, emitting
   the ordinary digest-bound candidate tables. Candidate selection grants no
   host authority; missing spellings reject only when the site is reached.

Symlink escape, root replacement, source replacement, package-provenance
mismatch, duplicate identity, ambiguous goal, noncanonical path component, or
resolver disagreement is a hard refusal. Audit does not turn any of these into
a would-deny allow.

## 3. Hard fences

Audit graph capture and execution have this closed input set:

- the explicit local entry and retained project tree;
- exact package manifests and source objects reached by typed static edges;
- compiled builtin sources and runtime identity;
- the compiled Oxc transform configuration and loaded Hermes identity.

The following are forbidden during graph capture:

- network fetches, package installation, registry lookup, remote URLs;
- user-selected transform binaries, compiler overrides, plugins, or loaders;
- environment-variable substitution that changes resolution or code bytes;
- production policy, authority, target-advertisement, or protected-artifact
  synthesis;
- fallback to the compatibility evaluator after capture, parse, admission,
  link, or execution failure.

An unadvertised platform cannot audit source through the native runner. Audit
uses the same verified advertisement authority as production arming, not the
CLI's weaker OS/architecture allowlist, and returns a stable target-unavailable
diagnostic. LLP 0031 must be accepted and the exact tuple promoted before its
source-audit release gate can pass; it never means executing source with the
legacy evaluator.

## 4. Decisions and would-deny evidence

Graph identity and executable admission happen before LLP 0021 effect
decisions. During evaluation every host effect carries the authenticated
module principal from the native frame/schedule/deputy intersection.

The decision algorithm is unchanged through all denial and containment
strata. `Workflow::DiagnosticAudit` may relax only the final
`missing-authority` result. A relaxed decision:

- proceeds for this diagnostic run;
- sets `wouldDeny: true` and preserves the original terminal branch,
  principal set, effect, resource, source site, and missing selector;
- is appended to a bounded run-local evidence stream;
- cannot be replayed as an authority, grant, cache admission, or production
  receipt.

Registry hard closure (including quarantine denial), invalid attribution,
cross-principal containment failure, protected-object refusal, malformed
effect, incomplete target cell, and every non-authority hard fence remain
blocking. Policy-authored principal denials and process/root ceilings are
unreachable-vacuous in a foreground audit because the command accepts no
durable policy input. This matches LLP 0021's rule that audit relaxes only
missing authority.

At completion the runtime emits one canonical
`ibex/diagnostic-audit-execution-receipt/1` containing:

- run nonce, target, entry `SourceId`, graph identity, producer and transform
  digests, loaded Hermes digest, and carrier kind;
- every executed record's semantic digest and authenticated principal;
- counts plus a digest of the ordered would-deny evidence stream;
- terminal execution outcome.

The receipt records `observedCount`, `retainedCount`, `droppedCount`, and
`truncated`. The bounded stream retains the latest 1,024 ordered entries; its
digest covers exactly that retained suffix, while per-terminal-class totals
cover every observed decision. Overflow can discard detail only with
`truncated: true` and a nonzero dropped count.

The receipt is labeled `diagnosticOnly: true` and
`authorizesProduction: false`. Its schema has no authority-bearing variant.

## 5. Artifact admission

Inline source artifacts use a new diagnostic admission variant that requires
the exact `SourceId`, source integrity, producer binary digest, transform
fingerprint digest, and diagnostic graph identity. It does not accept a policy
or authority projection.

V1 audit is inline-only. It neither reads nor writes production prepared
caches, creates a diagnostic prepared namespace, consumes HBC, nor promotes
diagnostic output. The smaller surface avoids giving would-deny filesystem
effects a cache-poisoning target. A future prepared-audit format requires its
own schema revision and review; it cannot be inferred from
`ibex/module-carrier/2` or production cache admission.

If inline admission is unavailable, the safe product fallback is a stable
source-audit refusal. Compatibility evaluation is never a fallback.

## 6. Failure classes

Failures are classified before prose formatting:

| Class | Examples | Audit behavior |
| --- | --- | --- |
| capture/identity | missing source, root escape, replacement, package mismatch | hard refusal |
| generation | Oxc parse/transform diagnostic, unsupported syntax quarantine | stable diagnostic; no execution receipt |
| admission | malformed artifact/carrier, digest or engine mismatch | hard refusal; no evaluation |
| authority decision | final missing authority only | proceed + would-deny evidence |
| hard security decision | registry hard closure, containment, attribution, target cell | hard refusal |
| invocation | reached computed site with an absent candidate spelling; computed `require` | ordinary rejected promise/throw at original source site |
| execution | application throw/rejection/exit | report outcome with evidence accumulated before it |

Dead code does not produce invocation failures or host-effect evidence.
Generation errors over unconditional reserved authoring vocabulary retain LLP
0028's separate failure-timing rule.

## 7. Conformance requirements

The implementation is incomplete until all of the following run through the
real `ibex capsec audit` command and native Hermes path:

1. root ESM, CommonJS, TypeScript, JSON, builtin, and mixed package graphs;
2. missing authority proceeds and yields exact would-deny evidence;
3. a quarantine-principal registry denial, missing/ambiguous attribution, and
   incomplete target cell remain hard refusals; the denial fixture is compiled
   registry state, not a denial-bearing policy supplied to the command;
4. missing source, source replacement, root escape, package-root substitution,
   and forged/cross-principal `SourceId` refuse before evaluation;
5. root-manifest computed-candidate declarations execute admitted spellings;
   absent spellings reject only at invocation without resolver probing;
6. inline diagnostic artifacts and receipts cannot pass production admission;
   audit does not access production or diagnostic prepared-cache namespaces;
7. stale producer, transform, graph, carrier, and engine versions refuse; any
   HBC carrier presented to diagnostic admission refuses categorically under
   inline-only v1, regardless of its version;
8. the repointed LLP 0019 loader corpus runs under audit with execution
   receipts proving the native path;
9. no compatibility-evaluator or SWC retirement-manifest needle is reached;
10. report bounds and digest determinism are tested under repeated,
    concurrent, and flooding runs; overflow sets the exact truncation counts;
11. audited code attempting to write the production cache, a diagnostic cache
    spelling, or its own report/receipt hard-refuses rather than would-deny;
12. an unadvertised tuple refuses before source capture, and a diagnostic
    receipt presented to production admission refuses;
13. only file entries are accepted in v1; `-e`, stdin, REPL, and `.load` audit
    forms refuse because they have no authenticated `SourceId`.

The denial/missing/cross-principal fixtures are release gates for LLP 0028
window close. Shape-only unit tests do not satisfy them.

## 8. Implementation sequence

1. Add the closed diagnostic snapshot/receipt schemas and mutation vectors.
2. Split graph capture identity from production authority so both builders use
   one resolver/source acquisition implementation with distinct sealed
   admission types.
3. Add the diagnostic artifact admission and inline native linker arm.
4. Connect `Runtime::from_audit_cli` and remove the unarmed-host compatibility
   bypass for advertised native targets.
5. Repoint the loader conformance runner and archive real-Hermes evidence.
6. Delete the audit reachability of the compatibility evaluator with LLP
   0028's window-close change.

## Open questions

1. Whether audit receipts are printed as JSONL, written to an explicit report
   path, or both. The canonical schema and digest are invariant.
2. Whether would-deny receipts become input to a future LLP 0014 grant-suggestion
   tool. V1 emits evidence only and never edits or generates authority.
