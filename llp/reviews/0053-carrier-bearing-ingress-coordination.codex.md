# LLP 0053 — codex family review artifact

## Round 1 (2026-08-24)
Reviewer: codex exec, gpt-5.6-sol @ ultra (read-only; effort verified in run log). Target: LLP 0053 r2 (sha256 032e0710be81393ca700c38063f54e2be1285c54d4d34c5ac8c139be7da1d06d, ibex revision 58899c284). Capsule: git-archive of origin/main; mutually blind. Orchestrator: Claude Fable 5 (author-side reviser, session exact-1d).

### Verbatim body

## Review result

Not ready. The one-JS-entry/sibling-setter direction is viable, and many cited facts are accurate, but r2 is not yet a complete fail-closed design.

### What checks out

- The current JS function requires exactly two arguments, so a three-argument caller fails loudly on the old implementation ([hermes_runtime.cc](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/src/engine/hermes_runtime.cc:16828)).
- The public ABI promises an inline callback on the runtime owner thread ([exact_runtime.h](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/include/exact_runtime.h:1960)).
- Current installation is owner-thread serialized, one-shot, and authorizes before mutating runtime or JSI state ([hermes_runtime.cc](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/src/engine/hermes_runtime.cc:16767)).
- A runtime claims one immutable `Arc<Host>` context. Replacing the ambient Host cannot tear the snapshot underneath that runtime. Consequently this is not fundamentally a threading race; it is a versioned-state-machine problem.
- Existing ingestion strictly parses JSON, rejects duplicate decoded keys, applies `deny_unknown_fields`, and explicitly permits only `/1` ([arming.rs](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/crates/capsec-semantics/src/arming.rs:292), [strict_json.rs](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/crates/capsec-semantics/src/strict_json.rs:160)).
- The armed digest covers all of `exactEmbedder`, and current builders embed it before nonce freshening and re-ingestion. That ordering is sound.

### Material concerns

1. **Attribution is not necessarily captured at the original call boundary.** The callback currently occurs inside a Promise executor, after payload extraction, a call-time lookup of global `Promise`, and Promise construction ([hermes_runtime.cc](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/src/engine/hermes_runtime.cc:16846)). The byte-view helper is duck-typed and invokes application-observable getters and proxy traps ([hermes_runtime_internal.h](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/src/engine/hermes_runtime_internal.h:2355)). Runtime nonce, principal/status, context, root projection, and carrier presence must be captured before any such property access. Carrier bytes should then be copied immediately. The implementation should also use a bootstrap-captured trusted Promise constructor or native promise primitive; otherwise the header’s unconditional inline guarantee depends on the mutable global binding, especially in diagnostic mode.

2. **There is no trusted Rust-to-C++ root-attribution bridge.** The proposed `carrier_capable` authorization returns only a boolean, as does the current hook ([host ABI](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/src/host/abi.rs:4397), [Host authorization](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/src/host/mod.rs:2606)). Nothing transfers authenticated `root_status/root_id` or the carrier-binding projection into runtime-owned storage. Borrowing from `exact_embedder_binding()` would also be unsafe because it returns an owned clone. The RFC needs a concrete caller-owned output/accessor or an installation-time copied immutable projection.

3. **The root ABI is unsafe while its grammar is deferred.** `const char *root_id` has no length, while JSON keys may contain embedded NUL. Two authenticated root IDs can therefore collapse at a C-string consumer. Add `root_id_len` and define UTF-8 byte semantics, or freeze a bounded no-NUL grammar before ABI v1.

4. **“Nothing in the attribution struct is app-suppliable” is false as written.** `carrier_status` is determined directly by application arity, and carrier bytes are explicitly untrusted application input. The right distinction is: engine attribution fields cannot be overridden by request data; carrier presence and bytes are merely engine-observed presentation facts and remain unauthenticated until Exact validates them.

5. **The v1/v2 state machine is underspecified.** Current lifecycle code keys everything off one v1-typed callback pointer: begin/finalize, one-shot checks, JS dispatch, rollback, sealing, and disposition activation. Adding an independent v2 pointer risks logically torn state or incompatible function-pointer dispatch. Require one owner-thread-only tagged state such as `None | V1 | V2`, with separate correctly typed callbacks and all lifecycle helpers operating on that state.

The required compatibility matrix is not closed by a sibling hook alone:

| Host state | Required result | Remaining r2 gap |
|---|---|---|
| Generic armed/no Exact binding | both setters `-8` | straightforward |
| `/1` | v1 only | v2 must reject through shared schema-aware authorization |
| `/2` | v2 only | the legacy hook must also become schema-aware; otherwise it still checks only manifest/context/operations |
| `/1` plus `carrierBinding`, or `/2` without it | arming refusal | requires a tagged Rust model or explicit cross-field validator; `Option<CarrierBinding>` is insufficient |
| `/2`, zero roots matching the runtime context | specified refusal/status | omitted; r2 defines one, multiple, and unarmed only |
| Unarmed | first setter wins | requires the shared tagged state |

Finalization currently reports only one schema-agnostic `EXACT_INGRESS` bit, so it cannot independently detect a `/1`/v1 versus `/2`/v2 mismatch.

6. **I2 schema and producer design are incomplete.** `rootGrantSets` needs a dynamic-key schema using `patternProperties` or `propertyNames` plus a value schema, `minProperties/maxProperties`, and nested Rust types with `deny_unknown_fields`. The root-ID and `grantSetId` grammars, cross-root uniqueness, and raw-hex-to-tagged-digest conversion are unspecified. The proposed singular producer `_v2` also misses that there are three Exact-bearing routes: prepare, ordinary build, and runtime-extension build ([exact_runtime.h](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/include/exact_runtime.h:2088)).

7. **Per-boot carrier pins are replayable under the existing install API.** Producers generate fresh nonces, but return persistable JSON. Direct installation accepts a matching snapshot/expected-identity pair again; the one-shot Host-context claim does not prevent replaying the pair into another Host. `/2` must either be bound to a non-replayable build/install transaction or define how stale pins refuse after grant-pool rotation.

8. **The I3 dependency claim is not structurally true, and I2 is insufficient.** It is true that r2’s chosen resolver obtains Exact root IDs from I2. But `rootGrantSets` maps root only to `app|agentIsolate`, not to a runtime, engine principal, or execution scope. Two same-context roots are permanently ambiguous; with one root, attribution is static context labeling and frame/principal machinery contributes nothing. The existing snapshot already has one authenticated `rootIdentity`, and LLP 0052 defines an owner-issued execution-scope binding carrying root/view/grant identity. Therefore:

   - coarse r2 I3 depends on I2 by construction;
   - I3 in general does not structurally require I2;
   - multi-root/view I3 requires LLP 0052’s execution-scope carrier or an equivalent authenticated principal/runtime-to-root join.

The supporting code claim is also overstated: `TimerEntry` and `NextTickEntry` carry principal stacks, but `FetchCallbackEntry` carries only a single principal.

9. **I4 targets the wrong subsystem and omits security-critical shape.** `capsec/session-semantics` is LLP 0024’s JavaScript declaration/session reference model, not CapSec stage ingestion ([model source](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/packages/ibex-devtools/src/scripts/session-semantics-model.mjs:1)). Runtime stage input is the strict `DecisionSet`/`DecisionContext` machinery, currently schema `/1` with no carrier-presentation field ([model.rs](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/crates/capsec-semantics/src/model.rs:1676)). A standalone JSON schema is not consumed automatically.

Candidate-to-commit linkage is not an implementation detail: a presentation ID/digest/replay relation changes the record shape and is necessary to prevent commit substitution. Likewise selector encoding determines canonical equality and no-row-collapse. The sketch also omits LLP 0052’s owner `bindingId`/view/grant identity. If the record retains its own `stage` beside `DecisionContext.stage`, exact equality must be enforced.

### r1 corrections

The RFC claims four folded corrections but explicitly identifies only three.

1. The `runtime-surface.json` correction is directionally right, but `capsec/generated/surface-inventory.md` explicitly says it is review output, not authority ([inventory](/private/tmp/claude-501/-Users-ccheever-projects-exact/7137c1ea-c8c0-4d61-9f8c-2f541d0f21e7/scratchpad/0053rev/capsule/capsec/generated/surface-inventory.md:1)). It also overlooks new C setter, Rust hook, producer, and ingress-inventory rows.

2. Replacing vague “real-input/no-user carriers” with code names is only partly successful because the Fetch stack claim is false and the resolver does not use the frame principal to select a root.

3. Adding I3→I2 is useful as a statement of r2’s chosen construction, but wrong as a structural claim and insufficient for multi-root attribution.

4. If the intended fourth correction is the inline-owner-thread evidence, the citation is correct, but the conclusion is too strong because current dispatch is Promise-mediated and getter-sensitive. If some other fourth correction was intended, r2 does not provide enough provenance to audit it honestly.

Before implementation, the RFC must decide: singleton-root-per-context versus genuine per-call root binding; the exact authenticated Rust/C++ projection and lifetime; root-ID wire encoding; non-replayable `/2` freshness; all three producer migrations; the I4 ingestion/versioning surface; and candidate/commit correlation.

Required conformance should cover the full snapshot/setter cross-product in both call orders and transaction modes, rollback/retry/off-owner/reentrant cases, proxy/getter/detached-buffer and replaced-Promise cases, zero/one/two roots per context, stale `/2` replay, strict unknown/duplicate/hybrid schema inputs, and candidate/commit substitution.

The document hash matches the supplied SHA-256. This capsule contains no `.git`, so revision `58899c284` and the claimed ancestry could not be independently verified. The workspace was read-only, so no `llp/reviews/` artifact was written.

VERDICT 0053: NOT READY + MATERIAL concerns. Binds to sha256 032e0710be81393ca700c38063f54e2be1285c54d4d34c5ac8c139be7da1d06d (ibex revision 58899c284).