# LLP 0002: The Host / Embedding ABI

**Type:** Spec
**Status:** Draft
**Systems:** Host ABI, Engine, Runtime
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Revised:** 2026-07-18 (Windows namespace and separator spellings of one
resolved filesystem object share one host-boundary authorization identity)
**Revised:** 2026-07-16 (ENG-24933 adds target-local Exact manifest validation/materialization and the public Exact-bound artifact preparer)
**Revised:** 2026-07-15 (ENG-25061 adds live indirect/star/namespace export links to native ModuleRecords); 2026-07-15 (ENG-25060 adds the generation-bearing native module-runner ABI and common eval/poll/runner/destroy drive gate); 2026-07-15 (LLP 0026 adopts owner-thread-only serialized runtime-driving entry points); 2026-07-15 (structured throw metadata now carries a closed, trap-free native Error class derived from the JSError's internal direct-prototype identity); 2026-07-15 (the independent C11 consumer now executes the adversarial structured-value and cancellation ABI cases at runtime in the conformance profile); 2026-07-14 (named aggregate/member output schemas and direction-exact nested callback contracts close ABI output membership); 2026-07-14 (ENG-24933 adds the dedicated binary Exact app/agent ingress and records the UI-worklet non-endowment); 2026-07-14 (source-derived ABI output signatures, roles, selectors, buffer pairs, ownership, Java/JNI declaration reconciliation, and opaque input-handle accounting); 2026-07-14 (Hermes-safe Error metadata and poll-checkpoint Promise rejection publication complete asynchronous-failure ABI v1, including schedule-time job provenance and top-level-await de-duplication); 2026-07-14 (owner-thread structured asynchronous-failure publication ABI v1 with rooted values, authenticated schedule-time attribution, and explicit bounded loss); 2026-07-14 (structured-evaluation result ABI v2 adds owned, length-bearing source-position records while keeping unimplemented safe-throw/source-position capability bits off); 2026-07-14 (source-derived capability inventory reconciliation with the complete typed worklet/Motion ABI); 2026-07-13 (the optional restricted-worklet surface now has an explicit source-artifact + typed-capture installer, fixed f32 invoke/output slots, a bounded typed app-runtime drain, and fixed rated-publish dispatch; earlier that day SharedValues moved from a raw slab pointer to typed validating callbacks); 2026-07-13 (bounded any-thread work-unit publication ABI, including timer due/undue scheduling identities); 2026-07-13 (structured-session import plan v2 carries the authenticated entry SourceId used by the private module cache); 2026-07-13 (normative structured-evaluation result ABI v1, migration rules, and the lowered-session extension's versioned static-import plan); 2026-07-13 (`allowed_hosts` is an outbound remote-host fence and no longer gates independent `network:listen` authority — ENG-24285); 2026-07-12 (armed runtimes reject the generic sync/async host-call bridge and its resolver before any callback/global/pending-state mutation); 2026-07-12 (production construction now requires a runtime-scoped armed Host context; the legacy constructor is non-executable and native fd/socket ownership is runtime-namespaced — ENG-24237, ENG-24244, ENG-24245); 2026-07-09 (host-boundary constraints: `root_dir`/`allowed_hosts` are now enforced fences, ENG-23876; previously 2026-07-07 for the capsec mode collapse); 2026-07-11 (generated capsec ABI inventory — ENG-24145); 2026-07-11 (immutable armed-snapshot install and Hermes handshake — ENG-24148)
**Related:** LLP 0000; LLP 0003 (Hermes engine bridge); LLP 0026 (module-runner owner-thread contract)

## Summary

This document describes the boundary that consumers (Exact, Snapback) link
against to embed Ibex. There are two halves: a small **C ABI** exposed from the
C++ Hermes adapter (`ex_hermes_*`) that creates and drives a runtime instance,
and a **Rust host surface** (`host::{install_host, Host}` plus the `ex_host_*` C
functions) that the engine calls back into for native capabilities. The
"narrow, stable contract" the root document names is the subset of this surface
treated as semver-major: the lifecycle/eval functions plus the host-call bridge
installer. The installer is executable only for explicitly unarmed diagnostic
embedders; its symbol and void signature remain stable, while armed runtimes
silently reject the generic channel. The full `ex_host_*` callback surface is
broader but is an implementation detail of how the engine reaches native
services.

This doc records what is observable in the extracted repo and owns the local
Ibex embedding contract map.

## The narrow consumer contract (semver-major)

The root document (LLP 0000 §Key invariants) names five C functions as the
stable contract. All five are declared in
`include/exact_runtime.h` and defined in `src/engine/hermes_runtime.cc`:

- `ExactHermesRuntime* ex_hermes_create(void)` is retained as the historical
  symbol but deliberately always returns NULL. Production construction is
  `ex_hermes_create_armed(snapshot_digest)`, which atomically claims the exact
  authenticated Host context and verifies structural lockdown, compartments,
  bootstrap seals, and frame attribution before returning a handle.
  `ex_hermes_create_diagnostic()` is an explicitly non-production constructor
  for isolated tests and foreground audit.
- `void ex_hermes_destroy(ExactHermesRuntime*)` `[observed]`
  (`include/exact_runtime.h:41`; `src/engine/hermes_runtime.cc:1455`).
- `int ex_hermes_eval(runtime, data, len, source_url, is_bytecode, out_value)`
  `[observed]` (`include/exact_runtime.h:56`; `src/engine/hermes_runtime.cc:1464`) —
  evaluates UTF-8 JS source or Hermes bytecode; on success `out_value` points to
  a malloc'd result string (or NULL for `undefined`); returns 0 on success,
  non-zero on error with the message in `out_value`.
- `void ex_hermes_free_string(char*)` `[observed]`
  (`include/exact_runtime.h:65`; `src/engine/hermes_runtime.cc:1809`) — frees any string the
  ABI returns; it is a thin wrapper over `free()`.
- `void ex_hermes_set_host_call(runtime, callback)` `[observed]`
  (`include/exact_runtime.h`; `src/engine/hermes_runtime.cc`) — installs the
  generic `__hostCall(op, argsJson)` JS function for an unarmed diagnostic
  runtime. It is a silent no-op for an armed runtime.

Treating these as the semver-major contract is asserted in LLP 0000; this doc
does not re-derive the inherited rationale `[inferred: the five are singled out
because they are the minimum surface a host must call to stand up and drive a
runtime — everything else is either a richer convenience (poll, timers,
debugger) or a callback the engine makes, not one the host makes]`.

## What actually crosses the boundary

The header `include/exact_runtime.h` declares far more than five functions
`[observed]` — runtime lifecycle, an event-loop poll API
(`ex_hermes_poll`, `ex_hermes_next_timer`, `ex_hermes_has_pending_tasks`,
`ex_hermes_notify_callback`, `include/exact_runtime.h:76-98`), iOS rendering
callbacks (`ex_hermes_set_dispatch_callback` and siblings,
`include/exact_runtime.h:109-195`), a
debugger surface (`include/exact_runtime.h:216-249`), and GC/heap introspection
(`include/exact_runtime.h:256-264`).
These are part of the embedding API but are convenience/optional layers, not the
minimal contract `[inferred]`.

### Structured evaluation result ABI v2 (normative amendment)

`EX_HERMES_STRUCTURED_EVAL_ABI_VERSION` is `2`. Structured evaluators receive a
caller-owned `ExHermesEvaluationResult` initialized by
`ex_hermes_evaluation_result_init`. They return `-1` only when that caller-owned
result has an incompatible `abi_version` or `struct_size`; otherwise they return
`0` and write a typed outcome, including an engine-fault outcome. JavaScript
values are never converted to the legacy `char **out_value` representation and
thenables are never assimilated.

The normative C field sequence is the declaration in
`include/exact_runtime.h`, using ordinary platform C alignment and no packed
layout:

| Structure | Fields in order |
| --- | --- |
| `ExHermesOwnedBytes` | `uint8_t *data`; `size_t length` |
| `ExHermesSourcePosition` | `ExHermesOwnedBytes source_label`; `uint32_t line`; `uint32_t column` |
| `ExHermesValueHandle` | `uint64_t runtime_nonce`; `uint64_t handle_id` |
| `ExHermesEvaluationResult` | `uint32_t abi_version`; `uint32_t struct_size`; `uint32_t outcome_tag`; `uint32_t fault`; `uint64_t work_target_id`; `ExHermesValueHandle value`; `uint32_t throw_metadata_status`; `uint32_t throw_metadata_fields`; `uint32_t throw_error_class`; `int32_t lifecycle_exit_code`; `uint32_t capability_flags`; `ExHermesOwnedBytes message`; `ExHermesOwnedBytes stack`; `ExHermesSourcePosition *positions`; `size_t position_count` |

On the supported 64-bit ABI this gives result offsets `0, 4, 8, 12, 16, 24,
40, 44, 48, 52, 56, 64, 80, 96, 104` respectively and
`sizeof(ExHermesEvaluationResult) == 112`; `ExHermesValueHandle` is 16 bytes,
each `ExHermesOwnedBytes` is 16 bytes, and `ExHermesSourcePosition` is 24 bytes
with its line and column at offsets 16 and 20. A target with a different pointer
width uses its ordinary C ABI layout and must pass its own exact `sizeof` in
`struct_size`; it may not copy the 64-bit offsets.

`outcome_tag` has six explicit discriminants: `1 Empty`, `2 Value`, `3
Throw`, `4 Cancelled`, `5 Lifecycle`, and `6 EngineFault`. The first five are
the language/session outcomes required by LLP 0024; the sixth is the separate
engine-fault branch that makes a native failure distinguishable from a thrown
JavaScript value. `fault` is zero except for `EngineFault`, where values `1`
through `17` are the named `EX_HERMES_EVAL_FAULT_*` reasons in the header.
Unknown tags, fault codes, capability bits, metadata bits, or illegal payload
combinations are protocol errors and must not be treated as a best-effort
result.

Payload and ownership rules are:

- `work_target_id` is nonzero for an admitted/evaluated submission, including
  its recoverable throw or later engine fault; zero means no work target was
  admitted. It is also the exact identity accepted by the any-thread
  cancellation API.
- `Value` and `Throw` carry a nonzero `(runtime_nonce, handle_id)` rooted in the
  producing runtime. A handle never crosses a process boundary, becomes stale
  when its runtime is destroyed, and is rejected on a wrong owner thread or
  runtime. The owner releases it exactly once with `ex_hermes_value_release`,
  or settles a pending display receipt with `ex_hermes_session_display_ack`.
- `message` and `stack` are independently length-bearing byte buffers, each
  capped at `EX_HERMES_SAFE_TEXT_MAX_BYTES` (16 KiB) of valid UTF-8 including
  the static `EX_HERMES_SAFE_TEXT_TRUNCATION_MARKER`. Embedded NUL is data, not
  a terminator. A present buffer is allocated by the native side and freed by
  `ex_hermes_evaluation_result_dispose`; an absent buffer is `{NULL, 0}`.
  Disposing does not release a value handle.
- `positions` is either `{NULL, 0}` or a native-allocated array whose every
  record owns its explicit-length UTF-8 `source_label`; `line` and `column` are
  one-based and nonzero. Result disposal frees every nested label and then the
  array. The third `throw_metadata_fields` bit is present only for a nonempty
  position array.
- `throw_metadata_status == Captured` permits message/stack/positions presence
  bits 0–2 plus independent message/stack truncation bits 3–4 in
  `throw_metadata_fields`; a truncation bit requires its presence bit and the
  exact trusted marker suffix. `Unavailable` carries no bits or owned payload.
  Throw metadata supplements the raw thrown handle and never replaces or
  coerces it.
- `throw_error_class` is the closed `ExHermesErrorClass` discriminant. Hermes
  derives it by comparing an internally branded JSError's **direct** prototype
  pointer with the pinned intrinsic Error prototypes. It never reads
  `.name`/`.constructor`, invokes a trap, or walks a mutable prototype chain;
  arbitrary values and subclass prototypes are `Unclassified`. Unknown values
  are protocol errors, and `Unavailable` metadata must carry `Unclassified`.
- `Lifecycle` alone carries `lifecycle_exit_code`. `capability_flags` advertises
  the exact supported stratum (`Base`, safe throw capture, source positions,
  rich inspection); a consumer must require the strata it uses.
- Allocation failure before an outcome value is rooted produces the named
  out-of-memory engine fault with no fabricated payload. Once a Throw handle
  is rooted, failure while capturing or copying optional safe metadata keeps
  the Throw and returns empty `Captured`/`Unclassified` metadata when
  `SafeThrow` was advertised; that no-throw fallback cannot cross the C ABI or
  rewrite the language outcome. Cancellation racing a normal return has one
  terminal typed outcome for the exact work target; stale-target cancellation
  cannot land on a successor.

The pinned Hermes patch stack exposes both trap-free raw thrown-value capture
and engine-owned Error metadata extraction. The latter reads only an actual
Hermes `JSError`'s own plain message slot, internal stack records, and direct
prototype pointer; it never consults JavaScript `.stack`, `.name`,
`.constructor`, accessors, proxies, `prepareStackTrace`, a mutable prototype
chain, or string coercion. The evaluator therefore advertises `Base |
SafeThrow`: an ordinary Error carries its closed class plus captured
message/stack fields, while an arbitrary thrown value is still the original
rooted handle with `Captured`, `Unclassified`, and no fabricated fields.
Lowered session source maps are supplied to Hermes' source-map-aware evaluator,
but the independent owned source-position records remain unimplemented, so
`SourcePositions` stays off.

`ex_hermes_value_stage1_text` returns an additional exact `0`/`1`
`out_truncated` scalar. String, Symbol, and BigInt text is produced directly
from bounded engine storage and is never larger than 16 KiB including the
trusted marker. `ex_hermes_value_safe_throw_metadata` likewise returns
`metadata_fields` alongside the closed error class and owned buffers, so direct
throws and asynchronous failures carry identical independent truncation facts.
All outputs, including these scalars, are zeroed before wrong-thread,
stale-handle, unavailable-profile, allocation-failure, and engine-fault exits.

The source buffers consumed by structured diagnostic/session evaluators are
borrowed, explicit-length UTF-8. Empty source is valid and embedded NUL in
source is preserved as a source byte; source labels are explicit length but
reject NUL. The diagnostic evaluator refuses armed runtimes. Production armed
source instead binds an opaque session token, admits a linear credential, and
continues through `ex_hermes_eval_lowered_session`; it never falls back to the
legacy evaluator or diagnostic route.

**Migration.** Existing diagnostic embedders may continue using the unchanged
five-function legacy surface, including `ex_hermes_eval`'s malloc'd string
result. An embedder adopting or migrating armed sessions must initialize a v2
structured result, branch on `outcome_tag` rather than the function status,
preserve and release runtime-scoped handles, dispose all owned metadata
payloads, and use the exact work target for cancellation/display settlement. It
must not cast a structured
result to the legacy `char **out_value`, infer throw-vs-fault from text, or retry
an armed request through `ex_hermes_eval`. LLP 0000 records this explicit
semver-major migration surface while retaining the five legacy declarations.

**Independent C evidence.** The C11 consumer in
`src/engine/exact_runtime_c_abi_check.c` owns both its public-ABI calls and its
behavioral assertions. In the conformance-observer profile it executes the
embedded-NUL output, typed allocation-failure/no-payload, stale, wrong-runtime,
wrong-thread, exact-once release, runtime-destruction cleanup, and
normal-return cancellation-race cases. Rust supplies only the foreign thread
and runtime-driving orchestration. The deterministic allocation and destruction
controls are conformance-only symbols: they are neither declared by this public
header nor compiled into production artifacts `[observed]`
(`src/engine/exact_runtime_c_abi_check.c`; `src/engine/hermes_runtime.cc`;
`src/engine/mod.rs`; `src/bin/ibex/engine/hermes.rs`).

### Native work-unit publication ABI v1

Authenticated session controllers consume engine work boundaries through
`ex_hermes_take_work_unit_event`, an any-thread, non-waiting operation. Its
caller-owned `ExHermesWorkUnitEvent` has this normative field order under the
ordinary C ABI: `uint32_t abi_version`, `uint32_t struct_size`, `uint32_t kind`,
`uint32_t phase`, `uint64_t target_id`, `uint64_t scheduling_id`. On the
supported 64-bit ABI the offsets are `0, 4, 8, 12, 16, 24` and the size is 32.
`EX_HERMES_WORK_UNIT_EVENT_ABI_VERSION` is `1`.

Kinds are `1 Evaluation`, `2 Callback`, `3 Timer`, `4 MicrotaskDrain`, and `5
CompletionQuery`. Phases are `1 Due`, `2 Undue`, `3 Begin`, `4 Suspended`, and
`5 End`. A Begin/Suspended/End transition carries a nonzero, runtime-monotonic
`target_id`. Timer Due/Undue instead carries `target_id == 0` and a nonzero
native scheduling identity in `scheduling_id`; this distinguishes two ready
timers before either has a cancellation target. An evaluation uses its
authenticated submission ordinal as `scheduling_id`; other non-timer units may
use zero.

The take result is `Empty`, `Available`, `Overflow`, or `Failed`. The native
queue has a fixed bound and never waits for consumer progress or queue space.
Overflow is sticky and fail-loud: the consumer must dispose the worker rather
than reconstruct a live-unit set from an active-target poll. The queue owns no
JSI values or caller memory. The existing any-thread active-target and
cancellation calls now name only the currently executing published unit;
suspended evaluations and due-but-not-begun timers return no active target, and
the target mutex prevents a stale request from landing on a successor
`[observed]` (`include/exact_runtime.h`; `src/engine/hermes_runtime.cc`;
`src/bin/ibex/engine/hermes.rs`; [LLP 0024](./0024-structured-evaluation-and-session.spec.md#6-evaluation-outcomes-and-the-abi);
[LLP 0025](./0025-terminal-session-ownership.spec.md#6-interruption-and-cancellation)).

### Native asynchronous-failure publication ABI v1

Authenticated engines report an uncaught background JavaScript throw through
`ex_hermes_take_async_failure_event`; they do not turn it into a poll error,
write its raw message to stderr, or set an exit code. The take is non-waiting
and owner-thread-only because an Available record transfers a live JSI value
handle. Its caller-owned `ExHermesAsyncFailureEvent` has this normative field
order under the ordinary C ABI: `uint32_t abi_version`, `uint32_t struct_size`,
`uint32_t kind`, `uint32_t principal_status`, `ExHermesValueHandle value`,
`uint64_t host_context_id`, `uint64_t owning_principal_id`, `uint64_t event_id`,
`uint64_t associated_evaluation`, `uint64_t dropped_count`. On the supported
64-bit ABI the offsets are `0, 4, 8, 12, 16, 32, 40, 48, 56, 64` and the size
is 72. `EX_HERMES_ASYNC_FAILURE_EVENT_ABI_VERSION` is `1`.

Kinds are `1 Timer`, `2 NextTick`, `3 Microtask`, `4 NativeCompletion`, and `5
NativeTask`. Principal status is a closed discriminator: `1 Authenticated`, `2
Unavailable`, or `3 Ambiguous`. An authenticated owner is the principal
captured by the scheduling source, validated on the Rust side against the
exact `host_context_id` and value-handle runtime generation. Missing or
ambiguous attribution remains explicit; a consumer must never substitute the
root principal. `event_id` names the timer, next-tick, microtask-drain, or
native scheduling source where one is available. `associated_evaluation` is
the authenticated submission ordinal inherited from the scheduling chain, or
zero when no association is available. The runtime generation plus its
claimed Host context and per-session worker channel bind the record to its
session; bearer session credentials do not enter the event.

The take result is `Empty`, `Available`, `Dropped`, or `Failed`. Available
transfers exactly one nonzero value handle to the caller, which must render and
release it on the live runtime owner thread before any process boundary. Only
the bounded, trap-free inspection result crosses to the supervisor, where the
session layer assigns a sequence number at receipt. The native queue has a
fixed bound and never waits. Once it fills, later failures coalesce into one
sticky pre-receipt loss window until the owner takes a `Dropped` marker carrying
its nonzero `dropped_count`; values in that window are never rooted, and a
handle whose queue insertion fails is released immediately. This prevents a
newer event from overtaking an older loss marker and makes loss visible without
inventing a worker-side session sequence.

The native reporter covers uncaught throws escaping timers,
`process.nextTick`, guarded Promise/microtask jobs, and native task/completion
callbacks. The patched Hermes job queue captures scheduler principal, a
monotonic job identity, and the associated evaluation when each job is enqueued;
the host consumes the exact failed-job context after an escaping reaction rather
than inferring an owner at report time. Hermes' Promise rejection hooks retain
the exact Promise and reason in a bounded owner-thread queue until the end of the
poll iteration, cancel by Promise identity when a handler attaches first, and
consult admitted JavaScript/process listeners before publishing. The private
top-level-await settlement rejection handler attaches to that same Promise, so
its evaluation `Throw` outcome cancels the pending rejection record and is never
duplicated as a background event. `ex_hermes_value_safe_throw_metadata` returns
the rejection-time engine metadata before the consumer renders and releases the
rooted value. No path in the authenticated reporter writes the raw value, returns
a fatal poll status, or sets an exit code `[observed]`
(`include/exact_runtime.h`; `src/engine/hermes_runtime.cc`;
`src/engine/hermes_structured.rs`; `src/bin/ibex/engine/hermes.rs`;
[LLP 0024](./0024-structured-evaluation-and-session.spec.md#9-asynchronous-failures)).

### The structured lowered-session extension

Authenticated session execution uses an explicitly versioned extension to the
embedding surface rather than widening the five-function semver-major
contract. `ex_hermes_eval_lowered_session` accepts caller-borrowed,
explicit-length UTF-8 buffers for the lowered wrapper, composed source map, and
source label, a checked declaration inventory, and an
`ExHermesSessionImportPlan`. The outer import plan and every nested static-import
and binding row carry both `abi_version` and `struct_size`. Native validation
requires the current exact layout, contiguous binding ranges, valid
kind/name combinations, and one-to-one agreement between published import
bindings and import declarations before it compiles or mutates session state
`[observed]` (`include/exact_runtime.h`; `src/engine/hermes_runtime.cc`).

The static-import plan contains the authenticated entry's canonical VFS
SourceId and file arguments plus logical referrer, specifier, binding kind, and
imported/local-name data produced by checked AST lowering. It contains no host
path, loader function, or caller-selected resolver. Before materializing an
edge, native code reserves the direct entry under that SourceId in the
bootstrap-captured private module cache. Self-import, relative imports,
`import.meta`, `require.main`, and the direct entry therefore share one typed
identity without treating the private host path as a cache key. Native code
then resolves every edge through the armed Host, passes the authenticated full
module record to the private loader, and roots the returned binding values. All
resolution, module evaluation, and default/named/namespace property reads
complete before the declaration transaction starts. Native then repeats
declaration feasibility, begins the transaction, and initializes the checked
read-only import cells. A resolution, authorization, module-evaluation, or
binding-read failure therefore publishes no declaration `[observed]`
(`src/engine/hermes_runtime.cc`; `src/engine/bootstrap/module-loader.js`;
`src/host/abi.rs`).

`EX_HERMES_SESSION_IMPORT_PLAN_ABI_VERSION` is currently `4`. Version 2
introduced the borrowed, explicit-length SourceId used for the direct-entry
cache reservation; the current v4 tail also carries the generated-entry
provenance record and closed structured-source kind. Native validation requires
the exact v4 size and rejects older or partially initialized layouts. The independent
C11 consumer `src/engine/exact_runtime_c_abi_check.c` compile-checks the version,
field layout, and exact function-pointer type in addition to the Rust/C++
consumers. Input pointers remain borrowed for the call; structured result-owned
byte buffers retain the ownership rules described below. This extension is
versioned and fail-closed but is not added to LLP 0000's narrow five-function
consumer contract; promoting it to that semver-major list would require an LLP
0000 amendment.

### Runtime-driving thread contract

Every entry point that drives one Hermes runtime — including creation,
`ex_hermes_eval`, event-loop polling and callback delivery, module-runner
ingresses, and destruction — is owner-thread-only and serialized per runtime.
An off-owner or concurrent drive refuses with a stable error before touching
JSI, graph state, or event-loop state. Same-thread nesting into a *different*
runtime remains permitted and restores the outer runtime's attribution context
on unwind; recursive or overlapping drive of the same runtime is not. A nested
runtime begins with its own root/no-native principal boundary: the guard saves,
clears, and restores the outer legacy module id, native callback principal, and
typed-filesystem principal stack as well as the VM attribution pointer and Host
context. Bare numeric principal ids are never translated between runtime/Host
generations; an intentional cross-runtime delegation requires an explicit
authenticated capability. The same dynamic boundary wraps construction before
trusted bootstrap and registered teardown/cleanup; worker scopes select no VM
pointer off-owner and install only their explicitly captured typed principal
stack.

This is the normative contract adopted with LLP 0026. ENG-25060 applies one
registry-backed refusal guard to eval, poll, module-runner operations, and
generation-bearing destruction. It checks liveness and nonce without first
dereferencing the caller's pointer, then owner thread and same-runtime active
drive. Same-thread nested different-runtime entry remains valid because active
drive state is per registry generation. The remaining public JSI-mutating
setter inventory must either use this gate or retain an equivalent explicit
owner check; the generated ABI inventory prevents an unreviewed new route.
Construction and the cleanup phase after the teardown refusal check use the
same runtime/Host/principal dynamic-boundary semantics even though an
unregistered or Closing runtime cannot enter the registry-backed drive guard.
Pre-registration bootstrap evaluation uses a private construction-only helper;
the public `ex_hermes_eval` symbol has no bootstrap exception and therefore
never inspects a caller-supplied runtime pointer after gate refusal. The
any-thread callback-backlog observation is not a runtime drive: it instead
holds the runtime registry's live-generation pin across both queue reads so a
concurrent teardown cannot free their mutexes between validation and access.

### Native module-runner ABI

The provisional `ex_hermes_module_*` and `ex_hermes_graph_context_*` family is
native-only: no symbol is installed on the JavaScript global. Its fixed
`ExactModuleRunnerHandle` payload is an opaque `(runtime nonce, graph
generation, registry id)` capability. Every use checks all three before JSI;
release, wrong-runtime use, destroy/recreate, and address reuse therefore fail
without dereferencing stale payload state.

Rust's safe compiler entry accepts only `VerifiedModuleArtifactV1`, then passes
the admitted semantic digest and factory bytes to the C ABI. Principal,
compartment, generation, and `GraphEvaluationContext` come from native graph
state rather than artifact JavaScript. The engine captures the real Function
constructor and Domain binder before lockdown, never republishes them, and
compiles package bytes through a trampoline whose authenticated Domain is bound
before invocation. Hermes consequently propagates both principal and
compartment to the package factory before compiling it. Opaque factory,
context, and ModuleRecord handles own all JSI values and are destroyed on the
runtime owner thread.

ModuleRecord setup is deliberately split into native-only operations:
declare the record's canonical export-cell set, link indirect, resolved-star,
and namespace exports as live views of authenticated target record/cell
handles, bind authenticated imports to those handles, instantiate the factory,
then run `declare` and `execute`. Instantiation creates one stable
null-prototype, non-extensible
namespace whose enumerable getters read checked cells. Uninitialized reads
throw the TDZ error; export updates mutate the same cells, so later importer
and re-export reads observe live values. Package factories cannot write through
an indirect export. Import lookup keys and all link targets are installed by
the native graph owner rather than accepted from package JavaScript.

CommonJS uses a distinct native record kind and a source-goal-stamped factory
handle. Record creation publishes the initial `module.exports` object before
body execution; `require` can reach only native-installed CommonJS record
links, and re-entry reads the target's current `module.exports`, including an
early replacement. Success retains the final value. A throw deletes the native
record, releases its context reference, and makes its opaque handle stale so a
later request must create a fresh record. After success, one native operation
creates an ESM adapter ModuleRecord whose `default` and `module.exports` cells
hold the final value and whose detector-approved named cells are snapshots.

The CapSec registry classifies graph/context construction and link setup as
authority-control-plane operations, release as authority release, factory
compile/instantiate/declare/execute, CommonJS evaluation, and CommonJS adapter
creation as closed `vm:evaluate`, and diagnostic namespace serialization as
closed `runtime:inspect`. The runner can acquire evaluator or inspection
authority only through the exact graph authorization profile registered by
ENG-25062; an absent or mismatched profile refuses rather than falling back to
a generic host bridge.

This family is a provisional extension, not an addition to LLP 0000's five-
function semver-major minimum. `ex_hermes_try_destroy(runtime, nonce)` is the
generation-bearing, status-returning lifecycle companion; the legacy void
destroy symbol delegates to it and reports owner/reentrancy refusal.

### Restricted-worklet SharedValue access

The optional UI-worklet embedding surface no longer exports or retains a raw
pointer to Exact's SharedValue storage. The embedder installs
`ExWorkletSharedValueReadCallback` and
`ExWorkletSharedValueWriteCallback` with
`ex_worklet_bind_shared_value_accessors`; every access carries the typed
`(slot, generation, epoch)` identity and any nonzero host verdict is a defined
stale/no-op `[observed]`
(`include/exact_runtime.h`; `src/engine/hermes_runtime_worklet.cc`). The
callbacks execute synchronously on the restricted runtime's owning UI thread;
they must not enter the app runtime or block on another domain. This is an
optional convenience surface, not part of the five-function semver-major
contract above.

### Restricted-worklet typed Motion ABI

The optional M6 embedding surface admits one explicit artifact format:
`EX_WORKLET_INSTALL_SOURCE_UTF8`. `ex_worklet_install_typed` evaluates a
function expression with an install-time vector of finite f32/boolean captures
or complete SharedValue identities and returns a stable content+capture hash;
same-generation reinstallation reuses the resident function `[observed]`
(`include/exact_runtime.h`; `src/engine/hermes_runtime_worklet.cc`). Unknown
formats and capture kinds fail closed. The source decision belongs to Exact's
LLP 0099/0297 contract; Ibex keeps the format discriminant explicit so adding
HBC later is an additive, testable ABI choice rather than byte sniffing.

`ex_worklet_invoke_typed` accepts at most 16 caller-owned f32 inputs and 16
caller-owned output slots. Worklet code writes output with
`worklet.output(index, value)` and can enqueue at most eight finite f32
arguments with `worklet.runOnJS(callbackIdentity, ...args)`. The successful
host path allocates no strings, JSON, or result container. Scheduled calls sit
in a fixed 256-record ring; overflow drops the oldest record and increments the
read-and-clear diagnostic counter. Each record carries stable source identity,
per-source sequence, and runtime generation `[observed]` (same sources).

The embedder drains those records into caller-owned storage, then calls
`ex_hermes_dispatch_worklet_calls` only on the app runtime's owning thread.
Compatibility JSON batches use `ex_hermes_dispatch_worklet_json_batch`. Both
look for app-installed dispatcher functions and return the standard defined
no-op result when absent. `ex_hermes_dispatch_motion_rated_publish` similarly
forwards one fixed, finite eight-value sample to the app-installed rated
publication dispatcher; pacing and lifecycle fencing remain embedder policy.
These are optional convenience surfaces, not additions to the five-function
semver-major contract.

### Capability-security ABI inventory

LLP 0021 adds a source-derived security inventory across the public ABI
families: the Rust/native `ex_host_*` callbacks, the `ex_hermes_*` embedding
surface, the `ex_worklet_*` surface, and the Android Java/JNI bridge. The
current generator finds 143 `ex_host_*`, 70 `ex_hermes_*`, 15 `ex_worklet_*`,
one `ex_android_*`, 39 Java, and 8 JNI surfaces (276 total). It groups source
definitions by target variant, including weak/default stubs, rather than
maintaining a copied symbol list `[observed]`
(`packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs`).

Each inventory row also carries the exact source-derived return and parameter
contract for every definition. A non-void return creates the real
`[[return]]` output slot; a void return does not create a synthetic slot.
Const pointers are borrowed inputs, scalar parameters are inputs, and mutable
pointers remain unknown unless their signature or a strict `@abi-output`
annotation proves an output/inout role and ownership. Nominal runtime/file
handles and callback-context pointers are borrowed inputs (destroy/free/close
entries are callee-consuming inputs), while the Java declaration is the source
of output membership and must agree with any bound JNI descriptor.
Buffer/length pairs, callback payloads, output selectors, and release functions
are explicit. Named C aggregate layouts expand only source-annotated members
actually written by a definition; nested owned bytes, value handles, and source
position arrays retain distinct member aliases and release/length metadata.
The result init/dispose helpers expose only the direct members they clear and
do not fabricate element payloads for the reset `positions` collection.
Callback registrations bind their complete nested signatures, including the
native-to-embedder payload direction and the embedder-to-native return/out
direction. Only native-to-embedder payloads are catalog outputs. The deprecated
raw-pointer watchdog registration remains structural because its implementation
provably never invokes the callback.

This produces 226 membership-complete output-bearing surface accounts and 50
structural-only accounts, with no unresolved membership accounts. The 226
output-bearing accounts expand to 417 catalog selectors (208 returns, 150 out
members, and 59 callback payloads). Fifty-one output-bearing accounts have
membership-complete pointer slots whose ownership still blocks safe execution.
Runtime observations of a pointer or aggregate value do not promote such a row
while ownership remains unbound. Executor fixture
coverage is evidence for a selected row, never the authority for whether the
row exists `[observed]` (`packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs`).
Those rows are classification and fixture obligations, not a conformance claim;
every WP1 target cell remains unsupported.

### The `__hostCall` bridge — the generic host channel

On an unarmed diagnostic runtime, `ex_hermes_set_host_call` installs a JSI host
function named `__hostCall` on the global object `[observed]`
(`src/engine/hermes_runtime.cc`). It is the generic, string-typed channel from
JS to the host:

- JS calls `__hostCall(op, argsJson)` with two strings `[observed]`
  (`src/engine/hermes_runtime.cc:1773-1774`).
- The host callback returns a malloc'd C string whose **first byte is a status
  sigil**: `+` = success (the remainder is a JSON payload), `-` = error (the
  remainder is the message, raised as a `jsi::JSError`) `[observed]`
  (`src/engine/hermes_runtime.cc:1781-1804`). A NULL or empty return becomes JS `null`.
- The C++ side frees the returned string with `free()` and `JSON.parse`s the
  success payload back into a JS value `[observed]` (`src/engine/hermes_runtime.cc:1785,
  1802-1804`).

On the JS side, the runtime wrapper calls `globalThis.__hostCall` directly and
throws if it is not installed `[observed]`
(`packages/ibex-runtime-js/src/core/host-call-bridge.ts:1-16`).

Armed runtimes never expose `__hostCall` or `__hostCallAsync`. Both void setter
ABIs return before storing the callback or mutating the global object, so a
post-lockdown replacement attempt is also a silent no-op. Likewise,
`ex_hermes_resolve_host_call` checks liveness and the armed bit while the
runtime registry is pinned and returns before looking up, removing, or invoking
a pending callback. These functions keep their existing void signatures: the
fail-closed result is intentionally observable as absence/no completion, not a
new ABI return code. Production callers must use dedicated, capability-aware
native APIs. Existing camera and accessibility wrappers already treat an absent
generic bridge as unavailable rather than granting fallback authority
`[observed]` (`src/engine/hermes_runtime.cc`;
`packages/ibex-runtime-js/src/camera/index.ts`;
`packages/ibex-runtime-js/src/core/accessibility.ts`).

### The Exact embedder ingress

Exact app and agent isolates use a dedicated binary channel rather than the
diagnostic string bridge. The native host calls
`ex_hermes_set_exact_host_call_async` once with an explicit context kind and a
strictly increasing set of nonzero 32-bit operation IDs plus the tagged digest
of Exact's operation manifest. In an armed runtime, the snapshot must carry an
`exact/host-operation-endowments/1` binding and protect the manifest as the
conditional `exact-operation-manifest` artifact. Ibex compares the manifest
digest, context kind, and complete canonical ID set against that authenticated
binding before storing native callback state, mutating JSI, or finalizing the
package baseline. A generic armed snapshot without the binding, a mismatched
digest, and narrowed or widened endowments all return `-8` before publication.
The runtime then
exposes only
`exact.invokeHostAsync(operationId, ArrayBuffer | ArrayBufferView) ->
Promise<Uint8Array>`.
Operation names and JSON envelopes do not cross Ibex's boundary, and a JS
caller cannot ask for an operation absent from its immutable endowment set.
Ibex creates one stable lowercase `exact` object before the package baseline is
captured. Successful installation defines `invokeHostAsync` as non-writable and
non-configurable on that shared object and, when the compartment finalizer is
still pending, completes that one-shot finalization in the same owner-thread
setter call. The finalizer hook is then deleted, so package code cannot refresh
or substitute the baseline. A failed refresh leaves no replaceable method.
The setter rejects malformed or duplicate/reordered endowments and rejects any
attempt to replace a successful installation `[observed]`
(`capsec/schema/armed-snapshot.schema.json`; `include/exact_runtime.h`;
`src/engine/hermes_runtime.cc`; `src/host/abi.rs`).
Because installation creates and publishes JSI values, the setter is an
owner-runtime-thread operation. An off-owner call returns `-7` before reading
or mutating JSI or publishing any endowment `[observed]`
(`include/exact_runtime.h`; `src/engine/hermes_runtime.cc`).
The common generation-backed drive gate also returns `-9` for a stale runtime
or same-runtime reentrant installation attempt, before endowment authorization
or baseline publication. This setter-specific code preserves the established
`-7` consumer contract instead of leaking the generic drive-status numbering.
The source inventory nevertheless classifies the JS invocation as closed
`ipc:channel` until the native set and its app/agent context are authenticated
by the armed artifact; the existence of a caller-selected allowlist is not
conformance evidence.

`ex_hermes_resolve_exact_host_call` is the only completion route for this
channel. Its call IDs are runtime-generation-scoped, single-use capabilities;
unknown, stale, replayed, and already-completed IDs are ignored. Completion
copies binary bytes onto the runtime thread through the ordinary native-worker
pin and callback queue. This route is valid for armed runtimes and does not
make either generic `__hostCall` global reachable again.

The channel is bounded to 1,024 pending calls and 16 MiB in either direction.
The native callback runs inline on the runtime owner thread, borrows its input
bytes only for that invocation, and must return promptly. Its callback and
opaque context live until runtime destruction; the embedder cancels outstanding
native work at destruction and never resolves using a destroyed runtime
pointer. Malformed/oversized completions consume and reject the call rather
than stranding its Promise.

The context model is deliberately closed:

- an **app** runtime receives the exact app operation-ID set authenticated by
  its armed artifact (or selected by its explicitly diagnostic host);
- an **agent** runtime receives the separately authenticated agent operation-ID
  set;
- a **UI worklet** cannot install this ingress at all. Its complete endowment
  remains the typed SharedValue/Motion ABI described above.

The native callback remains part of the trusted embedder. Exact owns the
operation registry, payload schemas, and the narrower app/agent sets. Ibex now
authenticates their opaque manifest digest and numeric projection; the normal
Ibex-to-Exact packaging path must supply that protected binding before an Exact
target may advertise. The
existence of this ABI by itself is not target-conformance evidence and does not
relax the unsupported-target refusal.

These three new symbols (`ex_hermes_set_exact_host_call_async`, its resolver,
and `ex_host_prepare_armed_embedder_artifacts`) are a public, provisional
extension for the pinned Exact consumer, not an expansion of LLP 0000's five-
function semver-major minimum. Until this Draft spec is accepted, a breaking
change requires an atomic Ibex commit plus Exact submodule/consumer update; it
must never silently preserve an older ambient bridge.

## The Rust host surface

The engine declares the `ex_host_*` callbacks as `extern "C"` functions on the
C++ side `[observed]` (`src/engine/hermes_runtime.cc`). They are implemented in
Rust in `src/host/abi.rs`. A compatibility Host remains process-visible for
unscoped diagnostic calls, but each live Hermes runtime owns a claimed immutable
Host-context ID. Engine entries and worker callbacks select that context for
their dynamic scope, so installing runtime B cannot replace runtime A's policy.

### Installing the host

- `host::install_host(host: Host)` updates the compatibility default and adds
  an immutable context row. Runtime construction claims one row; engine entry,
  asynchronous completion, and native-resource checks use that runtime's
  context rather than whatever was installed most recently.
- `ex_host_install()` installs only a closed, unarmed compatibility host. A
  production embedder must replace it with `ex_host_install_armed(...)` and
  create Hermes with the authenticated digest; absence or mismatch refuses.
- `EXACT_HOST_ABI_VERSION` is `1`, returned by `ex_host_version()` `[observed]`
  (`src/host/abi.rs:62, 579-581`).

### The `Host` type

`Host` (`src/host/mod.rs:71-76`) holds a `HostConfig`, an
`Arc<CapabilityManager>`, and an `Arc<ModuleLoader>` `[observed]`. Constructors
include `Host::new(config)` and `Host::new_armed(...)`; the latter is the
production constructor. `HostConfig` and `ex_host_install()` are closed by
default and do not parse a policy path. `Host` exposes
`check_capability`, `is_allow_all`, and `resolve_module` `[observed]`
(`src/host/mod.rs:146-174`). `SecurityMode` is `Permissive | Audit | Enforce`
`[observed]` (`src/host/mod.rs:37-45`); the legacy `strict`/`capability`
strings parse to `Enforce` for compatibility. The C++ bridge short-circuits
capability checks when `ex_host_is_allow_all()` returns 1 `[observed]`
(`src/host/abi.rs:597-599`).

### Host-boundary constraints

`HostConfig.root_dir` and `HostConfig.allowed_hosts` are the embedder's
**host-boundary fence** — a restriction plane distinct from the LLP 0013
capability policy (`src/host/mod.rs`, `src/host/capability.rs::fence_denial`,
ENG-23876; both fields were previously stored but never consulted, a fail-open
embedding API):

- `root_dir`: every `fs:*` capability value must name a path inside this root
  (compared symlink-resolved on both sides, same normalization as path-scoped
  grants). On Windows, authorization text folds the verbatim `\\?\` drive and
  `\\?\UNC\` namespace spellings to their ordinary equivalents and uses `/` as
  its platform-independent separator after resolving the object, so the same
  object cannot acquire two policy or fence identities and descendant matching
  has one component boundary syntax.
  Module loading is included: the `module-loader` principal's reads are fenced
  like everyone else's.
- `allowed_hosts`: every outbound `network:*` capability value must name a
  listed remote host. Entries are `host` or `host:port`; a port-less entry
  covers the host across ports via the same scope-specific endpoint matcher
  grants use. This compatibility fence does not gate `network:listen`: local
  bind authority remains an independent policy decision. An empty list denies
  all outbound network access `[observed]` (ENG-24285).

Composition with the capability policy: the fence is checked first and is a
**hard ceiling** — policy grants compose *within* it and cannot widen past it,
it applies to every principal (root and `module-loader` included), and it
denies in **every** `SecurityMode`. Permissive does not bypass it
(`Host::is_allow_all()` returns false whenever a fence is configured, so the
C++ boundary's short-circuit stays off), and Audit does not observe-and-proceed
past it the way it does for policy would-denies: a fence miss is a real denial
in all modes, recorded in the audit log with a `host-boundary:root_dir` /
`host-boundary:allowed_hosts` constraint tag. A capability outside the fence is
also not acquirable through the dynamic-permission prompt path
(`grant_status` reports 0) and cannot be minted into a passable handle.

The CLI does not set these fields (`src/bin/ibex/runtime.rs` passes `None`);
they exist for embedders. Resource-less class values (`fs:read`,
`network:fetch`) claim unbounded authority and are denied whenever the
corresponding fence is configured.

### What the host backs

The `ex_host_*` functions in `src/host/abi.rs` implement, against std/rusqlite/
getrandom: filesystem ops (`ex_host_fs_*`, `src/host/abi.rs:601-1262`), SQLite
(open/prepare/all/get/run/exec, `src/host/abi.rs:1264-1698`), env/time/random
(`src/host/abi.rs:1700-1737`), console mirroring (`ex_host_console_log`,
`src/host/abi.rs:1739`), capability check/grant/log
(`src/host/abi.rs:661-727`), and module resolution (`ex_host_module_resolve`
plus the metadata-only `ex_host_module_resolve_meta` that backs `require.resolve`
without reading/transpiling the body, ENG-23007,
`src/host/abi.rs:730-779` — see [LLP 0004](./0004-module-loading-and-builtins.explainer.md)).
Structured static imports use the C-only
`ex_host_session_static_import_resolve(logical_referrer, specifier,
resolution_kind)` seam. It
strictly parses the canonical logical referrer, derives its host directory only
through an authenticated root binding, validates the closed typed resolution
kind, and returns the same full source record used by the captured loader. No
caller-controlled host pathname or public
`require` function participates in this route `[observed]` (`src/host/abi.rs`;
`src/host/mod.rs`).
Strings returned to C are malloc'd via `CString::into_raw` and freed by
`ex_host_free_string`/`ex_host_free_buffer` `[observed]`
(`src/host/abi.rs:781-789, 650-659`).

### Memory ownership rules (observed)

- Strings out of the `ex_hermes_*` API are freed with `ex_hermes_free_string`
  `[observed]` (`include/exact_runtime.h:64-65`).
- Strings out of the `ex_host_*` API are freed with `ex_host_free_string`; raw
  buffers from `ex_host_fs_read_file` are freed with `ex_host_free_buffer`
  `[observed]` (`src/host/abi.rs:650-659, 781-789`).
- The `__hostCall` callback's returned string is freed by the C++ side, not the
  host `[observed]` (`src/engine/hermes_runtime.cc:1785`).

## Lifecycle (observed)

The typed production path adds an explicit authenticated lifecycle alongside
the legacy entry points: `ex_host_install_armed(snapshot, expected_identity)`
strictly parses and authenticates caller-owned bytes, copies them into an
immutable host decision context, and `ex_hermes_create_armed(digest)` creates
Hermes only when that installed context has the exact digest. Mismatch or
absence returns failure before a runtime exists. The ordinary
`ex_host_install` entry point installs a closed unarmed placeholder, not an
allow-all production runtime.

1. Host installs itself first: a Rust embedder can call
   `install_host(Host::new(...))`; the local `ibex` binary does this from CLI
   security configuration, while the C entry point `ex_host_install()` installs
   only the closed placeholder; production uses `ex_host_install_armed`
   (`src/host/abi.rs:107-121, 586-592`). The CLI/iOS split is recorded in a
   source comment and now in the local binary implementation `[observed]`
   (`src/host/abi.rs:586-588`; `src/bin/ibex/runtime.rs`;
   [LLP 0010](./0010-ibex-binary-ownership.decision.md)).
2. `ex_hermes_create()` builds the Hermes runtime, installs globals and runs
   bootstrap (see [LLP 0003](./0003-hermes-engine-bridge.explainer.md)).
3. An unarmed diagnostic embedder may call `ex_hermes_set_host_call()` to wire
   `__hostCall`; the same call on an armed runtime is a silent no-op.
4. The host drives execution via `ex_hermes_eval` and may pump the loop with
   `ex_hermes_poll(now_ms)` `[observed]` (`include/exact_runtime.h:71-91`;
   `src/engine/hermes_runtime.cc:1815-1949`). Source comments document a
   `cli-notify` replacement for the default callback path `[observed]`
   (`src/engine/mod.rs:18-37`).
   A host retaining a runtime for an asynchronous watchdog must snapshot its
   nonce with `ex_hermes_runtime_nonce()` while it owns the live handle and
   call `ex_hermes_schedule_watchdog_heartbeat_for_generation()`. The legacy
   raw-pointer-only watchdog symbol remains ABI-compatible but fails closed;
   it cannot safely infer which generation an address once named `[observed]`
   (`include/exact_runtime.h`; `src/engine/hermes_runtime.cc`).
   Authenticated terminal sessions instead admit an exact credential and drive
   checked source through `ex_hermes_eval_lowered_session`; its versioned
   import plan is validated and materialized through the armed Host before the
   persistent declaration transaction begins.
5. `ex_hermes_destroy()` must run on the runtime's owner thread. It marks the
   pointer-plus-nonce registry identity closing, unregisters/cancels native
   callback sources, drains generation-scoped producer pins, and destroys
   queued JSI captures on that owner thread before deleting Hermes. Registry
   removal happens only after the drain, so delayed work cannot enter a later
   runtime whose handle reuses the same address `[observed]`
   (`src/engine/hermes_runtime.cc`; [LLP 0003](./0003-hermes-engine-bridge.explainer.md#the-event-loop)).

## Notes / boundaries

- The Rust crate is named `ibex-runtime`. Many C ABI symbols and JavaScript
  internals remain `ex_`/`EXACT_`-prefixed for compatibility `[observed]`
  (`Cargo.toml:2`; LLP 0000 §Architecture).
- This is a Spec of the *observed* contract surface; changes to the narrow
  consumer contract should update this document and LLP 0000 together.
