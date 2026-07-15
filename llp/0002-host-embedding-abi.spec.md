# LLP 0002: The Host / Embedding ABI

**Type:** Spec
**Status:** Draft
**Systems:** Host ABI, Engine, Runtime
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Revised:** 2026-07-14 (source-derived ABI output signatures, roles, selectors, buffer pairs, and ownership); 2026-07-14 (Hermes-safe Error metadata and poll-checkpoint Promise rejection publication complete asynchronous-failure ABI v1, including schedule-time job provenance and top-level-await de-duplication); 2026-07-14 (owner-thread structured asynchronous-failure publication ABI v1 with rooted values, authenticated schedule-time attribution, and explicit bounded loss); 2026-07-14 (structured-evaluation result ABI v2 adds owned, length-bearing source-position records while keeping unimplemented safe-throw/source-position capability bits off); 2026-07-13 (bounded any-thread work-unit publication ABI, including timer due/undue scheduling identities); 2026-07-13 (structured-session import plan v2 carries the authenticated entry SourceId used by the private module cache); 2026-07-13 (normative structured-evaluation result ABI v1, migration rules, and the lowered-session extension's versioned static-import plan); 2026-07-13 (`allowed_hosts` is an outbound remote-host fence and no longer gates independent `network:listen` authority — ENG-24285); 2026-07-12 (armed runtimes reject the generic sync/async host-call bridge and its resolver before any callback/global/pending-state mutation); 2026-07-12 (production construction now requires a runtime-scoped armed Host context; the legacy constructor is non-executable and native fd/socket ownership is runtime-namespaced — ENG-24237, ENG-24244, ENG-24245); 2026-07-09 (host-boundary constraints: `root_dir`/`allowed_hosts` are now enforced fences, ENG-23876; previously 2026-07-07 for the capsec mode collapse); 2026-07-11 (generated capsec ABI inventory — ENG-24145); 2026-07-11 (immutable armed-snapshot install and Hermes handshake — ENG-24148)
**Related:** LLP 0000; LLP 0003 (Hermes engine bridge)

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
| `ExHermesEvaluationResult` | `uint32_t abi_version`; `uint32_t struct_size`; `uint32_t outcome_tag`; `uint32_t fault`; `uint64_t work_target_id`; `ExHermesValueHandle value`; `uint32_t throw_metadata_status`; `uint32_t throw_metadata_fields`; `int32_t lifecycle_exit_code`; `uint32_t capability_flags`; `ExHermesOwnedBytes message`; `ExHermesOwnedBytes stack`; `ExHermesSourcePosition *positions`; `size_t position_count` |

On the supported 64-bit ABI this gives result offsets `0, 4, 8, 12, 16, 24,
40, 44, 48, 52, 56, 72, 88, 96` respectively and
`sizeof(ExHermesEvaluationResult) == 104`; `ExHermesValueHandle` is 16 bytes,
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
- `message` and `stack` are independently length-bearing byte buffers. Embedded
  NUL is data, not a terminator. A present buffer is allocated by the native
  side and freed by `ex_hermes_evaluation_result_dispose`; an absent buffer is
  `{NULL, 0}`. Disposing does not release a value handle.
- `positions` is either `{NULL, 0}` or a native-allocated array whose every
  record owns its explicit-length UTF-8 `source_label`; `line` and `column` are
  one-based and nonzero. Result disposal frees every nested label and then the
  array. The third `throw_metadata_fields` bit is present only for a nonempty
  position array.
- `throw_metadata_status == Captured` permits only the message/stack/positions
  presence bits named by `throw_metadata_fields`; `Unavailable` carries none.
  Throw metadata supplements the raw thrown handle and never replaces or
  coerces it.
- `Lifecycle` alone carries `lifecycle_exit_code`. `capability_flags` advertises
  the exact supported stratum (`Base`, safe throw capture, source positions,
  rich inspection); a consumer must require the strata it uses.
- Allocation failure produces the named out-of-memory engine fault with no
  fabricated payload. Cancellation racing a normal return has one terminal
  typed outcome for the exact work target; stale-target cancellation cannot
  land on a successor.

The pinned Hermes patch stack exposes both trap-free raw thrown-value capture
and engine-owned Error metadata extraction. The latter reads only an actual
Hermes `JSError`'s own plain message slot and internal stack records; it never
consults JavaScript `.stack`, accessors, proxies, `prepareStackTrace`, or string
coercion. The evaluator therefore advertises `Base | SafeThrow`: an ordinary
Error carries captured message/stack fields, while an arbitrary thrown value is
still the original rooted handle with `Captured` and no fabricated fields.
Lowered session source maps are supplied to Hermes' source-map-aware evaluator,
but the independent owned source-position records remain unimplemented, so
`SourcePositions` stays off.

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

`EX_HERMES_SESSION_IMPORT_PLAN_ABI_VERSION` is currently `2`; v2 appends the
borrowed, explicit-length SourceId field used for the direct-entry cache
reservation. The independent
C11 consumer `src/engine/exact_runtime_c_abi_check.c` compile-checks the version,
field layout, and exact function-pointer type in addition to the Rust/C++
consumers. Input pointers remain borrowed for the call; structured result-owned
byte buffers retain the ownership rules described below. This extension is
versioned and fail-closed but is not added to LLP 0000's narrow five-function
consumer contract; promoting it to that semver-major list would require an LLP
0000 amendment.

LLP 0021 adds a source-derived security inventory across the public ABI
families: the Rust/native `ex_host_*` callbacks, the `ex_hermes_*` embedding
surface, the `ex_worklet_*` surface, and the Android Java/JNI bridge. The
current generator finds 141 `ex_host_*`, 65 `ex_hermes_*`, 10 `ex_worklet_*`,
one `ex_android_*`, 39 Java, and 8 JNI surfaces (264 total). It groups source
definitions by target variant, including weak/default stubs, rather than
maintaining a copied symbol list `[observed]`
(`packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs`).

Each inventory row also carries the exact source-derived return and parameter
contract for every definition. A non-void return creates the real
`[[return]]` output slot; a void return does not create a synthetic slot.
Const pointers are borrowed inputs, scalar parameters are inputs, and mutable
pointers remain unknown unless their signature or a strict `@abi-output`
annotation proves an output/inout role and ownership. Buffer/length pairs,
callback payloads, output selectors, and release functions are explicit. This
produces 149 membership-complete output-bearing surface accounts, 25
structural-only void/all-input accounts, and 90 unresolved accounts. The 149
complete output-bearing accounts expand to 180 catalog selectors (143 returns,
18 out parameters, and 19 callback payloads). Fifty-one unresolved accounts
already have 57 known channels but also retain an ambiguous parameter or
callback role that could hide another output slot, so those known channels do
not make the account complete. The other 39 unresolved accounts have no proven
slot. Thirty-five output-bearing accounts have membership-complete pointer
slots whose ownership still blocks safe execution. Runtime observations of a
pointer or aggregate value do not promote such a row while ownership remains
unbound. Executor fixture
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
  grants). Module loading is included: the `module-loader` principal's reads
  are fenced like everyone else's.
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
`ex_host_session_static_import_resolve(logical_referrer, specifier)` seam. It
strictly parses the canonical logical referrer, derives its host directory only
through an authenticated root binding, and returns the same full source record
used by the captured loader. No caller-controlled host pathname or public
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
