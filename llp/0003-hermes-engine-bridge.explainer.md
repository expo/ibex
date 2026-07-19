# LLP 0003: The Hermes Engine Bridge

**Type:** Explainer
**Status:** Draft
**Systems:** Engine, Runtime, Crypto
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Revised:** 2026-07-17 (projects ASSIGNED_DETACHED requestDevice results while preserving both admission forms); 2026-07-17 (records native-or-absent FinalizationRegistry ownership and persistent-runtime `FsHandle` reclamation coverage); 2026-07-16 (projects self-contained detached-loss requestDevice terminals to the wrapper before outer receipt settlement); 2026-07-16 (adds the additive Exact GPU ABI V2 typed mailbox, lifecycle replay authority, construction-private four-method bridge, and close/service-entry race fences); 2026-07-16 (adds the construction-private low-level GPU bridge, bounded Promise receipt drain, and cancellation/retirement lifecycle without publishing a WebGPU JS API); 2026-07-16 (adds the optional Exact GPU service mailbox and non-waiting detached teardown); 2026-07-15 (ENG-25061 links indirect/star/namespace exports to native ModuleRecords); 2026-07-15 (ENG-25060 implements the common runtime-drive gate and native module factory/context/record capabilities); 2026-07-15 (LLP 0026 adopts owner-thread-only serialized eval, poll, runner, and destroy entry); 2026-07-15 (ENG-25006: native fetch completion publishes its runtime callback before releasing the pending-fetch keepalive); 2026-07-13 (retained net/WebSocket owner identity installs before native WebSocket and shared-runtime capture while transport host functions remain lazy); 2026-07-12 (runtime callback identity is pointer-plus-nonce; teardown closes admission, cancels sources, drains producer pins, and destroys queued JSI captures on their owner thread — ENG-24244); 2026-07-12 (ENG-24261: Android's production WebSocket flow controller now has executable host-JVM flood, terminal-state, and repeated pause/resume coverage); 2026-07-12 (armed runtimes expose no generic `__hostCall`/`__hostCallAsync` bridge; its setters and resolver fail closed); 2026-07-12 (armed construction binds the actual loaded Hermes artifact and runtime-scoped Host context, while the historical unarmed constructor is non-executable — ENG-24237, ENG-24244, ENG-24245); 2026-07-11 (ENG-24259/ENG-24260/ENG-24261: bounded inspector and WebSocket buffering); 2026-07-11 (ENG-24219: engine entry points now scope frame attribution to the runtime handle being driven, so same-thread nested runtimes restore the outer attribution context); 2026-07-08 (ENG-23541: Windows async fs worker-pool hooks)
**Revised:** 2026-07-16 (host-owned REPL/inspector/explicit keep-alive turns now expose their external liveness to native polling without promoting unreferenced timers into runtime liveness); 2026-07-15 (ENG-25061 links indirect/star/namespace exports to native live cells and adds the synchronous graph lifecycle driver); 2026-07-15 (ENG-25060 implements the common runtime-drive gate and native module factory/context/record capabilities); 2026-07-15 (LLP 0026 adopts owner-thread-only serialized eval, poll, runner, and destroy entry); 2026-07-15 (ENG-25006: native fetch completion publishes its runtime callback before releasing the pending-fetch keepalive); 2026-07-13 (retained net/WebSocket owner identity installs before native WebSocket and shared-runtime capture while transport host functions remain lazy); 2026-07-12 (runtime callback identity is pointer-plus-nonce; teardown closes admission, cancels sources, drains producer pins, and destroys queued JSI captures on their owner thread — ENG-24244); 2026-07-12 (ENG-24261: Android's production WebSocket flow controller now has executable host-JVM flood, terminal-state, and repeated pause/resume coverage); 2026-07-12 (armed runtimes expose no generic `__hostCall`/`__hostCallAsync` bridge; its setters and resolver fail closed); 2026-07-12 (armed construction binds the actual loaded Hermes artifact and runtime-scoped Host context, while the historical unarmed constructor is non-executable — ENG-24237, ENG-24244, ENG-24245); 2026-07-11 (ENG-24259/ENG-24260/ENG-24261: bounded inspector and WebSocket buffering); 2026-07-11 (ENG-24219: engine entry points now scope frame attribution to the runtime handle being driven, so same-thread nested runtimes restore the outer attribution context); 2026-07-08 (ENG-23541: Windows async fs worker-pool hooks)
**Related:** LLP 0000; LLP 0002 (Host ABI); LLP 0004 (Module loading); LLP 0005 (Build pipeline); LLP 0026 (module runner)

## Summary

`src/engine/*.cc` is the C++ that drives the Hermes JS engine: it creates the
runtime, installs native globals and host functions through JSI, runs the
bootstrap JS, evaluates user code, pumps an event loop, and routes JS-to-native
calls. It also carries the **platform shims** — crypto, fs, process, net, http,
dns, etc. — each implemented natively per OS. This document maps that surface;
it does not restate the embedding ABI ([LLP 0002](./0002-host-embedding-abi.spec.md)).

## How Hermes is driven

Production uses `ex_hermes_create_armed(snapshot_digest)`; the historical
`ex_hermes_create()` symbol is intentionally non-executable, and the separately
named diagnostic constructor is not a project-execution API. Armed creation:

1. Builds a `hermes::vm::RuntimeConfig` with a microtask queue and `eval`
   enabled, then `facebook::hermes::makeHermesRuntime(config)`
   (`src/engine/hermes_runtime.cc:1391-1403`).
2. Wraps it in an `ExactHermesRuntime` handle, records the owning thread, a
   fresh runtime nonce, and the exact claimed immutable Host context.
3. Optionally constructs the async debugger if the Hermes build supports it
   (`src/engine/hermes_runtime.cc:1415-1432`).
4. Calls `installGlobals(handle)`, then verifies lockdown, compartments,
   bootstrap seals, and frame attribution structurally before registering or
   returning the runtime. Any mismatch destroys the partial runtime and
   refuses construction.

`ex_hermes_eval()` evaluates UTF-8 source or Hermes bytecode (`is_bytecode`
flag) and returns a result string `[observed]`
(`src/engine/hermes_runtime.cc:1464`).

Frame attribution is runtime-handle scoped, not merely thread scoped. A thread
may drive multiple runtimes or re-enter `ex_hermes_eval()` for a nested runtime
from an outer runtime's host call; runtime creation, `ex_hermes_eval()`, and
`ex_hermes_poll()` select the handle's attribution VM for the duration of that
entry and restore the prior selection on unwind `[observed]`
(`src/engine/hermes_runtime_internal.h`; `src/engine/hermes_runtime.cc`). This
keeps capability checks attached to the executing runtime without weakening LLP
0013's fail-closed no-user-principal rule.

LLP 0026 makes the runtime's owner-thread fact a contract for every operation
that drives Hermes: eval, poll/callback delivery, module-runner ingress, and
destroy are serialized and owner-thread-only. Off-owner or overlapping entry
must refuse before JSI or module-graph mutation. Same-thread nesting may select
a different runtime as described above, but may not re-enter the same runtime.
ENG-25060 implements this through `ExactRuntimeDriveGuard`: the process registry
stores owner thread and active-drive state beside pointer+nonce, so validation
happens before pointer dereference. Eval, poll, native module operations, and
generation-bearing destruction share the guard. The existing eval-internal
promise pump calls a private poll helper instead of recursively entering the
public poll ABI, preserving the non-reentrancy rule without changing its legacy
behavior.

The native module runner lives in `hermes_module_runner.cc`. It captures the
untamed Function constructor and Domain binder before bootstrap seals them,
keeps both references native-only, and returns generation-bearing registry
capabilities for compiled factories, immutable graph contexts, and native
ModuleRecords. The Rust wrapper admits only verified artifacts. For package
source, a principal-stamped trampoline is bound to the authenticated package
compartment before it invokes the captured constructor; Hermes' existing
eval/Function propagation then stamps both values onto the actual factory's
Domain at compile time. Handle registries are members of the runtime object, so
their JSI references are released on the owner thread before Hermes itself.

The first synchronous-record layer also keeps binding identity in Hermes. A
record declares cells before instantiation; the engine materializes one stable
namespace with checked getters, supplies a record-scoped `$export` callback,
and supplies `context.importValue` backed only by native-installed record
links. Indirect, resolved-star, and namespace exports are aliases to those same
native cells or namespace objects, not copied snapshots, and `$export` cannot
overwrite an alias. Declare and execute are separate one-shot phases. A thrown phase moves
the record to sticky `errored` state and later native calls return the retained
error text rather than partially rerunning factory state. The Rust graph plan
resolves explicit, namespace, and star exports by authenticated `SourceId`,
excludes ambiguous stars, reuses records through cycles, rejects resolver/
artifact graph disagreement, and refuses top-level-await closures before a
synchronous drive. Its native graph driver resolves each factory import to the
ultimate authenticated cell, creates the complete reachable record set before
linking, instantiates and declares the whole closure before body execution, and
then executes dependency-first in deterministic depth-first order. A retained
success or failure makes repeated graph evaluation idempotent rather than
partially re-running records.

CommonJS records keep their mutable `module` object, current exports value, and
detector-approved names in the same runtime-owned registry. The native
`require` callback follows only prelinked record IDs. It recursively evaluates
new targets, returns partial current exports for a cycle, retains replacement
identity, and erases every throwing record on the propagation path. A completed
record can mint one ESM adapter with frozen named snapshots plus `default` and
`module.exports`; the adapter is an ordinary evaluated native ModuleRecord, so
ESM consumers reuse the existing namespace/cell machinery.

The engine uses Hermes through **JSI** (`<jsi/jsi.h>`) `[observed]`
(`src/engine/hermes_runtime.cc:14-15`). Native functions are registered with
`jsi::Function::createFromHostFunction` and set as properties on `rt.global()`
`[observed]` (e.g. `__exactModuleResolve`, `__exactEnsure*`, and, on unarmed
diagnostic runtimes only, `__hostCall`; `src/engine/hermes_runtime.cc`).

### The `__hostCall` bridge

For an unarmed diagnostic runtime, `ex_hermes_set_host_call` installs the
generic `__hostCall(op, argsJson)` JSI host function `[observed]`
(`src/engine/hermes_runtime.cc`). The protocol — a `+` (JSON success) / `-`
(error) status sigil on the returned C string, freed by the C++ side and
`JSON.parse`d — is documented in
[LLP 0002 §The `__hostCall` bridge](./0002-host-embedding-abi.spec.md#the-__hostcall-bridge--the-generic-host-channel).
Armed runtimes reject both generic bridge setters and the async resolver before
mutating bridge state or invoking callbacks; they expose only dedicated native
functions. This removes the string-typed catch-all from the production
authority boundary while retaining it for diagnostic embedders.

### Lazy installation of host functions

Several subsystem functions are installed lazily on first use through
`__exactEnsure*` shims. Filesystem functions are behind `__exactEnsureFs` on
non-Windows platforms, while Windows installs them eagerly because the Windows
FS implementation is a separate file compiled only for that target `[observed]`
(`src/engine/hermes_runtime.cc`). HTTP, SQLite, DNS, child-process, and the full
Net/TLS transport surface are also registered on demand `[observed]`
(`src/engine/hermes_runtime.cc`). The transport-independent `__exactNetOwner`
primitive is the deliberate exception: each platform installs it before the
native WebSocket shim and shared runtime bundle capture it, so retained Socket,
WebSocket, and WebSocketStream wrappers have runtime/principal identity before
they have a transport selector without eagerly initializing network I/O
`[observed]` (`src/engine/hermes_runtime.cc`;
`src/engine/hermes_runtime_net.cc`;
`src/engine/hermes_runtime_platform_windows.cc`). `[inferred: keeping the rest
lazy trims startup cost for runtimes that never touch those subsystems.]`

### The bootstrap sequence

`hermes_bootstrap.cc` runs bootstrap JS after the runtime is created
`[observed]`. `eval_bootstrap_script` prefers precompiled Hermes bytecode when
available and falls back to the generated source header `[observed]`
(`src/engine/hermes_bootstrap.cc:19-69`). Two layers exist:

- The **shared runtime bundle** (`embedded_runtime_bundle.js`, the rolldown
  output of `packages/ibex-runtime-js`) is installed via
  `installSharedRuntimeBundle` `[observed]`
  (`src/engine/hermes_bootstrap.cc:71-154`).
- The per-file **bootstrap scripts** under `src/engine/bootstrap/*.js` install
  the module loader, compatibility globals, process/exact globals, and legacy
  lazy getters `[observed]` (`src/engine/hermes_bootstrap.cc:156-302, 413-797`).
  When the shared runtime bundle is successfully installed, the legacy
  `bootstrap_globals` step is skipped `[observed]`
  (`src/engine/hermes_bootstrap.cc:240-246`).

The HBC-vs-source selection and how these headers are produced is the build
pipeline's concern — see [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md).

The compatibility bootstrap preserves Hermes's native `FinalizationRegistry`
when the pinned engine provides it and leaves the global absent when an engine
does not. It does not install a JavaScript substitute: a registry that strongly
retains each target cannot observe collection and would turn cleanup coverage
into a false claim. `FsHandle` therefore registers its native handle id only
when the real primitive exists; `revoke()` remains the deterministic fallback
on runtimes where it does not `[observed]`
(`src/engine/bootstrap/compat-polyfills.js`;
`src/engine/hermes_runtime.cc`;
`src/engine/mod.rs::native_finalization_registry_reclaims_dropped_fs_handles_in_a_persistent_runtime`;
`src/engine/mod.rs::compat_and_fs_handle_sources_leave_finalization_absent_and_explicit_revoke_reclaims`).
The persistent-runtime test runs the native reclamation probe only when the
loaded Hermes artifact actually exposes the primitive; the repository does not
otherwise classify every supported Hermes artifact as FinalizationRegistry-
capable. The absence branch evaluates both authored production sources with the
global absent, then constructs and explicitly revokes a real `FsHandle` rather
than substituting a test-owned wrapper `[observed]` (`src/engine/mod.rs`).

## The event loop

The host pumps the loop by calling `ex_hermes_poll(runtime, now_ms)`
repeatedly `[observed]` (`src/engine/hermes_runtime.cc:1815`). Each poll:
cleans up fetch callbacks, drains the cross-thread callback queue (HTTP
responses etc.), runs queued cross-thread tasks on the runtime thread, runs the
`nextTick` queue, and drains microtasks `[observed]`
(`src/engine/hermes_runtime.cc:1820-1849`). Background threads signal readiness
via `ex_hermes_notify_callback`, whose default implementation sets an atomic
flag and invokes a registerable host wake hook `[observed]`
(`src/engine/mod.rs`); the `cli-notify` feature replaces it with a tokio
`Notify`-based version. Since ENG-23234 the CLI's default (non-`cli-notify`)
profile registers that hook at engine creation to signal the same parked
`select!` — previously the default profile had no wake-up at all, so a
cross-thread callback push racing a long timer park was not dispatched until
the timer expired. OS signal delivery rides this same path: the sigaction
handler marks a per-signal pending counter and writes to a self-pipe; a
detached watcher thread turns that into a `pushRuntimeCallback` that drains
pending signals into the JS `process` emitter `[observed]`
(`src/engine/hermes_runtime_crypto.cc`, `src/engine/bootstrap/stream-enhance.js`).

Unreferenced timers remain scheduled but do not make the runtime pending. An
ordinary `ex_hermes_poll` therefore skips one when no runtime-owned reference
keeps the loop alive. A host-owned loop which is independently live — an active
REPL, inspector, or explicit `--keep-alive` session — instead calls
`ex_hermes_poll_with_external_keep_alive`; that turn-local fact makes an
already-due unreferenced timer eligible without changing its `hasRef()` state
or `ex_hermes_has_pending_tasks()`. Future unreferenced timers consequently do
not prolong program quiescence, while a host which remains alive still observes
their callbacks, matching the Node/libuv liveness distinction `[observed]`
(`src/engine/hermes_runtime.cc`; `src/bin/ibex/engine/hermes.rs`).

Native fetch completion maintains continuous referenced-work visibility during
that handoff: it moves the resolve/reject closures out of the request entry but
keeps the entry registered until `pushRuntimeCallback` has published the
completion in the runtime queue. `ex_hermes_has_pending_tasks()` therefore sees
either the in-flight fetch or its queued completion, never a transient empty
state between them. Both entry-release branches re-pin the exact runtime
generation around `fetchMutex` access, while the native-worker pin remains held
through the final release and wake; teardown therefore cannot delete the handle
between callback publication and cleanup. The worker notifies again after
releasing the fetch entry, so a runtime that drained the newly queued callback
during the overlap cannot park on a keepalive that disappeared immediately afterward `[observed]`
(`src/engine/hermes_runtime_fetch.cc`; `src/engine/hermes_runtime.cc`).

Cross-thread callback identity is the pair `(ExactHermesRuntime*,
runtime_nonce)`, never the address alone. Destruction changes the registry row
from `Running` to `Closing`, unregisters or cancels event sources, and keeps
that exact generation present while already-admitted native producer pins
drain. Those producers may transfer JSI-owning completion closures into the
closing runtime queue; destroy discards them (without invoking user JS) on the
owner thread. Native finalizers, including a WebSocket context's final
`jsi::Object`, run on that same thread. Only after the pin count reaches zero
does teardown erase the generation and delete Hermes. An old completion can
therefore neither enter a new runtime allocated at the same address nor force
the former leak-on-dead-runtime fallback `[observed]`
(`src/engine/hermes_runtime.cc`; `src/engine/hermes_runtime_{dns,fs,http,fetch,websocket}.cc`).
The public watchdog bridge applies the same rule at the host boundary: the
host captures the live nonce and later supplies pointer plus nonce to the
generation-bearing entry point. Its retained three-argument compatibility
symbol rejects every request, because recovering the *current* nonce from a
stale address would relabel an old producer for a replacement runtime
`[observed]` (`include/exact_runtime.h`; `src/engine/hermes_runtime.cc`).

Async failures are fatal, matching Node: a callback that throws with no
`uncaughtException` handler consuming it — a timer, a `process.nextTick`, a
cross-thread task or callback — makes the poll report `-1`, which the host
loop turns into a nonzero process exit. Timers return `-1` directly; the other
paths set a one-shot `fatal_async_error` flag on the runtime that the same or
next poll consumes (one-shot so a REPL survives it the way it survives a
throwing timer). Likewise the JS-side `unhandledrejection` default action sets
`process.exitCode = 1` (preserving a user-set nonzero code) rather than
crashing mid-run. Before ENG-23130, all of these logged and exited 0 — a
silent green for any CI or agent using the exit code as the pass/fail signal.

### Optional GPU service mailbox

The optional Exact GPU service differs from ordinary fetch/filesystem workers:
backend work may legitimately outlive the Hermes realm, so it must not retain a
native-worker pin until provider completion. Registration copies a versioned
function table and gives Exact a ref-counted plain-native mailbox containing
only the runtime pointer-plus-nonce identity, atomic lifecycle state, and
bounded event metadata `[observed]` (`src/engine/hermes_runtime_gpu.cc`;
`src/engine/hermes_runtime_gpu_v2.cc`;
[LLP 0002 §The optional Exact GPU service registration seam](./0002-host-embedding-abi.spec.md#the-optional-exact-gpu-service-registration-seam)).

The mailbox moves `Installing -> Activating -> Live`, with
`ProtocolViolation` as a terminal authority-reduction branch, then
`Closing -> Detached`. The provider may call the sink's plain-native
`retain_client`/`release_client` ownership hooks during `open_realm`, and must
retain before storing the sink/context beyond that call. It may not call
`on_event` or publish an event-producing path until Ibex invokes the required
one-way `activate_realm` hook. Its invocation boundary is represented by the
`Installing -> Activating` transition and is the first event-admission point.
During `Activating`, any provider thread may deliver; this includes the
post-hook-return race before Ibex's `Live` compare-exchange. Delivery observed
while still `Installing` remains a protocol violation.

A live callback never touches JSI on the service thread. It validates the ABI
prefix, flags, realm, event kind, operation/completion pairing, and fixed byte/
count budgets, then copies borrowed payload bytes into the mailbox. A
pointer-plus-nonce pin is held only while publishing at most one callback-queue
drain. The owner drain resolves operation completions or rejects structured
operation/device/loss/realm/protocol errors. Pending Promise roots exist before
the provider `submit` call, so synchronous delivery is race-safe; recent
terminal tracking makes duplicate and stale events no-ops rather than a second
settlement. The complete success return carrier is also built before those
roots and submission records become observable. After successful provider
admission, returning that prebuilt carrier performs no fallible property
allocation. A pre-admission allocation failure reaches neither provider nor
maps; provider rejection rolls the records back before constructing its failure
carrier. If the provider synchronously publishes an accepted event and then
returns nonzero, those signals contradict each other. The owner path returns a
prebuilt `-8` protocol carrier, keeps the pending record for its scheduled
drain, and quarantines exactly once: queued events/payload are cleared,
outstanding work is cancelled, the realm is closed, and the receipt is rejected
as a protocol violation. It never uses ordinary admission rejection or event
discard for the contradiction. The completion is terminal before return, so a
late duplicate is merely stale and cannot trigger another reduction or
settlement.

The additive V2 path keeps V1 untouched but replaces opaque completion tokens
with exact generation-bearing realm/account/device/object identities and six
typed event records. Its preliminary admission consults realm-lifetime
lifecycle tombstones before the shorter recent-operation ring, so an exact
loss/close replay remains discardable after more than 2,048 operation
terminals while a same-key mutation quarantines. RequestDevice's
`ASSIGNED_DETACHED + OBJECT` form is instead a self-contained operation
terminal for a fresh service-detached already-lost device, preserves either
NOT_ADMITTED/zero or ADMITTED/nonzero sequence provenance, and consumes no
lifecycle tombstone. Owner drain calls the private wrapper sink with its full
result before resolving the receipt; the wrapper recognizes the explicit
`detachedAlreadyLost` projection, avoids its strong live-device registry, and
settles `device.lost`, so Hermes queues that reaction before the outer
requestDevice reaction. Service-attached device loss continues through the
ordinary typed lifecycle record and replay table.

V2 submit, cancel, and retire reserve an exact provider entry while holding the
mailbox admission mutex, then invoke provider code without that lock. Realm
close callback admission uses the same mutex and switches to `Closing` before
return, so later unreserved bridge calls—including the one-shot event-sink
installation—cannot cross. A pre-reserved call may finish after wall-clock
close. ProtocolViolation observed after any synchronous provider call
dominates its return and leaves Promise settlement to owner reduction.

Drain publication is fail-closed without being lossy. Allocation failure while
retaining the mailbox, pinning the runtime generation, materializing the
callback, or appending it to the callback queue is caught at the provider
boundary. Ibex leaves the copied event in place, poisons the realm, raises an
allocation-free owner-drain flag, and wakes the host; pending-work and callback-
backlog probes observe the same flag, and the next owner poll drains it before
the ordinary callback queue. Runtime teardown remains the final owner-thread
settler if the generation is already closing. No failure leg throws across the
C ABI, strands a Promise, or settles one twice.

Terminal fanout also has an aggregate bound: for as many as 1,024 pending
receipts, the owner creates one at-most-16-MiB opaque diagnostic JSI value and
attaches that shared read-only-by-contract value to each Error. Allocation work
is therefore O(payload bytes + receipts). If the optional diagnostic allocation
fails, every rejection still occurs exactly once with `payload: undefined`;
Ibex does not retry a maximum-size allocation once per receipt.

Successful finalization also creates a low-level JSI object with V1
`submit`/`cancel`/`retire` or V2
`submit`/`cancel`/`retire`/`setEventSink`, passes it directly through a one-shot construction
callback installed by the shared runtime bundle, verifies deletion of that
callback, and keeps the value in a module-private runtime-js slot. The capture
is closed by the common eval/debugger/module user-entry fence if unused.
Successful capture, feature-off/no-provider finalization, rollback, and that
common fence all verify that the construction property is actually absent;
throwing, non-callable, or non-configurable hostile replacements fail the
capability transaction and cannot advance the user-execution marker. The
package exports omit this module and the app loader refuses both deep and
filesystem paths into its directory. This is private plumbing for a future
generated wrapper, not `navigator.gpu`, an app global, or a WebGPU support
claim.

Runtime destruction revokes that module slot and reserves `Closing` under the
same mutex as callback admission. If teardown wins, it clears queued events,
cancels pending completions and rejects their receipts on the owner thread,
issues the nonblocking realm close, then marks the mailbox `Detached`. If a
service REALM_CLOSED callback wins, that accepted terminal owns cleanup before
poll; teardown neither cancels operations nor echoes close. It never waits for
a terminal provider callback. A service-retained mailbox can therefore receive
a late callback safely, report it discarded, and release itself after the
runtime and address are gone.

### Inspector resource discipline

The loopback CDP service treats handshakes and established sessions as one
bounded resource class. At most 16 sockets may occupy it concurrently; peek
and WebSocket handshakes have five-second deadlines, writes have a five-second
deadline, idle sessions close after five minutes, and tungstenite is configured
to reject frames and reassembled messages above the 256 KiB protocol budget
before allocating its much larger defaults. Every inbound data or control
message consumes the same rate budget.

The Network domain fans events into a separate bounded queue per enabled CDP
client, so clients cannot drain or disable one another. Each queue retains at
most 1,000 events and 2 MiB. Response bodies are capped at 1 MiB each and 16 MiB
in aggregate under byte-budgeted LRU eviction; request post data is capped at
64 KiB. Truncation and event eviction are explicit in diagnostic metadata.

### Blocking-work worker pools

Anything that would block the JS thread for longer than a scheduling quantum
runs on a bounded pool of detached worker threads and delivers its completion
back through `pushRuntimeCallback` + `ex_hermes_notify_callback`: DNS
resolution (`DnsWorkerPool`, ENG-22995), fetch on Linux (`FetchWorkerPool`,
ENG-23471), and — since ENG-23497/ENG-23541 — the async fs API
(`FsWorkerPool`, `src/engine/hermes_runtime_fs.cc` and
`src/engine/hermes_runtime_fs_windows.cc`). The fs pool backs
`__exactFsReadFileAsync` / `__exactFsWriteFileAsync` / `__exactFsReadAsync` /
`__exactFsWriteAsync` / `__exactFsReadvAsync` / `__exactFsWritevAsync` /
`__exactFsPathAsync` / `__exactFsStatAsync`; `src/builtins/fs.js` routes
`readFile`/`writeFile`/`appendFile`/`read`/`write`/`readv`/`writev`/
`stat`/`lstat`/`fstat`, directory/metadata path operations, `fs.promises`,
`FileHandle`, and the ReadStream/WriteStream data paths through them when
present, and falls back to the historical deferred-sync path when absent.
`*Sync` entry points remain synchronous by design. Before ENG-23497 the whole
"async" fs API ran its syscalls synchronously on the JS thread and only
deferred the callback, so one large `readFile` starved timers and sockets for
its full duration.

The Windows fs pool runs over the Rust `ex_host_fs_*` ABI rather than POSIX
file descriptors. Its opaque file handles are shared between sync JS-thread
calls and worker-thread async calls with a per-handle I/O mutex, because the
Windows positional read/write shims are save-cursor/seek/op/restore sequences
on one handle rather than atomic `pread`/`pwrite` syscalls. Close removes the
JS fd mapping immediately while an in-flight worker retains shared ownership,
so the native handle is released exactly once after the last operation. Append
is an open-handle mode rather than a reopen-by-path operation, preserving fd
identity across rename/unlink and OS append serialization. Filesystem failures
cross the ABI through a thread-local normalized errno slot; probing the path
after failure is forbidden because it misclassifies permission/type errors as
`ENOENT`. The same handle ABI exposes real `sync_all`/`sync_data` durability
for Windows `fsync`/`fdatasync`.

The shared pool discipline, learned the hard way:

- **Immortal heap singleton.** A pool with detached workers must be
  `static Pool* pool = new Pool(); return *pool;` — never a function-local
  by-value static. glibc deadlocks `exit()` when static destructors destroy a
  mutex/condvar that still has parked waiters (Linux-only; macOS never
  reproduces it). See `native_fetch_linux.cc`'s `FetchWorkerPool` and
  ENG-23471/ENG-23498.
- **Queue, don't early-reject.** Reject an enqueue only when the backlog is
  genuinely full; an `idle == 0 && total >= kMaxWorkers` early-reject turns a
  one-tick fan-out (`Promise.all`) into spurious failures (ENG-23022).
- **Keepalive counter.** Each subsystem counts in-flight ops in an atomic on
  the runtime handle (`pending_dns_lookups`, `pending_fs_ops`) that the loop's
  referenced-work checks consult; otherwise the process exits before the
  worker delivers its completion.
- **Teardown producer pin.** Any worker carrying a JSI resolve/reject/object
  holds a generation-scoped native-worker pin from queue admission through
  callback transfer. Closing refuses new pins, cancels sources that can be
  cancelled, waits for the rest, and destroys transferred captures on the
  runtime thread before Hermes.
- **No JSI off-thread; checks stay on the JS thread.** Workers touch plain
  data only. Argument validation and capability checks (the deputy stack is
  JS-thread-local) run before enqueue; errno capture happens on the worker at
  failure time and is rehydrated into a Node-shaped error on delivery.
- **Ordering matches Node.** Independent ops on the pool may reorder, exactly
  like Node's libuv threadpool (verified against Node v25: `writeFile`
  immediately followed by `readFile` of the same path can observe ENOENT).
  Anything that needs ordering must chain on the completion, which is what
  WriteStream's serialized `pendingWrites` queue does.

## The platform shims (map)

Each `src/engine/hermes_runtime_*.cc` file installs a family of native host
functions / globals for one subsystem and carries per-OS implementations behind
`#if` guards. `build.rs` lists the C++ sources and target-specific defines
`[observed]` (`build.rs:804-1224`):

| Subsystem | Files | Notes |
|---|---|---|
| Crypto | `hermes_runtime_crypto.cc`, `hermes_runtime_crypto_windows.cc` | platform-dependent; see below |
| Filesystem | `hermes_runtime_fs.cc`, `hermes_runtime_fs_windows.cc` | also via `ex_host_fs_*` Rust ABI |
| Process | `hermes_runtime_process.cc`, `_process_setup.cc`, `_platform_windows.cc` | spawn, env, signals |
| Net / sockets | `hermes_runtime_net.cc` | TCP/UDP |
| HTTP | `hermes_runtime_http.cc`, `hermes_runtime_fetch.cc`, `native_fetch_*` | fetch + server |
| WebSocket | `hermes_runtime_websocket.cc`, `native_websocket_*` | per-OS native impls |
| DNS | `hermes_runtime_dns.cc` | resolver |
| SQLite | `hermes_runtime_sqlite.cc` | bridges to rusqlite via `ex_host_sqlite_*` |
| Console/IPC/timers | `hermes_runtime_console.cc`, `_ipc.cc`, `_timers.cc` | |
| OS info / iOS | `hermes_runtime_osinfo.cc`, `hermes_runtime_ios.cc` | |
| Debugger | `hermes_runtime_debugger.cc` | gated on `HERMES_ENABLE_DEBUGGER` |
| Optional Exact GPU service | `hermes_runtime_gpu.cc`, `hermes_runtime_gpu_v2.cc` | additive V1/V2 service + construction-private bridge/typed receipt mailbox; no public WebGPU JS globals or support claim |

The `native_fetch_*` / `native_websocket_*` files are per-OS. macOS/iOS use
Foundation/NSURLSession implementations `[observed]`
(`src/engine/native_fetch_macos.mm:1-14`;
`src/engine/native_websocket_macos.mm:1-9`). Windows uses WinHTTP
implementations `[observed]` (`src/engine/native_fetch_windows.cc:1-5`;
`src/engine/native_websocket_windows.cc:1-5`; `build.rs:1072-1104`). Android
uses `native_android_networking.cc`, which preserves the same C++ fetch and
WebSocket ABI while delegating HTTP/WebSocket work to the Java OkHttp bridge
`IbexNetworking`; Android clipboard, raw DNS, location, camera
permission/device metadata, locale/screen/appearance globals,
app-state/deep-link/configuration events, and platform-version data are also
fed through that app-context bridge
`[observed]` (`src/engine/native_android_networking.cc`;
`src/engine/hermes_runtime_android.cc`;
`platform/android/java/dev/ibex/runtime/IbexNetworking.java`; `build.rs`).
Linux uses system libcurl as the supported native networking backend: `build.rs`
requires `pkg-config` and libcurl >= 7.86 so fetch and WebSocket both compile
with `EXACT_HAS_CURL` `[observed]`
(`build.rs:1175-1236`). A degraded fetch-only curl CLI fallback exists only
when `IBEX_ALLOW_CURL_CLI_FALLBACK=1`; WebSocket remains unavailable in that
profile `[observed]` (`src/engine/native_fetch_linux.cc`;
`src/engine/native_websocket_linux.cc`).

### WebSocket bridge threading and context ownership

The desktop WebSocket backends share two invariants that are easy to break
because nothing enforces them mechanically (ENG-23469 fixed violations of
both on Linux and Windows):

- **Context ownership transfers on success.** `__exactWsConnect` allocates
  the `NativeWebSocketCallbackContext` with `ref_count == 1` and releases it
  only when `native_ws_connect` returns 0. A nonzero ws_id transfers that
  single reference to the native implementation, whose teardown path
  (`remove_connection` / `destroy_entry`) performs the one balancing
  release. Backends must **not** retain again at connect time — the extra
  reference leaks the context and the `jsi::Object` pinning the whole JS
  WebSocket instance on every successful connection. Callback invocations
  take their own short-lived retain/release pairs around each call.
- **Connect returns immediately; the handshake runs off the JS thread.**
  WHATWG requires connection establishment to run "in parallel". All three
  desktop backends allocate the ws_id, register the entry (so `close`/
  `destroy` on a CONNECTING socket work), and return; the
  handshake runs on the backend's io/delegate thread and reports failure as
  an error callback followed by `close(1006, unclean)`.

The Android OkHttp bridge additionally bounds paused receive delivery at 256
messages and 8 MiB per socket. The queue owns each already-copied message once,
drains FIFO under the existing JS flow-control handshake, and closes with 1009
instead of silently dropping data when either bound would be exceeded. That
state machine lives in the Android source set but has no Android/OkHttp
dependency, so `scripts/test-android-java.sh` executes the production queue on
a host JVM: text/binary floods, terminal error/close ordering, transport
close/error cleanup, FIFO ownership, and repeated pause/resume are behavioral
tests rather than source-text assertions. Device coverage remains responsible
for the thin OkHttp and JNI adapters.

On Linux there is a third: **the io thread exclusively owns the CURL easy
handle.** libcurl forbids using one handle from two threads, and the io
thread frees the handle on exit, so the JS thread never touches it — sends
and client closes are enqueued (`outbound`, `close_requested` +
`close_code`/`close_reason` under `io_mutex`) and performed by the io
thread. A client close arms a 5s give-up deadline the moment the request is
observed (so a CLOSE frame that can never be written still cannot park
`readyState` at CLOSING forever), sends the CLOSE frame from the io loop,
then keeps reading — through a flow-control pause, discarding incoming data
frames, since WHATWG only fires message events while OPEN — until the
peer's CLOSE arrives (reporting the peer's code/reason) or the deadline /
connection teardown ends the wait (reporting the requested code with
`was_clean = 1`, the same shape Windows uses). The close-ack wait bounds
intentionally differ per backend: Windows completes the close handshake
synchronously inside `WinHttpWebSocketClose`, macOS delegates to
NSURLSession with a 1s grace period for the peer's frame, and Linux polls a
non-blocking socket so it uses a looser 5s upper bound.

Windows handle lifetime follows the same single-owner idea: pre-upgrade
handles (session/connect/request) belong to the handshake thread — a
concurrent close()/destroy only marks the entry closed (reporting an
unclean 1006, per WHATWG "fail the connection" for close-while-CONNECTING)
and the handshake thread disposes of its own handles when it notices,
because closing a handle out from under a blocking synchronous WinHTTP call
is documented-unpredictable. Post-upgrade, `WinHttpWebSocketSend` and
handle teardown serialize on `send_mutex` so a send can never run on a
freed (and possibly recycled) handle, and the per-entry `context_mutex`
makes a callback's context snapshot+retain atomic against the final
teardown release.

### Crypto is platform-dependent (the fragile axis)

Crypto is split between the non-Windows crypto shim and a Windows-specific file:

- **Apple / non-Windows file:** `hermes_runtime_crypto.cc` includes
  CommonCrypto/Security on Apple platforms `[observed]`
  (`src/engine/hermes_runtime_crypto.cc:23-44`). macOS sign/verify use Security
  APIs when not building iOS `[observed]`
  (`src/engine/hermes_runtime_crypto.cc:1335-1443`). Apple key generation is
  registered, but some iOS paths throw because OpenSSL/PEM export are not
  available `[observed]` (`src/engine/hermes_runtime_crypto.cc:1445-1691`).
- **OpenSSL profile:** when `EXACT_NO_OPENSSL` is not defined, the non-Windows
  file compiles OpenSSL-backed AES, PBKDF2/scrypt/HKDF, asymmetric
  sign/verify/key-generation, ECDH/X25519/Ed25519, RSA-OAEP, and key
  import/export paths `[observed]` (`src/engine/hermes_runtime_crypto.cc`).
- **Android:** `build.rs` defines `EXACT_PLATFORM_ANDROID` and requires the
  `openssl-crypto` profile, using vendored OpenSSL until an Android-native
  crypto backend exists `[observed]` (`build.rs:933-949`).
- **Non-Windows reduced profile:** when `EXACT_NO_OPENSSL` is defined outside
  Apple-specific branches, Linux compiles without OpenSSL and keeps a reduced
  runtime surface: portable MD5/SHA-1/SHA-2 hash/HMAC/hashRaw, PBKDF2, scrypt,
  and HKDF, plus throwing stubs for asymmetric sign/verify/key generation
  `[observed]` (`src/engine/hermes_runtime_crypto.cc`). AES and asymmetric key
  import/export remain outside the reduced profile.
- **Windows:** `build.rs` compiles `hermes_runtime_crypto_windows.cc` and
  defines `EXACT_NO_OPENSSL` `[observed]` (`build.rs:729-765`). That file
  registers Windows BCrypt-backed hash/hashRaw/HMAC functions plus stdin/signal
  noops; it does not register the non-Windows asymmetric throwing stubs
  `[observed]` (`src/engine/hermes_runtime_crypto_windows.cc:1-8, 141-221`).

The crypto profile axis and the platform matrix are owned by
[LLP 0001](./0001-target-platforms-and-ci-matrix.rfc.md); this section only maps
where the selection happens in the engine.

### Windows native smoke coverage

The Windows native backend contract is covered by the
`windows_runtime_uses_native_platform_backends` lib test in `src/engine/mod.rs`.
It exercises the public JS APIs against local test services so the C++ shims are
reached through the same bootstrap/builtin path embedders use: `fetch` and
`WebSocket` through WinHTTP, `crypto` hash/HMAC through BCrypt, `fs` through the
host filesystem ABI, `child_process.spawnSync` through `CreateProcessW`, and
DNS/TCP through Winsock. This is intentionally an end-to-end smoke, not a unit
test of individual C symbols.

## Boundaries

- This crate compiles the C++ via `build.rs` (`cc`); the engine links Hermes
  from platform-specific paths or `HERMES_*` overrides (see
  [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md)).
- The Rust-side `ex_host_*` implementations the shims call into live in
  `src/host` ([LLP 0002](./0002-host-embedding-abi.spec.md)); the engine declares
  them as `extern "C"` `[observed]` (`src/engine/hermes_runtime.cc:203-235`).
- Hermes is the only engine today, and the public C symbols still name Hermes
  (`ex_hermes_*`) `[observed]` (`include/exact_runtime.h:34-65, 151-156`).
  Any future engine-agnostic seam is a design posture, not an implemented
  abstraction `[inferred]` — see [LLP 0006](./0006-design-principles.principles.md).
