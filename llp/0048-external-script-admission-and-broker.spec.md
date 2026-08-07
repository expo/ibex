# LLP 0048: Restricted External Script Admission and Broker ABI

**Type:** Spec
**Status:** Accepted
**Systems:** Runtime, Host ABI, Module Loader, CapSec, Distribution
**Author:** Charlie Cheever / Codex
**Date:** 2026-08-03
**Revised:** 2026-08-05 (implementation checkpoint: app-bound wire/catalog
contracts, source admission, parent bridge, restricted-worker construction,
broker lifecycle/frame enforcement, policy/evidence fixtures, authenticated
reporting, and the public compile surface have landed; the complete §11
host-portable and exact-tuple acceptance/evidence gate remains open)
**Revised:** 2026-08-04 (align target-advertisement minimum-platform spelling
with the existing catalog and checked schema contract)
**Revised:** 2026-08-03 (round-3 minor reconciliation: full-frame function-id
reserve admission, explicit envelope-deadline ownership, precise grace timer
wording, and a closed target-advertisement artifact descriptor)
**Revised:** 2026-08-03 (round-2 review reconciliation: transformed-buffer and
limits binding; closed native event/fault ABI; branded broker-failure
transport; iterative strict-value bounds; static timer/frame rules; exact
pre-worker outcomes; and catalog/stub/plan/report-bound target evidence)
**Revised:** 2026-08-03 (round-1 review reconciliation: a separate restricted-
worker arming principal/receipt and concrete native ABI; fixed in-process
topology; complete broker/timer/settlement schemas; exact terminal and exit
table; transform/output/heap bounds; strict app-bound format and reporting
rotations; and an explicit StubContractV4 enable carrier)
**Revised:** 2026-08-03 (initial draft: bounded file/stdin admission, the
erasable-only external-script profile, a separately attributed broker-only
worker, the host-portable broker/lifecycle contract, and app-bound executable
acceptance)
**Related:** LLP 0002 (host/embedding ABI); LLP 0013 (compartments and threat
model); LLP 0014 (generated policy and authority ceilings); LLP 0024
(structured evaluation and cancellation); LLP 0028 (Oxc transform authority);
LLP 0029 (single-file executable packaging); LLP 0047 (standalone finish line);
Snapback LLP 0062 §3/§6/§7 (generated app CLI and code mode)

## Summary

An authenticated, trusted embedded parent may admit **one caller-selected local
`.ts` or `.js` file, or one stdin stream, as bounded source data** and start it
as a distinct restricted worker principal. The parent remains the executable's
only embedded entry. It retains credentials, target and transport authority,
the current API envelope, broker state, lifecycle control, and result framing.
The worker receives only a dedicated broker capability and the frozen
`api`, `snapback`, `args`, `signal`, bounded `console`, and bounded relative
timer surfaces derived from it.

This is the narrow ingress needed by an app-bound executable such as:

```sh
./example introspect
./example call createTodo --args-json '{"text":"Buy milk"}'
./example run analysis.ts
```

It is **not** a general `eval`, REPL, module-import, file-execution, or
runtime-selected compiled-entry facility. Source enters exactly once as bytes,
is size-bounded before allocation, hashed and attributed, transformed under
LLP 0028's pinned Oxc authority using the finite profile in §2, and evaluated
only in a newly created restricted worker. No server-provided JavaScript may
enter this lane.

The extension strengthens Snapback's Node-host non-transmission property on an
Ibex host: Ibex actually denies worker filesystem, direct network, module
loading, environment, subprocess, arbitrary clock, and randomness authority.
It does **not** turn LLP 0013's supply-chain capability mechanism into a
hostile-code sandbox. Engine defects, native-code defects, resource exhaustion
outside the named limits, and a malicious trusted parent remain outside the
claim.

### Implementation status — 2026-08-05

The implementation now includes the app-bound SFE/catalog contracts under
`crates/sfe-format` and `crates/sfe-catalog`, the restricted-worker Rust/native
boundary (`src/restricted_worker.rs`, `src/engine/hermes_restricted_worker.cc`,
and `src/engine/hermes_app_bound_bridge.cc`), the app-bound parent binding and
public compile/reporting surface, and canonical language-profile, broker,
policy, and global-inventory fixtures under `tests/fixtures/restricted-worker`.
Broker lifecycle, frame-body, settlement-fault, signal, policy-identity, and
typed-owner fixes have continued to land after acceptance.

This checkpoint is not a completion claim. Eligibility still requires every
§11 row against the final one-file artifact, including the single shared
Node/Ibex language corpus, planted-secret non-transmission, all resource and
lifecycle ceilings, complete native ABI mutation coverage, and the
target-bound advertisement/evidence chain for each enabled tuple. Until those
receipts pass, implementations must remain disabled or unadvertised and refuse
rather than fall back to parent or ambient execution.

## 1. Scope and ownership

This Spec owns four Ibex-side contracts:

1. admission of one external source object as a separately attributed
   principal;
2. the host-portable language and transform profile for that source;
3. the worker's enforced authority and injected-global inventory; and
4. the versioned parent/worker broker, lifecycle, resource, and result ABI.

Snapback LLP 0062 remains authoritative for Snapback product semantics: app
function kinds, diagnostic codes and safe fields, principal selection, API
envelope schemas, strict result projection, and the user-facing exit taxonomy.
This Spec freezes the Ibex substrate those semantics require. A Snapback
implementation maps its exit classes onto §7 without weakening or collapsing
them.

LLP 0029 remains authoritative for the outer executable, its one embedded
entry, graph/carrier/policy admission, platform closure, and provenance. This
Spec is an **application-requested child admission after outer admission**; it
does not add a second row to the embedded entry table. LLP 0028 remains the
transform authority. LLPs 0013/0014 remain the capability-policy authority.
LLP 0002 remains the public embedding-boundary authority.

## 2. External-script language and transform profile

The profile identifier is `ibex/external-script-profile/1`. Its canonical
configuration is part of the engine identity and the restricted-worker ABI
identity. Changing any row rotates the profile identifier or its configuration
digest and requires a host-portable fixture update.

| Property | v1 contract |
| --- | --- |
| Input | one strict UTF-8 byte string, at most 1 MiB before transform |
| Source kind | `file-ts`, `file-js`, or `stdin-ts`; file suffix is exactly `.ts` or `.js`; stdin always uses the TypeScript dialect |
| Parse goal | self-contained ECMAScript Module |
| TypeScript | `.ts` and stdin use erasable syntax only; `import type` and `export type` declarations erase completely; `.js` accepts no TypeScript-only grammar |
| Refused TypeScript | enums, namespaces, parameter properties, decorators, JSX/TSX, and every other emit-bearing extension |
| Imports | static value imports and runtime re-exports (`export ... from` / `export * from`), dynamic `import()`, `import.meta`, and CommonJS `require` are refused before evaluation; type-only imports and re-exports are accepted only when they erase completely |
| Top-level await | supported |
| Completion | await the module's default export; no default export means no result payload |
| Dynamic code | `eval`, indirect eval, `Function` and its constructor family, and runtime compiler hooks are disabled before worker code runs |
| Output target | the exact ECMAScript/Hermes target in LLP 0028's canonical transform manifest |
| Transformed output | at most 4 MiB; transform arena at most 64 MiB, both hard ceilings |

`import type` is accepted only when it erases completely; it cannot resolve,
probe, or cause a module read. A dead-branch import is still a profile
violation: unlike LLP 0028's prepared-graph invocation-time candidate errors,
this single-file profile has no module graph and admits no import site.

Ibex uses the same pinned Oxc dependency set, parser options, output target,
Hermes-compat passes, source-map rules, and configuration-manifest identity as
LLP 0028. The external-script profile contributes its own domain-separated
component to the transform fingerprint. The checked canonical
`external-script-profile-v1.json` manifest is a required implementation
artifact and fixes the dialect selection above, Oxc parser/transform versions,
the syntax-rejection pass, wrapper bytes, source-map composition, output
target, and the 4 MiB output/64 MiB arena ceilings. The transform adapter uses
a ceiling-aware arena and refuses before growing past it; an implementation
that cannot witness both ceilings cannot advertise this profile. A change to
accepted syntax, wrapper/completion behavior, or observable evaluation
semantics rotates the profile to `/2`; a digest change under `/1` is permitted
only for a toolchain/configuration change proven by the full corpus to preserve
the frozen semantics. The Node and Ibex hosts need not use
the same implementation language, but they MUST accept and reject the same
finite syntax corpus, produce the same observable values and failure classes,
and identify the exact profile/version in diagnostics and introspection.

Diagnostics compose original-source positions through the Oxc transform.
Generated code is never presented as the caller's source. Source labels are
logical and non-authoritative: `external-script:sha256:<digest>` plus the
caller-visible basename for diagnostics. The absolute input path is retained
only in the trusted parent's local diagnostic context and is never injected
into the worker or sent through the broker.

The v1 lowering is exact: after the rejection/erasure pass, zero or one
top-level `export default <AssignmentExpression>` is replaced by an engine-
reserved lexical binding; all other runtime export forms, including default
function/class declarations, refuse. The transformed statements execute once
inside an engine-owned async function whose parameters are exactly §5's
endowments. The binding is awaited after the statements; its fulfillment is
the provisional result. Absence of the binding means no result payload. The
reserved identifier is generated outside the caller's lexical namespace, and
goldens prove that authored identifiers cannot capture it. The wrapper itself
is fixed byte-for-byte by the manifest, and its source-map segment is composed
with Oxc's map before diagnostics are admitted.

## 3. Source admission and attribution

Admission is an ordered, fail-closed transaction:

1. **Outer admission first.** The executable authenticates its LLP 0029
   envelope, one embedded parent entry, graph, carriers, policy, engine,
   platform contract, and provenance before the parent handles `run`.
2. **Select one ingress.** `run <path>` and `run -` are the only forms. An
   absent source, multiple sources, another suffix, a directory, or a special
   file is a usage refusal. The host never interprets a path obtained from the
   target or API envelope.
3. **Bound the read itself.** File ingress opens one regular-file descriptor,
   snapshots its identity, reads at most 1 MiB plus one sentinel byte, and
   revalidates identity and length before closing it. It never reopens by path.
   Stdin is streamed through the same byte bound. Oversize input refuses before
   the full object is allocated or transformed.
4. **Attribute raw bytes.** The parent computes SHA-256 over the exact admitted
   bytes before UTF-8 decoding or BOM handling and records source kind,
   digest, byte length, and a fresh run nonce. Invalid UTF-8 refuses. A single
   leading UTF-8 BOM may be ignored by the parser, but remains part of the raw
   digest.
5. **Transform once.** The parent invokes only the authenticated
   `ibex/external-script-profile/1` transform and records its configuration,
   transformed-source, and composed-source-map digests. Profile failures occur
   before a worker exists.
6. **Fetch and admit the current envelope.** The parent fetches the current
   source-stripped API envelope from the fixed bound origin, authenticates its
   app id, digest, schema, function surface, declaration grammar, and protocol
   compatibility, and constructs §6's closed `start.surface`. Authentication
   refusal maps to exit 3, transport failure to 6, binding/integrity failure to
   7, protocol skew to 8, and establishment timeout to 9. No source or handler
   program from that envelope is accepted. The effective
   `LimitsV1.callEstablishmentMs` value selected from the admitted stub bounds
   this initial fetch as well as later call/live establishment.
7. **Authorize the feature.** The admitted StubContractV4 must carry
   `externalWorker.enabled: true`, all identities must match the engine and
   ApplicationBinding, and the tuple must advertise the exact restricted-
   worker profile. Disabled is exit 2; identity or version skew is exit 7 or 8
   according to §7's exact table.
8. **Create a distinct principal.** The worker identity is
   `(kind=external-script, app-binding digest, raw-source digest, run nonce)`.
   It is never root principal `0`, `module-loader`, runtime principal, or a
   package selector. No identity or cache entry survives into another run.
9. **Construct closed runtime state.** A fresh Hermes runtime and Host are
   created with the immutable policy in §4, a maximum heap, dynamic code
   disabled, an empty module registry, and only the broker-backed endowments in
   §5. Any setup failure destroys the partial worker before evaluation.
10. **Evaluate exactly once.** Only the transformed bytes from step 5 enter the
   worker's initial module evaluation. There is no subsequent source-submit,
   `.load`, debugger-eval, REPL, or generic host-call route.

Pre-worker failures have one owner and one outcome. Ingress form, suffix,
special-file, UTF-8, disabled-feature, argument, and refused language-profile
forms (including imports and emit-bearing TypeScript) are local admission
refusals, exit 2. An ECMAScript/Oxc parse failure after the input has been
identified as the selected profile is authored invalid syntax, exit 10.
Source, transformed-output, composed-map, transform-arena, or generated-start-
surface ceilings are witnessed resource exhaustion, exit 11. Transformer,
native ABI, profile-manifest, digest, or other engine-owned invariants are exit
1. Envelope fetch/authentication retains the typed 3/6/7/8/9 mapping in step
6. No implementation may classify the same pre-worker observation differently
depending on whether the Node or Ibex host was selected.

Transform-result caching is disabled in v1. A future cache needs a separately
specified authenticated receipt/index binding profile, raw source, transformed
output, transformer identity, and target; merely rehashing cached bytes would
verify corruption, not authenticate their origin. No runtime, global,
subscription, broker handle, or result object is reused.

## 4. Enforced worker policy

The policy profile is `ibex/restricted-external-worker-policy/1`. It is a
closed engine-owned template, compiled into and digest-bound by the engine
identity; it is not synthesized from caller source and the trusted parent
cannot add entries at run time. The app-bound stub contract may disable the
feature entirely, but neither it nor the canonical project policy may widen
the template. Its digest, the external-
script profile digest, broker ABI, global-inventory digest, and hard maxima are
fields of `StubContractV4.externalWorker` in §8. The required boolean
`externalWorker.enabled` is the single enable/deny carrier. It is authenticated
by the stub-contract digest and compile/provenance chain and is visible to
`inspect-executable` and `--ibex-info`. Canonical `ibex/capsec-policy/2` does
not grow a hidden feature bit.

This worker does **not** add a row to LLP 0014's package-oriented canonical
policy and does not pretend the current `Principal` enum can already express
it. It uses a separate arming contract,
`ibex/restricted-worker-arming/1`, with this exact canonical projection:

```json
{
  "schema": "ibex/restricted-worker-arming/1",
  "principal": {
    "kind": "external-script",
    "appBindingDigest": "sha256-...",
    "sourceDigest": "sha256-...",
    "runId": "00000000000000000000000000000000"
  },
  "transformedSourceDigest": "sha256-...",
  "sourceMapDigest": "sha256-...",
  "engineCompatibilityDigest": "sha256-...",
  "languageProfileDigest": "sha256-...",
  "workerPolicyDigest": "sha256-...",
  "brokerProtocol": "ibex/restricted-worker-broker/1",
  "globalInventoryDigest": "sha256-...",
  "effectiveLimitsDigest": "sha256-...",
  "dynamicCode": "disabled",
  "moduleRegistry": "empty",
  "capabilities": ["broker:snapback-app-cli:1"]
}
```

All keys are required and unknown keys refuse. The three content digests are
ordinary SHA-256 over the exact raw, transformed-source, and composed-source-
map byte strings, using the repository's `sha256-` unpadded-base64url spelling;
the remaining semantic digests use their named repository domains. `runId` is
exactly 32 lowercase hexadecimal
digits; the capabilities array has exactly the one shown element. Its digest is
the repository domain digest under `ibex:restricted-worker-arming:1`. The
native constructor in §6 receives the canonical bytes and independently
recomputes every engine-owned digest. This receipt creates a native
`ExternalScript` attribution record scoped only to the new Host; it does not
extend or serialize the general CapSec `Principal` enum, cannot participate in
package import/delegation, and is destroyed with the run.

The worker's Host and root ceilings deny all ordinary host capabilities.
The only authority-bearing object installed during arming is one unforgeable,
run-scoped `broker:snapback-app-cli:1` handle. It can invoke only the exact
operations in §6 and is revoked on terminalization. Possession never gives the
worker access to the parent's callback context, credentials, transport, target
origin, or raw envelope. The handle is retained inside engine-owned native
closures; it is never itself a JavaScript global or reflectable value.

| Surface | Enforced worker posture |
| --- | --- |
| Filesystem | no APIs, builtins, VFS mounts, cwd, path resolution, or handles after source ingress |
| Network | no `fetch`, XHR, WebSocket, DNS, sockets, listeners, or native network handles |
| Modules | empty static/dynamic/CJS import set; no module-loader endowment |
| Environment/process | no `process`, environment snapshot, argv, stdio handles, signals API, exit API, or host configuration |
| Subprocess/native | no spawn, worker, shell, FFI, native addon, inspector, debugger, generic host call, or runtime-extension registry |
| Clock | no `Date`, `performance`, temporal clock, timezone/locale clock, or direct monotonic reading |
| Randomness | no `Math.random`, crypto randomness, UUID, OS random, or entropy-bearing runtime identity |
| Dynamic code | disabled at Hermes construction; no re-enable operation |
| Persistence | no cache, SQLite, storage, clipboard, or other stateful host API |

This is enforced in three layers, all required:

- the worker uses an armed Host whose immutable ceilings deny every ordinary
  capability, including to its restricted root and module-loader identities;
- the compartment/global inventory contains only §5's exact endowments and is
  sealed before evaluation; and
- the native surface inventory proves no ungated ABI can reach the worker.

Permissive or audit fallback is forbidden. An unavailable CapSec prerequisite
is an admission refusal, never a reason to run the script in the parent or in
ambient standalone mode. The outer parent may itself use LLP 0047's ambient
posture; that does not change the worker's mandatory enforced posture. The
feature is unsupported on a tuple until the restricted-worker policy and all
three enforcement layers pass there.

The current armed project constructor and `ex_hermes_create_no_eval` do not
satisfy this contract. Implementing this Spec therefore requires the dedicated
constructor family in §6 and a corresponding LLP 0002/header conformance
amendment; using either existing constructor is a typed admission failure.

## 5. Injected worker surface

The worker global is created from a closed manifest and sealed before source
evaluation. Its application-facing additions are exactly:

- `api`: a frozen, null-prototype object of safe property aliases synthesized
  from the admitted API envelope. Hazardous, reserved, or invalid aliases are
  absent; the function remains reachable by stable id through
  `snapback.function(id)` when the Snapback contract permits it.
- `snapback`: a separate frozen, null-prototype object containing safe engine
  metadata and the `function(id)` fallback. It contains no target origin,
  credential source, bearer, raw envelope, parent handle, or arbitrary host
  operation.
- `args`: the frozen string array after `--`; it contains no executable path,
  selected source path, credential, or implicit environment value.
- `signal`: one concrete abort signal, initially clear and fired exactly once
  when §7 begins teardown.
- `console`: frozen `log`, `info`, `warn`, `error`, and `debug` functions that
  emit bounded broker console frames. They expose no stdin/stdout/stderr file
  handles.
- `setTimeout` and `clearTimeout`: relative, one-shot timers scheduled by the
  parent monotonic clock. A timer handle is a frozen, null-prototype engine
  object with an unforgeable run-scoped native slot. Timers do
  not reveal current time, support intervals, or survive teardown.

Standard pure language intrinsics remain available except for the removed
clock, randomness, and dynamic-code surfaces. The global inventory is a golden
fixture: additions are ABI changes, not harmless conveniences.

A safe alias matches ECMAScript identifier grammar exactly as the checked Oxc
Unicode tables define it: first scalar `$`, `_`, or `ID_Start`; subsequent
scalars `$`, U+200C, U+200D, or `ID_Continue`. NFC-normalized alias bytes must
equal the envelope name bytes. The closed hazardous-alias manifest v1 is,
byte-for-byte and in this order, `__proto__`, `constructor`, `prototype`,
`then`, `catch`, `finally`, `function`, `inspect`, `toJSON`, `toString`, and
`valueOf`. Its canonical digest is part of `globalInventoryDigest`. A name
that fails the grammar or appears in that manifest gets no `api` property but
remains addressable by stable id; duplicate normalized names or ids refuse the
surface. Changing the Unicode tables or hazard list rotates the global-
inventory identity and its corpus.

The v1 signature is exactly `setTimeout(callback, delayMs)`: `callback` must
already be callable, `delayMs` must already be a finite integer Number in
`0..1800000`, and extra arguments are refused with `TypeError`; there is no
string or user-defined coercion and no callback-argument forwarding.
`clearTimeout(handle)` is a no-op for any value lacking the matching live
run-scoped native slot and otherwise clears idempotently. The schedule consumes
a finite open-timer budget. v1 defaults to 1,024 simultaneously open timers and
has a hard maximum of 8,192. A delay beyond the remaining run time is legal but
will never fire because teardown consumes the row. Scheduling during teardown
refuses. Timers and the abort signal are lifecycle controls, not general host
capabilities.

The wrapper mirrors the authenticated open-timer credit count so
`setTimeout` can either return its opaque handle or throw synchronously without a
cross-thread round trip. Every accepted operation is still sent through §6's
`timerSet`/`timerClear` frames and revalidated by the parent, which owns the
monotonic schedule and registry. A mirror/parent disagreement is an engine-
internal protocol fault, not a reason to widen or guess. `timerFired` consumes
the registry row before the callback is enqueued, and `clearTimeout` is
idempotent for an already-fired, already-cleared, or unknown same-run id.

## 6. Broker ABI v1

The logical ABI identifier is `ibex/restricted-worker-broker/1`. v1 fixes one
topology: a separate Hermes runtime and Host on a dedicated Ibex-owned thread
inside the trusted parent's process. Two bounded typed queues connect it to the
parent coordinator. This is a distinct worker and authority domain, but not an
OS-process isolation claim. Child-process, re-exec, helper-file, and selectable
transport variants are not part of v1.

### 6.1 Native construction and ownership seam

The worker is exposed through a new opaque `ExactRestrictedWorkerV1`, never as
an `ExactHermesRuntime *`; generic eval, embedder-capability, module-runner,
debugger, and host-call functions therefore cannot be applied to it. LLP 0002
and `include/exact_runtime.h` must materialize this exact family before the
profile can advertise:

```c
#define EX_RESTRICTED_WORKER_ABI_VERSION_V1 1u

typedef struct ExactRestrictedWorkerV1 ExactRestrictedWorkerV1;

typedef struct ExRestrictedWorkerOptionsV1 {
  uint32_t abi_version;        /* exactly 1 */
  uint32_t struct_size;        /* exactly sizeof(this v1 struct) */
  const uint8_t *arming_json;  /* canonical restricted-worker-arming/1 */
  size_t arming_json_len;
  const uint8_t *limits_json;  /* canonical restricted-worker-limits/1 */
  size_t limits_json_len;
} ExRestrictedWorkerOptionsV1;

typedef enum ExRestrictedWorkerEventTagV1 {
  EX_RESTRICTED_WORKER_EVENT_FRAME_V1 = 1,
  EX_RESTRICTED_WORKER_EVENT_RESOURCE_V1 = 2,
  EX_RESTRICTED_WORKER_EVENT_ENGINE_FAULT_V1 = 3,
  EX_RESTRICTED_WORKER_EVENT_CLOSED_V1 = 4
} ExRestrictedWorkerEventTagV1;

typedef enum ExRestrictedWorkerFaultV1 {
  EX_RESTRICTED_WORKER_FAULT_NONE_V1 = 0,
  EX_RESTRICTED_WORKER_FAULT_HEAP_LIMIT_V1 = 1,
  EX_RESTRICTED_WORKER_FAULT_HERMES_V1 = 2,
  EX_RESTRICTED_WORKER_FAULT_LOCKDOWN_V1 = 3,
  EX_RESTRICTED_WORKER_FAULT_QUEUE_PROTOCOL_V1 = 4,
  EX_RESTRICTED_WORKER_FAULT_INTERNAL_V1 = 5,
  EX_RESTRICTED_WORKER_FAULT_INTERRUPT_UNAVAILABLE_V1 = 6
} ExRestrictedWorkerFaultV1;

typedef struct ExRestrictedWorkerEventV1 {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t tag;
  uint32_t fault;              /* ExRestrictedWorkerFaultV1 */
  uint64_t runtime_nonce;
  uint8_t *bytes;              /* owned; FRAME only */
  size_t bytes_len;
} ExRestrictedWorkerEventV1;

int32_t ex_restricted_worker_create_v1(
    const ExRestrictedWorkerOptionsV1 *options,
    ExactRestrictedWorkerV1 **out_worker,
    uint64_t *out_runtime_nonce);
int32_t ex_restricted_worker_start_v1(
    ExactRestrictedWorkerV1 *worker,
    const uint8_t *transformed_source, size_t transformed_source_len,
    const uint8_t *composed_source_map, size_t composed_source_map_len,
    const uint8_t *start_frame, size_t start_frame_len);
int32_t ex_restricted_worker_submit_frame_v1(
    ExactRestrictedWorkerV1 *worker,
    const uint8_t *frame, size_t frame_len);
int32_t ex_restricted_worker_take_event_v1(
    ExactRestrictedWorkerV1 *worker,
    uint32_t wait_ms,
    ExRestrictedWorkerEventV1 *out_event);
int32_t ex_restricted_worker_interrupt_v1(
    ExactRestrictedWorkerV1 *worker, uint64_t runtime_nonce);
int32_t ex_restricted_worker_destroy_v1(
    ExactRestrictedWorkerV1 *worker, uint64_t runtime_nonce);
void ex_restricted_worker_event_dispose_v1(
    ExRestrictedWorkerEventV1 *event);
```

All byte inputs are borrowed only for the call and copied only after their
declared length passes the relevant ceiling. `options`, output pointers, and
required byte pointers are non-null. Arming JSON is 1..4 KiB; limits JSON is
1..2 KiB. Transformed source is non-null and 1 byte..4 MiB; a source-map pointer
is null exactly when its length is zero and is otherwise non-null, with length
at most 8 MiB; start and submitted frames are non-null and 1 byte through the
effective `frameBytes`. A pointer/length disagreement is `-1`, and an exceeded
ceiling is `-5`, before allocation or copy.

`create` and `start` are each one-shot; a start failure permanently closes the
handle but the caller still owns it and must call `destroy` with the valid
nonce. Create parses canonical `LimitsV1`, verifies that its domain digest is
the arming receipt's `effectiveLimitsDigest`, and retains those exact canonical
bytes. Start requires the exact first parent→worker `start` frame. Its limits
must reserialize byte-identically to the retained creation limits; its profile
and content digests must equal the arming receipt. The native implementation
hashes the supplied transformed-source and source-map buffers and requires the
ordinary SHA-256 values to equal `transformedSourceDigest` and
`sourceMapDigest` before evaluation. A generated start frame or function
surface that exceeds `frameBytes` refuses pre-worker as witnessed exit 11.

The 128-bit `runId` in arming and frames is the script attribution/protocol
identity. `out_runtime_nonce` is a separate nonzero native-minted 64-bit
control lease, unique among live handles; it never enters arming, JavaScript,
or broker frames. Conflating, truncating, or deriving either identifier from
the other is an arming-identity failure.

The handle owns the OS thread, Hermes runtime, Host, queues, globals, and
native broker closures. All JSI work and physical destruction occur on that
internal owner thread. The coordinator thread that calls `create` is the only
thread permitted to call `start` and `destroy`; one consistent producer thread
owns all `submit` calls and one consistent consumer thread owns all
`take_event` calls. `interrupt` may be called from any thread. Overlapping
calls or a different producer/consumer/coordinator return `-4`; none executes
JavaScript on the caller. With a valid nonce, `destroy` posts mandatory owner-
thread destruction, joins, invalidates the nonce, and consumes the handle even
when cleanup returns `-9`. Invalid/stale nonce returns `-3` and leaves ownership
with the caller. After a consuming destroy returns, the pointer is invalid and
no worker function may be called with it; such a call is outside the C ABI
contract rather than a recoverable stale-handle probe.

Every status is a fixed-width `int32_t`: `0` success; `-1` invalid argument;
`-2` ABI/version/size mismatch; `-3` stale handle or nonce; `-4` invalid
lifecycle; `-5` input ceiling; `-6` queue closed/full; `-7` arming identity
mismatch; `-8` unsupported engine/tuple; `-9` engine fault. Every output is
zero/null initialized on failure. `take_event` returns `1` for a clean bounded
wait with no event and otherwise the statuses above. A FRAME event has
`fault=NONE`, non-null bytes of length `1..frameBytes`, and transfers that one
buffer to the caller. RESOURCE has `fault=HEAP_LIMIT` and null/zero bytes.
ENGINE_FAULT has one of `HERMES`, `LOCKDOWN`, `QUEUE_PROTOCOL`, `INTERNAL`, or
`INTERRUPT_UNAVAILABLE` and null/zero bytes. CLOSED has `fault=NONE`, null/zero
bytes, appears exactly once, is the final native event, and is emitted only
after no frame can follow and the owner JavaScript/event-production loop has
stopped; the owner control loop remains only to accept destroy. Any other
tag/fault/payload combination or an event whose `runtime_nonce` differs from
the live control lease is an exit-1 native invariant failure. CLOSED is defined
only after a successful start; a failed start yields no events and proceeds
directly to required destroy. `wait_ms` is `0..300000`, with zero meaning a
nonblocking poll. An event
buffer is caller-owned until its one `dispose`; non-FRAME events own no buffer
and contain no arbitrary engine string. Dispose accepts a valid returned event,
frees its FRAME buffer if present, and zeroes every field; disposing that
zeroed event again is a no-op. The header's C11/C++/Swift ABI checks,
output-ownership linter, failed-start/wrong-thread/stale-nonce fixtures, closed-
event ordering, and symbol allowlist cover the family.

Creation recomputes the §4 arming receipt, configures the exact heap ceiling,
irreversibly disables dynamic compilation, installs only the engine-owned
closures/global inventory, freezes the intrinsic/global graph, proves the
module/debugger/extension registries empty, then marks the worker startable.
There is no partially armed success and no generic fallback.

### 6.2 Canonical values and frames

The canonical queue/test representation is strict UTF-8 RFC 8785 JSON. A
`StrictValueV1` is exactly JSON null/boolean/string/number/array/object after
the source-side structural walk: numbers are finite IEEE-754 values other than
negative zero; strings contain no lone surrogate; arrays are dense and have no
named/symbol properties; objects have null or ordinary `Object` prototype,
enumerable own data properties only, no symbols or `toJSON`; the graph is
acyclic; accessors are never invoked. No `undefined`, bigint, Date, Map, Set,
typed array, function, proxy-observable descriptor, custom prototype, or cycle
is admitted. The receiver repeats the structural/domain validation after
decode. A value has maximum nesting depth 64 with the root at depth zero,
maximum 100,000 total value nodes, and maximum 100,000 aggregate object
properties plus array elements. Both ends use an explicit work stack, never
language or native recursion. Before any prototype, descriptor, key, or other
reflective operation, the worker asks an engine-native, non-trapping proxy-
identity predicate; a proxy or an engine unable to make that determination is
rejected. Ordinary-object prototype identity is then checked against the
captured intrinsic directly—never by reading a user-observable `constructor`
property. The parent preflights JSON token count, depth, and container
cardinality iteratively within the already-bounded byte slice before generic
decode. These bounds are refusal, not truncation, and apply independently of
the containing frame/result byte ceiling.

Every frame is one closed object with the exact top-level keys shown here:

```json
{
  "schema": "ibex/restricted-worker-broker/1",
  "runId": "<128-bit lowercase hex nonce>",
  "sequence": 1,
  "type": "call",
  "body": {}
}
```

Both directions start at sequence `1`; `sequence` is a positive JSON-safe
integer through `9007199254740991` and increases by exactly one independently
in each direction. Exhaustion is an engine-internal fault. The in-process
queue carries a fixed-width length before bytes: length is checked against the
effective frame maximum before allocation/copy, then canonical JSON is checked
within that already-bounded slice. No streaming decoder may allocate from an
untrusted nested length. Each direction holds at most eight frames and at most
twice the effective frame maximum in aggregate. Worker emission backpressures
its owner thread until the parent drains or terminalizes; parent submission
receiving status `-6` drains/retries without changing frame sequence. The run
deadline continues while either side is backpressured, so the queue is bounded
without inventing an “unlimited” or silently dropped lane. Unknown, duplicate,
skipped, wrong-run, oversized, or
non-canonical frames before terminal selection are protocol faults (exit 1),
because script code cannot access the channel encoder. After terminal
selection, only worker→parent bounded `console` frames during grace are
admitted; the parent may still deliver `timerFired` for a timer that was
already registered before `abort`, but no new timer can be registered. All
other late frames are dropped with one bounded parent diagnostic and cannot
alter the decision. No frame contains a pointer, descriptor, bearer, credential source,
origin, executable path, environment value, or arbitrary engine/server text.

Identifiers `callId`, `subscriptionId`, and `timerId` are decimal strings in
`1..18446744073709551615`, allocated monotonically by the worker and never
reused. `functionId` is UTF-8, 1–512 bytes, and must be present in the admitted
surface. `timeoutMs` is an integer in the static wire range `1..300000`.
`delayMs` is an integer in the static wire range `0..1800000`. The parent
computes a call's effective deadline as the minimum of requested timeout and
remaining run time; a timer beyond remaining run time is valid but cannot fire.
`args` and result values are `StrictValueV1`.

`BrokerErrorV1` is the exact closed object
`{code,exitClass,recognized,locus,safeFields,attribution}`. `code` is 1–128
ASCII `[A-Z][A-Z0-9_]{0,127}`; `exitClass` is integer 2–9; `recognized` is boolean;
`locus` is one of `request`, `result`, `live`, `broker`; `safeFields` is a
`StrictValueV1` object admitted by the engine's digest-bound per-code allowlist
(empty for an unknown code); `attribution` is either null or the admitted
Snapback attribution object. Unknown codes retain their code, set
`recognized:false`, use an empty `safeFields`, and take Snapback LLP 0062's
locus fallback. `message`, `details`, headers, arguments, source/path text, and
unknown attribution keys are never representable.

Every broker error delivered to JavaScript is an engine-created Error object
with immutable native metadata in an unforgeable internal slot. Catching and
rethrowing that same object preserves its exact `BrokerErrorV1` and class;
mutating readable properties cannot change the native record. A structural
copy, wrapper, subclass, or script-authored lookalike lacks the slot and is an
ordinary script error if it escapes. The terminal wrapper reads only the slot,
never user properties, when choosing the broker branch of `failed`.

The `start.profile` object has exactly
`{language,languageDigest,workerPolicy,workerPolicyDigest,broker,globalsDigest}`.
The identifiers are the constants in §§2/4/6 and every digest is `sha256-`
base64url. `start.surface` has exactly
`{envelopeDigest,functions}`, where `functions` is sorted by UTF-8 `id` and
each closed row is `{id,kind,alias}`; `kind` is one of `query`, `mutation`,
`action`, `live-query`, and `alias` is a safe identifier string or null after
hazard suppression. The surface contains no origin, app id, credential,
handler/declaration source, or raw envelope. `start.limits` is `LimitsV1`, the
closed integer object with exactly
`{sourceBytes,transformedSourceBytes,sourceMapBytes,transformArenaBytes,
runWallMs,callEstablishmentMs,brokerOperations,openSubscriptions,frameBytes,
resultBytes,stderrBytes,heapBytes,graceMs,openTimers}`. Fixed transform/input
rows equal their maxima; every other value is the admitted effective value.
The profile's identifiers and digests equal the arming receipt, and the start
limits reserialize byte-identically to the limits supplied at native creation.
`start.sourceDigest`, `start.transformedSourceDigest`, and
`start.sourceMapDigest` equal the receipt and the native-hashed input buffers.
`args` contains only the explicit tail, each string at most 64 KiB UTF-8 and
the complete array at most 1 MiB canonical bytes.

Surface admission renders both a `call` and `liveOpen` skeleton for every
function id using the maximum sequence/id/timeout spellings, the actual fixed
schema/run id and function-id bytes, and `args:{}`. For each skeleton, its
canonical byte length minus the two empty-args bytes must be at most 1,024.
Failure is envelope grammar/identity exit 7 before worker creation. Combined
with the `frameBytes - 1024` argument bound below, this proves every admitted
script-authored request fits; the encoder still checks the complete frame, and
a disagreement is exit 1.

Worker → parent frame bodies:

| Type | Exact body fields | Meaning |
| --- | --- | --- |
| `call` | `callId`, `functionId`, `args`, `timeoutMs` | invoke one non-live app function |
| `liveOpen` | `subscriptionId`, `functionId`, `args`, `timeoutMs` | establish one live query |
| `liveClose` | `subscriptionId` | explicitly dispose an iterator |
| `timerSet` | `timerId`, `delayMs` | schedule one parent-clock one-shot timer |
| `timerClear` | `timerId` | idempotently clear one timer |
| `console` | `level`, `values` | normalized script-authored stderr event |
| `settlementBegin` | `hasValue`, `byteLength`, `digest`, `chunkCount` | begin provisional canonical-result transfer |
| `settlementChunk` | `index`, `data` | one ordered base64url result chunk |
| `settlementEnd` | no fields | finish provisional result transfer |
| `failed` | either `{kind:"script",code}` or `{kind:"broker",error}` | terminal escaped failure; script `code` is exactly `SNAPBACK_APP_CLI_SCRIPT_ERROR`, broker `error` is the engine-branded `BrokerErrorV1` |

Parent → worker frame bodies:

| Type | Exact body fields | Meaning |
| --- | --- | --- |
| `start` | `profile`, `sourceDigest`, `transformedSourceDigest`, `sourceMapDigest`, `args`, `surface`, `limits` | immutable initial metadata; sent once before evaluation |
| `callResult` | `callId`, `ok`, exactly one of `value` or `error` | settle one call |
| `liveOpened` | `subscriptionId`, `ok`, exactly zero fields or one `error` according to `ok` | settle establishment |
| `liveValue` | `subscriptionId`, `value` | latest admitted live snapshot |
| `liveTerminal` | `subscriptionId`, `error` | terminal subscription failure |
| `liveClosed` | `subscriptionId` | acknowledge disposal |
| `timerFired` | `timerId` | enqueue one due callback after consuming its registry row |
| `abort` | `reason`, `signal` | fire `signal` and enter grace; `signal` is null or an integer 1–64 only when reason is `parent-signal` |

`abort.reason` is exactly one of `settled`, `run-timeout`,
`resource-exceeded`, `broker-failure`, `script-failure`, `parent-signal`, or
`engine-fault`. `callResult.ok:true` requires `value` and forbids `error`;
`ok:false` does the inverse with `BrokerErrorV1`. `liveOpened.ok:true` has no
third field; `ok:false` requires `error`. Every other body has all and only the
listed keys; “no fields” means `{}`.

Before its encoder sees a script-authored `call` or `liveOpen`, the worker
performs the iterative strict-value walk and JCS byte-count preflight. Args may
occupy at most `effectiveFrameBytes - 1024` canonical bytes. Invalid or larger
args reject that operation locally with an engine-branded catchable exit-2
`BrokerErrorV1` and emit no frame. That record is exactly code
`SNAPBACK_APP_CLI_USAGE`, `exitClass:2`, `recognized:true`, locus `request`,
`safeFields:{"reason":"invalid-arguments"}`, and null attribution. The parent independently validates admitted
call args before dispatch and validates values/errors before framing them.
Per-call/establishment timeout is a catchable exit-9 error. A parent call/live
result that cannot fit its one effective frame is witnessed resource exit 11.
An oversized or otherwise invalid closed frame emitted by engine-owned framing
code is exit 1. Run timeout, signal, or engine fault never masquerades as a
catchable call result; it enters §7 terminalization.

### 6.3 Settlement, console, live, and timer rules

For a present result, the worker first performs the strict structural walk,
serializes RFC 8785 bytes, and checks the aggregate result limit. It sends one
`settlementBegin` with `hasValue:true`, the byte length, ordinary SHA-256
digest using the repository spelling `sha256-` plus unpadded base64url, and
exact chunk count; contiguous `settlementChunk` indices start at zero; then one
`settlementEnd`. Each chunk's decoded payload is at most
`floor((effectiveFrameBytes - 1024) * 3 / 4)` bytes, with unpadded base64url
encoding. The effective frame limit is at least 64 KiB. A missing default sends
`hasValue:false`, length/chunk count zero, `digest:""`, no chunks, then end.
The parent streams chunks into an aggregate-bounded buffer, verifies count,
length, digest, canonical bytes, and strict value before settlement is
admitted. Duplicate begin/end, interleaving, gaps, or bytes beyond the declared
aggregate are protocol faults. This chunk family makes the 16 MiB result limit
independent of the 4 MiB per-frame maximum.

Console never invokes getters or user coercion. Each argument is normalized
depth-first to a `StrictValueV1`: supported values retain their value; depth
beyond 4, arrays beyond 100 entries, objects beyond the first 100 UTF-8-sorted
own keys, cycles, accessors, custom/proxy-observable descriptors, and unsupported
types become a closed marker object `{"$console":"<reason>"}` where reason is
one of `depth`, `entries`, `cycle`, `accessor`, `prototype`, `undefined`,
`bigint`, `symbol`, `function`, `number`, or `uninspectable`. Strings and keys
are clipped on Unicode-scalar boundaries to 16 KiB and 1 KiB respectively and
end with U+2026. A console body is capped at
`min(65536, effectiveFrameBytes - 1024)` canonical bytes by dropping whole
trailing arguments and appending `{"$console":"truncated"}`. `level` is
one of `log`, `info`, `warn`, `error`, `debug`. These rules are shared golden
code/data, not independently inferred Node/native formatting.

Live delivery is **latest-wins**. While a `liveValue` is queued but unconsumed,
a newer admitted snapshot replaces it; values already observed by the worker
are never rewritten. Establishment and every renewal have the requested
per-call deadline. Rotation or another terminal authorization failure closes
the subscription. Iterator `return`, loop exit, worker teardown, or an
abandoned iterator detected at run settlement emits or synthesizes exactly one
`liveClose`; the parent disposes the underlying subscription even if the
acknowledgement cannot be delivered.

`timerSet` consumes mirrored and parent registry credit and uses the parent
monotonic clock; `timerClear` and `timerFired` race by parent frame order. The
static `delayMs` range, token rules, two-argument `setTimeout` surface, and lack
of coercion are identical in the Node parity host. No timer frame exposes a
timestamp. All timer rows are consumed during teardown.

The implementation MUST NOT reuse `__hostCall`, `__hostCallAsync`, the
diagnostic source evaluator, `ex_hermes_eval`, or an untyped operation-name
bridge. The native family above and the closed frames are the complete v1 seam.
The current Snapback Node child protocol is implementation history, not the
parity oracle: it lacks this run/sequence framing, timer and chunk families,
canonical structured console projection, and fatal aggregate-ceiling behavior.
Node and Ibex eligibility therefore requires migrating both to one generated
schema and the single corpus in §11; “matches current Node code” is not a pass.

## 7. Lifecycle, limits, and outcome mapping

The trusted parent owns a monotonic state machine:

`admitting → running → terminal-selected → grace → cancelling → closed`.

The settlement chunk transaction is provisional. It becomes an “admitted
settlement” only after the parent has reconstructed the bytes, verified their
declared digest/canonical encoding, decoded and revalidated `StrictValueV1`,
and admitted the aggregate result size. The reconstructed immutable bytes are
the snapshot; grace-window mutation cannot change them. Missing default export
admits “no value.” Structural/serialization failure is script error 10; result
overflow is witnessed resource exhaustion 11.

Terminalization is signal-first:

1. atomically select one terminal record using the table and precedence below;
2. if the worker is still responsive, send `abort`, fire `signal` exactly once,
   and open the bounded grace window;
3. refuse new calls, subscriptions, and timers during grace while permitting
   local `finally` work and bounded console events;
4. after grace, interrupt any running Hermes evaluation using the
   nonce-authenticated LLP 0002 interrupt path;
5. require CLOSED within a fixed, non-configurable 250 ms interrupt-
   acknowledgement window. If it does not arrive, flush only already-owned
   bounded parent output and terminate the entire CLI process immediately with
   the already-selected exit; v1 makes no false claim that an in-process stuck
   engine can be force-killed while preserving its parent process;
6. when the owner responds, cancel outstanding calls, dispose subscriptions and timers, revoke the
   broker handle, flush the bounded stderr lane, and destroy the worker on its
   owner thread; and
7. emit the already-snapshotted result or typed failure. Orphan timers and
   abandoned iterators never keep a completed run alive.

The parent coordinator serializes observations and stamps them with its
monotonic clock. A record observed after terminal selection cannot replace it.
For candidates with the same clock tick, precedence is: admitted settlement;
parent process signal; witnessed engine/internal fault; run timeout; witnessed
resource ceiling; uncaught broker failure; script failure. This extends, rather
than changes, Snapback's settlement/timeout/resource/broker/script ordering.

| Terminal candidate | Catchable in script? | Selected outcome |
| --- | --- | --- |
| admitted settlement | no | exit 0 and snapshotted result/no-result |
| parent SIGINT/SIGTERM/SIGHUP | no | conventional `128+n` |
| native engine fault, invalid engine-generated frame in either direction, arming/queue invariant failure | no | exit 1 |
| run wall deadline | no | exit 9 |
| witnessed call-count, subscription/timer, parent call/live result-frame, settlement-result, transformed-input, map/arena, heap, or generated-start ceiling | no | exit 11 |
| ordinary `callResult`/`liveTerminal` error | yes | if uncaught, its exact class 2–9 |
| per-call or live-establishment deadline | yes | if uncaught, exit 9 |
| authored throw/rejection or out-of-profile result | no once uncaught | exit 10 |

“Catchable” applies only to the closed error delivered to an outstanding
operation before terminal selection. Hitting an aggregate budget does not
deliver a catchable resource error and let work continue: the parent selects
exit 11. A caught ordinary broker error is script control flow and does not
preselect an exit. If it later escapes as the script's final rejection, its
preserved 2–9 class wins over generic script error and is carried in the
`failed.kind="broker"` branch. The `failed.kind="script"` branch always maps
to 10. A copied, wrapped, or forged error is not broker-branded and therefore
cannot select 2–9.

v1 limits are part of the ABI:

| Limit | Default | Hard maximum | Enforcement |
| --- | ---: | ---: | --- |
| source bytes | 1 MiB | 1 MiB | parent ingress before full allocation |
| transformed source bytes | 4 MiB | 4 MiB | ceiling-aware Oxc output sink before worker copy |
| composed source-map bytes | 8 MiB | 8 MiB | transform sink before worker copy |
| transform arena | 64 MiB | 64 MiB | ceiling-aware allocator; no profile advertisement without witness |
| run wall time | 120 s | 30 min | parent monotonic deadline + Hermes interrupt |
| per-call / establishment | 60 s | 5 min | parent monotonic deadline |
| brokered calls, including opens/renewals/retries | 1,000 | 10,000 | parent counter |
| simultaneously open subscriptions | 16 | 256 | parent registry |
| one canonical broker frame | 1 MiB | 4 MiB | minimum selectable 64 KiB; both endpoints before allocation/decode |
| stdout result | 1 MiB | 16 MiB | worker preflight + parent revalidation |
| aggregate stderr frames | 1 MiB | 16 MiB | parent; one bounded elision record, not termination |
| Hermes heap | 128 MiB | 512 MiB | restricted-worker runtime GC configuration |
| graceful teardown | 2 s | 10 s | parent monotonic deadline |
| simultaneously open timers | 1,024 | 8,192 | parent timer registry |

The first four rows are fixed in v1. User-selected values for configurable rows
are positive integers within any stated minimum and no greater than the hard
maximum; there is no “unlimited” spelling. Retry, renewal, and resubscription work
consume the budgets that caused them. Heap exhaustion maps to resource
exhaustion only when the configured Hermes heap limit is the witness. The heap
limit is not a total-RSS guarantee; unexplained OS termination, native
allocation failure outside a named bound, and engine faults map to the engine-
internal class, never a fabricated resource-ceiling result.

The exact process outcome mapping is:

| Exit | Ibex/Snapback class in this profile |
| ---: | --- |
| 0 | admitted success |
| 1 | engine-internal/native/protocol invariant failure |
| 2 | usage, local admission/profile/args refusal, or disabled feature |
| 3 | authentication/authorization refusal |
| 4 | function id absent from the admitted surface |
| 5 | application function/server-result failure |
| 6 | transport failure |
| 7 | artifact, app-binding, envelope, or identity failure |
| 8 | engine/schema/broker/target compatibility mismatch |
| 9 | per-call, live-establishment, envelope-establishment, or run timeout |
| 10 | script throw/rejection, invalid syntax class owned by script error, or out-of-profile result |
| 11 | witnessed named resource ceiling |
| `128+n` | propagated parent process signal `n` |

Exit 1 is not usage, and a crash or unexplained native allocation failure is
never dressed as exit 11. The broker carries stable classes 2–9; 0/1/10/11 and
signals are selected by the parent lifecycle. Signal deaths remain outside the
1–11 taxonomy.

## 8. App-bound executable contract

The app binding is immutable, canonical non-executable data. It must be
inspectable without evaluating or reverse-engineering the parent's HBC. The
current `ibex/single-file-executable/2` section vocabulary is closed and has no
application-binding section, while `PackageProvenanceV1` and `CompilePlanV1`
are strict schemas. This extension therefore rotates the app-bound profile
explicitly rather than hiding data in an existing section:

- `StubContractV4` / `ibex/stub-contract/4` adds the external-script profile,
  restricted-worker-policy, broker-ABI, global-inventory, resource-maxima, and
  application-binding-schema identities;
- `ibex/sfe-catalog/2` adds a target-specific restricted-worker advertisement
  and its evidence carrier to the catalog entry;
- `ibex/single-file-executable/3` adds exactly one canonical
  `ApplicationBinding` section kind and requires it for the app-bound profile;
- `CompilePlanV2` / `ibex/compile-plan/2` binds the application-binding digest,
  app-bound stub contract, parent graph/policy, target, and producer inputs;
  and
- `PackageProvenanceV2` / `ibex/package-provenance/2` binds that compile plan
  and the final stub-core reconstruction exactly as LLP 0029 does today;
- `ibex/executable-inspection/4` adds the admitted binding and restricted-
  worker facts to non-evaluating inspection; and
- `ibex/standalone-executable-info/2` admits envelope V3/stub V4 and reports the
  same authenticated posture through `--ibex-info`.

The general one-entry artifact may remain on `StubContractV3` and envelope V2.
An app-bound producer and stub use stub V4, envelope V3, compile/provenance V2,
inspection V4, and standalone-info V2 as one lockstep profile; older readers
refuse it, and no dual parser or field-presence inference chooses the security
posture. Catalog V2 and the target advertisement rotate in the same lockstep;
the catalog records the exact profile and every digest.

### 8.1 Strict schema and binary definitions

Every JSON object below is RFC 8785 canonical UTF-8, has every named field,
rejects unknown fields, and uses the existing `sha256-` base64url digest type.
Arrays preserve the stated order and contain no duplicates. The checked JSON
Schemas and Rust `deny_unknown_fields` types must be generated/materialized
from these definitions before producer or reader code lands.

`StubContractV4` is `StubContractV3` with these exact coordinated changes:

- `schema` is `ibex/stub-contract/4` and its domain is
  `ibex:stub-contract:4`;
- `acceptedSchemas.envelope` is `ibex/single-file-executable/3` and a required
  `acceptedSchemas.applicationBinding` equals `ibex/app-bound-parent/1`, while
  required `acceptedSchemas.targetAdvertisement` equals
  `ibex/restricted-worker-target-advertisement/1`;
- `boot.informationSelector.reportSchema` is
  `ibex/standalone-executable-info/2`;
- `abis.restrictedWorker` is the string
  `ibex/restricted-worker-abi/1`; and
- required `externalWorker` is the closed object
  `{enabled,languageProfile,languageProfileDigest,armingSchema,workerPolicy,
  workerPolicyDigest,brokerProtocol,globalInventoryDigest,
  targetAdvertisementDigest,defaults,maxima}`.

The identifiers in that object equal §§2/4/6. `enabled` is boolean. Both
`defaults` and `maxima` are `LimitsV1` objects as defined in §6; fixed rows
repeat the same value in both. The domain digest
of the effective limits object under `ibex:restricted-worker-limits:1` is the
`effectiveLimitsDigest` in each run's arming receipt. A V4 artifact without an
ApplicationBinding remains invalid whether `enabled` is true or false.

The target evidence artifact is the following exact canonical object:

```json
{
  "schema": "ibex/restricted-worker-target-advertisement/1",
  "target": {
    "triple": "aarch64-apple-darwin",
    "minimumPlatform": "macos-14.0-arm64"
  },
  "engineCompatibilityDigest": "sha256-...",
  "nativeAbi": "ibex/restricted-worker-abi/1",
  "languageProfile": "ibex/external-script-profile/1",
  "languageProfileDigest": "sha256-...",
  "workerPolicy": "ibex/restricted-external-worker-policy/1",
  "workerPolicyDigest": "sha256-...",
  "brokerProtocol": "ibex/restricted-worker-broker/1",
  "globalInventoryDigest": "sha256-...",
  "defaultsDigest": "sha256-...",
  "maximaDigest": "sha256-...",
  "evidence": {
    "schema": "ibex/restricted-worker-target-evidence/1",
    "suiteDigest": "sha256-...",
    "engineArtifactDigest": "sha256-...",
    "policyArtifactDigest": "sha256-...",
    "brokerCorpusDigest": "sha256-..."
  }
}
```

All fields and keys are required and closed. `target.triple` is exactly the
catalog entry target; `minimumPlatform` is its canonical platform-floor string
(`macos-<major>.<minor>-arm64` for Darwin,
`linux-glibc-<major>.<minor>-x86-64-v1` for this Linux profile), using the same
spelling as the catalog entry rather than a second platform vocabulary.
`engineCompatibilityDigest` is the exact engine identity accepted by the
stub. Defaults and maxima digests use
`ibex:restricted-worker-limits:1`; the four evidence digests are ordinary
SHA-256 content digests of immutable target-specific result/artifact files.
The advertisement semantic digest uses
`ibex:restricted-worker-target-advertisement:1`. It authenticates evidence
identity, not an infallibility claim; the release process must reproduce and
verify the referenced artifacts.

Catalog V2 is catalog V1 with schema `ibex/sfe-catalog/2`, domain
`ibex:sfe-catalog:2`, and each otherwise-identical target entry extended by the
required field `restrictedWorkerTarget`. That field is either null or the
closed object `{advertisementDigest,artifact}`. `artifact` is the exact closed
object `{role,digest,size,mediaType}`: `role` is
`restricted-worker-target-advertisement`; `digest` is ordinary SHA-256 over
the exact artifact bytes; `size` is their positive integer length, at most 64
KiB; and `mediaType` is exactly
`application/vnd.ibex.restricted-worker-target-advertisement+json;version=1`.
Unknown keys and other role/media spellings refuse. The artifact bytes are the
exact canonical object above and their semantic domain digest equals
`advertisementDigest`. A V4 stub's
`targetAdvertisementDigest` is that digest, or null only when the catalog
field is null and `enabled` is false. `enabled:true` with null evidence or
digest, a nonmatching target, or any identity/digest mismatch is
invalid before parent evaluation.

Envelope V3 retains V2's 88-byte little-endian footer layout, range
preflight, 8-byte ordinary alignment, 4,096-byte carrier alignment, digest
spelling, canonical section ordering, 100,000-section/16-MiB-directory/2-GiB-
envelope ceilings, and bulk admission before section exposure. It changes
exactly: format integer `3`; 16-byte footer magic
`IBEX_SFE_V3\0\0\0\0\0`; directory schema
`ibex/single-file-executable/3`; and `SectionKindV2`, whose closed kebab-case
vocabulary is all eight V1 kinds plus `application-binding`. Exactly one row
has id `application-binding`, kind `application-binding`, no `pairId`,
alignment 8, nonzero length at most 16 KiB, and canonical
`ApplicationBinding` bytes. The V3 directory requires exactly one V4 stub
contract, V2 provenance manifest, existing graph/policy/entry/carrier
singletons and pairs, and this binding. V2 readers reject the new footer before
directory interpretation.

`CompilePlanV2` has exactly the V1 fields
`schema,graphSnapshotDigest,policyDigest,stubContractDigest,catalogDigest,
compilerIdentity,carrierEncoding,target,environmentProfileDigest` plus
`applicationBindingDigest,targetAdvertisementDigest`. Its schema is
`ibex/compile-plan/2`, its domain is
`ibex:compile-plan:2`, `carrierEncoding` keeps the V1 closed enum, and every
digest/target validation remains. `applicationBindingDigest` is the semantic
domain digest under `ibex:app-bound-parent:1`, not merely the directory's raw-
byte digest. `catalogDigest` is a V2 catalog digest and
`targetAdvertisementDigest` equals both the catalog entry and V4 stub value,
including null for a disabled/unadvertised profile.

`PackageProvenanceV2` has exactly
`schema,compilePlan,compilePlanDigest,catalogSequence,catalogEntryTarget,
stubCoreDigest,stubCoreReconstruction,producerIdentity`. Its schema is
`ibex/package-provenance/2`; `compilePlan` is V2;
`compilePlanDigest` uses the V2 plan domain; and every V1 sequence, target,
stub-core reconstruction, canonicalization, and acyclic final-file rule is
unchanged. The provenance record makes no self-authentication claim.

Inspection V4 is inspection V3 with schema
`ibex/executable-inspection/4`, envelope schema fixed to V3, stub schema fixed
to V4, compile/provenance fixed to V2, and a required closed `appBound` object
`{bindingDigest,origin,appId,externalWorkerEnabled,availability,
languageProfile,languageProfileDigest,workerPolicy,workerPolicyDigest,
brokerProtocol,globalInventoryDigest,targetAdvertisementDigest,defaults,maxima}`
derived only after full bulk admission. `availability` is exactly
`enabled-and-advertised`, `disabled-advertised`, or `disabled-unadvertised`;
there is no valid enabled/unadvertised state. Standalone-info V2 is
standalone-info V1 with schema
`ibex/standalone-executable-info/2`, the same V3/V4/V2 constants, and the same
`appBound` object; its outer authenticated-info descriptor pins report schema
V2. Neither report includes release credentials, cached envelope data, source,
or run-specific identities.

The binding's canonical projection is:

```json
{
  "schema": "ibex/app-bound-parent/1",
  "origin": "https://normalized.example",
  "appId": "example",
  "engineCompatibility": ["<closed identifiers>"],
  "brokerProtocols": ["ibex/restricted-worker-broker/1"],
  "releaseLineage": {
    "schema": "ibex/app-cli-release-lineage/1",
    "publisherKeyId": "<stable key id>",
    "channel": "stable",
    "recipeDigest": "sha256-..."
  }
}
```

`origin` is the WHATWG serialized origin of an absolute HTTPS URL: lowercase
ASCII/punycode host, default port removed, and no userinfo, path beyond `/`,
query, or fragment; distributable v1 bindings admit no HTTP or loopback
exception. `appId` is NFC UTF-8, 1–256 bytes, contains no control/NUL, and is
compared byte-for-byte with the admitted envelope. `engineCompatibility` is a
sorted nonempty list (at most 32) of 1–256-byte closed identifiers and must
contain the stub's exact engine compatibility identity. `brokerProtocols` is
exactly `["ibex/restricted-worker-broker/1"]`. `publisherKeyId` and `channel`
are NFC UTF-8 1–128 bytes without control/NUL; `recipeDigest` is a digest. The
complete canonical binding is at most 16 KiB before it becomes a section.

It contains exactly the normalized fixed origin, expected app id, closed
engine/protocol compatibility identifiers, and release provenance binding. It
contains no credential, credential source, current envelope, generated API
program, application handler source, runtime-selected origin, or deployment
generation.

`releaseLineage` contains only pre-build publisher/channel/recipe facts. It
does not contain the final executable, provenance-manifest, or app-binding
digest. `CompilePlanV2` binds the application-binding digest; provenance then
binds the plan and final stub core. This one-way ordering avoids a digest cycle.
The detached publisher statement may authenticate the final file separately,
as in LLP 0029; it is not copied back into the binding.

Admission equations are all mandatory: the ApplicationBinding section's
canonical bytes must parse and reserialize identically; its ordinary section
digest must match the V3 directory; its domain digest must equal
`CompilePlanV2.applicationBindingDigest`; the provenance's plan digest and
target must validate; the plan's stub-contract, graph, policy, catalog,
environment, target, binding, and target-advertisement digests must match the
admitted sections and V2 catalog entry; the advertisement target, engine,
native ABI, profile, policy, broker, globals, defaults, and maxima must match
the catalog entry and StubContractV4; StubContractV4's accepted schemas/ABIs/
worker identities must match the reader and binding; the binding's engine/
protocol set must admit the stub's exact identities; the two reports must
project the same digests and availability; and the provenance stub-core
reconstruction/digest must match the final file. Any missing/duplicate row,
cross-version pairing, normalization change, or equality failure refuses
before parent evaluation.

The trusted parent fetches and authenticates the current source-stripped API
envelope at invocation. Ordinary schema/function deployment therefore does
not rebuild the executable. Rebuild and redistribution occur only when the app
binding, trusted parent/engine, restricted-worker policy/profile, compatible
protocol set, platform tuple, or release provenance changes. Offline behavior
is limited to honestly cached `--help`, `introspect`, and `types`; calls,
subscriptions, pairing, and worker broker operations require the fixed bound
target.

The outer file remains literally self-contained: no Node installation, npm
tree, source tree, policy/carrier sidecar, dynamically loaded Hermes, or helper
worker executable. v1 uses §6's in-process dedicated worker thread and has no
re-exec/bootstrap selector, reserved argv/environment channel, or second
process entry.

## 9. Threat model and boundary honesty

The positive claim is:

> Given an admitted engine and policy implementation, worker code cannot obtain
> ambient parent authority through the supported Ibex surfaces. Credentials
> are never transmitted to the worker; app operations are possible only by
> bounded possession of the broker handle and remain parent-authorized and
> audited.

This addresses supply-chain authority growth and accidental disclosure. It is
stronger than the Node host's legitimate-channel non-transmission property
because the Ibex worker's ambient host surfaces are actually absent or denied.

It is not a hostile-code or process-isolation claim. The trusted parent owns
all authority and may deliberately disclose it. Hermes, Ibex, Oxc, native
libraries, broker validation, and the authenticated policy/toolchain are in
the trusted computing base. Engine memory-safety/correctness defects, native
side channels, OS compromise, same-user process inspection, denial of service
beyond the named watchdog/heap/frame limits, timing through relative timers or
broker response latency, and values the script itself explicitly asks the
parent to return are residual risks. Platform sandboxing, a separate OS user,
or a container may add defense in depth but is not required or implied here.

Audit output minimizes engine-owned values but cannot hide values a script
chooses to print through `console`. All console, audit, and diagnostic events
share the aggregate stderr ceiling. Engine-owned audit records use a closed
safe-field allowlist; low-entropy result correlation uses only a per-run keyed,
domain-separated commitment whose key never leaves the parent. No stable
unkeyed digest of intermediate values is emitted.

## 10. Inspection and evidence

`inspect-executable` and the authenticated `--ibex-info` path report, without
evaluating parent or worker code:

- whether external-script admission is disabled or enabled;
- the external-script profile and configuration digest;
- the restricted-worker policy and broker ABI identifiers;
- the default and hard resource limits;
- the exact target tuple and whether its restricted-worker enforcement profile
  is advertised;
- the app id and normalized origin from the binding, but no credentials or
  cached envelope contents;
- the stub-V4/envelope-V3/plan-V2/provenance-V2/inspection-V4/info-V2 app-
  bound identities and application-binding digest; and
- the standing threat-model label: `supply-chain-capability-boundary`, never
  `sandbox`.

Evidence binds exact engine, transform, policy, broker, target, and executable
identities. A pass on macOS cannot advertise Linux, and an ambient-parent pass
cannot substitute for the mandatory enforced worker profile.

The advertisement intentionally contains no final-executable digest: the
final stub/plan/provenance chain binds the advertisement digest in the forward
direction, so adding the final-file identity back to the evidence would create
a cycle. “Binds executable identity” means this one-way inclusion in the
admitted executable, not that the evidence artifact predicts its own consumer.

The eligibility equation is mechanical: catalog-V2 pinned digest → selected
target entry → admitted advertisement artifact and semantic digest → equal
StubContractV4 and CompilePlanV2 `targetAdvertisementDigest` → equal
inspection/info report field. Within the advertisement, target, engine,
native ABI, language profile/digest, worker policy/digest, broker protocol,
global inventory, and defaults/maxima digests must equal the selected catalog
and stub values. Only `availability:enabled-and-advertised` may execute `run`.
The two disabled availability values are inspectable but never silently
upgraded by a catalog, host, or current envelope. The general LLP 0029 profile
continues to use catalog V1 and makes no restricted-worker claim.

## 11. Acceptance

The extension is eligible on a tuple only when all rows pass against the final
one-file artifact:

1. **Literal product flow.** One `example` file runs `./example introspect`,
   `./example call ...`, and `./example run analysis.ts`; `run -` also passes.
   The file is copied to a clean location with the source tree and catalog
   unavailable. No Node/npm tree, sidecar, or dynamically loaded Hermes exists.
2. **Ingress.** Regular file and stdin succeed; oversize, invalid UTF-8,
   unsupported suffix/special file, replacement race, second source, and
   server-supplied source refuse before a worker evaluates. Raw-byte digest,
   logical label, transform identity, and fresh principal attribution are
   asserted.
3. **Language parity.** The same corpus on the Node and Ibex hosts covers TLA,
   file-JS/file-TS/stdin-TS dialect selection, erased types and type-only
   imports/re-exports, every refused emit-bearing TS form, all runtime
   import/`require`/`import.meta` forms, the exact default-expression wrapper
   and refused default declarations, default-export settlement, no-result,
   source-map composition, transformed-output/arena ceilings, dynamic-code
   taming, iterative strict-value depth/node/property boundaries, and native
   proxy rejection before reflection. Semantic corpus changes rotate `/1`.
4. **Policy inspection and denial.** The worker global inventory is exact.
   Planted attempts at filesystem, environment, direct network, DNS/socket,
   import, subprocess, clock, randomness, storage, debugger, generic host call,
   runtime extension, and dynamic code fail through the final binary. The
   worker is observably non-root and every action is attributed to its raw
   source digest and run nonce.
5. **Broker conformance.** Closed frame goldens and mutation tests cover every
   type, exact-key rejection, canonical encoding, sizes, ids, sequence/run
   binding, caught/rethrown/copied/forged errors of every exit class, per-call and live-
   establishment deadlines, latest-wins delivery, renewal, explicit iterator
   disposal, timer set/clear/fire races, chunked settlement boundaries and
   digest/count failures, console normalization including the 64-KiB frame
   boundary, script-argument preflight with no emitted frame, parent result-
   frame overflow, late-frame dropping, and parent-side args/result
   revalidation. Native ABI tests cover every status, pointer/zero-length and
   input-ceiling rule, output/ownership rule, distinct run id/control nonce,
   failed start, stale nonce, wrong/concurrent thread and lifecycle, queue
   ceiling, every legal and illegal event/fault/payload combination, exactly-
   last CLOSED, owner-thread destruction, and generic-ingress refusal.
6. **Lifecycle and ceilings.** Every default and hard maximum is exercised;
   CPU-bound code is interrupted; heap failure is classified only with its
   witness; signal-first grace runs local cleanup but refuses new broker
   operations and new timer registrations while permitting an already-
   registered timer to fire under §6;
   forced teardown follows expiry, including whole-process immediate exit when
   CLOSED misses its 250-ms acknowledgement; provisional settlement, snapshot-before-
   signal, race precedence, abandoned iterators, orphan timers, output overflow,
   stderr elision, and engine-fault fallbacks match §7.
7. **Non-transmission.** Planted admin, session, agent, connection, and low-
   entropy secrets appear in none of the worker's argv/args, globals, source
   metadata, environment, frames, console, result, timers, errors, or audit
   records. The parent inserts only the selected short-lived carrier on the
   actual app-data transport. The 500-row intermediate case appears in neither
   stdout nor stderr unless the script explicitly prints it.
8. **Binding and rebuild rules.** Wrong origin/app id, protocol skew, engine
   skew, policy/profile skew, and provenance tampering fail before worker
   creation. Changing only the fetched current envelope/deployment does not
   change executable bytes. Changing the app binding, engine/policy, platform,
   or provenance does. Stub-V3/envelope-V3, stub-V4/envelope-V2,
   plan-v1/binding, provenance-v1/plan-v2, inspection-v3/app-bound,
   info-v1/envelope-v3, catalog-v1/app-bound, missing/duplicate binding,
   missing/null/mutated/wrong-target advertisement, stub/plan/report evidence-
   digest disagreement, and cyclic/self-described provenance forgeries all
   refuse under strict schema and cross-binding checks. Enabled and disabled
   V4 facts both inspect exactly; `run` succeeds only for
   `enabled-and-advertised`.
9. **Target matrix.** Current phase-2 eligibility is evaluated for
   `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu`. Each result is bound
   into its own advertisement/evidence artifact and changing any suite,
   engine, policy, broker corpus, tuple, or minimum-platform byte invalidates
   the digest chain. Unsupported or unadvertised tuples refuse the external-
   worker feature rather than falling back to parent evaluation or ambient
   standalone execution.

The Node-versus-Ibex host-portable suite is a single versioned corpus with one
expected semantic projection, not two hand-maintained test lists. Every
advertised host runs that corpus plus its enforcement-specific rows.

## 12. Non-goals and future extensions

- treating arbitrary local scripts as hostile-code-safe;
- multiple external scripts or workers in one run;
- imports, packages, remote source, REPL, inspector, or debugger evaluation;
- granting filesystem/network/environment/subprocess/clock/random authority;
- persistent worker/cache state or cross-run principal identity;
- server-side code mode;
- Windows, macOS x86-64, cross-target compilation, or additional standalone
  tuples before their own evidence exists; and
- changing LLP 0047's general standalone ambient default. The restricted
  worker is enforced regardless of the trusted parent's outer posture.

Any widening gets a new profile and broker version, an explicit authority-
expansion review, a new host-portable corpus row, and target-specific evidence.
