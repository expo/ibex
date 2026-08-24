# LLP 0053 — grok family review artifact

## Round 1 (2026-08-24)
Reviewer: grok CLI, grok-4.6 @ xhigh (headless; terminal ban). Target: LLP 0053 r2 (sha256 032e0710be81393ca700c38063f54e2be1285c54d4d34c5ac8c139be7da1d06d, ibex revision 58899c284). Capsule: git-archive of origin/main; mutually blind. Orchestrator: Claude Fable 5 (author-side reviser, session exact-1d).

### Verbatim body

I'll start by reading the LLP review skill and the RFC itself, then check the cited code and schemas in this tree.The RFC is loaded. Next I’ll pull the cited code, schemas, and related LLPs so the review can check the r2 claims against the tree, not the document’s citations.I’ll now read the cited ABI, arming, and snapshot surfaces plus a prior review artifact so the line-level claims can be checked against this tree.The ABI cites look real so far. Next I’ll open the setter, snapshot schema, and authorization paths that the fail-closed matrix depends on.The cited setter and schema lines match. I’ll now check frame attribution, principal stacks, and the remaining strict-ingestion and surface-inventory claims.A few citations already look tight; I’m now checking principal/root identity, schema evolution, and the fail-closed setter matrix for holes.I’m now checking Principal identity, snapshot additionalProperties, digest defs, and the authorize/setter exclusivity rules the matrix depends on.I’ve confirmed several citations; next I’ll check ingestion (JSON Schema vs serde), producer ordering, ArrayBuffer extraction, and the I4 session-semantics surface.I have enough tree evidence. Next I’ll write the review artifact with verified line claims, the fail-closed holes, and a READY/NOT READY verdict.Adversarial soundness review of LLP 0053 r2 against this tree. Provenance is in `llp/reviews/0053-carrier-bearing-ingress-coordination.grok.md` (family grok, 2026-08-24). Binds RFC sha256 `032e0710be81393ca700c38063f54e2be1285c54d4d34c5ac8c139be7da1d06d` at ibex revision `58899c284`. This session did not author the draft.

The skeleton is right: one JS entry point, a sibling C setter, an engine-filled attribution struct, one `/2` snapshot addition, and “absence is never an ibex refusal.” It is not implementation-ready. The fail-closed matrix is a table, not a set of invariants on the authorize/latch/serde machinery that actually exists.

## File:line claims

Almost all of the cited lines are real. Two are not.

| Cite | Result |
| --- | --- |
| `hermes_runtime.cc:16828-16831` throws unless arity is 2 | True (bundled with type checks). |
| `root_global_disposition.generated.h:1029` `exact.invokeHostAsync` | True — conditional live-sweep row, not the main table. |
| `exact_runtime.h:1966-1967` callback inline on owner thread | True. Invoked from the Promise executor at `hermes_runtime.cc:16905-16911`. |
| AsyncFailureEvent / principal-status / “missing ≠ root” (`:1397-1432`) | True. |
| `ExactEmbedderContext` `:247-251`; nonce+principal `:585-593`; v1 setter `:1972`; producer `:2111-2117` | True. Zero is a legitimate **root** principal. |
| `Host::authorizes_exact_endowment` `src/host/mod.rs:2606-2630` | True; function continues through `:2635`. **It does not read `binding.schema`.** |
| `armed-snapshot.schema.json:75-95` optional `exactEmbedder`, const `/1` | True. |
| `arming.rs:293-298` `deny_unknown_fields`; `:1829-1831` refuses non-`/1` | True. |
| Frame-attribution VM pointer `hermes_runtime_internal.h:745-749` | True. |
| Principal stacks at `hermes_runtime_internal.h:65-107` | **False for Fetch.** `TimerEntry` / `NextTickEntry` have `principalStack`. `FetchCallbackEntry` has only `uint64_t principal`. |
| Stage enum `:598-608` | True, but it is the **runtime-extension operation** fragment, not a session-semantics presentation record. |

JSON Schema is not an ingest path. `ArmedSnapshot::load` walks a `Value`; the operational gate for this field is `ExactEmbedderBinding` serde plus `validate_exact_embedder_binding`. Nesting `carrierBinding` inside `exactEmbedder` is the only old-engine-loud place.

## Four r1 corrections

The RFC claims four and labels three.

1. **`runtime-surface.json` is the CLI surface.** Sound. `exact.invokeHostAsync` lives on the disposition row and `capsec/generated/surface-inventory.md`.
2. **I3 depends on I2.** Sound for ATTRIBUTED Exact `root_id` strings (`Principal` has no Exact rootId). Overstated for the rest of the struct, which can be delivered unarmed as `UNAVAILABLE`.
3. **“real-input/no-user principal carriers” names nothing here.** Sound. Live names are `currentPrincipalId`, `ScopedNativePrincipal`, `principalStack`, `ExHermesAsyncFailurePrincipalStatus`.
4. **Not listed.** The FetchCallbackEntry stack claim is a new miss, not a correction of r1.

## Callback thread and non-app-suppliable attribution

The callback **does** run inline on the runtime owner thread. Capturing engine truth at that call is sound if and only if the struct is **filled before** the embedder callback runs, then borrowed for that invocation only.

The proposed struct is not app-suppliable at the ABI: there is no JS field for it, the third argument is only carrier bytes, and the pointer is engine-owned `const*`. Keep it that way.

Do not treat it as live TLS. Do not borrow JS `ArrayBuffer` memory for the carrier (payload is already copied into a C++ vector first). Map `kNoUserPrincipalId` (`0xFFFFFFFE`) to `principal_status=UNAVAILABLE`; do not confuse it with root principal `0`.

## Fail-closed matrix holes

Stated table:

- generic armed → both setters `-8` (matches today: no `exactEmbedder` ⇒ authorize false)
- `/1` → v1 allowed, v2 `-8`
- `/2` → v1 `-8`, v2 allowed
- unarmed diagnostic → both allowed
- at most one of v1/v2 per runtime

Holes against this tree:

**v1 on `/2`.** Today’s `authorizes_exact_endowment` matches digest + endowment set only. A `/2` snapshot with the same vectors would authorize the **existing** v1 setter. “Via a sibling v2 hook” does not close that. The v1 path itself must refuse `schema == …/2`.

**v1/v2 latch.** One-shot, rollback, `begin_embedder_capabilities_v1`, and finalize all key off the **v1-typed** `exact_host_call_async_fn`. The v2 callback has extra parameters; stuffing it into that slot is a calling-convention bug. A second slot that is not on the same latch lets both install.

**I2 ingest shape.** New engine + `/1` must still arm. A required `carrierBinding` on the current single struct would refuse `/1`. An `Option` would accept `/1` *with* pins. The RFC never writes `/1` ⇒ field absent, `/2` ⇒ field present. `validate_exact_embedder_binding` is still hard-`/1`. `additionalProperties: false` on a `rootId` map forbids every key; that sketch is unimplementable as written.

**I3 zero pins.** ATTRIBUTED = exactly one pin for this context; multiple = AMBIGUOUS; unarmed = UNAVAILABLE. Zero matching pins on an armed `/2` runtime is unspecified. App and agent endowments must both be nonempty; `rootGrantSets` is 1..=256 **total**, not per context.

## I3-requires-I2

The dependency is true for ATTRIBUTED Exact `root_id` strings: those IDs are not ibex `Principal`s, so they have to enter under authentication. I2 `rootGrantSets` keys are that introduction.

It is not true that I3 “rides frame attribution with no parallel channel.” `principal_id` rides the live frame walk. `root_id` is a lookup of I2 pins against the runtime’s setter `ExactEmbedderContext` — runtime-granularity, not “which JS frame issued the call.” If one app Hermes runtime hosts multiple Exact roots, v1 I3 is always AMBIGUOUS.

The matrix also couples **I1 v2** to I2: v2 is refused on `/1`, so the carrier-bearing ABI cannot be used on armed Exact until I2 lands.

## I4

One record with a stage tag is a fine shape. The join point is wrong in the same way r1’s `runtime-surface.json` cite was wrong: `capsec/session-semantics/` is the LLP 0024 **evaluation-session** generator, not CapSec stage facts. Those already live on `capsec/schema/effect.schema.json` (`requested|discovery|candidate|commit|delivery|repeat|cleanup`). LLP 0052 has no “no-row-collapse” rule.

## Definitely / possibly wrongheaded

**Definitely:** enforcing `/2`⇒v1-refuse only on a new hook; a second callback slot without the existing latch; `additionalProperties: false` on a dictionary; describing Exact `root_id` as frame attribution with no parallel channel; parking I4 on `capsec/session-semantics/`.

**Possibly:** unique-pin-per-context as 0510 §6.1 step 3 if production is multi-root per app runtime; refusing v2 on `/1` (fail-closed, but it serializes I1-v2 behind I2).

**Not wrongheaded:** sibling C setter; one JS method with optional third arg (the arity throw is real); engine-filled struct; opaque 1..=64 carrier; one `/2` addition; pins as inputs not authority; delivering `CARRIER_ABSENT` rather than ibex-refusing.

## Open questions before implementation

1. One Hermes app runtime = one Exact root, or many?
2. Dual `/1`/`/2` serde shape (internally tagged enum).
3. Zero pins for this context: arming refusal, fourth status, or UNAVAILABLE?
4. Must every endowed context have ≥1 pin at arming?
5. Unified ingress latch + v1 authorize MUST refuse `/2`.
6. `root_id` lifetime; `kNoUserPrincipalId` mapping.
7. I4’s real schema home; what “no-row-collapse” names.
8. Host-task-ingress-inventory row for the v2 setter.

**VERDICT 0053: NOT READY** — MATERIAL: v1 can still authorize on a `/2` snapshot if only a sibling hook is added; v1/v2 callback-slot/latch torn state; `/1`/`/2` ingest shape unspecified (map `additionalProperties` unimplementable as written); I3 zero-pin status unspecified and “no parallel channel” false for `root_id`.
