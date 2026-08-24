# LLP 0053: Carrier-Bearing Ingress Coordination (Exact 0510 Carrier Arc — Asks I1–I4)

**Type:** RFC
**Status:** Draft
**Systems:** Host ABI, Engine, CapSec, Security, Conformance
**Author:** Charlie Cheever / Claude
**Date:** 2026-08-23
**Revised:** 2026-08-23 (r1 — the four coordination asks from the Exact 0510 carrier arc, drafted as a proposal into this corpus per that plan's own rule: "their process decides shape; this plan only names the need." Nothing here is decided until this corpus decides it.)
**Related:** LLP 0002 (host-embedding ABI — I1's surface), LLP 0021 (typed CapSec effect model, armed snapshot — I2's surface), LLP 0049 (Draft — armed-snapshot evolution I2 rides), LLP 0013 / LLP 0040 (principal carriers — I3's natural vehicle), LLP 0024 (Draft — structured evaluation and session semantics — I4's surface), LLP 0052 (durable authority mint/verify — the lease-side machinery already consuming Exact-side lineage), Exact LLP 0510 (native boundary schemas v2 — the carrier model these asks serve; §6.1 dispatch order, §6.2 lease presentation, §6.4 "Ibex is a carrier, never an installer"), Exact LLP 0554 §5 (carrier sequencing), Exact docs/reports/carrier-arc-implementation-plan.md §3 (the tree-verified needs statement this RFC transcribes), `runtime-surface.json` (the ENG-22429 surface authority any new `exact.*` surface must join)

## Summary

Exact's 0510 carrier arc — the work that takes capability-carrier
binding from accepted policy to enforced reality on the Hermes app
ingress — needs four things from this corpus. This RFC names them as
proposals and deliberately does not design them: each ask states the
need, the boundary rule it must respect, and the ibex surface it
touches. The governing division of labor is Exact LLP 0510 §6.4
item 1: **ibex is a carrier, never an installer** — it transports and
authenticates presentation; the host session enforces.

## I1 — Carrier-bearing typed ingress ABI

**Need:** `exact.invokeHostAsync` and
`ex_hermes_set_exact_host_call_async` (include/exact_runtime.h) carry
no carrier today. The Exact host needs an ABI revision letting the
app present a grant handle per invocation — an envelope field or a
sibling entry point — delivered to the host callback alongside
`(operation_id, payload)`.

**Boundary rules:** ibex transports the handle opaquely; validation,
consumption, and attenuation are host-session acts. Any new `exact.*`
surface joins `runtime-surface.json` under the ENG-22429 authority.
Absence of a carrier on an armed target is a host-side refusal, not
an ibex default — the ABI must make "no carrier presented"
distinguishable from "carrier field absent because old ABI."

## I2 — Carrier identity in the armed snapshot

**Need:** the armed snapshot already authenticates the
operation-manifest digest. Host-side carrier issuance needs it to
additionally bind the mapping digest, `authorityCommitmentDigest`,
and per-root grant-set pins, so issuance is provably against the
artifact ibex armed — the in-process analogue of the transport
`ConnectionAuthorization`.

**Boundary rules:** schema evolution rides LLP 0021/0049's
armed-snapshot process (`capsec/schema/armed-snapshot.schema.json`
et al.); strict ingestion (unknown-field refusal) is preserved; the
pins are authenticated inputs to host issuance, never authority in
themselves.

## I3 — Derived-root attribution on ingress

**Need:** Exact LLP 0510 §6.1 step 3 requires the engine/host
session's own attribution of which admitted root's execution issued a
call. The principal-carrier machinery (LLP 0013/0040 class — the
real-input/no-user carriers already in the engine) is the natural
vehicle. What Exact needs surfaced is a **trusted root discriminator
on the ingress callback** — engine-attributed, never a request field
the app supplies.

**Boundary rules:** the discriminator is attribution, not
authorization; a call whose root cannot be attributed fails closed on
the Exact side. The carrier-vs-payload distinction that already
separates real-input from synthetic principals is the precedent.

## I4 — CapSec presentation of the carrier tuple

**Need:** Exact LLP 0510 §6.2's lease-presentation tuple (items 1–7
plus the embedded row and derived root) is presented to capsec at
candidate and commit stages, additive to the LLP 0052/Exact-0476
stage facts. The presentation record's capsec-side shape belongs to
this corpus (LLP 0024/0021's session-semantics surface under
`capsec/session-semantics/`).

**Boundary rules:** additive to existing stage facts — no removal or
re-interpretation of what LLP 0052 already presents; the shape is
this corpus's decision.

## Sequencing and what does NOT wait

Exact's slices S2 (Hermes-path carrier custody + dispatch bind) and
S5 (terminal receipts on that path) wait on I1–I3 landing here. I4
gates lease-path conformance claims, not the walking skeleton.
Exact's pure-Rust worker-path slices (S1/S3/S4), its label mechanics,
and its bypass checks proceed independently — nothing in this RFC
blocks them, and none of them preempt this corpus's design choices.

## Open questions (for this corpus)

1. I1's vehicle: envelope field on the existing entry point vs a
   sibling carrier-bearing entry point (old surface retired at the
   Exact epoch boundary)?
2. I2: are the three pin classes one schema addition or staged
   (mapping digest first, commitment + per-root pins with I1)?
3. I3: does the root discriminator ride the existing principal
   carrier records or a parallel attribution channel?
4. I4: candidate-stage and commit-stage records — one shape with a
   stage tag, or two?
