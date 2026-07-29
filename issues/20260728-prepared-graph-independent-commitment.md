# Independent prepared-graph commitment (armed + session-bound dev)

**Status:** Open
**Systems:** Module loader, CapSec, Arming, Host embedding
**Author:** Claude Fable 5 (Claude Code)
**Date:** 2026-07-28

**Filed:** 2026-07-28 (Exact LLP 0413 §5.7, accepted; round-1 codex
material finding)
**Related:** LLP 0026 (writable prepared cache is not an independent trust
root — it reconstructs the authenticated inline source graph, parses, and
byte-compares; production-prepared needs an independently authenticated
deployment commitment "unavailable to the writable cache"); LLP 0027
(deployment-graph binding); LLP 0036 (target advertisement)

**Impact:** 5
**Urgency:** 3
**Ease:** 2
**Confidence:** 3
**Score reviewed:** 2026-07-28
**Score rationale:** Without this contract, Exact's parse-free prepared
lane forks between violating parse-free (source rejoin) and violating
admission (trusting a self-consistent cache). It is the named prerequisite
for Exact LLP 0413 Phases 2–3 and a Phase 1 design exit.

Design and implement the commitment LLP 0026 already names:

- **Production:** bind the prepared publication root through the armed
  resources/snapshot commitment (e.g. an armed-snapshot field), so warm
  prepared startup admits without reconstructing/parsing the source graph.
- **Development:** a run/session-scoped, explicitly non-production
  commitment binding target, graph digest, producer identity, semantic
  inventory, principal set, policy identity, and lifetime (credential
  shape, binding surface, revocation are open — Exact LLP 0413 §16 Q14).
- **Adversarial gate:** an attacker who substitutes a self-consistent
  index/carrier set and recomputes every cache-local digest MUST still be
  refused because the independent commitment does not match.

## Acceptance

- A prepared generation admits against the commitment with zero
  application-source parsing on the warm path.
- The authority-substitution fixture refuses before effects.
- The development commitment cannot be confused with production authority
  (distinct schema/marking; visible in diagnostics).

**LLP:** design drafted as `llp/0042-prepared-graph-independent-commitment.rfc.md` (Draft, 2026-07-28); this ticket now tracks implementation once the design is reviewed.
