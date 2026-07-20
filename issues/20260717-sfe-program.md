# Single-file executable program (LLP 0029) — umbrella and execution map

**Status:** Open
**Severity:** P2
**Systems:** Issue tracking, Build, Module Loader, Runtime, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 (Draft, revision `d3cb7dcc`); LLP 0014, 0021, 0022, 0023, 0025, 0026, 0027, 0028

Execution map for LLP 0029: `ibex compile <entry> -o <file>` producing
a single self-contained executable (stub + envelope: embedded graph,
per-principal carriers, policy, provenance). The RFC is the design
authority; these issues are the work breakdown. Filed as filesystem
tickets at Charlie's direction; issues graduate to Linear (Exact
project) with pointers here if PM state becomes necessary. LLP 0029 is
`Draft` with an author-decision register (§7); tickets marked
**blocked-on-decision** wait for the named decision.

**Execution order** (RFC §7 phases; parallelizable within a phase):

0. `sfe-format-spike` (de-risk before the static-Hermes long pole)
1. `sfe-static-hermes-macos`, `sfe-linux-static-audit`,
   `sfe-stub-crate-and-contract`, `sfe-catalog`
2. `sfe-envelope-format`, `sfe-embedded-module-graph`,
   `sfe-macho-segment-signing`
3. `sfe-graph-snapshot-domain`, `llp0014-canonical-policy-v2`
   (shared with LLP 0028), `sfe-root-ceiling-and-bootstrap`,
   `sfe-mount-contract`, `sfe-embedded-admission-and-arming`
4. `sfe-hbc-production-wiring`, `sfe-compile-cli`
5. `sfe-environment-sequence`
6. `sfe-process-semantics`, `sfe-capsec-advertisement`
7. `sfe-measured-budgets`

**Cross-program sequencing** (RFC §7): the 2026-07-18 Snapback decision makes
LLP 0028 candidate tables required for 0.2. Phase 4 now carries each canonical
table as a digest-addressed candidate section, binds its projection into the
authenticated graph/policy identity, and links it in the compiled stub;
unlabeled or absent rows still refuse only when reached. The LLP 0014 schema
revision remains one coordinated change shared with the 0028 program
(`llp0014-canonical-policy-v2`).

**Author-decision register** (LLP 0029 §7): (1) stdio/cwd implicit vs
policy-explicit (blocks `Accepted`); (2) env allowlist contents
(blocks `Accepted`); (3) factory-table release status (blocks phase-7
exit); (4) **resolved 2026-07-18:** 0.2 waits for verified CapSec
advertisements on both selected tuples; (5) **resolved 2026-07-18:** LLP 0031
keeps Windows and macOS x64 deferred rather than pulling them ahead for
Snapback; (6) lean-vs-full
engine (phase-1 measurement, ratified); (7) phase-7 budget numbers,
fixed before measurement; (8) publisher-statement key custody/trust.

Close this umbrella when all seven phase gates are green on both v1
tuples and LLP 0029 moves to `Active`.
