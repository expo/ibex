# Single-file executable program (LLP 0029) — umbrella and execution map

**Status:** Open — standalone v1 release closure
**Impact:** 5
**Urgency:** 4
**Ease:** 1
**Confidence:** 4
**Score reviewed:** 2026-07-26
**Score rationale:** The ticket evidence for “Single-file executable program (LLP 0029) — umbrella and execution map” shows the issue reaches a security, correctness, release, or core product boundary; delay compounds an active rollout, reliability, or verification risk, while delivery is a dependency-heavy, multi-stage program, with specific cited code, progress, or acceptance criteria.
**Severity:** P2
**Systems:** Issue tracking, Build, Module Loader, Runtime, Security
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-07-17
**Related:** LLP 0029 (Accepted); LLP 0014, 0021, 0022, 0023, 0025, 0026, 0027, 0028

Execution map for LLP 0029 as sequenced by LLP 0047: `ibex compile <entry> -o <file>` producing
a single self-contained executable (stub + envelope: embedded graph,
per-principal carriers, policy, provenance). The RFC is the design
authority; these issues are the work breakdown. Filed as filesystem
tickets at Charlie's direction; issues graduate to Linear (Exact
project) with pointers here if PM state becomes necessary. LLP 0029 is
`Draft` with an author-decision register (§7); tickets marked
**blocked-on-decision** wait for the named decision.

**Historical execution order** (LLP 0029 §7 phases; retained to map the
original work breakdown):

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
exit); (4) **re-resolved 2026-08-01 by LLP 0047:** standalone v1 ships an
ambient-default dual-mode artifact without verified advertisements; an
explicit CapSec request remains fail-closed, and the first successful
advertised tuple is v1.1; (5) **resolved 2026-07-18:** LLP 0031
keeps Windows and macOS x64 deferred rather than pulling them ahead for
Snapback; (6) lean-vs-full
engine (phase-1 measurement, ratified); (7) phase-7 budget numbers,
fixed before measurement; (8) publisher-statement key custody/trust.

Close this umbrella when all seven phase gates are green on both v1
tuples and LLP 0029 moves to `Active`.

## LLP 0047 reconciliation — 2026-08-01

LLP 0047 supersedes the phase-only scheduling above with product milestones:

1. green SFE foundation and fixed Hermes recipe;
2. real catalog-pinned producer path;
3. authenticated ambient-default / CapSec-selected dispatch;
4. real HBC envelope execution on both tuples;
5. bounded process semantics;
6. distribution and usability evidence.

The close condition is now LLP 0047 §9, not merely completion of the original
seven implementation phases. In particular, a verified CapSec advertisement
is not a standalone-v1 release criterion, but the selector and its monotonic
fail-closed behavior are. The mandatory-policy, Linux-network, ambient-default
ratification, and recipient-disclosure decisions are tracked by LLP 0047 §12;
all four are now resolved.

Linux-network item 2 was resolved on 2026-08-01: Snapback CLIs are the flagship
first workload and require Fetch, so the Linux release stub carries the
existing libcurl Fetch/WebSocket backend through a pinned static libcurl/TLS
closure. The remaining close evidence is the final-image audit plus the
static-backend Fetch fixtures, not a further product decision.

## Implementation checkpoint — 2026-08-01

Milestones 0 and the basic macOS arm64/Linux x86-64 legs of milestones 1–3 are
now exercised through the public producer: a V2 catalog-pinned release `ibex`
compiled real TypeScript/HBC, authenticated inspection reported the dual-mode
contract, and each relocated executable ran with source and catalog
unavailable. Ambient argv/environment/timer/output/exit behavior passed; the
same file refused an unadvertised `--ibex-capsec` launch before entry. The
kit gate now also compiles and runs explicit `.mts` top-level await plus an
ESM/CommonJS/builtin/literal-dynamic/computed-dynamic graph on both tuples. It
independently corrupts every load-bearing section in the final image and proves
inspection and launch refuse before any carrier side effect, including an
unselected computed-import candidate. The Linux ELF retains static libcurl,
passes the Ubuntu 24 host's truthful GLIBC 2.39 dependency/ISA audit, and
completes real HTTP Fetch after relocation and catalog withdrawal. The
release kit now carries a target-bound, digest-pinned policy-authoring tree;
both host gates generate policy with an empty environment, poisoned checkout
pointer, and no ambient Bun/Node, and a separated `ibex` proves there is no
fallback. An isolated candidate-kit installation was removed after compiling a
two-module TypeScript Fetch program; only the executable was transferred to a
second Ubuntu host, where it ran under `env -i` with no Ibex/Hermes on `PATH`.
At this checkpoint, the official published-artifact GLIBC 2.35 receipt, M4
signal/backend inventory, two-builder/performance evidence, and open author
decisions in LLP 0047 §12 remained before closing this umbrella.

## Implementation checkpoint — 2026-08-02

Milestone 4 is green for the ambient v1 product on both target tuples. The V2
contract authenticates the exact backend inventory; inspection exposes it;
macOS and Linux final artifacts prove Fetch through the advertised target
implementation and a loopback `node:http` server over POSIX sockets,
authenticate their WebSocket implementation, and prove stable HTTP/2,
inspector, WASI, and worker limitations. The same relocated
source-free fixtures prove foreground and detached failures, unhandled
rejection, numeric `process.exitCode`, immediate `process.exit`, and
SIGINT/SIGTERM/SIGHUP statuses 130/143/129 with bounded flush. Async graph
records now outlive referenced callbacks, so post-await imported bindings stay
valid.

The umbrella remains open for M5: exact published-installation artifacts, the
macOS two-clean-builder receipt, and size/startup budgets. The recipient
disclosure and other LLP 0047 §12 author decisions were resolved on
2026-08-02. The
Ubuntu 22.04/GLIBC 2.35 builder and fresh-recipient exercise now passes, and two
physical Jammy builders produced exact native-stub and unsigned-application
identities with both full matrices green.

The final relocated artifacts on both v1 tuples also refuse a raw invalid
UTF-8 argv field before application output while naming its zero-based index.
That closes `sfe-process-semantics`; a successful advertised-CapSec lifecycle
exercise remains v1.1 advertisement work rather than an ambient-v1 process
gate.

The final local implementation audit additionally makes each stub compare the
embedded contract's schema, ABI, and generated semantic identities with its
own compiled authorities; producer-newer/stub-older fixtures refuse. macOS kit
construction and final-image validation now cross-check `LC_BUILD_VERSION`
against the catalog baseline, and a fresh current-source macOS kit passes the
full installed-user matrix. The unresolved v1 close conditions are therefore
publication, Developer ID/notarization and the macOS second-builder receipt,
precommitted performance budgets and measurements, and LLP 0047 §12 author
items 1, 3, and 4. CapSec arming/environment/mount/advertisement tickets remain
the explicitly deferred v1.1 path, not ambient-v1 blockers.

The final inspection audit found and closed one additional local LLP 0029 gap:
the inspector had displayed the provenance-recorded stub digest without
rehashing the actual outer file. Release provenance now carries the facts
needed to invert ELF appending or Mach-O injection despite platform-signature
rewrites, and `stubCoreConsistency` refuses an independent outer-stub mutation.
The macOS system-signature remove/replace gate preserves that exact identity.

## Maintenance reconciliation — 2026-08-05

The later LLP 0047 and physical-builder records supersede several remaining
items above. The matching macOS two-builder comparison passed at `2a611b4f`,
and LLP 0047's four author decisions are resolved. Ambient standalone v1 now
remains open for the release actions that have not yet produced durable
published evidence: publish and reinstall the exact catalog-pinned artifacts,
obtain the macOS notarization ticket, record both target measurements against
the accepted `config/sfe-performance-budgets.json` blob, and retain the
mandatory clean CI receipts on the published revision. Disk-free arming, compiled CapSec environment/mount
semantics, and the first successful target advertisement remain separate v1.1
work and do not block ambient v1.
