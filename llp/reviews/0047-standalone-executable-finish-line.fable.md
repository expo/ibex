# Reviews: LLP 0047 — Standalone Executable Finish Line (Claude Fable family)

## Round 1 — 2026-08-01 (cluster loop: LLP 0029 + 0039 + 0047)

**Reviewer family:** Claude (Fable)
**Provider / runtime:** claude-code sub-agent, model `claude-fable-5`, fresh context (independent of the authoring/orchestrating session)
**Date:** 2026-08-01
**Redacted:** no (repository content only; no secrets present)
**Revision reviewed:** LLP 0047 at git-blob `9890e6bb6587ec906ef09049ba84c03b77ceaec6` (repo HEAD `54761987`)
**Brief:** `brief-r1.md`, hash `2d2438a011e9e43161263d6b58c45222bfa84552`
**Verdict:** NOT READY

**Topology note.** This was a lockstep cluster review of LLP 0029 + LLP 0039 +
LLP 0047. Per the review-artifact rule, the cluster review is preserved
**verbatim once**, in the primary target's artifact:

> `llp/reviews/0029-single-file-executable-packaging.fable.md`, Round 5 —
> 2026-08-01.

What follows is this target's per-target verdict section, excerpted from that
single verbatim body for discoverability.

### Per-target section (excerpt from the verbatim cluster review)

Verified true before findings: every §2 current-state claim checks out — `IBEX_RELEASE_SFE_CATALOG_DIGEST` is set by nothing in the repo (`src/bin/ibex/sfe.rs:50`, `option_env!` only); release compiled boot deliberately refuses after full admission (`crates/compiled-stub/src/main.rs:277-284`); the compiled-stub crate has genuinely drifted from the carrier admission API — I reproduced the failure: `cargo check -p ibex-compiled-stub` fails with two E0308 errors (main.rs:180, main.rs:424; `BTreeSet<Digest>` vs the new `Arc<BTreeSet<Digest>>` at `src/module_loader/carrier.rs:115` / `src/module_loader/artifact.rs:306`), and the only CI that builds it is the conditionally-run artifact workflow, not ci.yml, so M0.1's "normal workspace/CI check" is the right fix; grammar, envelope, catalog, admission types, and both target contracts exist where claimed. The "admission identical in both modes" claim is achievable with the stub as written: admission (self-file pin, layout validation, envelope, provenance, graph, policy, carriers, candidate tables) all precede the current release-refusal point that M2 replaces with mode dispatch.

- [MATERIAL] Coherence: LLP 0031 — listed in Related as "v1 platform matrix" — still says "If either selected tuple lacks a verified CapSec advertisement at release time, 0.2 waits" (0031:44-46), "Release scheduling is coupled to verified CapSec advertisements for both selected tuples. Missing evidence holds the release" (0031:68-69), and "Single-file executable catalog population follows the same two tuples" with per-tuple required evidence including "complete verified CapSec target advertisement" (0031:40-41,55). §9 here says "CapSec advertisement completion is explicitly not a v1 release criterion." The plan amends 0029 and 0039 explicitly but neither amends 0031 nor acknowledges the conflict; 0031 carries no 2026-08-01 revision. The corpus now contains a Decision that flatly forbids what this Plan schedules. (0031's unadvertised-tuple refusal language — "do not select ... an ambient Hermes build, or an unverified prepared carrier", 0031:48-51 — also needs an explicit scoping statement relative to ambient compiled boot.)
- [MATERIAL] Decision quality/Coherence: the plan never addresses that every compile — including the flagship ambient-default flow — requires an authored, committed, registry-bound `purpose: production, mode: enforce` CapSec policy. LLP 0029 §1 step 2 mandates it and the implementation enforces it (`src/bin/ibex/sfe.rs:145-158` refuses with "run `ibex policy generate --entry ... --target-triple ...` and commit the result"; the envelope structurally requires a singular `ResolvedPolicy` section, `crates/sfe-format/src/lib.rs:1056-1061`; the stub validates it in the shared admission path, main.rs:137-140). So v1's "short, authored scripts" default requires authoring a full CapSec policy artifact that the default mode never enforces. M5's exit ("install one release ibex, compile a short program, copy, run") and M1's exit ("using only the pinned catalog") are written as if this step doesn't exist. Either the plan owns the friction explicitly, or it amends the producer contract (auto-generated minimal policy would contradict 0029's "compiling never generates policy silently") — right now the cluster leaves the flagship flow's biggest product wart undecided and unmentioned.
- [MINOR] Safety: the one-artifact-two-modes decision means every distributed standalone binary contains the complete enforcement-off machinery, and `--ibex-capsec`'s fail-closed guarantee rests on pre-runtime dispatch integrity rather than compile-time absence (the property LLP 0039's secure builds and promotion-evidence rules treat as security-relevant, e.g. feature closures rejecting `insecure`). The design is defensible (enforcement is in-process either way; the selector is one-way, captured pre-runtime, fixture-proven monotonic), but §1's "CapSec remains real when selected" should state the changed trust model in one sentence rather than leaving it implicit.
- [MINOR] Feasibility (implementation-phase, no defective decision): M2's ambient item 3 ("inherited environment ... with ordinary non-sandboxed semantics") interacts with the stub's unconditional pre-init environment scrub (`environment_preinit.c` via `crates/compiled-stub/build.rs:58-107`): the C shim scrubs the real environment before `main`, but the mode is determined by argv[1]. A sound implementation exists (init-array/constructor receives argc/argv on both v1 tuples, so the shim can branch on the selector; or capture-and-restore), but neither M2 nor 0029 §4 names the interaction, and 0029 §4's "sanitize before every constructor under Ibex's control" guarantee for CapSec must survive the dual-mode shim. Worth one sentence.
- [MINOR] Coherence: the Summary's identical-in-both-modes list ("Envelope integrity, graph/carrier admission, HBC compatibility, provenance, and platform layout") omits policy, while M2 ambient item 1 says "policy bytes" and the current shared admission path validates policy content against the compiled-in registry and graph identity (main.rs:527-563). Say explicitly whether ambient boot semantically validates the embedded policy (as today's code does) or only digest-admits it; §9's "envelope/integrity admission is identical across modes" is ambiguous on exactly this point.
- [MINOR] Correctness (wording): §2 lists "compile-plan ... sections"; there is no CompilePlan section kind (`SectionKindV1`, sfe-format/src/lib.rs:597-605) — the plan is a field of the provenance section.

**LLP 0047 verdict: NOT READY**

Cross-document findings bearing on this target (Linux ambient network, the LLP
0022 compiled-program exception, the incomplete amendment discipline covering
LLP 0031 and LLP 0022, and the stale SFE umbrella ticket) are in the cluster
review's cross-document section.

## Rounds 2–3 — 2026-08-01 (delta rounds)

Both were lockstep cluster delta rounds. The verbatim bodies live once in
`llp/reviews/0029-single-file-executable-packaging.fable.md` (Round 6 and Round 7), together with the loop close-out,
the full verdict history, the round-3 disposition ledger, and the revision
hashes the final verdicts bind to.

- **Round 2 verdict (Fable): NOT READY**
- **Round 3 verdict (Fable): READY**

Both rounds found **no MATERIAL concern in pre-existing text** — the
delta-convergence criterion. Every MATERIAL concern after round 1 was
IN-DELTA, i.e. introduced by the loop's own revisions.

The loop terminated on round-budget exhaustion and escalated to the author. A
later **unreviewed** revision exists, addressing every round-3 finding; its
hash is recorded in the close-out.
