# Reviews: LLP 0039 — Secure and Insecure Modes (Claude Fable family)

## Round 1 — 2026-08-01 (cluster loop: LLP 0029 + 0039 + 0047)

**Reviewer family:** Claude (Fable)
**Provider / runtime:** claude-code sub-agent, model `claude-fable-5`, fresh context (independent of the authoring/orchestrating session)
**Date:** 2026-08-01
**Redacted:** no (repository content only; no secrets present)
**Revision reviewed:** LLP 0039 at git-blob `b8a6e07c79ad6931a52d10734895a40b9ad0e53f` (repo HEAD `54761987`)
**Brief:** `brief-r1.md`, hash `2d2438a011e9e43161263d6b58c45222bfa84552`
**Verdict:** NOT READY

**Topology note.** This was a lockstep cluster review of LLP 0029 + LLP 0039 +
LLP 0047, because LLP 0047 is a scoped amendment to LLP 0029's release
sequencing and LLP 0039's product defaults, and cross-document coherence was
the primary review axis. Per the review-artifact rule, the cluster review is
preserved **verbatim once**, in the primary target's artifact:

> `llp/reviews/0029-single-file-executable-packaging.fable.md`, Round 5 —
> 2026-08-01.

That file carries the full provenance block, the reviewer's verified-true
findings, the other targets' sections, and the cross-document findings. What
follows is this target's per-target verdict section, excerpted from that single
verbatim body for discoverability.

### Per-target section (excerpt from the verbatim cluster review)

Verified true before findings: `default = ["standard"]`, `insecure` non-default and implying `unadvertised-dev-arming` (`Cargo.toml:173-200`, with the doc's exact secure-dev build line at 166-168); `check-secure-mode.sh` exists with the behavioral probe and `BAD(permitted)` (`scripts/check-secure-mode.sh:33,61`), wired into the CapSec macOS job (`.github/workflows/compartment-conformance.yml:109-111`); `ex_host_is_armed` insecure gating and the ~46-gate description match `src/host/abi.rs:7723-7735`; the armed-observer `#[cfg(not(feature = "insecure"))]` story matches the referenced closed ticket.

- [MATERIAL] Coherence/Safety (blast radius understated): the 2026-08-01 revision carves the LLP 0047 exception into the Decision paragraph and trip-wire 3, but the rest of the document's acceptability apparatus was not reconciled with it. (a) Trip-wires 1, 2, and 4 key exclusively on the `insecure` feature, yet everything they warn about — running third-party/generated code with full ambient authority, including by agents in this repo — is now reachable through a supported zero-feature-flag path (`ibex compile` + run, ambient default). Item 4's rationale applies verbatim and no wire covers it. (b) "Preventing an accidental ship" is entirely about keeping no-sandbox builds out of release pipelines, while the amended Decision makes shipping enforcement-off artifacts the standalone default; the section does not say how its build-time-refusal ambition coexists with a product whose release stub deliberately contains the enforcement-off path selected at runtime (today enforcement-off absence is compile-time: `src/host/abi.rs:7731`, `src/host/mod.rs:4617`; the dual-mode artifact necessarily gives that property up, and no document in the cluster states this shift). (c) The closing trigger — "revisited the first time Ibex executes code it did not author — that event, not a date, is the trigger" — now describes designed, routine behavior of the sanctioned product (an ambient compiled app embedding npm dependencies), and the document does not say whether the trigger excludes LLP 0047's contract or has effectively fired. Each fix is a paragraph, but this document's entire job is recording when the posture stops being acceptable, so the unreconciled register is material.
- [MINOR] Coherence: trip-wire 3 conditions the exception on the standalone application's "help ... mak[ing] the lack of sandboxing explicit", but under the cluster's argv contract the application owns its help surface entirely (the stub reserves only argv[1] `--ibex-capsec`); Ibex controls `ibex compile`'s help/notice, inspection, and release metadata, not the app's help. Restate the condition over surfaces Ibex actually controls (0047 M5 gets this right).
- [MINOR] Correctness: the Context still cites LLP 0036 as "~22k unresolved rows" — 0036's own header now reports 17,179 (Apple) / 17,193 (Windows) unresolved as of 2026-07-27, and LLP 0021's 2026-07-28 lines report 16,628. The qualitative claim (months, no bulk win) survives; the figure is stale in a doc revised 2026-08-01.
- [MINOR] Coherence: "It uses the enforcement-off mechanics" points (via "Mechanically the modes are described in LLP 0038") at mechanics LLP 0038 defines as the compile-time `insecure` feature — the very thing LLP 0047 forbids reusing. The runtime-selectable substrate actually exists (`SecurityMode::Permissive`/`is_allow_all` at `src/host/mod.rs:4600-4605`; unarmed native-gate diagnostic branches), but neither document names it, leaving a reader one plausible step from concluding the release stub compiles with `insecure`.

**LLP 0039 verdict: NOT READY**

Cross-document findings bearing on this target (Linux ambient network, the LLP
0022 compiled-program exception, and the incomplete amendment discipline
covering LLP 0031 and LLP 0022) are in the cluster review's cross-document
section.

## Rounds 2–3 — 2026-08-01 (delta rounds)

Both were lockstep cluster delta rounds. The verbatim bodies live once in
`llp/reviews/0029-single-file-executable-packaging.fable.md` (Round 6 and Round 7), together with the loop close-out,
the full verdict history, the round-3 disposition ledger, and the revision
hashes the final verdicts bind to.

- **Round 2 verdict (Fable): READY**
- **Round 3 verdict (Fable): READY**

Both rounds found **no MATERIAL concern in pre-existing text** — the
delta-convergence criterion. Every MATERIAL concern after round 1 was
IN-DELTA, i.e. introduced by the loop's own revisions.

The loop terminated on round-budget exhaustion and escalated to the author. A
later **unreviewed** revision exists, addressing every round-3 finding; its
hash is recorded in the close-out.
