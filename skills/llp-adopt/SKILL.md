---
name: llp-adopt
description: Bring LLP to a repository, greenfield or brownfield — the single entry point for "set up LLP here". Detects how much already exists and runs scaffold mode (fresh structure) or retrofit mode (survey the codebase, draft a provenance-tagged root LLP, propose an adoption plan).
source: ccheever/llp@v0.2.0
---

# llp-adopt

<!-- @ref https://github.com/ccheever/llp/blob/v0.2.0/llp/0001-adopting-llp.guide.md — the workflow this automates -->
<!-- @ref https://github.com/ccheever/llp/blob/v0.2.0/llp/0000-linked-literate-programming.explainer.md#provenance-for-generated-rationale — tagging rules for generated docs -->

One entry point for "add LLP to this project". Greenfield and brownfield are two ends of one spectrum — how much design knowledge already exists to mine — so this skill picks a mode rather than making the user choose.

Invoke as `/llp-adopt` (auto-detect), or force with `--mode scaffold` / `--mode retrofit`.

## Trigger

"Set up / bring LLP to this repo," for any repository state.

## Invariants

- MUST extend an existing `llp/` tree if one exists — never start a second setup layer.
- MUST write only new files and clearly-marked managed blocks; existing user prose is never overwritten without showing a diff and asking. Reruns MUST be idempotent (no duplicate files or blocks).
- MUST keep every generated document `Draft` and provenance-tagged: claims are `[observed]` (say where), `[confirmed]` (named human + date), or `[inferred]` — and `[inferred]` claims never survive into a document proposed for promotion.
- MUST propose `@ref` annotations and apply them only after approval — no mass annotation, and none on volatile early code.
- MUST NOT create a batch of speculative LLPs in either mode; establish orientation and the loop, then hand off.
- When a tool expects `CLAUDE.md`, symlink it to `AGENTS.md` when safe rather than maintaining divergent copies.

## Workflow

> **Recipe (advisory)** — inspect first: existing `llp/`? agent-instruction files? how much code and docs? Little to mine → **scaffold**; substantial code/history → **retrofit**; ambiguous → say which way you're leaning and proceed. Both modes share the spine: create `llp/`, write LLP 0000 (`Explainer`, `**Role:** Root` — what the project does, major subsystems, non-obvious invariants), and write the `AGENTS.md` managed block (orient-first rule + skill index). **Scaffold** then suggests 1–2 follow-on documents for real decisions already made. **Retrofit** additionally: survey the codebase (structure, entry points, git activity, existing docs as source material); draft the root LLP; propose the 2–5 highest-value subsystem LLPs (provisional title, type, systems, why); recommend the layered annotation plan (module-level refs → key functions → boy-scout rule) from LLP 0001.

## Artifact

Scaffold: `llp/`, an LLP 0000 skeleton, the managed blocks. Retrofit: those plus a survey summary, `Draft` provenance-tagged document(s), and a proposed adoption plan — nothing promoted, nothing mass-applied.

## Hand-offs

- Corpus exists → daily work starts with `llp-orient`; author follow-on docs with `llp-create`.
- Ratify generated drafts with `llp-review` where stakes warrant; keep healthy with `llp-maintain`.
