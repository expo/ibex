# Agent Instructions

This project uses **Linked Literate Programming (LLP)** as defined in [LLP 0000](./llp/0000-ibex.explainer.md). Read that document before making substantial changes.

## LLP documents

- LLP documents live in `llp/` and follow the numbering convention `NNNN-slug.type.md` (e.g. `0001-target-platforms-and-ci-matrix.rfc.md`). Numbers are never reused.
- When creating a new LLP, use the next available number and include the standard metadata header (`Type`, `Status`, `Systems`, `Author`, `Date`; optional `Role`, `Revised`, `Related`).
- Standard types: **RFC**, **Spec**, **Decision**, **Plan**, **Explainer**, **Principles**, **Guide**, **Issue**, **Research**.
- Review intensity is stakes-scaled and author-judged ([LLP 0005 in ccheever/llp](https://github.com/ccheever/llp/blob/main/llp/0005-rfc-process.guide.md)): setting `Status: Review` opts into a formal multi-model loop; honesty rules (never fabricate a review, artifacts under `llp/reviews/`, the author decides) always apply.
- LLP documents are living documents. Update them as the system evolves; move historical-but-useful ones to `llp/tombstones/`. Don't leave stale docs unmarked.

## @ref annotations

- When writing or modifying code that implements a non-obvious design decision documented in an LLP, add an `@ref` annotation: `// @ref LLP NNNN#section — short gloss`
- When modifying code that already carries a `@ref`, check that the referenced section still applies.
- Don't annotate mechanically — a reference should tell you something you wouldn't know from the code and filename alone.
- `./ref-check` validates references + metadata deterministically.

> **Inherited cross-repo refs (known debt).** Ibex was extracted from the
> `exact` monorepo (LLP 0180 there), so its code still carries `@ref LLP NNNN`
> comments pointing at **exact/snapback** LLP numbers (0003, 0006, 0074, 0086,
> 0141, 0159, 0177, 0178) that do **not** exist under this repo's `llp/`. Until
> those are converted to URL refs (e.g. `@ref https://github.com/ccheever/exact/blob/main/llp/0159-…`),
> `./ref-check` will report them as broken and CI does **not** yet gate on it
> (LLP 0001-adopting Phase 4). Reconciling them is a tracked follow-up.

## Agent skills

This repo ships the LLP workflow skills under `skills/` (from ccheever/llp). Install by copying into your agent's skills dir (e.g. `cp -r skills/* ~/.claude/skills/`).

<!-- BEGIN LLP SKILLS MANAGED BLOCK -->
Before editing a subsystem with documented design, orient first: read its
governing LLP, and for non-trivial work invoke `llp-orient` to assemble a
context pack of the constraints the change must respect.

Skills: orient = context before coding · create = author one LLP · review = LLP 0005 loop, scaled to stakes · adopt = set up LLP in any repo · maintain = drift / pre-PR / reconcile / retire checks
<!-- END LLP SKILLS MANAGED BLOCK -->

## Working on this project

- Read relevant LLP documents before implementing features or fixing bugs in the areas they cover.
- If you make a design decision worth documenting, write or update an LLP.
- Prefer updating an existing LLP over creating a new one when the topic is covered.
- Land doc updates in the same commit as the code change that motivated them.
