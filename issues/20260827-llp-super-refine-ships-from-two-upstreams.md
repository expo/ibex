# llp-super-refine ships from two upstreams with different content

**Status:** Open
**Systems:** Tooling, Agent Skills
**Severity:** P3
**Author:** Charlie Cheever
**Date:** 2026-08-27

`ccheever/llp` and `ccheever/skills` both ship a `llp-super-refine` skill, and the two have diverged. The llp copy is version-pinned (`source: ccheever/llp@v0.5.2`), was last touched 2026-08-25, and is model-family-agnostic. The skills copy dates from 2026-07-11, hardcodes specific model names in its description, and carries an extra `agents/openai.yaml`. It reads as the superseded original, from before the skill graduated into the llp repo.

Before this was noticed, `scripts/sync-agent-skills.sh` linked whichever source ran last — `skills` — so ibex was silently running the older copy.

Ibex is no longer affected. `ccheever/skills` was dropped as a managed source the same day, for the separate reason that a project should share a few prebaked lanes rather than a general skill library, so ibex now resolves `llp-super-refine` from its owning upstream. Two guards were added on the way past: first-wins precedence with a warning in `sync-agent-skills.sh`, and stale-link pruning in `install-agent-skills.sh`, which had only ever added links and would otherwise have left `cdc-linear-do` dangling in five agent directories.

What remains is the upstream duplicate itself, which any other repo consuming `ccheever/skills` will still pick up. This issue closes when `llp-super-refine` is deleted from `ccheever/skills`, since `ccheever/llp` owns it.

Do not resolve it by reordering sources in the sync script. The order encodes which upstream owns what, and reordering to dodge one collision silently changes precedence for every other skill.
