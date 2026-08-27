# Rules

**ibex is the runtime everything above it waits on. Its budget is measured in
milliseconds because Exact's is.**

Speed is the constraint. Everything below exists to keep the edit-to-verified loop short
and to stop this repository accreting apparatus faster than anyone can remove it.

Each rule is **[check]** (enforced in CI) or **[review]** (enforced by a human).

## Budgets — every budget is a trade, not a limit

- **5 blocking checks, 60s total.** A sixth requires deleting one, in the same PR. **[check]**
- **55 active design docs.** A 56th requires archiving one. **[check]**
- **This file: 700 words.** If it grows, something becomes a check or stops being a rule. **[check]**
- **1,500 lines per source file**, baseline 133. Generated files exempt — and generated
  files are built, not committed. **[check]**

A limit gets exceptions. A trade doesn't: it forces someone to name what matters less.

## Loop shape

- **Every check reports all failures in one run.** Fail-fast is banned. A check that
  surfaces one defect per run turns N bugs into N x runtime. **[check]**
- **Nothing blocks on anything slower than 60 seconds.** Slow verification runs
  asynchronously, per-commit, on fleet hardware, attributed to the breaking commit.
  Run everything; block on almost nothing. **[review]**
- **Fix loops get 3 rounds.** Then stop and either escalate to a human or descope the
  target. Never "iterate until green." **[review]**

## Time budgets

Tracked every commit. A regression is a P0 with a name on it. The loop rows are targets
pending their first measurement on this repository; tighten them once measured.

| | |
|---|---|
| Incremental rebuild after a one-line edit | 30s |
| Test what you just changed | 60s |
| Blocking gate suite | 60s |
| Full build, warm cache | 5 min |
| **Process start to app entry evaluated** | **30ms** |

The product row is derived, not invented: Exact budgets 100ms from launch to an
interactive first frame, and ibex sits underneath layout and paint. Thirty milliseconds is
ibex's share. Today the boot path transpiles ESM to CommonJS per module at runtime, so
this row is aspirational until modules ship as bytecode.

## Scope

- **`NOT-DOING.md` is binding.** Moving something onto the doing-list means writing why
  and taking something off. **[review]**
- **Delete; don't deprecate.** No compat shims or migration paths before 1.0. **[review]**
- **Nothing is compiled, transpiled, or generated at runtime that could be built ahead of
  time.** This is the rule ibex most conspicuously breaks today. **[check]**
- **A spec needs an implementer and a date, or it isn't written.** **[review]**
- **Only implemented specs bind.** A document with no running code behind it is a
  proposal, and a proposal cannot block a PR or justify a check. **[review]**

## Agents

- **Agents remove apparatus freely and add none.** An agent PR that adds a check, script,
  registry, config file, or design doc needs explicit human approval saying so. **[review]**

## Shared machines

- Warm, pre-provisioned worktrees, one lane each. Never clone fresh.
- **Never `git stash`** — the stash stack is global across worktrees.
- Kill only PIDs you recorded at launch. Never by name or pattern.

## The five checks

`build` · `test` · `lint` · `caps` · `ref-check`

`caps` enforces the budgets above. `ref-check` validates the LLP corpus and every `@ref`.
Everything else runs async.
