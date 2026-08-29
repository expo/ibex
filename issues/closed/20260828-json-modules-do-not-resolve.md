# `require('pkg/data')` cannot reach a `.json` file

**Status:** Closed
**Resolved:** 2026-08-28
**Impact:** 2
**Urgency:** 2
**Ease:** 3
**Confidence:** 5
**Severity:** P3
**Systems:** Module Loader
**Author:** Claude (Opus 5), directed by Charlie Cheever
**Date:** 2026-08-28
**Related:** LLP 0065 §1, LLP 0064

Found by an adversarial review of the package-resolution change.

`loader::EXTENSIONS` is `[".ts",".tsx",".mts",".js",".mjs",".jsx",".cjs"]` and
is passed to `oxc_resolver` as its `extensions`, replacing the default
`[".js",".json",".node"]`. Dropping `.node` is correct — native addons are not
a thing here. Dropping `.json` was not deliberate.

So `require('pkg/data')` intending `data.json` does not resolve, and neither
does a relative `require('./config')` next to a `config.json`.

Not fixed with a one-line extension addition, because resolution is only half
of it: a resolved `.json` would then be handed to `lower_and_wrap` and compiled
as JavaScript. JSON modules need a load path that parses rather than evaluates,
and a decision about the ESM shape (`default` export, and whether import
attributes are required as they are in Node and the browser).

Worth measuring against Exact's graph before building: if nothing imports JSON,
the right answer may be to keep refusing it with a message that says so.

**Done when:** either `.json` imports work with a decided ESM shape, or the
refusal names JSON explicitly instead of reporting a missing module.

## Resolution (2026-08-28)

Measured against Exact's graph, as the ticket asked: the native boot graph
imports two JSON modules, and `@exact/core`'s `color-v1.policy.json` is the
first non-JavaScript module `main.tsx` reaches — the run stopped on it. So
JSON is a module format, not a refusal to word better.

Both halves landed. `.json` is last in `loader::EXTENSIONS`, so `require('pkg/data')`
and an extensionless relative specifier find it and a `.js` sibling still wins.
`loader::to_javascript` turns a `.json` module into
`module.exports = JSON.parse("…")` — parsed, not evaluated as a literal, so
`__proto__` keys are own properties — and from there it is an ordinary
CommonJS module: lowered, wrapped, compiled to bytecode, keyed like any other.
Default import, `require`, and the `with { type: 'json' }` attribute all work;
the attribute is accepted rather than required, and named imports are
permitted, both recorded as permissive divergences in LLP 0064 §8.

Tests: `a_json_module_is_parsed_not_evaluated` (unit) and
`json_modules_load_as_their_parsed_value` (engine).

