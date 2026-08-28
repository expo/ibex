# LLP 0061: Conformance suites, and what each one governs

**Type:** Decision
**Status:** Draft
**Systems:** Runtime, Engine, Build, Product
**Author:** Charlie Cheever / Claude (Opus 5)
**Date:** 2026-08-28
**Revised:** 2026-08-28 (initial draft)
**Related:** LLP 0058 (the engine seam — this discharges its OQ3), LLP 0059 (the measured surface, whose §7 remains the scope authority), LLP 0059.000 (the API specifications this oracle checks), LLP 0027 (module artifact and interop — the frozen-subset pattern this generalizes), LLP 0060 (authority is carried)

## Summary

Two suites, two jobs, and confusing them is the failure this document exists to
prevent.

**Test262** is the ECMA-262 conformance suite: the language and JavaScript's own
built-ins. Under LLP 0059's tiers that is **Tier E** — what the engine provides.
It measures Hermes, not Ibex 2.

**Web Platform Tests** covers the WHATWG and W3C surface: `fetch`, `URL`,
`TextEncoder`, `console`, `atob`. That is **Tier I** — what Ibex 2 implements.

The mapping is exact, and it is why "does our `fetch` pass Test262" has no
answer: Test262 contains no `fetch` tests, because `fetch` is not part of
ECMA-262.

## 1. The decision

**D1 — WPT is an oracle, never a scope definition.** It answers *did we
implement this correctly*. It does not answer *what should we implement*.
LLP 0059 §7 remains the sole scope authority: a Tier I entry requires a measured
call site or an explicit author requirement, and **"the web platform defines
it" is not a reason**. WPT is a to-do list of the entire web platform; treating
it as a target inverts the one rule that keeps Ibex 2 small, and that inversion
is how the current standard library reached 46,000 lines of JavaScript for a
surface this size.

**D2 — Adoption is by frozen subset with a baseline and a recorded divergence
list.** Per suite: the upstream path, its SHA-256, the pass count, and what
fails and why. The pass count may not fall; raising it is deliberate work. This
is LLP 0027's pattern for its 20-case test262 subset, generalized rather than
reinvented.

Baselined rather than required-100% for the reason `caps` grew baselines: a
check that is red the day it lands gets switched off within a week, which is
strictly worse than a check calibrated to where the code actually is.

**D3 — Test262 gates the engine seam, not the standard library.** It qualifies
a candidate engine (LLP 0058 §4 requires a conformance gate before any swap)
and guards the engine configuration Ibex 2 selects — `MicrotaskQueue` on,
`EnableEval` off. It is not a target for Ibex 2's own work and carries no
percentage goal, because per LLP 0058 OQ3 the percentage measures the wrong
population once the standard library is Rust.

**D4 — A divergence is a recorded decision, not a defect by default.** Each one
is either *accepted* with a reason, or *scheduled* with a ticket. An
unclassified divergence is the only kind that is a bug.

## 2. Evidence: the first suite adopted

`url/resources/urltestdata.json` is the ideal first adoption — 893 cases of
pure data, no browser, no server, no harness. Vendored at
`third_party/wpt/urltestdata.json` and run by `crates/ibex2/tests/wpt_url.rs`:

**828/893 pass (92.7%)**, with divergences concentrated rather than scattered:

| category | count | disposition |
|---|---|---|
| `file:` scheme | 40 | **Accepted.** Windows drive letters and `file:` hosts. Ibex resolves paths through the virtual filesystem namespace (LLP 0023), not `file:` URLs, and the measured surface contains none. |
| other | 13 | **Mixed** — see §3. |
| IDNA / punycode | 7 | **Accepted.** Invalid punycode labels such as `xn--pokxncvks`, which the spec passes through and the `idna` crate refuses. Refusing is the safer direction. |
| non-special scheme | 5 | **Accepted.** Percent-encoding inside opaque paths for schemes no measured code uses. |

Sixty-two percent of the gap is `file:` URL handling in a runtime that does not
address files by URL. That is the shape a good divergence list has: a
disposition, not a backlog.

## 3. The one divergence worth scheduling

`///test` against an `http://example.org/` base should resolve to
`http://test/`; we report *empty host*. This is the `http` scheme, which is the
measured surface, so unlike the rest it is not academic. Three cases in the
suite. Ticketed rather than accepted.

The remaining "other" rows are `^` percent-encoding in non-special and `wss`
paths, and drive-letter logic leaking into an `abc://` base — same disposition
as their categories above.

## 4. What WPT cannot yet check

Most of `fetch/` needs `wptserve` and a browser-shaped client, and it leans
heavily on CORS, credentials, cache modes, streaming, and service workers —
all explicitly out of v1 (LLP 0059.000 §3.5, §5). Adopting `fetch/` wholesale
would be red on arrival for surface we have decided not to build.

What *is* reachable without a server is the object surface:
`fetch/api/headers/*` and the `Response` constructor tests run entirely
in-process. They are gated not by the transport but by the **binding layer** —
today a `Response` reaches JavaScript as a numeric handle with accessor
functions, and WPT expects `Response`, `Headers`, and `Request` objects. That
binding layer is the next piece of work, and these tests are the reason to
build it correctly rather than approximately.

## 5. Open questions

**OQ1 — The testharness subset.** `.any.js` WPT tests need `testharness.js`
(`test`, `promise_test`, `assert_equals`, `assert_throws_js`). The subset those
files actually use is small. Implement that subset, or vendor upstream
`testharness.js` and run it on the runtime?

**OQ2 — Where the engine's Test262 run lives.** It is slow and belongs to the
per-commit fleet lane rather than the 60-second blocking gate
(`rules/RULES.md`). Which subset, and against which pin?

**OQ3 — Encoding next.** `encoding/` is the other data-driven suite and covers
`TextEncoder`/`TextDecoder` directly. Cheap, and probably the second adoption.
