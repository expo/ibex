# Per-module binding construction doubled the bytecode load cost: 23 → 41 µs a module

**Status:** Open
**Impact:** 3
**Urgency:** 2
**Ease:** 3
**Confidence:** 4
**Severity:** P3
**Systems:** Module Loader, Runtime, Host ABI
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-29
**Related:** LLP 0063 §5.1 (13 ms for 570 modules, as measured then), LLP 0060 D1 (authority carried by the binding), `scripts/metrics.mjs`

LLP 0063 recorded a 570-module graph loading from bytecode in **13 ms**
(`d48f0587b`). The same test today — `boot_real`, release, same machine — gives
**23.2 ms**, and `scripts/metrics.mjs` gives 20 ms for 500: about **41 µs a
module against 23**. Nothing in the loader's file path changed; what changed
between the two measurements is what every module load now *constructs* in
`hermes_shim.cc::load_module`, whether the module uses it or not:

- an `fs` object with ten host-function properties, each a `make_async_binding`;
- a `process` object and an `env` object built from the grant set;
- an `import.meta` object with its URL string;
- the `fetch` binding, which was already there.

That is roughly a dozen JSI host objects and functions per module. At 570
modules it is the difference between a boot that spends 13 ms in the loader
and one that spends 23 ms, and it grows with every capability added to
`MODULE_PARAMETERS`.

The fix is not to take the parameters away — LLP 0060 D1 is right that
authority arrives with the binding — but to stop paying for them before they
are used. Options, cheapest first: build `fs`/`process`/`meta` lazily behind a
getter on first access; share one `fs`/`process` object per *grant set* rather
than per module (modules with equal grants get equal objects, and most
modules have the default set); or intern the ten `fs` host functions once per
grant set. The measurement that decides is `graph_500_bytecode_per_module_us`
in the metrics log.

**Done when:** the per-module bytecode load cost is back under ~25 µs on
`scripts/metrics.mjs` with all three bindings still injected as parameters
and every grant test still passing.
