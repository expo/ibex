# Per-module binding construction doubled the bytecode load cost: 23 → 41 µs a module

**Status:** Closed
**Resolved:** 2026-08-29
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

## Resolution (2026-08-29)

The hypothesis in this ticket was wrong, and the instrument said so. Sharing
`fetch`/`fs`/`process` per grant set (`ef35a2030`) — kept, because the shared
bindings are frozen and that is a better integrity property than a dozen
private mutable objects — moved the per-module cost from 36 to 37 µs. A
resolve/read/eval breakdown added to `examples/speed.rs` then showed where the
36 µs was: **resolve 26 µs** (two `realpath(3)` and up to five `stat(2)` per
module, both added by the containment fix after LLP 0063's 13 ms was
measured), **artifact read 14 µs**, **eval 1 µs**. Not the bindings at all.

`loader::ResolveCache`: one `readdir` and one `realpath` per directory answer
every extension probe and give each file its on-disk spelling; a full
`canonicalize` only for a symlink entry or a case-different spelling; the
canonical root once; one `oxc_resolver` per loader. Resolution: 13.2 → 0.96 ms
for 499 modules. The 500-module bytecode load: **36 → 15 µs a module** (min
18.1 → 7.5 ms), under the 25 µs this ticket asked for. Containment decides
exactly what it did (`the_resolve_cache_answers_as_the_filesystem_does`).

What remains is the read: 14 µs a module to open, read, and close one 10 KB
artifact per module, 500 times. One bundle read once would make that ~0, and
is the next item if the number ever matters — 7.5 ms for 500 modules does not
today.

