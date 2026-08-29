# `ibex2 run` SHA-256s the engine framework on every start: 25 ms of a 30 ms budget

**Status:** Closed
**Resolved:** 2026-08-29
**Impact:** 4
**Urgency:** 4
**Ease:** 4
**Confidence:** 5
**Severity:** P1
**Systems:** Build, Runtime, Provenance
**Author:** Claude (Fable 5), directed by Charlie Cheever
**Date:** 2026-08-29
**Related:** LLP 0058.000.001 §5 (the receipt), LLP 0063 §2 (the floor), `scripts/metrics.mjs`

Found by the process row of `scripts/metrics.mjs` on its first run, then
decomposed. A precompiled one-module program, median of 7, spawn included:

| | |
|---|---|
| `/usr/bin/true` | 1.7 ms |
| `ibex2` (prints usage) | 4.4 ms |
| `ibex2 run hello.js --no-compile` | 7.9 ms |
| `ibex2 run hello.js --precompiled` | **32.6 ms** |

Everything the runtime does — dyld of a 9 MB binary, construction, stdlib,
bindings, freeze, loading and running the module — is the 7.9 ms row. The
other **25 ms** is `Compiler::discover_for_engine`, which `run` calls
whenever it has a compiler, and which calls `HermesInput::verify_binary`:
`std::fs::read` of `hermesvm.framework/Versions/1/hermesvm` followed by a
SHA-256 of the whole file, per process. It also locates `hermesc` on the
`--precompiled` path, where nothing will ever be compiled.

So the shipping path — bytecode, no compilation, the thing every rule here
optimizes for — pays 25 ms of provenance ceremony before the 2 ms floor, on
a 30 ms budget. And it verifies the wrong thing: the runtime links the
engine *statically* from `macos-static/libhermesvm_a.a`; the dylib being
hashed is a file beside the receipt, not the engine that is running.

The receipt is right to exist and wrong to be checked here. Verification
belongs where the engine is *bound*: at build time, with the digest folded
into the artifact key (which `with_engine` already does with the receipt's
digest string) and, for the binary itself, into `build.rs` — the engine the
runtime links is fixed when it is linked. At run time, `--precompiled`
should read the manifest and the receipt's *digest string* and nothing else;
a compiler should be discovered only when something is going to be compiled.

**Done when:** `ibex2 run hello.js --precompiled` is within ~1 ms of
`--no-compile` on `scripts/metrics.mjs`'s process row, the receipt is still
required for `build`, and an artifact built against one engine is still
refused by another.

## Resolution (2026-08-29)

Verification moved to where the engine is bound. `build.rs` hashes the
archive the binary actually links (`libhermesvm_a.a`) once per link and
bakes it in as `IBEX2_LINKED_ENGINE_DIGEST`; `Compiler::linked_engine()`
reads the constant. Every artifact key folds it in (ARTIFACT_VERSION 3), and
the manifest now carries an `#engine` header the runtime checks at load — a
manifest built by another binary, or one from before binding, is refused
under `--precompiled` and ignored otherwise. `Compiler::for_run` reads the
receipt's 2 KB for its digest strings and hashes nothing; under
`--precompiled` it does not even look for `hermesc`. `discover_for_engine`
keeps the build posture — receipt required, dylib and now hermesc verified
against it — because a build is where trusting the files on disk is the
point.

`scripts/metrics.mjs`, process row, precompiled one-module program: **33 →
7.4 ms** (7.9 ms was the `--no-compile` floor it should have matched), RSS
24.8 → 12 MB, because the runtime no longer reads a 25 MB dylib to hash it.

Tests: `a_manifest_records_its_engine_and_reads_it_back`,
`a_manifest_built_for_another_engine_is_refused_under_precompiled`; the
receipt-refusal tests in `tests/loader.rs` are unchanged and still pass.
