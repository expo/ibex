# What ibex 2 Does Not Do

This is the most valuable file in the repository. It is longer than the doing-list on purpose.

## The bar that makes this list derivable

ibex 2 is a **Rust standard library with JavaScript bindings**. It is done when an Exact
app boots to an interactive first frame inside its 30ms share of Exact's 100ms budget,
and when a no-JS consumer — a Rust root, the Linux/DRM path — gets the same standard
library with no engine in the process at all. *(The second half exists since 2026-08-29:
`ibex2::host`, LLP 0068, tested with the engine feature off. The consumer is Exact 2's
plan runner.)*

Everything not required by that does not exist.

## Not doing

- **Compiling anything at runtime.** Modules ship as bytecode. Today the loader
  transpiles ESM to CommonJS per module on every launch, through the slower of two
  transform engines because Oxc cannot lower general ESM yet. That is the single largest
  thing ibex 2 exists to delete.
- **A JavaScript standard library.** `http`, `stream`, `fs`, `tls`, `net`, `crypto`,
  `child_process` move to Rust behind a stable host-call boundary, with platform-native
  implementations where the platform has one. Rust owns the *semantics*; the platform
  owns transport. Not the reverse — a platform that defines behavior gives you four
  different `fetch`es.
- **A second executor for anything.** One implementation per capability, everywhere.
- **A large CLI.** `src/bin/` is 137K lines against a 152K-line runtime core. `run`,
  `build`, and probably `repl` is the surface.

## Decided (were open until 2026-08-28)

**Node compatibility: deleted.** LLP 0059 §6 removed `http`, `net`, `tls`,
`child_process`, and `zlib`; `fs` returned as a promise-only subset over the
capability model. Ibex 2 is an app runtime, not a general JavaScript one.

**capsec: in, and whole.** Exact 2 is expected to run npm dependencies
(LLP 0057 OQ2), so the boundary model stays — authority as module parameters,
grants by package, one check in Rust, the freeze — and is stated on one page,
LLP 0067, whose §7 says what counts as evidence. The compartment machinery,
caller attribution, and the proof program (LLP 0058.000.001, tombstoned) are
not ported and not coming back.

## Process not doing

- **No speculative specs.** A spec of what you are about to build is transcription. A
  spec of what nobody is assigned to build is how a corpus reaches millions of words.
- **No blocking check the author did not run locally in under a minute.**
- **No gate slower than the loop it guards.**

## Deliberately worse

- No backwards compatibility before 1.0. No API stability. No migration guides.
- Generated files are built, never committed.
- Sparse prose. The code and the checks are the authority.

## Moving something off this list

Write one line naming what it unblocks, and take something off the doing-list in the same
PR. If nothing can come off, the answer is no.
