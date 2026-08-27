# What ibex 2 Does Not Do

This is the most valuable file in the repository. It is longer than the doing-list on purpose.

## The bar that makes this list derivable

ibex 2 is a **Rust standard library with JavaScript bindings**. It is done when an Exact
app boots to an interactive first frame inside its 30ms share of Exact's 100ms budget,
and when a no-JS consumer — a Rust root, the Linux/DRM path — gets the same standard
library with no engine in the process at all.

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

## Open — decide before scoping the work

These two are one decision, and they set the size of everything:

**Node compatibility.** Port `http`/`net`/`tls`/`fs`/`child_process` to Rust, or delete
them? An app runtime for web, macOS, iOS, and Linux plausibly needs only `fetch`,
`WebSocket`, timers, `crypto.subtle`, storage, `URL`, and `TextEncoder`. Deleting is much
cheaper than porting. *Recommendation: delete, unless `ibex` is meant to stay a general
JS runtime for tooling. Confidence: moderate — it depends on a product question, not a
technical one.*

**capsec.** Its enforcement point is JavaScript globals, which is why it needs ~7,700
lines of engine glue and why LLP 0039 records ~16,628 unresolved rows and "months of
work, not days" before a default build can arm. Moving the standard library to Rust
relocates enforcement to the host-call boundary — one chokepoint instead of thousands of
global references. *Recommendation: do not port the compartment machinery; put the grant
check at the Rust boundary, and let per-package compartments ride on the npm answer
above. Confidence: high on the mechanism, low on the timing.*

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
