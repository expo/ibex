# Ibex

Ibex is the Ibex 2 runtime: a Rust standard library with JavaScript bindings,
a vanilla-Hermes runtime, and capability-carrying host APIs. The workspace's
engine-facing crates follow the three public doors:

- `ibex2` is the engine-free Rust library. Its optional `bindings` feature
  builds the JSI installer and binding bytecode but links no VM.
- `ibex2-runtime` owns Hermes, loading, hardening, the loop, the CLI, and
  engine-bearing tests.
- `hermes-lean-sys` selects the matching VM, JSI headers, and `hermesc`.

`ibex2-sqlite` remains the optional native SQLite provider.

Engine-free consumers can use the default Rust library surface directly:

```sh
cargo test -p ibex2 --no-default-features
```

The supported library feature combinations have a CI-ready compile check:

```sh
./scripts/check-ibex2-features.sh
```

The bindings door is off by default:

```sh
cargo test -p ibex2 --no-default-features --features bindings
cargo test -p ibex2-runtime --all-features --no-fail-fast
```

This first `hermes-lean-sys` version resolves only local artifacts. It uses the
repository platform layouts (`ios/Frameworks-vanilla`,
`linux/Frameworks-vanilla`, or `tools/hermes-vanilla`) unless
`HERMES_LEAN_SYS_DIR` selects another complete install. The selected install
provides both the VM and compiler, so binding bytecode cannot silently drift
from the linked engine. Verified pinned-bundle downloads belong to L1c.

An embedder using `ibex2[bindings]` must evaluate
`ibex2::bindings::HARDEN_SOURCE` or its matching precompiled bytecode before
application code. The crate exposes both `HARDEN_BYTECODE` and
`HARDEN_BYTECODE_PATH` for that bootstrap step.

Design and maintenance conventions live in `llp/`, `AGENTS.md`, and `rules/`.
Run `./ref-check` after changing LLP references.
