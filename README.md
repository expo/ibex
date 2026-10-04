# Ibex

Ibex is the Ibex 2 runtime: a Rust standard library with JavaScript bindings,
an optional vanilla-Hermes engine adapter, and capability-carrying host APIs.
The workspace contains `ibex2` and its optional native SQLite provider.

Engine-free consumers can use the default Rust library surface directly:

```sh
cargo test -p ibex2 --no-default-features
```

Hermes builds use the unmodified pinned engine and the `hermes` feature. Build
the platform artifacts with the matching script under `scripts/`, or set
`IBEX2_VANILLA_HERMES_DIR` and `IBEX2_HERMESC` to an existing vanilla install.

```sh
cargo test -p ibex2 --features hermes --no-fail-fast
```

Design and maintenance conventions live in `llp/`, `AGENTS.md`, and `rules/`.
Run `./ref-check` after changing LLP references.
