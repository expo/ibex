# Ibex patch provenance

This directory vendors `ring` 0.17.14 from the crates.io package recorded in
the root `Cargo.lock`. Its upstream license files are preserved beside this
note.

Ibex changes one implementation detail in `build.rs`: recursive source
discovery is sorted before emitting `cargo:rerun-if-changed`. Cargo includes
the directive sequence in its build fingerprint, while filesystem enumeration
order is unspecified. Sorting preserves the exact watched source set and makes
the `ring`/`rustls` dependency identity reproducible across clean builders.

The patch is selected by the root `[patch.crates-io]` entry. When upgrading
`ring`, re-check whether upstream has made this traversal deterministic before
refreshing or removing the vendored copy.
