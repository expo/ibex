# Third-Party Notices

Ibex is MIT-licensed; see [LICENSE](./LICENSE).

## Hermes — MIT

The optional engine profile links an unmodified build of Meta's Hermes engine
at the commit pinned by `scripts/hermes-version.sh`. Binary distributors must
carry Hermes's MIT notice from its upstream source distribution.

## ring — ISC-style license

The workspace patches crates.io `ring` to the checked-in source under
`vendor/ring/`. Its license and notices are preserved in
[`vendor/ring/LICENSE`](./vendor/ring/LICENSE).

## Web Platform Tests

Selected upstream WPT fixtures and their manifest are pinned under
`third_party/wpt/`. Individual fixtures retain their upstream copyright and
license headers; WPT is distributed under the W3C 3-clause BSD license.

## SQLite

`ibex2-sqlite` uses `rusqlite`'s bundled SQLite build. SQLite is in the public
domain.

## Rust dependencies

Additional Rust crates and their exact versions are recorded in `Cargo.lock`.
Their license texts ship with their source distributions.
