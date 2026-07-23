# Third-Party Notices

Ibex is MIT-licensed (see [LICENSE](./LICENSE)). This file records the
third-party software that is vendored in this repository or compiled into
distributed Ibex binaries, together with the license obligations each one
carries. Components are listed with where they live and how they enter a
build.

## Hermes (Meta Platforms) — MIT

Ibex embeds a patched build of the [Hermes JavaScript
engine](https://github.com/facebook/hermes).

- The pinned upstream source is `facebook/hermes` at commit
  `ac8c6e6c80ec5fc22da39a77379ffb2fdbdde138` (Ibex Hermes version
  `260318099.0.0`; see `scripts/hermes-version.sh`, which is the single
  authority for the pin).
- The patch series under `patches/hermes/` modifies Hermes VM sources and is a
  derivative work of Hermes: each patch embeds upstream source context. The
  patches themselves are released under Ibex's MIT license; the embedded
  upstream context remains under Hermes' MIT license below.
- Build artifacts (the `hermesvm` framework/library and any Ibex binary
  linking it) include compiled Hermes code and must carry this notice.

```
MIT License

Copyright (c) Meta Platforms, Inc. and affiliates.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## Brotli (Google) — MIT

`vendor/brotli/` vendors the Brotli compression library's C sources
(common/dec/enc + headers). Its license is preserved verbatim at
[`vendor/brotli/LICENSE`](./vendor/brotli/LICENSE) (Copyright (c) 2009, 2010,
2013–2016 by the Brotli Authors). Brotli is compiled into Ibex binaries that
provide `node:zlib` brotli support.

## cjs-module-lexer (Guy Bedford) — MIT

`third_party/cjs-module-lexer/` vendors the `cjs-module-lexer` WebAssembly
build used for CommonJS named-export analysis. Its license is preserved at
[`third_party/cjs-module-lexer/LICENSE`](./third_party/cjs-module-lexer/LICENSE)
(Copyright (C) 2018–2020 Guy Bedford).

## web-streams-polyfill — MIT

`src/engine/bootstrap/web-streams-polyfill.js` embeds
[web-streams-polyfill](https://github.com/MattiasBuelens/web-streams-polyfill)
v4.2.0 (Copyright 2025 Mattias Buelens, Diwank Singh Tomer and other
contributors, MIT). The file retains its upstream `@license` header, and the
polyfill is compiled into the embedded runtime bundle
(`vendored-generated/embedded_runtime_bundle.js`).

## SQLite — public domain

The `exact:sqlite` builtin uses `rusqlite` with the `bundled` feature, which
compiles the SQLite amalgamation into Ibex binaries. SQLite is in the public
domain and requires no attribution; this entry records its presence in
distributed binaries.

## OpenSSL — Apache License 2.0

Builds with the optional `openssl-crypto` feature (and Android builds, which
use it by default) statically link a vendored OpenSSL built at compile time
via the `openssl-src`/`openssl-sys` crates; the OpenSSL source is fetched by
the build, not stored in this repository. OpenSSL 3.x is licensed under the
Apache License 2.0. Binary distributions built with this feature include
OpenSSL and this product includes software developed by the OpenSSL Project
for use in the OpenSSL Toolkit (https://www.openssl.org/).

## zlib — zlib license

Windows builds statically link zlib via `libz-sys` (`static` feature) because
Windows ships no system zlib; other platforms use the system library. The
zlib license (Jean-loup Gailly and Mark Adler) permits this use without
notice reproduction in binaries; this entry records its presence.

## Rust and JavaScript dependencies

Ibex binaries additionally link Rust crates resolved through `Cargo.lock`,
and the devtools use JavaScript packages resolved through `bun.lock`. These
are predominantly MIT / Apache-2.0 dual-licensed; their license texts ship
with the registry packages and are not duplicated here. `Cargo.lock` and
`bun.lock` are the authoritative inventories of exact versions.

---

Local build artifacts that are not part of this repository (for example the
git-ignored `ios/Frameworks/` Hermes builds and `node_modules/`) carry their
own upstream licenses; the entries above cover everything this repository
distributes in source form or compiles into released binaries.
