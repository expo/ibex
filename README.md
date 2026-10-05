# Ibex

Ibex is the Ibex 2 runtime: a Rust standard library with JavaScript bindings,
a vanilla-Hermes runtime, and capability-carrying host APIs. The workspace's
engine-facing crates follow the three public doors:

- `ibex2` is the engine-free Rust library. Its optional `bindings` feature
  builds the JSI installer and binding bytecode but links no VM.
- `ibex2-runtime` owns Hermes, loading, hardening, the loop, the CLI, and
  engine-bearing tests.
- `hermes-lean-sys` selects the matching full or lean VM, JSI headers, and
  `hermesc`.

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

`hermes-lean-sys` resolves vanilla Hermes in this order: a complete local
install selected by `HERMES_LEAN_SYS_DIR`; this checkout's platform layout
(`ios/Frameworks-vanilla`, `linux/Frameworks-vanilla`, or
`tools/hermes-vanilla`) when present; then the SHA-256-pinned
`hermes-vanilla-d412d3bd8512-v2` release bundle for the Cargo target. The
release fallback needs no consumer configuration once the publication
placeholders in the pin table have been filled.

Downloaded bundles are cached at
`$CARGO_HOME/hermes-lean-sys/<tag>/<archive-sha256>/` (`$HOME/.cargo` when
`CARGO_HOME` is unset). Set `CARGO_NET_OFFLINE=true` or
`HERMES_LEAN_SYS_OFFLINE=1` to forbid network access; an already verified
cache entry or `HERMES_LEAN_SYS_DIR` is then required. Mirrors can set
`HERMES_LEAN_SYS_MIRROR` to a base URL that serves `<tag>/<asset>`. The pinned
digest is enforced for every origin. Cross builds select `hermesc` for the
host, require its HBC version to match the target receipt, and require every
available receipt to describe the exact engine archive and compiler selected
by the build.

Each v2 bundle contains both source-capable `hermesvm_a` and bytecode-only
`hermesvmlean_a`. Enable exactly one `hermes-lean-sys` link feature: `link`
for the full VM or `link-lean` for lean. Enabling both is a compile-time error.
The full identity remains `DEP_HERMES_LEAN_ARCHIVE` /
`DEP_HERMES_LEAN_ENGINE_DIGEST`; lean is
`DEP_HERMES_LEAN_LEAN_ARCHIVE` / `DEP_HERMES_LEAN_LEAN_ENGINE_DIGEST`.
When one link feature is active, `DEP_HERMES_LEAN_LINKED_ARCHIVE` and
`DEP_HERMES_LEAN_LINKED_ENGINE_DIGEST` name the archive actually linked.
The Rust constants are `ARCHIVE`, `ENGINE_DIGEST`, `LEAN_ARCHIVE`,
`LEAN_ENGINE_DIGEST`, `LINKED_ARCHIVE`, and `LINKED_ENGINE_DIGEST`.

`ibex2::bindings::ENGINE_DIGEST` continues to name the full archive;
`ibex2::bindings::LEAN_ENGINE_DIGEST` is the identity a lean embedder checks.
Both VMs consume one HBC version, asserted while binding bytecode is built.
Old local layouts without a lean archive continue to support full-VM builds
and fail with a targeted message only when `link-lean` is requested. The
end-to-end lean proof can be run against a complete v2 bundle:

```sh
HERMES_LEAN_SYS_DIR=/path/to/extracted-v2-bundle \
  cargo test --locked --manifest-path crates/ibex2-lean-embedding/Cargo.toml
```

An embedder using `ibex2[bindings]` must evaluate
`ibex2::bindings::HARDEN_SOURCE` or its matching precompiled bytecode before
application code. The crate exposes both `HARDEN_BYTECODE` and
`HARDEN_BYTECODE_PATH` for that bootstrap step.

## Windows x64

Install Rust through rustup, Visual Studio's C++ desktop workload with the
Windows SDK, CMake, Ninja, Python, and Node.js. The repository pins Rust 1.97.0;
rustup selects it from this directory. Run the following from the repository
root in an **x64 Visual Studio Developer PowerShell**, with `cl`, `dumpbin`,
`cmake`, `ninja`, `python`, `node`, and Windows `tar` available on PATH.

Build the pinned, unmodified Hermes source; the builder also writes its v2
receipt:

```powershell
./scripts/build-hermes-windows-vanilla.ps1
cargo build --locked --release -p ibex2-runtime --bin ibex2
```

The builder downloads the source if it is not cached. It installs headers and
static libraries under `tools/hermes-vanilla/windows-x64`, and the matching
compiler at `tools/hermes-vanilla/hermesc-windows-x64.exe`. The receipt step
checks the installed engine's symbols and records its engine/compiler hashes.
`ibex2 build` requires that receipt; building the executable alone does not
produce it. No custom Hermes INCLUDE or LIB environment settings are needed.
The build cache lives under `%LOCALAPPDATA%/Exact/hermes2-windows-vanilla`;
keep that path short, because some MSVC tools still limit generated path lengths.

Leave `HERMES_LEAN_SYS_DIR` unset for the repository builder's output above:
that layout keeps the compiler beside, rather than inside, `windows-x64`.
For a separate complete vanilla install, set it to the absolute root containing
`hermes-headers/`, `windows-static/`, and the matching `hermesc.exe` (or
`bin/hermesc.exe`). The full CLI's `build` command also requires
`hermes-input-receipt.json` in that root. Pointing the override at the repository's
`windows-x64` directory alone fails because it does not contain that compiler.
Set this variable before Cargo builds: the selected engine and compiler paths
are baked into the runtime, so moving an install requires rebuilding it.

Compile a small application ahead of time and run it:

```powershell
New-Item -ItemType Directory -Force target/windows-smoke | Out-Null
"console.log('hello');" | Set-Content target/windows-smoke/index.js -Encoding utf8
./target/release/ibex2.exe build ./target/windows-smoke/index.js --root ./target/windows-smoke
./target/release/ibex2.exe run ./target/windows-smoke/index.js --root ./target/windows-smoke --precompiled
```

Applications receive no capabilities unless an explicit grant manifest is
supplied. `run --no-compile` loads source for development; ship precompiled
artifacts. A smaller, run-only executable omits the loader and default optional
families, and executes the same compiled application:

```powershell
cargo build --locked --release -p ibex2-runtime --no-default-features --bin ibex2 --target-dir target/run-only
./target/run-only/release/ibex2.exe run ./target/windows-smoke/index.js --root ./target/windows-smoke --precompiled
```

The run-only executable still needs Hermes and its compiler during the Cargo
build, which precompiles its builtin bindings. Executing `--precompiled` needs
no compiler. Windows system/ICU libraries and the Microsoft C++ runtime remain
normal runtime dependencies. The supported engine target is x64 MSVC; other
Windows architectures and toolchains are not qualified here.

Design and maintenance conventions live in `llp/`, `AGENTS.md`, and `rules/`.
Run `node ./ref-check` after changing LLP references.
