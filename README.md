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

For an existing vanilla install, set `HERMES_LEAN_SYS_DIR` to the absolute
`windows-x64` directory; the install supplies both the engine and its matching
compiler. Leave it unset to use the repository-local installation above.

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
