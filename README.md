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

## Windows x64

Install Rust through rustup, Visual Studio's C++ desktop workload with the
Windows SDK, CMake, Ninja, Python, and Node.js. The repository pins Rust 1.97.0;
rustup selects it from this directory. Run the following from the repository
root in an **x64 Visual Studio Developer PowerShell**, with `cl`, `dumpbin`,
`cmake`, `ninja`, `python`, `node`, and Windows `tar` available on PATH.

Build the pinned, unmodified Hermes source and then generate its receipt:

```powershell
./scripts/build-hermes-windows-vanilla.ps1
node ./scripts/hermes-input-receipt.mjs ./tools/hermes-vanilla/windows-x64
cargo build --locked --release -p ibex2 --features hermes --bin ibex2
```

The builder downloads the source if it is not cached. It installs headers and
static libraries under `tools/hermes-vanilla/windows-x64`, and the matching
compiler at `tools/hermes-vanilla/hermesc-windows-x64.exe`. The separate receipt
command checks the installed engine's symbols and records its engine/compiler
hashes. `ibex2 build` requires that receipt; building the executable alone does
not produce it. No custom Hermes INCLUDE or LIB environment settings are needed.
The build cache lives under `%LOCALAPPDATA%/Exact/hermes2-windows-vanilla`;
keep that path short, because some MSVC tools still limit generated path lengths.

For an existing vanilla install, set `IBEX2_VANILLA_HERMES_DIR` to the absolute
`windows-x64` directory and `IBEX2_HERMESC` to its matching compiler executable.
Leave both unset to use the repository-local installation above.

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
cargo build --locked --release -p ibex2 --no-default-features --features hermes --bin ibex2 --target-dir target/run-only
./target/run-only/release/ibex2.exe run ./target/windows-smoke/index.js --root ./target/windows-smoke --precompiled
```

The run-only executable still needs Hermes and its compiler during the Cargo
build, which precompiles its builtin bindings. Executing `--precompiled` needs
no compiler. Windows system/ICU libraries and the Microsoft C++ runtime remain
normal runtime dependencies. The supported engine target is x64 MSVC; other
Windows architectures and toolchains are not qualified here.

Design and maintenance conventions live in `llp/`, `AGENTS.md`, and `rules/`.
Run `node ./ref-check` after changing LLP references.
