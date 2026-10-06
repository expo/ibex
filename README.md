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

Linux Intl is a second, independent opt-in. Enable `ibex2/intl` (or the
forwarding `ibex2-runtime/intl` feature) to compile the Intl scripts and C++
shims against the small English ICU data tier. The `intl` feature implies
`bindings`, but neither crate enables it by default. Consumers that need ICU's
other locales select the additional `intl-all-locales` feature:

```sh
cargo test -p ibex2-runtime --no-default-features --features intl
cargo test -p ibex2-runtime --no-default-features --features intl-all-locales
```

`Groups::INTL` keeps its stable bit so stored group masks do not change, but
group validation refuses it unless the build is Linux or Windows with
`ibex2/intl`.
Without that feature it is absent from both `Groups::DEFAULT` and
`Groups::ALL`; with it, the normal Linux profile installs it. The observable
engine fallback when the group is not installed is platform-specific:

| build / installed group | `typeof Intl` | `(1234.5).toLocaleString("de-DE")` | resolved locale |
|---|---:|---:|---:|
| Linux, `intl` off (or group omitted) | `"undefined"` | `"1234.5"` | — |
| Linux, `intl` on and `INTL` installed | `"object"` | `"1,234.5"` | `"en-US"` |
| Linux, `intl-all-locales` on and `INTL` installed | `"object"` | `"1.234,5"` | `"de-DE"` |
| Apple, `INTL` unavailable | `"object"` | `"1.234,5"` | OS supplied |

Linux Hermes is built with engine Intl disabled and Unicode-lite disabled. Its
basic Unicode backend always links ICU 74.2 code plus the receipt-bound base
archive, unchanged from v3. No data was added to that always-linked tier: the
existing `en_US_POSIX` parent is required by Hermes when the process locale is
`C`. `intl` swaps in the English archive and adds Ibex's selected ECMA-402
surface; `intl-all-locales` swaps in full locale data. On the English tier
`supportedLocalesOf` reports only
available English requests, and an unsupported request such as `de-DE`
resolves to the available default `en-US` locale instead of formatting with
German-looking root fallback. It does not expose German or other absent locale
data. Apple Hermes retains
its operating-system-backed native implementation, so omitting Ibex's
Linux-only group does not remove Apple's engine-owned `Intl`. Every Linux v4
bundle carries matching ICU headers, shared code archives, and all three data
variants, so no build compiles or links against a different system ICU.

Windows Intl uses the same `intl` feature and `INTL` group, backed by the
operating system's `icu.dll` rather than a bundled ICU. No ICU data is
added; the release CLI grows by 243,712 bytes (238 KiB). The shims are
compiled against the Windows 10 2004 API, so that is the floor for `INTL`. Nothing links
against `icu.dll`: the few entry points only it exports are bound once, as
function pointers, from System32's `icu.dll` loaded by full path, and
everything else goes through the `icuuc`/`icuin` imports Hermes already has.
An `intl` binary therefore still starts on an older Windows and refuses `INTL`
with a clear error (the `ibex2` CLI runs without Intl there and says why).
`ibex2::bindings::os_icu()` reports the observed ICU, Unicode, CLDR, and
tzdata versions. They are unpinned facts about the machine running the
binary: Windows Update changes them, tzdata can be years old, and Microsoft
modifies CLDR (for example, en-US time styles put an ASCII space before
AM/PM). There is no `LINKED_ICU_DATA_*` identity on Windows;
`hermes_lean_sys::LINKED_OS_ICU` names the DLL instead. An embedder that links
`ibex2/intl` into its own executable needs no linker flags. On Windows:

```powershell
cargo test -p ibex2 --features bindings,intl
cargo test -p ibex2-runtime --features intl
```

`scripts/check-ibex2-features.sh`, which covers `ibex2-runtime --features
intl` among its configurations, also runs on Windows under Git for Windows's
`usr\bin\bash.exe`. Put MSVC's `link.exe` ahead of Git's `/usr/bin/link` on
`PATH` (append `C:\Program Files\Git\usr\bin` to an MSVC developer
environment rather than using the `bin\bash.exe` wrapper). See LLP 0057.000
§5.1.1.

`hermes-lean-sys` resolves vanilla Hermes in this order: a complete local
install selected by `HERMES_LEAN_SYS_DIR`; this checkout's layout when it
actually contains the Cargo target (`ios/Frameworks-vanilla` for macOS,
`tvos/Frameworks-vanilla` for `aarch64-apple-tvos`, and
`tvos-simulator/Frameworks-vanilla` for `aarch64-apple-tvos-sim`); then the
SHA-256-pinned `hermes-vanilla-d412d3bd8512-v4` release bundle for the Cargo
target. tvOS has a device bundle and an arm64-only Simulator bundle;
`x86_64-apple-tvos` (the Intel tvOS Simulator) has no bundle and needs
`HERMES_LEAN_SYS_DIR`. In
particular, an iOS cross build does not select the repository's macOS archive;
it falls through to its target bundle or uses `HERMES_LEAN_SYS_DIR`.

There are two supported release-bundle modes. In the default automatic mode,
a Cargo build downloads a missing pinned bundle and caches it. For a build
that must never access the network, install the host bundle and any cross
targets once, before enabling offline mode. Use the installer from the same
Ibex source revision as `hermes-lean-sys`; the build error prints its absolute
manifest path, so the command works from a consumer directory for both Cargo
Git checkouts and vendored/path copies. The pins are identified by the release
tag and the SHA-256 the build error prints.
The installer is the explicit online step, so it ignores `HERMES_LEAN_SYS_OFFLINE`: a consumer that forces offline mode in `.cargo/config.toml` `[env]` can still run it. A vendored copy must include `crates/hermes-lean-sys-installer` beside `hermes-lean-sys` (same Ibex revision); without it, the build error says so instead of printing a command.
Install with:

```sh
# Host only.
cargo run --manifest-path \
  ../ibex/crates/hermes-lean-sys-installer/Cargo.toml --

# Host, plus one or more cross targets.
cargo run --manifest-path \
  ../ibex/crates/hermes-lean-sys-installer/Cargo.toml -- \
  --target aarch64-apple-ios \
  --target aarch64-apple-ios-sim

HERMES_LEAN_SYS_OFFLINE=1 cargo build --locked -p ibex2-runtime
```

Both paths use the same implementation. They verify the compiled-in archive
SHA-256 before extraction, reject unsafe tar entries, retain the archive,
compare its per-file manifest with the extracted tree, and validate the
canonical receipt, selected VM, compiler digest, and HBC version. The
installer always includes the host bundle because a cross build uses its
authenticated `hermesc`. A downloaded bundle remains in a private staging
directory until every applicable check, including host/target HBC pairing,
succeeds; only then is it atomically made visible as a cache entry.

Bundles are cached at
`$CARGO_HOME/hermes-lean-sys/<tag>/<archive-sha256>/` (`$HOME/.cargo` when
`CARGO_HOME` is unset). Set `CARGO_NET_OFFLINE=true` or
`HERMES_LEAN_SYS_OFFLINE=1` to forbid network access; an already verified
cache entry or `HERMES_LEAN_SYS_DIR` is then required. Mirrors can set
`HERMES_LEAN_SYS_MIRROR` to a base URL that serves `<tag>/<asset>`. The pinned
digest is enforced for every origin. Cross builds select `hermesc` for the
host, require its HBC version to match the target receipt, and require every
available receipt to describe the exact engine archive and compiler selected
by the build.

For repositories such as exact2 that prohibit downloads from `build.rs`, the
recommended checked-in Cargo configuration is explicit because Cargo's
`[net] offline` setting does not itself set a build-script environment
variable:

```toml
[env]
HERMES_LEAN_SYS_OFFLINE = { value = "1", force = true }
```

Run the manifest-path command printed by an offline cache miss before enabling
this setting. It names the exact release tag, asset digest, and Ibex pin-set
revision compiled into the dependency. Configure Cargo's separate `[net]`
`offline = true` setting if Rust dependencies must also be resolved without
the network.

Each v4 bundle contains both source-capable `hermesvm_a` and bytecode-only
`hermesvmlean_a`. Enable exactly one `hermes-lean-sys` link feature: `link`
for the full VM or `link-lean` for lean. Enabling both is a compile-time error.
On Linux both VM features imply the independent `icu` feature, which is the
one owner of ICU link lines and selects the v3-compatible base data.
`ibex2/intl` enables `icu-en-data`, swapping in `libicudata-en.a`;
`ibex2/intl-all-locales` enables
`icu-full-data`, swapping in `libicudata-full.a` while reusing the ICU code
archives. Feature precedence is full, then English, then base. A Hermes
embedder may select either data feature directly without Ibex's Intl shims;
both remain valid for the engine's basic Unicode backend.
The full identity remains `DEP_HERMES_LEAN_ARCHIVE` /
`DEP_HERMES_LEAN_ENGINE_DIGEST`; lean is
`DEP_HERMES_LEAN_LEAN_ARCHIVE` / `DEP_HERMES_LEAN_LEAN_ENGINE_DIGEST`.
When one link feature is active, `DEP_HERMES_LEAN_LINKED_ARCHIVE` and
`DEP_HERMES_LEAN_LINKED_ENGINE_DIGEST` name the source archive selected for the
process and its digest (the receipt-authenticated identity for a bundle).
For the universal iOS Simulator bundle, `hermes-lean-sys` authenticates every
static archive in the link closure, uses Xcode's `lipo` to thin only the fat
ones to Cargo's target architecture in `OUT_DIR`, and links those derivatives.
Thin device and arm64-only tvOS Simulator archives are linked in place. Missing
`lipo` is an Xcode command-line-tools installation error. The selected VM's
actual derivative and its SHA-256 are exported separately as
`DEP_HERMES_LEAN_LINKED_ENGINE_DERIVATIVE_ARCHIVE` and
`DEP_HERMES_LEAN_LINKED_ENGINE_DERIVATIVE_DIGEST`; the receipt identity above
does not change.
On Linux `DEP_HERMES_LEAN_LINKED_ICU_DATA_ARCHIVE` and
`DEP_HERMES_LEAN_LINKED_ICU_DATA_DIGEST` name the exact selected data variant;
this is the data-variant half of R-e and is deliberately separate from the VM
digest. All three available data identities are exported in every resolver-v2
context. The bindings door exposes them as `ICU_DATA_*`, `ICU_EN_DATA_*`, and
`ICU_FULL_DATA_*`, but exposes no selected identity because it links none.
Only the linking instance's `LINKED_ICU_DATA_*` says what the process links.
The Rust constants are `ARCHIVE`, `ENGINE_DIGEST`, `LEAN_ARCHIVE`,
`LEAN_ENGINE_DIGEST`, `LINKED_ARCHIVE`, `LINKED_ENGINE_DIGEST`,
`LINKED_ENGINE_DERIVATIVE_ARCHIVE`, and `LINKED_ENGINE_DERIVATIVE_DIGEST`.

`ibex2::bindings::ENGINE_DIGEST` continues to name the full archive;
`ibex2::bindings::LEAN_ENGINE_DIGEST` is the identity a lean embedder checks.
Both VMs consume one HBC version, asserted while binding bytecode is built.
Whenever an install has a receipt and a lean archive, the receipt's archive
manifest authenticates the lean bytes in every feature context before any lean
metadata is exported. A receipt that does not bind those bytes is refused.
Old local layouts without a lean archive export no lean path, digest, or HBC
version; they continue to support full-VM builds and fail with a targeted
message only when `link-lean` is requested. The
end-to-end lean proof can be run against a complete v4 bundle:

```sh
HERMES_LEAN_SYS_DIR=/path/to/extracted-v4-bundle \
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
