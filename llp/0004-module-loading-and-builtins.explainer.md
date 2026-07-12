# LLP 0004: Module Loading and Builtins

**Type:** Explainer
**Status:** Draft
**Systems:** Runtime, Module Loader, Build
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Revised:** 2026-07-12 (armed resolution authenticates exact requester/target locator, package root, and whole-tree integrity before import or `require.resolve` disclosure — ENG-24234, ENG-24235, ENG-24241); 2026-07-08 (ENG-23505: incremental native zlib stream codec; ENG-23492: native TLS bridge for out-of-process endpoints; ENG-23526: Windows native TLS bridge enablement; ENG-23448: documented the loopback-only tls emulation); 2026-07-11 (ENG-23505: stream lifecycle and concatenated-member boundaries; LLP 0021 generated builtin-export security inventory — ENG-24145)
**Related:** LLP 0000; LLP 0002 (Host ABI); LLP 0005 (Build pipeline)

## Summary

Module loading has two layers: a **builtin registry** that maps bare/`node:`/
`bun:`/`exact:` specifiers to embedded JS sources, and an **on-disk resolver**
(oxc_resolver) for everything else. Both live in `src/module_loader/mod.rs`. The
builtin surface is data-driven: a manifest authored in TypeScript (`modules.ts`)
is compiled to a generated Rust table (`builtin_manifest.generated.rs`) and a
set of transformed builtin JS files, which the loader includes at compile time.
This document maps that resolution path and the builtin surface; how the
manifest/builtins are *generated and vendored* is [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md).

## Resolution order

`ModuleLoader::resolve_meta` (`src/module_loader/mod.rs:113-144`) resolves a
specifier in this order `[observed]`:

1. **Private package imports** (`#`-prefixed): resolved against the nearest
   `package.json` `imports` map (`src/module_loader/mod.rs:118-125, 146-161`).
2. **Builtin registry hit**: if the specifier is a key in the builtins map, it
   returns a `ModuleKind::Builtin` with the embedded source inline — no disk
   access (`src/module_loader/mod.rs:126-133`).
3. **Unknown `exact:`/`node:` guard**: a specifier that *starts with* `exact:`
   or `node:` but missed the registry is a hard error
   (`Unknown exact builtin` / `Unsupported node builtin`,
   `src/module_loader/mod.rs:135-141`).
   `[observed]` Note this only fires for specifiers the manifest did not
   register; registered ones like `node:fs` hit step 2.
4. **On-disk resolution** via oxc_resolver (`resolve_with_oxc`,
   `src/module_loader/mod.rs:143`).

In an armed runtime the C ABI carries the numeric requester module ID into both
full and metadata-only resolution. The Host resolves first, derives the target
principal from the most-specific authenticated root binding, and requires the
exact graph edge including locator and integrity. Package-relative imports must
remain inside that package's authenticated root; package-to-project-root and
absolute escapes are refused rather than reclassified as principal 0. The
resolver returns exact package name, locator, root, and whole-tree integrity,
and module registration accepts the mapping only when all fields match the
armed graph. Installed content is recomputed before project code, so replacing
a package body without changing its self-reported manifest cannot inherit its
reviewed authority.

`Host::resolve_module_meta` applies the same requester, import-edge, logical
`fs:list`/`fs:read`, root-object, and integrity checks but stops before
`load_source`, returning only path and authenticated package metadata.
`resolve_module` is `resolve_module_meta` plus source loading. This backs every
`require.resolve` route without turning metadata-only lookup into an import or
filesystem-disclosure bypass.

### The oxc_resolver configuration

The resolver is configured (`src/module_loader/mod.rs:67-105`) with
`[observed]`:

- Extensions `.js .cjs .mjs .ts .tsx .jsx .mts .cts .json`.
- Condition names `node, require, import, default`.
- TS `extension_alias` so `./x.js` in TS sources resolves to `./x.ts` on disk
  (`src/module_loader/mod.rs:88-98`), matching the TS NodeNext / Vite convention.

### Loading and on-the-fly transpilation

`load_source` reads the resolved file (`src/module_loader/mod.rs:163-186`) and
transpiles when needed: `.ts/.tsx/.jsx/.mts/.cts` always (`needs_transpile`,
`src/module_loader/mod.rs:188-193`),
and `.js/.mjs/.cjs` when the source uses syntax Hermes can't run directly —
async generators, `for await`, `using`, certain block-scoped loop closures —
which are down-leveled (`needs_js_downlevel` + the `source_needs_*` scanners,
`src/module_loader/mod.rs:195-228`). Transpilation runs through
`src/module_loader/transpile.rs`, which imports swc parser/codegen/transform
crates and lowers to CommonJS for the loader's synchronous `require()` chain
`[observed]` (`src/module_loader/transpile.rs:1-16, 20-34, 36-45`;
`Cargo.toml:56-64`).

## The builtin module surface

The builtin registry is built at runtime from a generated table:

- `src/module_loader/mod.rs:58` does
  `include!(concat!(env!("OUT_DIR"), "/builtin_manifest.generated.rs"))`,
  pulling in `BUILTIN_MANIFEST_REGISTRATIONS` (specifier -> source_key) and
  `BUILTIN_MANIFEST_DEBUG_ENTRIES` `[observed]`. The vendored snapshot shows
  the generated registration table and debug entries `[observed]`
  (`vendored-generated/builtin_manifest.generated.rs:1-5, 136-142`).
- `build_builtin_registry` (`src/module_loader/mod.rs:1047-1070`) resolves each registration's
  `source_key` to an embedded JS string via `generated_builtin_source` and
  builds the `HashMap<String, String>` of specifier -> source `[observed]`.

### One source, many specifiers

The manifest maps multiple public specifiers to one source. From the generated
table and its authoring file `[observed]`
(`vendored-generated/builtin_manifest.generated.rs:5-132`; `modules.ts:671-730`):

- `exact:*` are the native/runtime builtins (`exact:process`, `exact:crypto`,
  `exact:clipboard`, `exact:http`, `exact:sqlite`).
- Node compatibility: `node:fs`, `fs`, and `bun:fs` all map to `node_fs`;
  `node:crypto`/`crypto` map to `exact_crypto`; etc.
- Bun compatibility: `bun:sqlite` maps to the same source as `exact:sqlite`;
  `bun:fs` to `node_fs`.

So `node:`, `bun:`, and bare specifiers are deliberate aliases onto a shared set
of embedded sources `[observed]` (`modules.ts:693-699, 728-729`).
`[inferred: the single-source-many-aliases design lets Ibex present a Node- and
Bun-compatible import surface without maintaining separate implementations.]`

Not every registry entry is an advertised alias. Groups authored with both
`moduleBuiltin: false` and `bundleExternal: false` appear in neither
`module.builtinModules` nor the bundler's external set. Those flags do not,
however, remove an exact name from the generated registry or authenticated
import gate: a package whose policy lists the name can still resolve it. The
source inventory therefore retains such registry-only names as package-facing
probe entry points. `internal/fs/utils` is the stricter exception: it is also
named in `bootstrapInternalModules`, and the JS loader's `loadInternal()`
returns the bootstrap-owned object before consulting the generated manifest.
Consequently the inline `internal_fs_utils` manifest source cannot be evidenced
by importing that same-named specifier
`[observed]` (`modules.ts`; `src/engine/bootstrap/module-loader.js`;
`packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs`).

The LLP 0021 capability inventory uses the same source-key boundary: it records
each specifier alias, then statically inventories exported APIs once per source
key rather than treating `fs`, `node:fs`, and `bun:fs` as three independent
implementations. Export and prototype-member additions are source-derived and
participate in `check:capsec-registry`, so a new builtin API cannot silently
bypass classification `[observed]`
(`packages/ibex-devtools/src/scripts/capsec-surface-inventory.mjs`).

`exact:http` and `exact:sqlite` are not generated builtin files: their source
keys point at repo files under `packages/ibex-runtime-js`, and the generated
manifest includes those files directly from `CARGO_MANIFEST_DIR` `[observed]`
(`modules.ts:549-555`;
`vendored-generated/builtin_manifest.generated.rs:140-142, 271-272`).

The transformed builtin JS files are committed under
`vendored-generated/builtins/*.js` and authored under `src/builtins/*.js`
`[observed]` (`vendored-generated/README.md:11-27`). Two specifiers (`sqlite`,
`sea`) are reserved Node-only `[observed]` (`modules.ts:19-21`).

### The zlib builtin

The `zlib` builtin (`src/builtins/zlib.js`) has two native codec layers
`[observed]`:

- **One-shot sync hooks** (`__exactDeflateSync` / `__exactInflateSync`) back
  `gzipSync`, `deflateSync`, `gunzipSync`, `inflateSync`, raw variants, and
  JS-only harness fallback behavior.
- **Stateful stream hooks** (`__exactZlibCreate` / `__exactZlibWrite` /
  `__exactZlibParams` / `__exactZlibClose`) back `createGzip`,
  `createDeflate`, `createGunzip`, `createInflate`, and raw/unzip stream
  variants when the native bridge is present.

The stream hooks keep `z_stream` state natively and process each Transform
chunk without concatenating the full compressed or decompressed payload in JS.
`flush()` maps to zlib flush modes, `_final` maps to `Z_FINISH`, and
`params()` calls `deflateParams()` so compression-level changes affect
subsequent input without rebuilding a one-shot buffer `[observed]`.

The JS implementation still keeps the historical one-shot fallback for Bun
unit tests and embedded profiles that stub only the old hooks, but that path is
explicitly degraded: mid-stream `flush()` cannot emit a true zlib boundary
without the stateful native host functions `[observed]`.

The native state lives in `src/engine/hermes_runtime_zlib_streams.h`, registered
from both the non-Windows and Windows crypto host-function roots so zlib stream
parity follows the same platform availability as the existing zlib sync hooks
`[observed]`. Stream IDs are bound to the `ExactHermesRuntime` that created
them, and runtime destruction removes streams that JS did not explicitly
close. The incremental inflater also retains a partial gzip magic byte across
writes so concatenated members remain valid at every input-chunk boundary
`[observed]`.

### The tls builtin

The `tls` builtin (`src/builtins/tls.js`) has two client paths, chosen per
connection when the TCP connect completes `[observed]` (`tls.js` `connect()`):
an **in-process loopback emulation** (no wire cryptography) for peers that are
`tls.Server`s in the same process, and a **native TLS bridge** (ENG-23492)
performing real wire TLS for every other destination. Real TLS *serving*
remains out of scope — `tls.createServer` is loopback-emulation only.

#### The loopback emulation for in-process servers

What it emulates (ENG-23448):

- `tls.createServer` wraps a plain `net` server; listening servers register in
  an in-process registry keyed by their listening **port**
  (`_tlsServersByPort`).
- `tls.connect` opens a plain TCP connection. On connect it decides whether the
  peer is an **in-process** `tls.Server`: the destination host must be a
  loopback address (`localhost`, `127.0.0.0/8`, `::1`, the unspecified
  address; `_isLoopbackHost`) *and* a registered server must be listening on
  the destination port. Only then does it run the emulated handshake: cipher
  suites are negotiated from both sides' options, certificate material is
  parsed from the configured PEMs (or synthesized), and Node-shaped
  authorization/identity validation runs against it. Application data then
  flows as **plaintext TCP**, loopback-only.
- The Node-facing contract of the emulated socket (`authorized` /
  `authorizationError` under `rejectUnauthorized:false`, the
  `TLSSocket`-extends-`net.Socket` prototype chain, `renegotiate()` semantics
  including the TLSv1.3 failure mode) is pinned against real Node v25.9.0 in
  `tests/node_tls_builtins.rs`.

Known limits of the detection, accepted deliberately: the registry is
port-keyed, so an in-process server reached via a non-loopback address of
this machine (e.g. its LAN IP) is treated as out-of-process and gets a real
TLS handshake its emulated server cannot answer; TLS-over-IPC (`path:`
options) never participated in the registry and likewise takes the
bridge/fail-loud path.

#### The native TLS bridge for out-of-process endpoints (ENG-23492)

Every `tls.connect` destination that is not an in-process loopback
`tls.Server` — real HTTPS endpoints, databases, SMTP, and `https.js` client
sockets (which route through `tls.connect`) — gets **real wire TLS** through a
native engine:

- **Sans-IO rustls engine, no threads.** One rustls `ClientConnection` per
  socket lives in Rust (`src/engine/tls_bridge.rs`, `ibex_tls_*` extern "C"
  surface), exposed to JS through thin JSI shims
  (`src/engine/hermes_runtime_tls.cc`, `__exactTlsEngine*`) installed
  together with the TCP host functions from `installNetHostFunctions`
  `[observed]`. tls.js owns ALL I/O: it shovels ciphertext between the
  existing `net.Socket` and the engine, and plaintext between the engine and
  the `TLSSocket` wrapper — the existing async-connect/DNS/timeout machinery
  is reused and the bridge spawns **zero threads**, so the by-value-static
  pool exit() deadlock class (ENG-23471/ENG-23498) cannot occur here.
- **Hermetic dependency profile.** rustls uses the `ring` provider
  (cc-compiled; no cmake, no system OpenSSL) and `webpki-roots` bundles the
  Mozilla CA store, mirroring Node's bundled-roots philosophy and LLP 0005's
  hermetic-default pipeline. Node's `ca` option **replaces** the root store,
  as in Node.
- **Trust-evaluation split.** Chain trust (signatures, validity window,
  issuer path) is evaluated **natively**: the JS `_validatePeerAuthorization`
  is a fingerprint-list comparator and cannot verify signatures. A recording
  verifier wraps rustls's WebPKI verifier, always completes the handshake,
  and reports the verdict to JS — so `rejectUnauthorized:false` still gets
  `secureConnect` with `authorized:false` plus the real error code, and the
  strict default destroys the socket with that code. Hostname/identity
  checking stays in JS (`checkServerIdentity`, user-overridable per Node),
  fed the REAL peer DER chain parsed by the existing PEM/DER machinery,
  producing Node's exact `ERR_TLS_CERT_ALTNAME_INVALID` shape.
- **Oracle-pinned against Node v25.9.0** (measured, not remembered):
  `CERT_HAS_EXPIRED`, `DEPTH_ZERO_SELF_SIGNED_CERT`,
  `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, `ERR_TLS_CERT_ALTNAME_INVALID` (with
  `reason`/`host` properties and message shape),
  `ERR_SSL_WRONG_VERSION_NUMBER` for plaintext-speaking peers, `ECONNRESET`
  for mid-handshake hangups, `alpnProtocol === false` when nothing was
  negotiated, OpenSSL-style `valid_from`/`valid_to` strings
  ("Jul  2 07:13:53 2046 GMT"), and the measured SNI rule: **bare
  `tls.connect({host})` sends no SNI** — SNI goes out only when `servername`
  is explicit (ibex `https.js` always sets it). Pinned hermetically in
  `tests/node_tls_builtins.rs` by handshaking the `ibex` binary against an
  in-process rustls server over loopback.
- **Write hold until the path is chosen.** Consumers (http.js) write the
  request the moment `'connect'` fires — before any handshake. `connect()`
  holds application writes until the loopback-vs-bridge decision, then
  releases them into the raw socket (emulation) or the post-handshake
  encrypted queue (bridge); without the hold the request would leak as
  plaintext ahead of the ClientHello.

Rejected alternatives `[inferred: judgment call recorded at decision time]`:
platform TLS C APIs (Security.framework / system OpenSSL — non-hermetic on
Linux, deprecated SecureTransport on macOS, per-platform trust-evaluation
semantics, two implementations to keep Node-shaped); the optional vendored
`openssl-crypto` feature (off by default, so tls would work in only some
builds, violating the hermetic-default invariant); a native-owned TCP+TLS
thread pool like native fetch (duplicates net.js's async-connect machinery
and reintroduces the exit-deadlock class).

Known divergences, accepted deliberately: `getPeerCertificate(true)`'s
`issuerCertificate` chain reflects the chain **as presented on the wire**
(rustls `peer_certificates()`), while Node/OpenSSL completes it from the
local trust store; session resumption is not implemented
(`isSessionReused()` always false); TLS < 1.2 is not supported (rustls), so
requested minimums below 1.2 clamp to 1.2.

**Windows:** ENG-23526 enables the same native bridge through the Winsock TCP
host functions in `src/engine/hermes_runtime_platform_windows.cc`. The shared
Rust `tls_bridge` module, rustls dependencies, and `hermes_runtime_tls.cc` JSI
shims now compile on Windows, and `installNetHostFunctions` installs the
`__exactTlsEngine*` host functions after the Windows TCP globals. Windows has a
synchronous `tests/node_tls_builtins.rs` smoke that proves the TLS engine host
surface installs, constructs a rustls engine, and emits initial ClientHello
bytes. After the Windows CLI timer/output fixes (ENG-23639/ENG-23705), the full
timer-driven `tls.connect` oracle suite runs on Windows too; ENG-23716 also
routes option-carrying HTTPS requests through the socket/TLS path, so the HTTPS
roundtrip oracle is no longer platform-gated.

#### Fail-loud boundary without the bridge

In builds/harnesses where the `__exactTlsEngine*` host functions are absent
(the bun test harness, embedded hosts without net host functions),
`tls.connect` to an out-of-process peer destroys the socket with
`ERR_TLS_EMULATION_LOOPBACK_ONLY` instead of fabricating a handshake. Before
ENG-23448 it emitted an immediate `secureConnect` with `authorized=true` and a
synthetic peer certificate — i.e. it reported a secure, authorized connection
over cleartext while the remote server stalled waiting for a ClientHello.
Refusing loudly is the LLP 0006 "honest reduced profile" behavior.

## How the runtime consumes this

- At **resolution** time, the Rust loader returns the inline builtin source (no
  bytecode here) `[observed]` (`src/module_loader/mod.rs:126-133`).
- The C++ engine reaches the loader through `__exactModuleResolve` /
  `__exactNativeModuleResolve` JSI functions, which call the Rust
  `ex_host_module_resolve` ABI (`src/engine/hermes_runtime.cc:1191-1193`;
  `src/host/abi.rs:730-779`) `[observed]`. The Rust side returns a JSON object
  carrying `id`, `kind` (`builtin`/`cjs`/`json`/`esm`), `path`, and `source`
  `[observed]` (`src/host/abi.rs:758-769`).
- `require.resolve` instead uses the metadata-only bridge
  `__exactModuleResolveMeta` / `__exactNativeModuleResolveMeta` ->
  `ex_host_module_resolve_meta`, which returns the identical record minus
  `source` so no body is read/transpiled (ENG-23007) `[observed]`. The loader
  prefers it and falls back to the full bridge when the meta binding is absent
  (older embedded runtimes / tests).
- The JS module-loader bootstrap (`src/engine/bootstrap/module-loader.js`)
  drives `require`/`import` against this resolve function `[observed]`
  (`src/engine/hermes_bootstrap.cc:193-204`).
  The C++ installer comments that the native alias survives a dev-server
  hot-reload override of the canonical resolver `[observed]`
  (`src/engine/hermes_runtime.cc:1186-1190`). `[inferred: registering both names
  keeps a stable native escape hatch while allowing development overrides.]`

## Boundaries / open questions

- The manifest and transformed builtins are **generated artifacts**, vendored
  for hermetic builds; editing the runtime surface means editing `modules.ts` /
  `src/builtins` and regenerating, not editing `vendored-generated/` —
  see [LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md).
- ESM/CJS interop and full Node package resolution are described in-code as
  "implemented incrementally (see TODOs)" `[observed]`
  (`src/module_loader/mod.rs:3-5`); the
  resolver is called "minimal." Exact gaps are not enumerated here.
