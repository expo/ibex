# LLP 0004: Module Loading and Builtins

**Type:** Explainer
**Status:** Draft
**Systems:** Runtime, Module Loader, Build
**Author:** Charlie Cheever / Claude (Tuft)
**Date:** 2026-06-13
**Revised:** 2026-07-19 (bounds the `dns/promises` cross-source export projection to a canonical two-source AST review and keeps its 45 derived callable rows as residual presence evidence); 2026-07-17 (reconciled the shipped typed resolver and advertised-target native-runner route: import/require condition sets are separate; file-backed metadata resolution does not acquire, parse, transpile, or disclose executable source, while trusted integrity hashing may read raw bytes and builtin metadata retains embedded source internally; bootstrap resolution is compatibility-only); 2026-07-15 (ENG-25066 made authenticated ordinary ESM use the native module graph by default; unsupported interop retains the bounded 0.1 legacy path); 2026-07-13 (retained native-wrapper owner isolation and retry-safe release across filesystem, network, HTTP, WebSocket, SQLite, zlib, and TLS; TLS transport identity, bounded state, honest loopback authentication, strict client-identity verification, exact-size native reads, and fail-loud host errors); 2026-07-12 (armed resolution authenticates exact requester/target locator, package root, and whole-tree integrity before import or `require.resolve` disclosure — ENG-24234, ENG-24235, ENG-24241; desktop TLS accepts password-protected PKCS#12 and encrypted PKCS#8 client identities — ENG-24272); 2026-07-08 (ENG-23505: incremental native zlib stream codec; ENG-23492: native TLS bridge for out-of-process endpoints; ENG-23526: Windows native TLS bridge enablement; ENG-23448: documented the loopback-only tls emulation); 2026-07-11 (ENG-23505: stream lifecycle and concatenated-member boundaries; LLP 0021 generated builtin-export security inventory — ENG-24145)
**Related:** LLP 0000; LLP 0002 (Host ABI); LLP 0005 (Build pipeline); LLP 0023 (source identity); LLP 0026 (module runner); LLP 0027 (artifact wire and interop)

## Summary

Module loading shares two mechanisms: a **builtin registry** that maps
bare/`node:`/`bun:`/`exact:` specifiers to embedded JS sources, and an
**on-disk resolver** (`oxc_resolver`) for everything else. Both live in
`src/module_loader/mod.rs`. On advertised native-runner targets, the ordinary
authenticated ESM path reaches those mechanisms through the Host-authenticated
typed graph operations adopted by
[LLP 0026](./0026-esm-module-runner.rfc.md). Explicitly unsupported shapes, and
unadvertised targets while the 0.1 window remains open, use the same underlying
resolver through the bounded compatibility loader's JavaScript bridge. The
builtin surface is data-driven: a manifest authored in TypeScript
(`modules.ts`) is compiled to a generated Rust table
(`builtin_manifest.generated.rs`) and a set of transformed builtin JS files,
which the loader includes at compile time.

This Explainer maps the shared resolver/builtin mechanics and their shipped
routing. LLP 0026 owns the typed-resolution, module-graph, linking, and
evaluation architecture; LLPs 0014, 0021, and 0023 own authorization ordering
and source identity. How the manifest/builtins are *generated and vendored* is
[LLP 0005](./0005-build-pipeline-and-hermetic-default.explainer.md).

## Resolution order

The unarmed/diagnostic `ModuleLoader::resolve_meta_typed` route resolves a
specifier in this order `[observed]` (`src/module_loader/mod.rs`,
`resolve_meta_typed`):

1. **Private package imports** (`#`-prefixed): resolved against the nearest
   `package.json` `imports` map.
2. **Builtin registry hit**: if the specifier is a key in the builtins map, it
   returns a `ModuleKind::Builtin` with the embedded source inline — no disk
   access.
3. **Unknown `exact:`/`node:` guard**: a specifier that *starts with* `exact:`
   or `node:` but missed the registry is a hard error
   (`Unknown exact builtin` / `Unsupported node builtin`).
   `[observed]` Note this only fires for specifiers the manifest did not
   register; registered ones like `node:fs` hit step 2.
4. **On-disk resolution** via oxc_resolver (`resolve_with_oxc`).

Armed on-disk native-graph and compatibility callers do not enter that exact
method route. The C ABI or native graph carries the authenticated requester and
`ResolutionKind` into the Host. For file and package targets, the Host selects
`resolve_meta_authenticated_typed` or the authenticated bound-package variant.
Registered builtin requests instead take the in-memory `resolve_meta_typed`
branch after Host import preflight; they do not enter Oxc or the filesystem.
Before Oxc can probe an on-disk request, the Host authenticates the requester
and constrains the lookup to the exact graph edge and retained binding object,
including locator and integrity. Package-relative imports must remain inside that package's
authenticated root; package-to-project-root and absolute escapes are refused
rather than reclassified as principal 0. The resolver returns exact package
name, locator, root, and whole-tree integrity, and module registration accepts
the mapping only when all fields match the armed graph. Installed content is
recomputed before project code, so replacing a package body without changing
its self-reported manifest cannot inherit its reviewed authority.

For file-backed targets, the Host's typed metadata-resolution operations apply
the same requester, import-edge, logical `fs:list`/`fs:read`, root-object, and
integrity checks but do not acquire, decode, parse, transpile, or return
executable module source. Full module resolution shares its
requester/graph/root authentication and then uses the executable source-loading
path. Package-facing `require.resolve` therefore does not turn lookup into an
import or filesystem-disclosure bypass: it authorizes `fs:list` at requested
before resolver probing, then binds the canonical final and parent objects at
discovery and authorizes `fs:read` at commit and repeat before returning the
path. Cache-hot lookups repeat all four stages, and a symlink is classified by
its canonical target binding rather than its lexical spelling. For an
authenticated package target, Repeat may read and hash raw installed bytes as
an integrity witness; it does not return those bytes as executable source.
Registered builtins have no file path and therefore do not run these filesystem
stages.

### The oxc_resolver configuration

The resolver's common configuration has `[observed]`:

- Extensions `.js .cjs .mjs .ts .tsx .jsx .mts .cts .json`.
- Distinct canonical condition membership sets selected by `ResolutionKind`:
  ESM static import, dynamic import, and entry use `{import, node}`; CommonJS
  require uses `{node, require}`. `default` is not an active condition —
  for Oxc conditional exports and armed package `#imports`, package-object key
  order remains authoritative and `default` is the unconditional branch. The
  unarmed/diagnostic private-import helper remains a compatibility divergence:
  it tries the active condition names in their stored order and then `default`.
- TS `extension_alias` so `./x.js` in TS sources resolves to `./x.ts` on disk,
  matching the TS NodeNext / Vite convention (`module_resolve_options`).

Armed resolution additionally disables `NODE_PATH` and gives Oxc only a
descriptor-backed filesystem plus authenticated captured manifest bytes. For
file-backed requests, Oxc may classify a module from extension or manifest data
but cannot open its executable body; acquisition, parsing, transpilation, and
disclosure remain later authorized operations. Registered builtin metadata is
the explicit in-memory exception: it already carries the embedded source
internally, although the metadata-only ABI does not serialize that source.

### Loading and on-the-fly transpilation

For ordinary ESM on advertised native-runner targets, the default path resolves
and authenticates the complete reachable graph, produces Oxc-backed
`ModuleArtifact`s, and links native module records on Hermes. Warm loads may
admit the corresponding prepared graph and carriers from the Rolldown cache
only after reconstructing the authenticated source graph; that cache is a
source-mode acceleration, not yet parse-free prepared production startup. This
path does not call the bootstrap `transformEsmToCjs` scanner. Authorization,
parse, link, and evaluation failures fail closed.

The file-at-a-time behavior below remains the compatibility path for explicitly
unsupported CommonJS/JSON/builtin interop, authored call-time dynamic import,
and unadvertised target tuples while the window remains open. It is bounded to the
Ibex 0.1 line and can be disabled with `IBEX_LEGACY_MODULE_LOADER=0`; an
unadvertised target refuses after that window closes.

`load_source` reads the resolved file and always sends
`.ts/.tsx/.jsx/.mts/.cts` through the selected in-process transform engine
(`needs_transpile`). `.js/.mjs/.cjs` enters that Rust transform only when the
`needs_js_downlevel` scanners select async generators, `for await`, `using`, or
certain block-scoped loop closures. Ordinary JavaScript — including ordinary
ESM-heavy JavaScript — is served unchanged by Rust `[observed]`
(`src/module_loader/mod.rs`, `load_module_source`, `needs_transpile`, and
`needs_js_downlevel`). The legacy in-process engine is SWC and lowers its
selected inputs to CommonJS, but it applies no configured target-compatibility
pass; describing that path generically as target "down-leveling" was therefore
too broad `[observed]` (`src/module_loader/transpile.rs`,
`transpile_with_swc`). On that legacy path, the embedded bootstrap's
`transformEsmToCjs` scanner rewrites ESM syntax file by file before the
synchronous `require()`-shaped evaluator sees it `[observed]`
(`src/engine/bootstrap/module-loader.js`). The implementation-neutral current
path inventory and Node/Hermes divergence baseline live under
`tests/fixtures/module-semantics/`.

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

`dns/promises` is one narrow, review-bound carrier exception to ordinary
single-source export discovery. Its generated source exports the exact
`dns.promises` object supplied by `node_dns`; the inventory therefore projects
42 callable carrier rows from the provider's reviewed top-level, Resolver
prototype, and nested Resolver `_handle` shapes. It also records the same three
nested `_handle` callables on the provider's exported Resolver instance shape,
for 45 derived rows total. The proof requires the exact carrier/provider source
keys and paths, their exact forwarding and construction structure, and a pinned
canonical AST digest over both complete source files. Location and comment
changes do not perturb that digest, but any semantic AST change fails discovery
until the two-source shape is deliberately reviewed again. These rows prove
only callable presence and source ownership: their enforcement routes retain
an explicit cross-source or constructor-instance ambiguity and no execution
terminal, so LLP 0021 WP10 cannot promote them without dedicated bounded
carrier/provider recipes.

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

### Retained native-wrapper invariant

Builtin objects may be retained and invoked after control crosses a package
principal boundary. A forgeable numeric descriptor or a caller-writable
underscore field is therefore not authority. Filesystem `FileHandle`, net and
dgram sockets/listeners, native HTTP responses/listeners, WebSockets, SQLite
databases/statements, zlib streams, and TLS engines keep their authoritative
selector and terminal lifecycle in module-private `WeakMap` or closure state;
native registries independently bind the selector to its runtime nonce and
creating principal `[observed]`.

Every public operation that can enqueue work authenticates synchronously before
mutating a queue, and deferred work retains an owner/generation stamp rather
than inheriting the principal of a later timer, poll, or drain callback. Release
is ordered native-first: `close`, `destroy`, `abort`, `finalize`, and EOF commit
JS terminal state or forget the selector only after native ownership validation
and release succeed. A rejected foreign call consequently leaves the wrapper
and selector retryable by the real owner. Listener poll loops likewise capture
the exact selector generation so a callback from a closed listener cannot be
reattributed to a subsequently reopened listener `[observed]`.

WebSocket wrappers also mint a runtime/principal owner stamp whose lifetime is
independent of transport teardown. Public metadata and `on*` attributes,
EventTarget listener maps, generic-stream request records, and their saved
base-prototype entry points authenticate that stamp before exposing, retaining,
or converting caller data. Authority-bearing readable/writable lifecycle,
controller, queue, and reader/writer compatibility fields are authenticated
projections; their deferred queues contain only opaque one-shot identities,
while inbound and outbound payloads remain module-private until an admitted
read or write consumes them. Native callbacks dispatch through captured
methods, so shadowing `dispatchEvent`, a reader method, or a sink algorithm
cannot intercept owner traffic or recover an admitted payload `[observed]`.

Compatibility properties that remain observable (for example `FileHandle.fd`)
are projections, not selector storage; writes are rejected or inert. The CapSec
surface census continues to classify these accessors explicitly even when
their implementation moves from direct fields to dynamically installed private
state `[observed]`.

### The zlib builtin

The `zlib` builtin (`src/builtins/zlib.js`) has two native codec layers
`[observed]`:

- **One-shot sync hooks** (`__exactDeflateSync` / `__exactInflateSync`) back
  `gzipSync`, `deflateSync`, `gunzipSync`, `inflateSync`, raw variants, and
  JS-only harness fallback behavior.
- **Stateful stream hooks** (`__exactZlibCreate` / `__exactZlibWrite` /
  `__exactZlibParams` / `__exactZlibCheckOwner` / `__exactZlibClose`) back `createGzip`,
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
`[observed]`. Stream IDs are kept in module-private JS storage and bound
natively to both the runtime nonce and creating package principal; every
write, parameter change, and close validates those identities regardless of
capability posture. Runtime destruction removes streams that JS did not
explicitly close. The incremental inflater also retains a partial gzip magic
byte across writes so concatenated members remain valid at every input-chunk
boundary `[observed]`.

Decompression is allocation-bounded at the native choke point: the JS wrapper
passes the decoder's remaining `maxOutputLength`, and one-shot zlib/Brotli plus
incremental zlib loops check that budget before growing their output vector.
Every host call also has a fixed 64 MiB ceiling when no smaller budget is
configured, so a compressed bomb cannot allocate until exhaustion before JS
gets a chance to validate the result. A future zstd bridge must accept the same
budget; the current runtime exposes no native zstd decoder. Gzip accepts
concatenated members and zero padding, but rejects any other trailing bytes,
including garbage arriving in a later stream write. The stream core retains the zlib owner guard in a
private `WeakMap` and runs it from inherited readable, writable, listener, and
lifecycle paths, so calling a saved `EventEmitter`, `Readable`, `Writable`,
`Transform`, or `Stream` prototype method cannot enqueue work or observe owner
output under another principal. Guarded transforms project their listener maps,
queues, and callback/dispatch slots through non-configurable owner-checked
properties, preventing a foreign holder from planting `_transform`, `emit`, or
`push` code for a later owner-context call. Zlib wrappers retain a separate
runtime/principal identity stamp after the native codec selector closes, so
those projections do not reopen during terminal cleanup or reset `[observed]`.

### The tls builtin

The `tls` builtin (`src/builtins/tls.js`) has two client paths, chosen per
connection when the TCP connect completes `[observed]` (`tls.js` `connect()`):
an **in-process loopback emulation** (no wire cryptography) for peers that are
`tls.Server`s in the same process, and a **native TLS bridge** (ENG-23492)
performing real wire TLS for every other destination. Real TLS *serving*
remains out of scope — `tls.createServer` is loopback-emulation only.

#### The loopback emulation for in-process servers

What it emulates (ENG-23448):

- `tls.createServer` wraps a plain `net` server. The in-process registry is
  port-indexed for lookup, but every entry records the listener's normalized
  address and family. Selection prefers an exact address, then a same-family
  wildcard; the IPv6-wildcard dual-stack fallback is allowed only when no IPv4
  listener can collide. This prevents same-port IPv4/IPv6 listeners from
  cross-pairing (`_registerTlsServer`, `_lookupTlsServer`) `[observed]`.
- `tls.connect` opens a plain TCP connection. Before forwarding its `connect`
  event to user code, `tls.js` freezes the actual connected transport's local
  and remote address/family/port tuple in a module-private `WeakMap`. Loopback
  eligibility uses that snapshot rather than caller-writable socket metadata:
  the remote endpoint must be loopback and match the registered listener, and
  the client and accepted server socket must then match on the complete
  normalized local-to-remote endpoint tuple (`_captureTlsTransportIdentity`,
  `_tlsClientConnectionKey`, `_tlsServerConnectionKey`) `[observed]`.
- Caller-supplied `options.socket` transports are deliberately ineligible for
  loopback emulation. Their public metadata cannot authenticate which accepted
  transport they correspond to; they therefore take the real native-bridge (or
  fail-loud reduced-profile) path even when their apparent endpoint names a
  local registered server `[observed]`.
- Once paired, the emulation negotiates protocol/cipher metadata and parses
  configured certificate material, but application data flows as **plaintext
  TCP** and no TLS record exchange, signature, or proof of key possession
  occurs. The strict client default therefore fails with
  `ERR_TLS_LOOPBACK_AUTH_UNSUPPORTED`; `rejectUnauthorized:false` may use the
  compatibility transport but is always published as `authorized:false` with
  that authorization error. Likewise, a requested synthetic client identity
  is never reported as authenticated: a strict mTLS server rejects it, while a
  permissive server may publish it only with `authorized:false` `[observed]`.
- The Node-facing contract of the emulated socket (`authorized` /
  `authorizationError` under `rejectUnauthorized:false`, the
  `TLSSocket`-extends-`net.Socket` prototype chain, `renegotiate()` semantics
  including the TLSv1.3 failure mode) is pinned against real Node v25.9.0 in
  `tests/node_tls_builtins.rs`.
- **Private, same-principal state.** Server state, transport snapshots, native
  selectors/tokens, and all authority-bearing `TLSSocket` control fields live
  in module-private `WeakMap`s. Forged public `_tls*` / `_bridge*` lookalikes
  cannot influence them; control-plane accessors reject external reads or
  writes, while event storage and Node-visible state remain owner-checked.
  Native owner tokens bind each server
  and socket to its runtime nonce and creating package principal. Registry
  lookup and every stateful callback/handoff require that owner, so a server
  registered by another principal is not an emulation candidate `[observed]`.
- **Server-owned bounded handoff.** A client may only deposit a handshake
  message; it never calls server-owned socket methods or emits server events.
  A short-interval pump running as the server owner applies the message and
  emits `secureConnection` / `tlsClientError`. Both unmatched accepted sockets
  and unmatched handshake messages are capped at 1,024 per server and expire
  after 30 seconds; overflow fails with `ERR_TLS_HANDSHAKE_QUEUE_FULL`, and
  expiry fails with `ERR_TLS_HANDSHAKE_TIMEOUT` `[observed]`.
- The PEM/DER certificate parser shared by emulation and the native peer-chain
  adapter returns clones and keeps only a bounded LRU: at most 256 entries and
  approximately 4 MiB, with entries larger than 1 MiB bypassing the cache
  (`_certificateParseCache`, `_cacheParsedCertificate`) `[observed]`.

Known limits of the detection, accepted deliberately: an in-process server
reached via a non-loopback address of this machine (for example its LAN IP), a
TLS-over-IPC `path:`, or a caller-supplied transport is treated as a real
out-of-process TLS peer and takes the bridge/fail-loud path. The emulation is a
narrow same-principal compatibility mechanism, not a claim that local plaintext
is cryptographically secure.

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
- **Pending-length native reads.** Before allocating a JSI `ArrayBuffer`, the
  C++ shims query Rust for the exact pending ciphertext count or the next
  contiguous plaintext chunk length. Empty polls, EOF, and errors allocate no
  payload buffer; successful reads allocate only `min(pending, maxBytes)` and
  let rustls fill that buffer directly. The ciphertext count uses a
  non-consuming writer probe, so avoiding the former speculative 64 KiB
  allocation does not drain or reorder records (`ibex_tls_tls_bytes_pending`,
  `ibex_tls_plaintext_bytes_pending`) `[observed]`.
- **Hermetic dependency profile.** rustls uses the `ring` provider for every
  wire operation and `webpki-roots` bundles the Mozilla CA store, mirroring
  Node's bundled-roots philosophy. Desktop builds use vendored OpenSSL only as
  a bounded decoder for the PKCS#12 and encrypted-PKCS#8 client-identity
  containers required by Node's `pfx` / `passphrase` options; no system TLS
  implementation or trust behavior enters the wire path. PFX input is capped
  at 16 MiB before JS base64/JSON expansion and independently at the native
  decoder; its base64 and DER envelopes must be canonical. Node's `ca` option
  **replaces** the root store, as in Node. The iOS reduced profile rejects
  those two container formats explicitly until a hermetic iOS decoder lands.
- **Trust-evaluation split with pre-disclosure mTLS abort.** Chain trust
  (signatures, validity window, issuer path) is evaluated **natively**: the JS
  `_validatePeerAuthorization` is a fingerprint-list comparator and cannot
  verify signatures. Ordinarily the recording WebPKI verifier reports its
  verdict to JS while allowing the wire handshake to finish: this lets
  `rejectUnauthorized:false` publish `authorized:false` plus the real error,
  while a strict client without an identity destroys the socket with that
  result. A strict client configured with `cert`/`key` or `pfx` is different:
  any WebPKI rejection aborts natively before rustls can answer a server
  `CertificateRequest` with the client's certificate and proof. Because a
  user-defined `checkServerIdentity` cannot run before that disclosure point,
  strict client identities reject that combination explicitly. Outside that
  pre-disclosure profile, hostname/identity checking remains in JS, fed the
  REAL peer DER chain and producing Node's
  `ERR_TLS_CERT_ALTNAME_INVALID` shape `[observed]`.
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
- **Guarded, ordered receive handoff.** An already-connected or custom raw
  socket can deliver bytes, EOF, or close before the deferred path decision,
  including reentrantly while native output is written. `tls.js` retains a
  bounded ordered event queue and keeps the raw input paused until every older
  event has entered the selected path. Bridge events become ciphertext/EOF;
  any pre-selection event on the plaintext loopback-emulation path fails
  closed rather than exposing unauthenticated application data `[observed]`.
- **Private, owner-bound engine handles.** Numeric native engine selectors
  live only in a module-private `WeakMap`; the Rust registry binds every
  selector to both runtime nonce and creating principal. Release reports a
  wrong-owner attempt distinctly, and JS forgets its selector only after
  native close succeeds, so the real owner can retry cleanup `[observed]`.
- **Fail-loud native lifecycle.** Status parsing, plaintext/ciphertext host
  calls, peer-certificate extraction, and transport EOF propagate native
  errors into one terminal TLS failure rather than converting them to an empty
  poll. EOF is marked applied only after the engine accepts it, and engine
  release precedes JS failure-state mutation so an owner rejection remains
  retryable `[observed]`.

Rejected alternatives `[inferred: judgment call recorded at decision time]`:
platform TLS C APIs (Security.framework / system OpenSSL — non-hermetic on
Linux, deprecated SecureTransport on macOS, per-platform trust-evaluation
semantics, two implementations to keep Node-shaped); using the optional
`openssl-crypto` feature as the TLS engine (off by default and behaviorally
different from rustls); a native-owned TCP+TLS thread pool like native fetch
(duplicates net.js's async-connect machinery and reintroduces the
exit-deadlock class). The narrowly scoped vendored identity decoder above does
not negotiate records or evaluate peer trust.

Known divergences, accepted deliberately: `getPeerCertificate(true)`'s
`issuerCertificate` chain reflects the chain **as presented on the wire**
(rustls `peer_certificates()`), while Node/OpenSSL completes it from the
local trust store; session resumption is an explicit fail-loud reduced profile
(`getSession()` returns null, `isSessionReused()` is false, and a non-null
`session` option throws `ERR_TLS_SESSION_UNSUPPORTED`). rustls does not expose
a supported serialization/import API for its sensitive client-session values,
and Node's input is an incompatible OpenSSL `SSL_SESSION` blob; silently
accepting it or inventing a process-local lookalike would misreport security
state and weaken runtime/principal isolation. TLS < 1.2 is not supported
(rustls), so requested minimums below 1.2 clamp to 1.2.

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

- On advertised native-runner targets, ordinary authenticated ESM has the CLI
  admit the exact file request before graph discovery.
  `module_loader::runner_pipeline` then calls the retained Host's typed
  resolver, produces provenance-bound Oxc `ModuleArtifact`s, and supplies the
  linked graph to the native Hermes module runner `[observed]`.
- At **builtin resolution** time, the Rust loader returns the inline builtin
  source (no bytecode here) `[observed]`.
- The bounded compatibility loader reaches Rust through `__exactModuleResolve`
  / `__exactNativeModuleResolve` JSI functions, which call the Rust
  `ex_host_module_resolve` ABI `[observed]`. The Rust side returns a JSON object
  carrying `id`, `kind` (`builtin`/`cjs`/`json`/`esm`), `path`, and `source`.
- `require.resolve` instead uses the metadata-only bridge
  `__exactModuleResolveMeta` / `__exactNativeModuleResolveMeta` ->
  `ex_host_module_resolve_meta`, which omits `source` from the public record.
  For file-backed targets it does not acquire, decode, parse, transpile, or
  disclose executable source, although trusted package-integrity revalidation
  may read and hash raw bytes. Builtin metadata may retain embedded source
  internally but does not serialize it through this ABI (ENG-23007)
  `[observed]`. The loader prefers the metadata binding and falls back to the
  full bridge when it is absent (older embedded runtimes / tests); that fallback
  may acquire source.
- The JS module-loader bootstrap (`src/engine/bootstrap/module-loader.js`)
  drives the bounded compatibility `require`/`import` path against this resolve
  function `[observed]`
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
- The remaining native call-time dynamic-import and authored-`require` gaps are
  explicitly bounded and tracked by LLP 0026. This Explainer does not promote
  the compatibility path or the in-code "minimal" resolver label into a second
  architecture contract.
