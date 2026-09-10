# LLP 0068: The standard library for a Rust consumer

**Type:** Spec
**Status:** Draft
**Systems:** Rust Stdlib, Host ABI, CapSec, Build
**Author:** Charlie Cheever / Claude (Fable 5)
**Date:** 2026-08-29
**Revised:** 2026-09-09 (native processes, installable JS/TS, filesystem teardown); 2026-09-07 (app-scoped filesystem and separate SQLite provider); 2026-09-06 (§2: author-required streaming and cancellation); 2026-09-03 (LLP 0057.000 plans how `Bindings` grows — one field per family, feature-gated where a family pulls a dependency or a framework, present and refusing when the feature is off — and answers OQ3 in its lane L3 with a `Receiver`; neither is built yet) 2026-08-30 (§1: `Bindings` grew `secrets` (LLP 0069) and `kv` (LLP 0070), and `Host` carries their stores beside the transport — caught by the LLP 0070 review as drift on this page; §3: the whole-surface sentence now says where the fourth and fifth bindings' tests live, caught by its round 2)
**Related:** LLP 0057 (§3.1 — the split, and the reason for a Rust standard library that survived: the non-JS consumer), LLP 0067 (the capability model this states in Rust), LLP 0059.000 (§4 — the families; §3.8 — the env snapshot), `rules/NOT-DOING.md` (the bar: a no-JS consumer gets the same standard library with no engine in the process)

## Summary

**Implemented 2026-09-09 (Codex, author-required for Fleet):** the native
process/PTY capability in §2.1 extends the Rust surface with an installable
JS/TypeScript adapter over the same implementation. This replaces
the earlier deliberate omission for this named consumer, not the decision to
exclude Node compatibility.

Charlie Cheever decided on 2026-08-29 that the no-JS consumer of Ibex 2's
standard library is Exact 2's plan runner, which is Rust, and that this must
be supported. This document is the surface: `ibex2::host`. It is not a second
implementation — existing JavaScript bindings call these same Rust functions,
behind the same `boundary::admit`, taking the same `GrantSet` a manifest
section parses to — and it links no engine. What it states in Rust is
LLP 0067's model: a consumer is endowed with bindings that carry their grant.

## 1. The shape

```rust
let host = Host::new();                       // the platform transport, once per process
let app = host.endow(GrantSet::parse(
    "net.fetch https://api.example.com\nfs.read /data\nenv.read HOME\n")?);
let response = app.fetch.get("https://api.example.com/things")?;   // Rust's redirects, headers, errors
let bytes    = app.fs.read_file("/data/things.json")?;            // checked as spelt and as realized
let home     = app.env.get("HOME");                               // None if not granted: absent, not refused
```

`Host` is the runtime without an engine: the platform transport, stores, and
explicit host configuration. `endow` is instantiation:
`Bindings { fetch, fs, env, secrets, kv, sqlite, process }` (secrets and kv are LLP 0069 and LLP 0070; SQLite is LLP 0059.000 §3.15; native processes are §2.1) is the module parameter list as a struct, each binding holding an
`Arc` of the grant set for its whole life. A binding handed from one consumer to another carries the
first's authority, as LLP 0067 §3 says a JavaScript binding does. A consumer
granted nothing holds bindings that refuse — not absent bindings — so the
failure is a denial rather than a panic.

`Fs` offers the eleven operations the JavaScript `fs` has, with the same rules:
absolute paths, normalized lexically and checked as spelt and as the
filesystem will really resolve them; read on the source and write on the
destination for `rename` and `copy_file`, plus source write for `rename`. `Env` is the snapshot LLP 0059.000
§3.8 specifies. The pure tier — `stdlib::url`, `base64`, `text`, `headers` —
is plain Rust and needs no host at all.

App storage is configured by the embedder, not inferred from its environment:

```rust
let directories = AppDirectories::new(data_dir, cache_dir, temp_dir)?;
let host = Host::new()
    .with_app_directories(directories)
    .with_sqlite_provider(Arc::new(ibex2_sqlite::SqliteProvider));
let app = host.endow(GrantSet::parse(
    "fs.read app:/data\nfs.write app:/data\nsqlite.open app:/data/app.db\n")?);
app.fs.atomic_write_file("app:/data/settings.json", br#"{"theme":"dark"}"#)?;
let database = app.sqlite.open("app:/data/app.db")?;
database.execute("CREATE TABLE IF NOT EXISTS notes (body TEXT)", &[])?;
database.close()?;
```

Directories must already exist. The SQLite provider is a separate linked
artifact, not a core feature switch. A host that needs only files installs no
provider. JS embedders set the same directories/provider on `Hermes` before
running modules. The SQLite library uses native VFS/journaling and requires
host-owned stable database parents while open; app file operations use pinned
directory handles (LLP 0059.000 §3.11, §3.15).

## 2. Synchronous, and why

The primitives block. An executor is the consumer's: a runner with its own
loop — Exact 2's has a seekable clock and a data seam — puts them on its own
workers, or wraps them in whatever future type it already uses. Ibex 2 does
not pick an async runtime for a consumer, and does not ship timers here,
because the consumer's clock is its own. The JavaScript path's task queue
(`task.rs`) is the engine's executor, not a general one.

`Fetch::stream(request, &signal)` returns headers and an owned, demand-driven
`StreamingResponse`. Read its body into caller-provided byte slices, collect it,
or drop it to close an unread request. `stdlib::abort::AbortController::abort`
interrupts the native request through its signal, including blocked header and
body reads. Buffered `send`/`get` collect this same transport path; origin grants
are checked on every redirect. Cancellation introduces no Rust timer or runtime.

**Filesystem teardown (2026-09-09, author-required lifecycle fix):** the
asynchronous filesystem dispatcher now admits work through a per-context gate.
`RuntimeState::shutdown`, including borrowed-adapter detach and `Context` drop,
closes admission and waits for operations already inside the gate. Queued old
writes refuse; admitted writes, including the final atomic rename, finish
before shutdown returns. A replacement session started after that return
cannot be overwritten by an old generation's file job. Native filesystem I/O
is not interruptible here, so teardown can block on an admitted operation.
This fixes the confirmed pre-existing cancelled `cancel` write overwriting
replacement `again`; it does not weaken the consumer's unload assertion.
Engine-free tests force queued and active-write schedules; the borrowed Hermes
fixture checks detach with 32 pending writes and a replacement context.

### 2.1 Native processes and PTYs

Fleet's ad hoc Node / `node-pty` bridge is the consumer target this capability
replaces; adopting the dependency is Fleet's work. Rust owns launch validation,
byte I/O, cancellation, status, and lifetime. `std::process::Command`, POSIX
pipes, POSIX PTY allocation, `poll`, and terminal ioctls provide the OS facilities
on macOS and Linux. No engine, async runtime, new dependency, or legacy process code is
required. Other targets retain the API and refuse before execution.

```rust
use ibex2::{grant::GrantSet, host::Host, stdlib::{abort::AbortSignal, process::Command}};
let app = Host::new().with_process_support().endow(
    GrantSet::parse("process.spawn /usr/bin/git\nprocess.pty /bin/sh")?);
let child = app.process.spawn(Command {
    executable: "/usr/bin/git".into(), args: vec!["status".into(), "--short".into()],
    cwd: "/work/repository".into(), env: Default::default(),
}, &AbortSignal::default())?;
// Move child.stdin/stdout/stderr to caller workers; drop stdin for EOF.
// Drain both output pipes concurrently with child.wait() when necessary.
```

Two explicit gates precede execution: the trusted host opts in with
`with_process_support`, and the binding carries `process.spawn <executable>`
or `process.pty <executable>`. Targets are exact absolute native path spellings,
never prefixes, PATH searches, or wildcard grants. Missing authority returns
`Denied`; malformed grants, NULs, relative/dot paths, invalid env names, and
zero terminal dimensions refuse before spawn. A pre-aborted signal never
executes. Cwd and the complete child environment are supplied explicitly;
the host environment is cleared. Arguments receive no shell interpretation
from Ibex. `TERM`, `PATH`, and locale are consumer choices.

An executable grant is **OS execution authority** for arbitrary arguments,
cwd, and supplied env, including interpreter arguments and dynamic-loader
variables. The host must trust the executable and keep its path/ancestry
stable; symlinks and executable contents remain the host's responsibility.
Child effects are not mediated by `fs`/`net` grants. This is the existing
in-process capability model, not confinement of child programs.

`Process` exposes optional owned `stdin`/`stdout`/`stderr`; `Pty` exposes
`input`/`output` (merged stdout/stderr), `resize(PtySize { rows, cols })`, and
`close`. Streams implement `Read`/`Write`, preserve arbitrary bytes, and have
only OS buffering. PTY descriptors are atomically close-on-exec, preventing
inheritance races with concurrent spawns. An unread stream backpressures the child; waiting never
silently drains it. PTYs start raw with a controlling terminal in a new session;
the child can subsequently change termios. Dropping PTY input is not half-close.

Both handles provide `id`, `try_wait`, `wait`, and `cancel`. Status retains an
exit code or signal, and repeated waits return the same status. Abort, cancel,
close, and owner drop wake blocked I/O, kill the owned process group, reap the
direct child, and release descriptors even if stream objects are retained.
Normal wait also kills remaining group members before reaping: `waitid` with
`WNOWAIT` keeps the leader PID reserved until signalling finishes. Darwin's
zombie-only `EPERM` and Linux PTY EOF-as-`EIO` are handled explicitly.
There is no background reaper: callers wait/poll or drop the owner; blocking
wait polls at 10ms and cancellation wakes it immediately. Hosts must not reap
these children themselves or ignore `SIGCHLD`. Cleanup covers the original
process group; descendants creating other groups/sessions are outside that
guarantee. Closing all PTY masters also invokes ordinary OS terminal hangup.

`tests/process.rs` exercises real processes and PTYs, refusals, binary streams,
backpressure, exit and signal status, concurrent cancellation, failed exec,
group cleanup, and reaping. The host explicitly installs the JS/TypeScript
adapter below when needed.

**Installable JS/TypeScript (2026-09-09):** the trusted embedder calls
`Context::enable_process_support()` and separately supplies executable grants.
Without opt-in, even a granted opener refuses. No JS operation enables the
host capability. Compile `bindings::PROCESS_SOURCE` ahead of time and pass
its factory value to `Adapter::process(grants, factory)` during trusted
initialization. The frozen result exposes `spawn(command, signal?)` and
`pty(command, size, signal?)`; the host passes it to the intended child effect.
It installs no globals, creates no engine, and adds no JS before first pixel.
The caller constructs the adapter before app code and evaluates the existing
precompiled `HARDEN_SOURCE` before use, as for SQLite.

Both openers return promises for frozen owners. Pipes have `stdin.write(bytes)`
and `stdin.close()` plus `stdout.read(maxBytes?)` and `stderr.read(maxBytes?)`.
PTYs have `input.write(bytes)`, `output.read(maxBytes?)`, and `resize({rows,cols})`.
Both expose `pid`, `wait()`, `cancel()`, and `close()`; status is
`{code: number|null, signal: number|null, success: boolean}`. Reads yield
`Uint8Array` or `null` at EOF; writes accept `ArrayBuffer`/`Uint8Array` and
resolve only after all bytes reach the native stream. `close()` is idempotent
cancellation plus descriptor cleanup, including after `wait()`. A structural
standard `AbortSignal` cancels the owner, preserving its reason if opening is
aborted. Wait never drains output: consume output concurrently as needed.
Structural signal hooks cannot prevent native cancellation: listener removal
is best-effort, and registration failure closes the prepared owner before
rejecting with the original setup error, even if a hook retained the callback.

Rust bounds adapter admission: at most 16 live owners, one outstanding operation
per stream (write and input close share a slot), separate wait/cancel/resize
slots, 64 KiB per read/write, and 128 pending operations per context. Tickets
remain held through queued completion delivery or detach, not merely until OS
I/O finishes. There is no queued stream reader/writer. Commands admit at most
256 argv elements, 256 environment entries, and 1 MiB of command text. Private
native owners hold resources; native cleanup on GC/detach uses a separate
bounded set of threads, so blocked I/O cannot starve it. Explicit awaited
cancel/close completes reaping; GC/detach schedules cleanup. Thread creation
failure during cleanup falls back to synchronous cancellation.

`bindings::PROCESS_TYPESCRIPT` exports the declarations in `process.d.ts`.
`tests/process_binding.rs` exercises actual caller-owned Hermes with binary
pipes/PTYs, OS backpressure, cancellation, resize, host opt-in, grants,
hardening, checkpoints, and detach. Direct ABI tests leave completions
undrained to verify the stream and global admission bounds, and saturate all
64 shared host workers to verify process shutdown still kills and reaps.

## 3. No engine in the process

The `hermes` feature is the engine. With it off — the crate's default — no
Hermes is linked, and `cargo test -p ibex2 --no-default-features` runs the
whole surface: `--test rust_consumer` covers a fetch through `NSURLSession`,
filesystem operations inside and outside a granted prefix, an env snapshot,
and the pure tier; the fourth and fifth bindings run beside it — secrets in
the crate's `--lib` suite (LLP 0069 §5), kv there and end-to-end in
`--test kv` (LLP 0070 §5). The platform
transport is compiled whether or not there is an engine; it had been gated
on the engine by accident of `build.rs`, which would have left a Rust
consumer with the development TCP transport and no TLS.

### Caller-owned JavaScript runtimes

Implemented 2026-09-07 (Charlie: make the bindings available in Rust and
TypeScript; Codex). `ibex2::bindings::Context` supplies a separate Rust state
and host-admitted grant set. Its directories and optional SQLite provider are
configured exactly as the Rust host's. `include/ibex2_jsi.h` and
`src/engine/ibex2_jsi.cc` are the installable JSI adapter; the embedder compiles
them against its own JSI headers, with no `hermes` feature required. The
existing Ibex2 Hermes runtime uses this same adapter.

The caller bakes `src/bindings/sqlite.js` with its engine's compiler. Its
completion value is a factory passed to `Adapter::storage`, which returns
frozen `{fs, sqlite}` capabilities and modifies no globals. The host decides
how to pass that object to app code. The adapter is constructed during trusted
initialization. After installing its own prelude, the caller evaluates the
precompiled `bindings::HARDEN_SOURCE` before app code: SQLite checks that its
intrinsics and their global bindings are locked before opening any database.
Captured validators prevent app code from substituting that check. The Rust
API needs no JS hardening. `src/bindings/storage.d.ts` declares that
TypeScript API; `bindings::TYPESCRIPT` makes the same declarations available
to a Rust-based bake. `fs.readdir` returns an array, `fs.stat` a record, and
`fs.readFile` an `ArrayBuffer`. Writes require bytes, never silently treating
an unsupported value as an empty file. SQLite integers return as `bigint`.

The adapter delivers at most one completion when asked; it runs no timers or
microtask checkpoints. `Context::set_wake` schedules the caller's executor
from a publishing worker, outside queue locks; `wait` is the blocking
alternative. Only the owner thread touches JSI. The caller detaches the
adapter before destroying either its runtime or Rust context. Detach clears
JS roots; retained capability functions fail closed. Detach shuts down its
borrowed context; a replacement uses a fresh context. Shutdown quiesces
filesystem effects (§2), cancels process owners (§2.1), and releases other
Rust resources, including outstanding database operations. The borrowed-runtime
fixture tests installation, explicit checkpoints, persistence, grants and
detach without the Ibex2 loader.

This is the reusable storage door. Exact2's data-source continuation integration
is separate work: installing the bindings alone does not teach its executor
how to resume an answer awaiting storage.

## 4. Exact 2

The runner creates one `Host` at boot with the platform's transport and
endows each application from its manifest — the same manifest grammar as
LLP 0065 §4.2, minus the sections that name JavaScript modules — so an
application's data seam holds a `Bindings` and nothing ambient. Whether an
application's Rust code is trusted (a crate the author wrote) or endowed
(code the author did not write, as wasm with explicit imports per LLP 0057
OQ4) is Exact 2's decision; this surface serves both, since a `Bindings` is
what a wasm host would hand its module as imports.

## 5. Open questions

**OQ1 — The crate boundary.** *Resolved the same day:* the loader — Oxc's
parser, transformer, and resolver — is behind the `loader` feature, on by
default. A Rust consumer depends on `ibex2` with `default-features = false`
and compiles none of it; the same cut is the run-only binary of LLP 0065
§3.3, 5.6 MB against 9.6 MB.

**OQ2 — Linux.** *Resolved 2026-08-30, for Exact 2's Linux host (its LLP
1016 D2):* the default transport off Apple platforms is
`transport::rustls_http` — HTTP/1.1 over rustls through `ureq`, the webpki
roots compiled in, a thirty-second timeout, no redirect following (that is
`fetch`'s, above, as on Apple). Pure Rust: a builder with no system TLS and no
-dev packages runs it as is. It is a transport and not a second `fetch`: every
status is a response, and what never connected is `TypeError: Failed to
fetch`. **Trust is the platform's**, as §3 of LLP 0057 says and as
`NSURLSession` has it on Apple: the roots are the machine's CA bundle
(`rustls-native-certs`: `/etc/ssl/certs`, `SSL_CERT_FILE`/`SSL_CERT_DIR`), so
an enterprise CA or a development proxy works there as everywhere else; only a
machine with no bundle at all gets the compiled-in webpki roots — Mozilla's
set, the one a distro installs — and `RustlsHttpTransport::roots` says which,
for the consumer's journal (Charlie, 2026-08-30). The development TCP transport
stays for tests that want plaintext and no dependency. A
`cfg(not(target_vendor = "apple"))` dependency, so an Apple build carries none
of it.

**OQ3 — Async.** If every consumer ends up wrapping these in the same future
type, that type belongs here. Not before.
