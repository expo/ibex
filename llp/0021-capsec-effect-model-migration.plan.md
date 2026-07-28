# LLP 0021: Capability Security Effect-Model Migration

**Type:** Plan
**Status:** Draft
**Systems:** Security, Policy, Runtime, Engine, Host ABI, Module Loader, Build, CLI, CI
**Author:** Charlie Cheever / Codex
**Date:** 2026-07-10
**Revised:** 2026-07-28 (promotes direct `_transform(Buffer, "buffer", callback)` on exactly eleven Apple zlib owners and nine Windows owners: each fixed encoder or complete decoder input returns undefined, invokes the callback exactly once without error, records the exact accepted byte length, leaves the receiver non-terminal, destroys it, closes any native handle, quiesces, and observes zero decisions; zstd wrappers are confined to the current no-bridge retained-input branch and make no codec claim; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/input/encoding/callback/accepted-state/cleanup contract; final Apple accounting is 23,590 required / 3,800 fully executable / 3,040 internally verified / 16,750 unresolved and Windows is 23,249 / 3,441 / 3,026 / 16,782; advertisements remain empty)
**Revised:** 2026-07-28 (promotes public `params(1, 0, callback)` on exactly eleven Apple zlib owners and nine Windows owners: every selected call fixes compression level 1 and default strategy 0, returns its fresh receiver, invokes the callback exactly once without error, proves the selected `_level` and `_strategy` while the receiver remains non-terminal, destroys it, closes any native handle, quiesces, and observes zero decisions; Brotli, decoder, and zstd wrappers are included only for their source-defined retained-state control path, while native deflate-family compressors additionally enter the installed parameter bridge; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/arguments/callback/selected-state/cleanup contract; final Apple accounting is 23,590 required / 3,789 fully executable / 3,040 internally verified / 16,761 unresolved and Windows is 23,249 / 3,432 / 3,026 / 16,791; advertisements remain empty)
**Revised:** 2026-07-28 (promotes public `flush(callback)` on exactly eleven Apple zlib owners and nine Windows owners: every selected call uses the first-argument callback form and therefore the source-defined default full-flush branch, returns its fresh receiver, invokes the callback exactly once without error, proves the receiver is still non-terminal before cleanup, destroys it, closes any native handle, quiesces, and observes zero decisions; the owner vocabulary includes the two zstd wrappers because this exact control write is a safe source-defined no-op when the zstd bridge is absent, without claiming zstd codec execution; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/callback/return/non-terminal/cleanup contract; final Apple accounting is 23,590 required / 3,778 fully executable / 3,040 internally verified / 16,772 unresolved and Windows is 23,249 / 3,423 / 3,026 / 16,800; advertisements remain empty)
**Revised:** 2026-07-28 (promotes direct incremental `write(Buffer, callback)` on exactly nine Apple zlib owners and seven Windows owners: every selected call must return a boolean, invoke its dedicated callback exactly once without error, retain the fixed input until a separate harness-owned empty terminal `end`, emit a nonempty encoded byte view or exact decoded bytes `[105, 98, 101, 120]`, emit exactly one `finish`, reach flushed and ended writable state, destroy the receiver, close the native handle, quiesce, and observe zero decisions; this terminal-write contract accommodates the Apple Brotli wrappers, which buffer writes until finalization, without conflating the selected `write` return/callback with the auxiliary `end`; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/input/callback/terminal/output/cleanup contract; the merged diagnostic loader's two late-resolver selector functions are also classified as exact WP3 control-plane surfaces, adding six fixture obligations (four internally verified, two unresolved) without executable credit; final Apple accounting is 23,590 required / 3,767 fully executable / 3,040 internally verified / 16,783 unresolved and Windows is 23,249 / 3,414 / 3,026 / 16,809; both zstd owners remain residual and advertisements remain empty)
**Revised:** 2026-07-28 (strengthens 19 already executable `node:timers` calls from generic captured-output receipts to direct, source-bound lifecycle contracts: `active`, `clearInterval`, `clearTimeout`, `enroll`, `Immediate.close`, `Immediate.hasRef`, `Immediate.ref`, `Immediate.unref`, `setImmediate`, `setInterval`, `setTimeout`, `Timeout.close`, `Timeout.hasRef`, `Timeout.ref`, `Timeout.refresh`, `Timeout._scheduleNative`, `Timeout.unref`, `unenroll`, and `_unrefActive`; each contract fixes the exact root or inherited-prototype descriptor, owned setup, arguments, result, inert callback behavior, complete cancellation/cleanup, quiescence, and zero decisions, with a fixed 60-second delay ensuring cancellation rather than timer delivery; `clearImmediate` remains on its existing closed/generic route and the two constructors remain generic captured-output rows; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact contract; the generic captured-output set falls from 141 to 122 and the descriptor residual manifest from 485 to 466, while Apple accounting remains 3,758 fully executable / 3,036 internally verified / 16,790 unresolved and Windows remains 3,407 / 3,022 / 16,814; advertisements remain empty)
**Revised:** 2026-07-28 (promotes direct synchronous `_processChunk(Buffer, Z_FINISH)` on exactly nine Apple zlib owners and seven Windows owners: every call must return a nonempty encoded byte view or exact decoded bytes `[105, 98, 101, 120]`, close the constructor-created idle native selector, quiesce, and observe zero decisions; Apple additionally covers `BrotliCompress` and `BrotliDecompress`, while Windows leaves them target-unavailable and both targets leave zstd residual because no native zstd bridge exists; the receipt is explicitly one-shot and does not cover incremental write, transform, parameter, flush, or finalization state; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/input/flush-flag/output/cleanup contract; Apple accounting is 3,758 fully executable / 3,036 internally verified / 16,790 unresolved and Windows is 3,407 / 3,022 / 16,814; advertisements remain empty)
**Revised:** 2026-07-28 (promotes terminal `end(Buffer)` on exactly nine Apple zlib owners and seven Windows owners: every call must return the receiver, deliver a nonempty encoded byte view or exact decoded bytes `[105, 98, 101, 120]`, emit exactly one `finish`, reach terminal writable state, leave no native codec ownership live, quiesce, and observe zero decisions; Apple additionally covers `BrotliCompress` and `BrotliDecompress`, while Windows leaves them target-unavailable and both targets leave zstd residual because no native zstd bridge exists; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact owner/input/output/lifecycle contract; Apple accounting is 3,749 fully executable / 3,036 internally verified / 16,799 unresolved and Windows is 3,400 / 3,022 / 16,821; advertisements remain empty)
**Revised:** 2026-07-28 (promotes exactly four Apple-only one-shot Brotli routes: `brotliCompressSync`, `brotliDecompressSync`, `brotliCompress`, and `brotliDecompress`; the synchronous calls require a nonempty encoded byte view or exact decoded bytes `[105, 98, 101, 120]`, while the callbacks return `undefined`, deliver exactly once without error, satisfy the same output proof, and reach quiescence; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact four-name vocabulary, source descriptor, fixed input/compressed bytes, dispatch, and output contract; Apple accounting is 3,740 fully executable / 3,036 internally verified / 16,808 unresolved while Windows remains 3,393 / 3,022 / 16,828 because it does not install the native Brotli bridge; advertisements remain empty)
**Revised:** 2026-07-28 (promotes exactly seven one-shot `node:zlib` callback wrappers: `deflate`, `deflateRaw`, `gzip`, `gunzip`, `inflate`, `inflateRaw`, and `unzip`; the loaded harness passes a dedicated callback credential, awaits exactly one deferred delivery, rejects errors, and verifies a nonempty encoded byte view or the exact decoded bytes `[105, 98, 101, 120]` before quiescence; authoring, independent evidence validation, Rust validation, and loaded-engine validation repeat the exact seven-name vocabulary, source descriptor, compressed/input bytes, callback contract, undefined source return, and delivery proof; Apple accounting is 3,736 fully executable / 3,036 internally verified / 16,812 unresolved and Windows is 3,393 / 3,022 / 16,828; advertisements remain empty)
**Revised:** 2026-07-28 (promotes exactly four isolated `node:zlib` synchronous decoders: `gunzipSync`, `inflateRawSync`, `inflateSync`, and `unzipSync`; each public root call receives one fixed deflate, raw-deflate, or gzip Buffer and must return the exact decoded bytes `[105, 98, 101, 120]`, with no retained stream and zero decisions; authoring, independent evidence validation, Rust validation, and the loaded-engine harness separately repeat the exact four-name vocabulary, source descriptor, compressed input, dispatch, and decoded-byte proof; Apple accounting is 3,729 fully executable / 3,036 internally verified / 16,819 unresolved and Windows is 3,386 / 3,022 / 16,835; advertisements remain empty)
**Revised:** 2026-07-28 (promotes exactly three isolated `node:zlib` synchronous encoders: `deflateRawSync`, `deflateSync`, and `gzipSync`; each public root call receives the fixed Buffer bytes `[105, 98, 101, 120]`, returns a nonempty byte view, retains no codec stream, reaches quiescence, and observes zero decisions; authoring, independent evidence validation, Rust validation, and the loaded-engine harness separately repeat the exact three-name vocabulary, source descriptor, input, dispatch, result, and byte-view proof; Apple accounting is 3,725 fully executable / 3,036 internally verified / 16,823 unresolved and Windows is 3,382 / 3,022 / 16,839, while the descriptor residual manifest falls from 521 to 518; decoders, callback codecs, and stream-processing calls remain residual)
**Revised:** 2026-07-28 (promotes exactly two additional fresh `node:dgram` operations: the owner-checked `Socket._closed` boolean read and `Socket.dropMembership("224.0.0.1")` on an unbound udp4 receiver; construction creates only source-owned state and a principal stamp, `_closed` reads the own non-configurable accessor, and `dropMembership` returns before the native hook because the handle remains `-1`; authoring, independent evidence validation, Rust validation, and the loaded-engine harness separately repeat the exact constructed-instance/call descriptors, udp4 setup, literal group address, result types, quiescence, and zero-decision contract; Apple accounting is 3,722 fully executable / 3,036 internally verified / 16,826 unresolved and Windows is 3,379 / 3,022 / 16,842, while the descriptor residual manifest falls from 522 to 521)
**Revised:** 2026-07-28 (promotes exactly five terminal calls on fresh `node:net` receivers: `Server.close`, `Socket.close`, `Socket.resetAndDestroy`, `Stream.close`, and `Stream.resetAndDestroy`; the dedicated setup constructs each receiver without a transport, attaches one harness close observer before dispatch, and requires exact close delivery plus terminal in-memory state before completion; authoring, independent evidence validation, Rust validation, and the loaded-engine harness repeat the closed five-name vocabulary, exact source descriptor, owner setup, dispatch, cleanup fields, quiescence, and zero-decision contract; Apple accounting is 3,720 fully executable / 3,036 internally verified / 16,828 unresolved and Windows is 3,377 / 3,022 / 16,844, while the descriptor residual manifest falls from 527 to 522)
**Revised:** 2026-07-28 (promotes exactly three fresh `node:https` server constructors: `Server`, `Server.constructor`, and `createServer`; each source call layers one private-state HTTP wrapper over one idle TLS server without binding a transport or creating an HTTP selector, while the inner TLS server still mints one runtime/principal owner token; the dedicated loaded-engine setup closes the outer server, awaits outer close delivery and delayed inner token retirement, and requires a later outer `address()` call to reach the guarded inner server and fail with `ERR_TLS_SERVER_CLOSED`; authoring, independent evidence validation, Rust validation, and physical Hermes execution repeat the exact `node:https` descriptor, `member-assignment` provenance, dispatch, cleanup, and quiescence contract; Apple accounting is 3,715 fully executable / 3,036 internally verified / 16,833 unresolved and Windows is 3,372 / 3,022 / 16,849, while the descriptor residual manifest falls from 530 to 527)
**Revised:** 2026-07-28 (promotes exactly three fresh `node:tls` server constructors: `Server`, `Server.constructor`, and `createServer`; each source call creates no transport or native listener but does mint one private runtime/principal owner token and install the two registry lifecycle listeners, so the dedicated loaded-engine setup attaches one harness close observer, invokes exact `close`, awaits the internal close hook and delayed retirement timer, and requires a subsequent guarded lifecycle call to fail with `ERR_TLS_SERVER_CLOSED`; authoring, independent evidence validation, Rust validation, and physical Hermes execution repeat the exact descriptor/dispatch/cleanup contract; Apple accounting is 3,712 fully executable / 3,036 internally verified / 16,836 unresolved and Windows is 3,369 / 3,022 / 16,852, while the descriptor residual manifest falls from 533 to 530)
**Revised:** 2026-07-28 (promotes exactly the `node:tls` `SecureContext.context` read on a fresh harness-owned `SecureContext`: source construction installs one own enumerable, non-writable, non-configurable, frozen opaque object without allocating a TLS engine or consulting native trust state; the author, independent evidence validator, Rust validator, and loaded-engine harness repeat the exact constructed-instance descriptor, empty constructor, object result, quiescence, and zero-decision contract; Apple accounting is 3,709 fully executable / 3,036 internally verified / 16,839 unresolved and Windows is 3,366 / 3,022 / 16,855)
**Revised:** 2026-07-28 (promotes exactly five transport-free `node:tls` socket calls: `TLSSocket`, `TLSSocket.close`, `TLSSocket.destroy`, `TLSSocket.ref`, and `TLSSocket.unref`; the harness constructs every receiver without an underlying transport, so no native TLS owner token, engine, selector, listener, or timer exists before the selected call, while close/destroy must drain their terminal timer before quiescence; the author, independent evidence validator, Rust validator, and loaded-engine harness repeat the exact closed vocabulary and zero-decision contract; Apple accounting is 3,708 fully executable / 3,036 internally verified / 16,840 unresolved and Windows is 3,365 / 3,022 / 16,856)
**Revised:** 2026-07-28 (strengthens the four already executable `node:http` header validators from generic captured-output evidence to dedicated `ibex/capsec-builtin-call-invocation/1` contracts: `_checkInvalidHeaderChar("ibex")`, `_checkIsHttpToken("x-ibex")`, `validateHeaderName("x-ibex")`, and `validateHeaderValue("x-ibex", "ibex")`; the author, independent evidence validator, Rust validator, and loaded-engine harness repeat the literal arguments, direct root-call dispatch, result type, quiescence, and zero-decision proof; because all four rows were already executable, Apple accounting remains 3,703 fully executable / 3,036 internally verified / 16,845 unresolved and Windows remains 3,360 / 3,022 / 16,861, while the generic captured-output set falls from 145 to 141 and the descriptor residual manifest from 542 to 538)
**Revised:** 2026-07-28 (promotes exactly `node_readline.Interface.pause` through a separate harness-owned non-terminal `Interface` lifecycle receipt: the selected call must return the receiver object while leaving it open but paused, preserve the constructor's exact data/error/end/close listener set, record one resume and one pause, and emit no close event; the harness then invokes exact `Interface.close` as auxiliary cleanup and proves all listeners detached, two total pauses, one close event, quiescence, and zero decisions; the three constructor-instance `_on*` closures remain residual; Apple accounting is 3,703 fully executable / 3,036 internally verified / 16,845 unresolved and Windows accounting is 3,360 / 3,022 / 16,861)
**Revised:** 2026-07-28 (promotes exactly `node_readline.Interface.close` on a fresh harness-owned non-terminal `Interface` whose inert input shim proves the constructor installed the exact data/error/end/close listener set and resumed once, then proves the selected close call detached every listener, paused once, marked the receiver closed, emitted one close event, returned `undefined`, reached quiescence, and emitted zero decisions; `Interface.pause` remains residual because it returns while retaining those constructor listeners; Apple accounting is 3,702 fully executable / 3,036 internally verified / 16,846 unresolved and Windows accounting is 3,359 / 3,022 / 16,862)
**Revised:** 2026-07-27 (promotes exactly `exact_crypto.KeyObject.equals` for two separately constructed harness-owned secret `KeyObject` instances containing the same fixed four-byte `ibex` value; the author, independent evidence validator, Rust validator, and loaded-engine JavaScript harness repeat a dedicated pair-owner setup, exact prototype descriptor, peer binding, boolean result, quiescence, and zero-decision contract without adding a generic nested-constructor facility; Apple accounting is 3,701 fully executable / 3,036 internally verified / 16,847 unresolved and Windows accounting is 3,358 / 3,022 / 16,863)
**Revised:** 2026-07-27 (promotes exactly three source-only compatibility calls: `exact_crypto.createPrivateKey("ibex-key")`, `exact_crypto.createPublicKey("ibex-key")`, and `node_readline.CSI(["31m"])`; the first two construct only in-memory compatibility wrappers without parsing, importing, or consulting a native key store, while CSI concatenates a harness-owned string array without opening a terminal or retaining a stream; authoring, independent evidence validation, Rust validation, and the loaded-engine JavaScript harness repeat the complete source descriptor, literal argument, root-call setup, result type, quiescence, and zero-decision contract; the cross-source `dns/promises.getDefaultResultOrder` projection remains residual; Apple accounting is 3,700 fully executable / 3,036 internally verified / 16,848 unresolved and Windows accounting is 3,357 / 3,022 / 16,864)
**Revised:** 2026-07-27 (promotes exactly two bounded X509 instance operations: an own `raw` accessor read and `toString()` on a fresh harness-owned `X509Certificate("ibex-x509-fixture")`; the locked primordial `Object.prototype.toString` previously swallowed ordinary prototype assignment, so `crypto.js` now installs the intended own override with an explicit descriptor while preserving lockdown; the author, independent evidence validator, Rust validator, and loaded-engine JavaScript harness separately repeat the exact constructor, access/call, result type, quiescence, and zero-decision contract; Apple accounting is 3,697 fully executable / 3,036 internally verified / 16,851 unresolved and Windows accounting is 3,354 / 3,022 / 16,867)
**Revised:** 2026-07-27 (promotes exactly six fresh `node:dgram` udp4 construction/lifecycle calls: `Socket`, `Socket.close`, `Socket.constructor`, `Socket.ref`, `Socket.unref`, and `createSocket`; construction creates the principal stamp but no native handle, binding, poll timer, or peer route, while close must drain its terminal event before quiescence; the author, independent evidence validator, Rust validator, and loaded-engine JavaScript harness each repeat the real `src/builtins/dgram.js` descriptor, canonical `node:dgram` invocation, exact udp4 setup, result, and normal-return proof; bind, connect, send, address, membership, and buffer operations remain residual; Apple accounting is 3,695 fully executable / 3,036 internally verified / 16,853 unresolved and Windows accounting is 3,352 / 3,022 / 16,869)
**Revised:** 2026-07-27 (promotes exactly nine fresh `node:http` construction/lifecycle calls: `Agent.destroy`, `Server`, `Server.close`, `Server.closeAllConnections`, `Server.closeIdleConnections`, `Server.constructor`, `Server.ref`, `Server.unref`, and `createServer`; the author, independent evidence validator, Rust validator, and loaded-engine JavaScript harness each repeat the complete source descriptor, empty arguments, exact fresh receiver setup, result type, and normal-return proof; no receiver has a listener, socket, or native selector, and `Server.close` must drain its terminal event before quiescence; listening, client-request, and transport-retaining routes remain residual; Apple accounting is 3,689 fully executable / 3,036 internally verified / 16,859 unresolved and Windows accounting is 3,346 / 3,022 / 16,875)
**Revised:** 2026-07-27 (promotes exactly seven inert `closed` boolean reads on fresh harness-owned `default`, `Duplex`, `PassThrough`, `Readable`, `Stream`, `Transform`, and `Writable` instances; the inventory's inherited/prototype rows do not describe a value on those prototypes, so authoring, independent validation, and Rust execution require the separate `constructed-instance-property` access kind, exact owner setup, own getter, boolean result, quiescence, and zero decisions; mutable `readableState` and `writableState` graphs remain residual; Apple accounting is 3,680 fully executable / 3,036 internally verified / 16,868 unresolved and Windows accounting is 3,337 / 3,022 / 16,884)
**Revised:** 2026-07-27 (promotes idle `destroy` on exactly 11 Apple zlib owners and the nine installed Windows owners: construction establishes the principal-bound native selector, the public source path authenticates before delegating, `_destroy` closes the selector, and the harness performs idempotent cleanup before proving quiescence; authoring, independent validation, and Rust execution repeat the exact owner/method/result contract; Windows Brotli owners remain residual because their native codec prerequisite is not installed; Apple accounting is 3,673 fully executable / 3,036 internally verified / 16,875 unresolved and Windows accounting is 3,330 / 3,022 / 16,891)
**Revised:** 2026-07-27 (promotes exactly six lifecycle calls on the base `node:stream` module-value constructor: `_close`, `_emitClose`, `_undestroy`, `constructor`, `destroy`, and `unpipe`; authoring, validation, and physical execution independently require `["prototype", method]` rather than the nonexistent `["default", "prototype", method]`, and only this closed name set receives the module-value correction; `default.pipe` remains residual because it retains listener and pipeline ownership; Apple accounting is 3,662 fully executable / 3,036 internally verified / 16,886 unresolved and Windows accounting is 3,321 / 3,022 / 16,900)
**Revised:** 2026-07-27 (promotes exactly eight explicit-parameter `exact_crypto` Diffie-Hellman calls: `DiffieHellman`, `createDiffieHellman`, and `getGenerator`, `getPrime`, `getPrivateKey`, `getPublicKey`, `setPrivateKey`, and `setPublicKey` on a harness-owned instance constructed from fixed prime 23 and generator 5; the author, independent validator, and Rust executor separately repeat the exact setup, arguments, result types, and ordinary-return proof, while `generateKeys` and `computeSecret` remain residual because they enter random or modular work; Apple accounting is 3,656 fully executable / 3,036 internally verified / 16,892 unresolved and Windows accounting is 3,315 / 3,022 / 16,906)
**Revised:** 2026-07-27 (promotes exactly 24 Promise-returning readable-stream consumers: `every`, `find`, `forEach`, `reduce`, `some`, and `toArray` on `Duplex`, `PassThrough`, `Readable`, and `Transform`; every recipe constructs an already-ended empty stream, awaits the exact returned Promise inside the observation, then requires event-loop quiescence and zero decisions, while the independent validator and Rust executor repeat the closed owner/method/argument/result contract; `wrap`, `compose`, and `pipeline` remain residual because their delegated ownership is not closed by this receipt; Apple accounting is 3,648 fully executable / 3,036 internally verified / 16,900 unresolved and Windows accounting is 3,307 / 3,022 / 16,914)
**Revised:** 2026-07-27 (promotes exactly 15 post-initialization scalar reads from `cluster`, `http`, and `os`: each capability-bearing module is loaded and quiesced before the export observer opens, so initialization receives no credit, while an independently duplicated descriptor/type allowlist requires the later authenticated cached read to return its exact boolean, number, object, string, or symbol type with zero decisions; generic exports from these three modules remain excluded; Apple accounting is 3,570 fully executable / 3,036 internally verified / 16,977 unresolved and Windows accounting is 3,229 / 3,022 / 16,991)
**Revised:** 2026-07-27 (promotes exactly 24 locally authored `dns/promises` error-code data reads through an independently duplicated name and descriptor allowlist: inventory may retain the conservative `unknown` static shape only when the source is the exact `node_dns_promises` member assignment and the recipe requires a runtime string; both physical engines returned strings with zero decisions for all 24 while generic unknown-shape reads, 42 DNS promises callables, and three Resolver `_handle` callables remain residual; Apple accounting is 3,555 fully executable / 3,036 internally verified / 16,992 unresolved and Windows accounting is 3,214 / 3,022 / 17,006)
**Revised:** 2026-07-27 (thirteen exact public loader routes now require a fresh armed runtime, real public `require` traversal, one matching receipt from a loader-private source point, quiescence, engine re-attestation, and zero legacy or typed decisions; a 100-route Apple audit rejected 87 static candidates that bypassed, cached, or entered typed authority, while all retained routes pass physically on Apple and Windows at source `362e21c7` / tree `sha256-7Rdvzwm5tGaDVNqW1U9sUiyp1VabIIhRuCT_iN-uOPI`; Apple catalog `sha256-YwyEGiU906sxfdDbSQreOmeQUuFcp_FzeFgFj-x5qbQ` reports 23,844 required / 3,531 fully executable / 3,134 internally verified / 17,179 unresolved and Windows catalog `sha256-Emt8544W78pVLMizBGhKaQt2tIJuqWE6Se383StPlu8` reports 23,503 / 3,190 / 3,120 / 17,193; the source inventory also excludes preprocessor predicates and Mach-O section metadata from pseudo-function/native-operation discovery; both advertisement sets remain empty)
**Revised:** 2026-07-26 (the artifact-independent armed import boundary now closes the process-wide `node:diagnostics_channel` and legacy `node:domain` registries alongside the previously terminal runtime-inspection and execution builtins, even under an authenticated overbroad snapshot; 31 additional source and alias facets per exact target execute as direct closed-import evidence, bringing the terminal-builtin tranche to 137 without converting imports that still contain supported export operations into module-wide denials)
**Revised:** 2026-07-26 (the residual installed Windows filesystem plane now refuses armed execution before path conversion, descriptor lookup, caller-buffer acquisition, worker dispatch, or legacy capability probing: whole-file write, mkdir, realpath, readlink, access, truncate, statfs, path/descriptor async whole-file write, every generic async path/stat operation, and the JavaScript synchronous writev fallback all return structured EPERM; the already typed retained-object routes remain unchanged)
**Revised:** 2026-07-26 (armed POSIX and Windows `__exactFsWriteAsync` / `__exactFsWritevAsync` now retain bounded caller input and submit one exact-object `fs:write` Repeat on the filesystem worker immediately before their sole scalar or aggregate mutation; Windows restricts the typed worker route to an existing append-only retained file, and both Windows descriptor durability surfaces plus their POSIX counterparts use distinct public-edge Repeats immediately before flushing, promoting eight async-write recipes on both targets and eight additional durability recipes on Windows)
**Revised:** 2026-07-26 (armed Windows TCP now authorizes requested host/port before DNS, every member of the complete canonical candidate set before connect, and the verified `getpeername` peer at Commit; retained socket identity and connection id bind generation-aware Repeat to each read/write while the registry lock prevents close/reuse races, and five connect plus three lifecycle recipes become executable)
**Revised:** 2026-07-26 (armed POSIX and Windows `__exactFsReadAsync` / `__exactFsReadvAsync` now carry the runtime/owner/principal/retained-object operation lease to the filesystem worker and submit one exact-object `fs:read` Repeat immediately before their sole scalar or aggregate acquisition; vector destinations are bounded without caller-sized preauthorization allocation and receive bytes only from the successful owned result, positioned reads preserve the cursor, and eight recipes become executable on each exact target while worker-backed writes and durability remain residual)
**Revised:** 2026-07-26 (armed Windows `__exactFsReadFileAsync` now captures one schedule-time runtime/principal operation lease and performs both path and retained-descriptor reads on the filesystem worker through typed VFS ABIs: path reads authorize requested/discovery `fs:list` plus commit/per-chunk `fs:read`, descriptor reads serialize the retained cursor and reauthorize every 64 KiB chunk plus EOF, denial precedes lookup or disclosure, eleven Windows recipes are newly executable, and worker-backed scalar/vector reads plus other installed Windows effects remain residual)
**Revised:** 2026-07-25 (armed Windows exact-string `"a"` open now admits only an existing regular file through an append-only retained handle: `fs:write` Requested precedes lookup, `fs:list` Requested/Discovery authenticates the existing object, `fs:write` Commit binds its identity/generation, and scalar `__exactFsWrite` performs one exact-object Repeat immediately before a short-write append; absence never creates, denial never mutates, package-source hard-link aliases refuse at Commit, ten Windows recipes are newly executable, and all other writable/async/durability modes remain residual)
**Revised:** 2026-07-25 (armed Windows synchronous `__exactFsReadv` now validates the runtime/owner-bound retained descriptor before inspecting a bounded vector, authorizes one exact-object `fs:read` Repeat, acquires bytes through the same retained file with positional-cursor restoration, and scatters only after success; four public scenarios are executable on each exact target while worker-backed vector reads remain residual)
**Revised:** 2026-07-25 (armed Windows read-only `__exactFsOpen` now returns the exact retained VFS file behind a runtime/owner-bound opaque registry entry, preserves the optional bearer for later operations, and `__exactFsFstatSync` authorizes Repeat against that same object and handle identity before metadata disclosure; write-capable opens fail closed before resolution, ten exact-target recipes are executable, and descriptor reads/mutations/async routes remain residual)
**Revised:** 2026-07-25 (armed Windows `__exactReaddir` retains the exact directory object, enumerates it through that handle, authorizes requested/discovery `fs:list` plus repeat before each disclosed member, and never falls back to pathname enumeration; physical replacement-race and public denial tests pass, five exact-target recipes are executable, and descriptors/mutations/async routes remain residual)
**Revised:** 2026-07-25 (armed Windows `__exactLstat` retains the final reparse object without following it, authorizes requested/discovery/repeat `fs:list` with `no-follow-final`, and never falls back to pathname lstat; physical replacement-race and public denial tests pass, five exact-target recipes are executable, and enumeration/descriptors/mutations/async routes remain residual)
**Revised:** 2026-07-25 (armed Windows `__exactStat` is the second installed filesystem effect moved to the retained-object VFS: file and authenticated mount-root metadata authorize requested/discovery/repeat `fs:list`, serialize only after repeat, and never fall back to pathname stat; five exact-target recipes are now executable while enumeration, descriptors, mutations, and async routes remain residual)
**Revised:** 2026-07-25 (armed Windows `__exactReadFile` is the first installed filesystem effect moved from the legacy pathname oracle to the runtime VFS retained-object state machine: frame-derived constrained principals authorize requested/discovery `fs:list` and commit/repeat `fs:read`, denial never falls back, and five exact-target recipes are now executable; async reads and all other installed Windows filesystem effects remain residual)
**Revised:** 2026-07-25 (Windows retained relative opens stage long and short directory-entry names plus 128-bit file identity, refuse selection through any 8.3 name, withhold delete sharing, and repeat/object-match the entry; physical custom-short-name and entry-replacement fixtures close the arbitrary 8.3 alias gap, leaving the typed installed filesystem backend and incomplete exact-target evidence as the Windows promotion blockers)
**Revised:** 2026-07-25 (Windows binds ASCII case-folding into selector and occurrence identity, uses the same key for resolver manifests/absences/denied subtrees, refuses non-ASCII and tilde components, and refuses case-sensitive traversal directories while preserving lexical SourceId and distinct hard links; arbitrary administrator-assigned 8.3 aliases, the installed native filesystem effect backend, and incomplete exact-target evidence keep Windows unadvertised)
**Revised:** 2026-07-25 (Windows VFS and armed Oxc resolution now decode contained Microsoft symlink/junction reparses from retained no-follow handles, object-match and double-read mutable payloads, authorize complete target-plus-tail paths before lookup, and restart from the retained root; unsupported providers, the Windows alias-canonicalization gap, the installed native filesystem effect backend, and incomplete exact-target evidence keep the target unadvertised)
**Revised:** 2026-07-25 (mixed filesystem dispatchers now carry exact branch-local closure: unbound path/descriptor mutations and recursive mkdir select deny-only `fs:unbound-mutation` branches before lookup, while retained-object branches remain effectful; target predicates preserve Apple worker-backed `chmod`/`utime`, close them on Windows, and source inventory binds the POSIX filesystem translation unit only to targets that compile it; Apple accounting is 2,760 fully executable / 3,114 internally verified / 17,849 unresolved and Windows accounting is 2,341 / 3,102 / 18,099)
**Revised:** 2026-07-25 (`node:fs.opendirSync` adds five empty-directory Apple public recipes with exact `__exactReaddir` evidence, path-bound `Dir` results, and mandatory close proof; Apple accounting is now 2,666 fully executable / 3,114 internally verified / 18,260 unresolved)
**Revised:** 2026-07-25 (`node:fs.openSync` adds fifteen flag-selected Apple public recipes across exact read, write, and read-write authority branches; every successful descriptor is closed and the three synthetic branch-selection rows remain residual; Apple accounting is now 2,661 fully executable / 3,114 internally verified / 18,265 unresolved)
**Revised:** 2026-07-25 (`node:fs.readlinkSync` corrects stored-link-byte authorization from ambient `fs:list` to `fs:read` commit/repeat, adds exact translated-string and denial evidence, and promotes five Apple rows; Apple accounting is now 2,646 fully executable / 3,114 internally verified / 18,280 unresolved)
**Revised:** 2026-07-25 (`node:fs.mkdirSync` adds five Apple public recipes that physically select absolute, non-recursive creation, bind the exact absent-create decision chain, and prove creation/no-creation postconditions; Apple accounting is now 2,641 fully executable / 3,114 internally verified / 18,285 unresolved)
**Revised:** 2026-07-25 (`node:fs.appendFileSync` adds five Apple public recipes with exact open/write decisions, prefix-plus-suffix mutation proof, and deny-no-mutation proof; Apple accounting is now 2,636 fully executable / 3,114 internally verified / 18,290 unresolved)
**Revised:** 2026-07-25 (`node:fs.truncateSync` adds five Apple public recipes with retained-object `fs:write` commit/repeat evidence and exact mutation/non-mutation postconditions; Apple accounting is now 2,631 fully executable / 3,114 internally verified / 18,295 unresolved)
**Revised:** 2026-07-25 (`node:fs.existsSync` adds five value-bound Apple public recipes, proving that permission denial is retained as a typed denied decision even though the API returns `false`; Apple accounting is now 2,626 fully executable / 3,114 internally verified / 18,300 unresolved)
**Revised:** 2026-07-25 (`node:fs.statfsSync` adds five bound-engine Apple public recipes through its exact six-decision `fs:list` sequence; Apple accounting is now 2,621 fully executable / 3,114 internally verified / 18,305 unresolved)
**Revised:** 2026-07-25 (retires the generated `malformed-branch-facts` execution scenario because logical-branch predicates are authenticated registry metadata rather than runtime input, preserving registry-shape validation plus real branch-selection/no-effect evidence; confirms the empty production bootstrap floor as the exact least-authority declaration while retaining the generic one-shot seal and nonempty-floor mechanism)
**Revised:** 2026-07-25 (reconciles module-runner conformance with invocation-time activation: the 19 production-reachable ABI lifecycle surfaces execute while authenticated `require` resolution and source reads remain attributed to two reviewed auxiliary effect edges; six eager dynamic/require-link ABIs and teardown-only generation unpin remain residual; separates the public callback Cargo filter from its containing module so it cannot also select the bound internal-evidence producer; refreshes the source-derived Apple and Windows fixture totals)
**Revised:** 2026-07-25 (deletes the legacy `PolicyFile` parser, public module, `HostConfig` policy/path/allow/deny seams, policy-string mode parser, and runtime readiness dependency; foreground audit remains an explicitly policyless diagnostic host and historical compatibility-manager algebra is covered only through private test setup)
**Revised:** 2026-07-25 (removes `insecure` from Cargo defaults: plain builds enforce the supported profile and refuse before project code while no exact target is advertised; unadvertised secure development and no-sandbox execution require explicit compile-time features; invocation-time ESM import and CommonJS require now cover source and prepared targets)
**Revised:** 2026-07-24 (production native-graph dependency source reads authorize the exact typed edge and retain a digest-bound receipt; dependency carriers derive a carrier receipt from that continuation, while entry-only carriers require an opaque graph/request join minted before any cache discovery; armed transpilation has no persistent cache-read path; every promotion-facing conformance Cargo executor now disables defaults and selects the production observer feature set explicitly)
**Revised:** 2026-07-25 (adds the product-neutral native runtime-extension
authority capsule projection, fixed exact extension resource semantics,
launcher-observed linked-artifact identity binding, construction-time
authority-digest and exact native-registry projection claims, and context-local
operation leases)
**Revised:** 2026-07-20 (extends authenticated fresh-engine, zero-decision source receipts to 30 additional reviewed public builtin spellings, binds their exact root value types, and leaves both `stream/consumers` spellings residual because compatibility loading shadows their manifest source)
**Revised:** 2026-07-19 (binds the exact `dns/promises` carrier/provider callable shape to independent inventory and classifier review pins while leaving all 45 derived routes residual; strengthens four DNS no-effect alias receipts with exact cache-miss, VFS source, body-completion, alias, and runtime-nonce evidence)
**Revised:** 2026-07-18 (ENG-25076 adds the target-local Exact GPU binding/profile producer and independently executed preparation evidence while preserving empty advertisements)
**Revised:** 2026-07-17 (ENG-24578 moves the lockdown startup postcondition to authenticated direct-file native-graph execution while retaining a separate zero-decision startup window, because persistent-session lowering intentionally closes evaluator syntax)
**Revised:** 2026-07-17 (ENG-24578 moves the four lockdown-tamed evaluator probes from the deliberately syntax-closed persistent-session route to authenticated direct-file native-graph admission, preserving exact loaded-engine evidence without reopening REPL dynamic code)
**Revised:** 2026-07-18 (CLI protected-artifact publication now uses the
target durability boundary, and external JavaScript tools receive ordinary
Windows path spellings only after authenticated canonical selection)
**Revised:** 2026-07-18 (Windows module resolution restores canonical object
identity after the Oxc compatibility projection, and byte-authenticated Rust
fixtures use checkout-stable LF authorities)
**Revised:** 2026-07-18 (the Windows full-matrix Rust product gate preserves
the fail-on-zero wrapper while binding Cargo to the configured MSVC linker and
vendored OpenSSL to native Perl before Git Bash can shadow those tools)
**Revised:** 2026-07-18 (Windows replacement translation units preserve
cross-target integration-test C ABI shape so the full Rust gate can link before
the test reports target/profile inapplicability)
**Revised:** 2026-07-18 (target-local protected-artifact publication fsyncs
the parent directory on Unix and flushes the pinned linked file on Windows,
where opening a directory through `std::fs::File` is refused)
**Revised:** 2026-07-18 (Windows builtin recipes keep callable Brotli exports
residual because the target installs deflate/inflate but not the native Brotli
codec globals those exports require)
**Revised:** 2026-07-18 (Windows source-bound builtin recipes keep the default
`src/builtins/crypto.js` implementation residual because the target installs a
reduced bootstrap-local `node:crypto` replacement)
**Revised:** 2026-07-18 (Windows package-source authentication inventories
the integrity tree twice and opens every object relative to the pinned package
root handle while refusing reparse traversal)
**Revised:** 2026-07-18 (Windows recipe generation keeps all 134 filesystem
public probes residual while the backend still lacks the non-Unix typed
retained-object adapter)
**Revised:** 2026-07-18 (Windows evaluator review canonicalizes CRLF to LF
for checked-in PowerShell authorities while release manifests continue to
attest the platform-native builder bytes exactly)
**Revised:** 2026-07-18 (the origin/main integration restamps the reviewed
Hermes evaluator identity after adding static-library packaging to the source
build authority; evaluator reachability and lockdown taming are unchanged)
**Revised:** 2026-07-18 (ENG-24933 binds direct path truncation to retained-object typed authorization and physically proves five Apple scenarios)
**Revised:** 2026-07-18 (ENG-24933 removes the stale descriptor durability-read branch under LLP 0023's write-authorized durability contract, physically executes the asynchronous durability-write branch on Apple, and keeps the aggregate metadata-write branch residual pending an exact open/closed split)
**Revised:** 2026-07-18 (ENG-24933 physically executes open-family retained descriptor truncation on an exact Apple-owned file while keeping closed metadata mutation, absent Windows surfaces, and prerequisite-conflicting denial residual)
**Revised:** 2026-07-18 (ENG-24933 physically executes retained descriptor durability on Apple through typed fsync/fdatasync repeat gates and owned-file cleanup, while prerequisite-conflicting denial remains residual)
**Revised:** 2026-07-18 (ENG-24933 physically executes retained descriptor metadata on Apple, closes the setup descriptor outside observation, and leaves prerequisite-conflicting denial and the legacy Windows path residual)
**Revised:** 2026-07-18 (ENG-24933 keeps POSIX evidence directories mode-private while treating Windows' synthetic POSIX mode bits as non-authoritative)
**Revised:** 2026-07-18 (ENG-24933 executes all three asynchronous descriptor-open branches through event-loop quiescence on Apple, closes returned descriptors, and keeps the uninstalled Windows surface residual)
**Revised:** 2026-07-18 (ENG-24933 executes all three direct descriptor-open access branches against exact pre-seeded files, closes returned descriptors, proves non-mutation, and removes the fixtures)
**Revised:** 2026-07-18 (ENG-24933 binds direct append to an exact pre-seeded file, proves preserved prefix bytes and denial non-mutation, and removes the owned fixture)
**Revised:** 2026-07-18 (ENG-24933 executes direct directory enumeration against one harness-owned entry with retained repeat evidence and unconditional cleanup)
**Revised:** 2026-07-18 (ENG-24933 binds direct whole-file creation to source-derived bytes, an exact harness-owned floor, and verified content cleanup)
**Revised:** 2026-07-18 (ENG-24933 binds direct non-recursive directory creation to an exact harness-owned floor and proves post-operation cleanup)
**Revised:** 2026-07-18 (ENG-24933 binds direct terminal-builtin import-gate closure when the static route has no downstream alternative, after the complete Apple run exposed the validator mismatch)
**Revised:** 2026-07-17 (ENG-24933 closes the armed Exact/Bun accessibility application-state namespace after trusted bootstrap and binds its source-derived cells to physical absence)
**Revised:** 2026-07-17 (ENG-24933 restamps the reviewed Hermes evaluator identity after the Release artifact builder changed, preserving fail-closed source-authority drift detection)
**Revised:** 2026-07-17 (ENG-24578 binds native-public async completion to event-loop quiescence, reconciles retained-path live traces with the source-bound internal observer-stage contract, and keeps armed `mkdtemp` residual because its public entry point remains closed)
**Revised:** 2026-07-17 (ENG-25062 was reopened after merge-prep review confirmed that graph-link receipts are produced and retained, but production source/cache/prepared-carrier reads do not yet enter the receipt-revalidated access closures; the existing Host edge authentication and exact prepared-byte comparison remain in force without claiming the stronger closure-gated boundary)
**Revised:** 2026-07-16 (the module-runner safety review classifies exact generated manifest-builtin fan-out as closed private runtime linkage that may be eagerly materialized without a package/filesystem probe, but activation is confined to the exact builtin record's synchronous evaluation and cannot escape or re-enter through a retained `require` closure)
**Revised:** 2026-07-17 (ENG-24933 versions the conformance cache by the no-debugger build profile and reattests every restored framework before execution)
**Revised:** 2026-07-17 (ENG-24933 explicitly binds CI artifact selection and wrapper compilation to the Release profile and makes symbol attestation SIGPIPE-safe)
**Revised:** 2026-07-17 (ENG-24933 binds 33 legacy-bootstrap global paths to physical absence from the armed shared runtime without dereferencing missing roots)
**Revised:** 2026-07-17 (ENG-24933 binds all nine debugger ABI functions and their nine native-operation facets to physical null/zero/no-event results on the exact no-debugger Apple artifact)
**Revised:** 2026-07-17 (ENG-24933 binds all 106 source and alias facets of the terminal `async_hooks`, inspector, VM, WASI, and worker-thread builtins to loaded-engine denial of every public alias under an authenticated overbroad snapshot)
**Revised:** 2026-07-17 (ENG-24933 completes a source-, tree-, engine-, target-, and catalog-bound physical Apple Release report with 24/24 prerequisite commands passing; the report remains fail-closed with 1 conformant cell, 7,107 incomplete cells, and no advertisement)
**Revised:** 2026-07-17 (ENG-24933 implements Windows mapped-DLL object identity and a pinned patched no-debugger Release artifact pipeline while retaining the target's unsupported status pending runtime evidence)
**Revised:** 2026-07-18 (LLP 0030 separates policyless foreground source audit
from historical armed `diagnostic-audit` artifacts: foreground audit uses a
non-authorizing graph/decision context, the production verified-target gate,
and its own evidence digests; no new durable audit snapshot may arm)
**Revised:** 2026-07-17 (arming ABI v2 adds the evaluator-owned one-shot bootstrap authority floor/seal, an immutable root-only authority ceiling, and authenticated embedded protected ranges while retaining host-path protected objects)
**Revised:** 2026-07-17 (LLP 0014 canonical policy v2 rotates the policy digest domain while retaining the same checked semantic-set projection)
**Revised:** 2026-07-17 (ENG-24933 binds every exact-target evidence producer to the Apple OpenSSL crypto profile after a physical no-debugger Release run exposed the missing feature contract)
**Revised:** 2026-07-17 (ENG-24933 credits 14 source-bound asymmetric/EVP crypto executions on the Apple OpenSSL target profile)
**Revised:** 2026-07-17 (ENG-24933 credits nine bounded authority-control refusals and the post-capture absence of the loader-private manifest resolver)
**Revised:** 2026-07-17 (ENG-24933 credits six owner-authenticated refusals for unknown retained HTTP server and spawned-process identifiers)
**Revised:** 2026-07-17 (ENG-24933 credits synchronous and asynchronous filesystem close through harness-owned, source-bound descriptors)
**Revised:** 2026-07-17 (ENG-24933 credits two incomplete authority-call refusals and the exact invalid spawned-process handle refusal)
**Revised:** 2026-07-17 (ENG-24933 proves immutable module-level intrinsic receivers in builtin routes, removing 404 false ambiguous-route residuals without promoting unexecuted fixtures)
**Revised:** 2026-07-17 (ENG-24933 authenticates timer cancellation and ref-state mutation to the retained timer owner, replacing four closed native/global rows with eight executable non-capability and invariant recipes)
**Revised:** 2026-07-17 (ENG-24578 reconciles module-runner evidence with the production security boundary and credits 24 exact executions: four loader/source-acquisition surfaces, 19 native ABI lifecycle surfaces, and one armed namespace-inspection closure; six eager dynamic/require-link ABIs and the teardown-only generation-unpin ABI remain residual)
**Revised:** 2026-07-16 (ENG-24933 removes thirteen closed memory-debug implementation surfaces by capturing diagnostic state behind its deliberate API)
**Revised:** 2026-07-16 (ENG-24933 removes ten closed internal locale/accessibility state surfaces by retaining mutable state in module singletons)
**Revised:** 2026-07-16 (ENG-24933 completes malformed, missing-attribution, and wrong-principal scenarios for bounded loopback TCP connect)
**Revised:** 2026-07-16 (ENG-24933 completes thirty-six malformed, missing-attribution, and wrong-principal scenarios for system information, environment, and stdout)
**Revised:** 2026-07-16 (ENG-24933 closes twelve malformed, missing-attribution, and wrong-principal scenarios for retained metadata and whole-file reads)
**Revised:** 2026-07-16 (ENG-24933 binds direct `statfs` metadata to retained typed `fs:list` authorization and closes five exact public scenarios)
**Revised:** 2026-07-16 (ENG-24933 binds asynchronous `chmod` and `utime` to retained files, repeats authorization on the worker, and closes twelve exact public scenarios with owned cleanup)
**Revised:** 2026-07-16 (ENG-24933 adds target-local Exact manifest validation/materialization and the Exact-bound artifact preparer while preserving empty advertisements)
**Revised:** 2026-07-15 (ENG-25062 registered the module-runner factory, record, CJS-to-ESM edge, generation-lease, and compatibility-marker surfaces as closed non-capability control-plane operations)
**Revised:** 2026-07-15 (ENG-25066 made the authenticated graph decision set and process-stable principal projection the ordinary-ESM execution path)
**Revised:** 2026-07-15 (LLP 0026 adoption defines the module-initialization task boundary and trusted-loader source-acquisition classification)
**Revised:** 2026-07-16 (ENG-24578 residualizes 3,018 rationale-only
callback/control-plane rows because a generic invariant run cannot prove an
arbitrary carrier's selected branch; it retains eight exact embedder-mechanism
executions and requires every authenticated work-unit publication to be
consumed before teardown.)
**Revised:** 2026-07-15 (ENG-24578 residualizes raw resolver-output rows:
the resolver bridges are bootstrap-private and sealed before authenticated
project-source ingress, so unarmed or pre-bootstrap bare evaluation cannot
serve as execution evidence.)
**Revised:** 2026-07-15 (ENG-24578 binds cwd disclosure to the public
`process.cwd` facade over the sealed private bridge, and records the legacy
`.node`/`.wasm` resolver facets as residual until an authenticated source-bound
executor can distinguish their private rejection branches.)
**Revised:** 2026-07-15 (ENG-24578 aligns non-recursive armed `mkdir`
with LLP 0023's one-`mkdirat` contract: authorization retains the parent and
preauthorizes the absent child, but a failed post-create commit never performs
name-bound rollback that could unlink a racing replacement.)
**Revised:** 2026-07-14 (ENG-24578 binds the armed environment to an explicitly
empty base plus per-principal overlays, and replaces ambient compatibility
switches with fixed, digest-bound bootstrap modes; the Bun facade remains absent
unless the authenticated snapshot opts in.)
**Revised:** 2026-07-14 (ENG-24578 constrains diagnostic child IPC to a private one-shot POSIX socket handoff while armed IPC remains closed and unadvertised); 2026-07-14 (ENG-24933 introduces the dedicated binary Exact app/agent ingress while preserving the unadvertised Apple target and records the remaining artifact/conformance gate); 2026-07-12 (ENG-24263: the complete exact-engine prerequisite matrix and artifact evidence now run in CI, which requires the incomplete candidate to remain unadvertised rather than treating expected refusal as conformance); 2026-07-12 (ENG-24278 bounds POSIX TCP/UDP repeat work with socket-identity, exact-peer/destination, principal-set, and mutable-generation leases); 2026-07-12 (post-cutover security review hardened WP3–WP5: exact package content/graph roots and import edges, checked digest/set invariants, actual-engine and runtime-scoped arming, complete closed-startup controls, race-safe retained filesystem objects, analysis-byte/package-tree joining, and content-addressed report-derived target advertisements; the current registry still advertises no executable target — ENG-24232 through ENG-24281); 2026-07-12 (ENG-24233/24239/24247/24249–24253 remediate conformance evidence, policy identity, selector constraints, generation publication, atomic evidence, drift classification, package-root ceilings, and descriptor authorization leases); 2026-07-12 (ENG-24267/24268/24273/24276/24278/24280 align canonical ordering and mapped-IP semantics, harden generators, correct RFC 8785 numbers and staged decisions, and bound repeat-stage work); 2026-07-12 (ENG-24462/ENG-24465 bind filesystem occurrences separately to every constrained principal and protect every authenticated package subtree lexically against writes; ENG-24464 makes production run nonces construction-fresh; ENG-24466 explicitly closes diagnostic file execution in the advertised registry pending authenticated ingress); 2026-07-11 (WP0 semantic contract frozen by ENG-24144: profile, 38-action vocabulary, 57-bit reconciliation, typed occurrence/containment semantics, digest projections, and enforce-default target rule); 2026-07-11 (WP1 generated source-surface inventory, production registry, unsupported target matrix, and cross-language bindings implemented by ENG-24145); 2026-07-11 (WP2 typed Rust policy and decision core implemented by ENG-24146 with strict contract ingestion, canonicalization/digests, typed containment, decision precedence, staged conjunction/intersection, generations, and exact cache identities); 2026-07-11 (WP3 typed ESM/CJS import authoring and integrity-bound canonical generation implemented by ENG-24147); 2026-07-11 (WP4 strict immutable snapshot ingestion, production CLI arming, and explicit host/Hermes digest handshake implemented by ENG-24148); 2026-07-11 (WP5 initial retained checked-object record plus exact logical-branch schema and filesystem branch migration in progress under ENG-24149); 2026-07-11 (WP6 retained verified-peer record, metadata-peer denial, and exact logical network branch migration landed under ENG-24150, with runtime typed gates and red-team coverage still pending); 2026-07-11 (WP7 deny-only escape/process catalog invariant plus exact loader, process, stdio, environment, and host-default branch migration landed under ENG-24151, with runtime gates and red-team coverage still pending); 2026-07-11 (WP8 structured decision evidence, exact Android media-operation branches, and immutable snapshot-to-verified-decision-context arming landed under ENG-24152, with live handles/grants/deputy gate migration still pending); 2026-07-11 (WP10 exact-target report schema and fail-closed execution-evidence binding introduced by ENG-24154; the macOS candidate remains unadvertised pending complete executed fixtures)
**Revised:** 2026-07-17 (ENG-24933 records the retained TCP metadata residual gate after physical loopback execution exposed repeat decisions on actionless logical fixtures)
**Revised:** 2026-07-17 (ENG-24933 proves armed whole-environment enumeration selects its empty zero-decision branch without crediting the unreachable legacy wildcard path)
**Revised:** 2026-07-17 (ENG-24933 closes both public cr-sqlite enablement exports through exact in-memory refusal evidence)
**Revised:** 2026-07-18 (Windows public recipes remain residual where platform globals, including setup prerequisites, use legacy capability oracles, install explicit unsupported placeholders, or exclude their default-source registration from the target build)
**Revised:** 2026-07-17 (ENG-24933 closes both public SQLite extension-loading exports through exact in-memory refusal evidence); 2026-07-17 (ENG-24933 closes public messaging roots and executes debugger/shared-runtime/native absence evidence on both exact candidates); 2026-07-16 (ENG-24933 adds target-local Exact manifest validation/materialization and the Exact-bound artifact preparer while preserving empty advertisements); 2026-07-14 (ENG-24933 introduces the dedicated binary Exact app/agent ingress while preserving the unadvertised Apple target and records the remaining artifact/conformance gate); 2026-07-12 (ENG-24263: the complete exact-engine prerequisite matrix and artifact evidence now run in CI, which requires the incomplete candidate to remain unadvertised rather than treating expected refusal as conformance); 2026-07-12 (ENG-24278 bounds POSIX TCP/UDP repeat work with socket-identity, exact-peer/destination, principal-set, and mutable-generation leases); 2026-07-12 (post-cutover security review hardened WP3–WP5: exact package content/graph roots and import edges, checked digest/set invariants, actual-engine and runtime-scoped arming, complete closed-startup controls, race-safe retained filesystem objects, analysis-byte/package-tree joining, and content-addressed report-derived target advertisements; the current registry still advertises no executable target — ENG-24232 through ENG-24281); 2026-07-12 (ENG-24233/24239/24247/24249–24253 remediate conformance evidence, policy identity, selector constraints, generation publication, atomic evidence, drift classification, package-root ceilings, and descriptor authorization leases); 2026-07-12 (ENG-24267/24268/24273/24276/24278/24280 align canonical ordering and mapped-IP semantics, harden generators, correct RFC 8785 numbers and staged decisions, and bound repeat-stage work); 2026-07-12 (ENG-24462/ENG-24465 bind filesystem occurrences separately to every constrained principal and protect every authenticated package subtree lexically against writes; ENG-24464 makes production run nonces construction-fresh; ENG-24466 explicitly closes diagnostic file execution in the advertised registry pending authenticated ingress); 2026-07-11 (WP0 semantic contract frozen by ENG-24144: profile, 38-action vocabulary, 57-bit reconciliation, typed occurrence/containment semantics, digest projections, and enforce-default target rule); 2026-07-11 (WP1 generated source-surface inventory, production registry, unsupported target matrix, and cross-language bindings implemented by ENG-24145); 2026-07-11 (WP2 typed Rust policy and decision core implemented by ENG-24146 with strict contract ingestion, canonicalization/digests, typed containment, decision precedence, staged conjunction/intersection, generations, and exact cache identities); 2026-07-11 (WP3 typed ESM/CJS import authoring and integrity-bound canonical generation implemented by ENG-24147); 2026-07-11 (WP4 strict immutable snapshot ingestion, production CLI arming, and explicit host/Hermes digest handshake implemented by ENG-24148); 2026-07-11 (WP5 initial retained checked-object record plus exact logical-branch schema and filesystem branch migration in progress under ENG-24149); 2026-07-11 (WP6 retained verified-peer record, metadata-peer denial, and exact logical network branch migration landed under ENG-24150, with runtime gates and red-team coverage still pending); 2026-07-11 (WP7 deny-only escape/process catalog invariant plus exact loader, process, stdio, environment, and host-default branch migration landed under ENG-24151, with runtime gates and red-team coverage still pending); 2026-07-11 (WP8 structured decision evidence, exact Android media-operation branches, and immutable snapshot-to-verified-decision-context arming landed under ENG-24152, with live handles/grants/deputy gate migration still pending); 2026-07-11 (WP10 exact-target report schema and fail-closed execution-evidence binding introduced by ENG-24154; the macOS candidate remains unadvertised pending complete executed fixtures)
**Revised:** 2026-07-19 (ENG-24933 executes each reviewed `util`/`sys`
public spelling in a fresh engine and binds its first-load `NODE_DEBUG` read to
the independently observed native environment gate; platform and lazy DNS
aliases remain residual.)
**Revised:** 2026-07-19 (ENG-24933 reconciles the current lazy DNS sources with
the coverage model: the four exact `dns`/`node:dns` and promises import
spellings, plus both default namespace rows, are module-reachability-only;
each import spelling now requires fresh-engine observation from before its
first `require` through event-loop quiescence, while `getServers`, `Resolver`,
and other exported operations remain separate and uncredited; the promises
spellings now execute their declared `node_dns_promises` manifest source rather
than a bootstrap-internal shadow; `getServers` and `Resolver` now carry the
conditional native-resolution/filesystem-fallback effects that the lazy source
actually triggers.)
**Related:** LLP 0002 (host ABI); LLP 0004 (module loading); LLP 0005 (generated build artifacts); LLP 0013 (per-package enforcement mechanics); LLP 0014 (import-site grants and generated policy); LLP 0016 (architecture assessment); LLP 0020 (Oden portability research); LLP 0026 (module-runner authority amendments); LLP 0027 (module artifacts and interop); Oden LLP 0019 (Capability Security, Revision 2); Oden LLP 0020 (Capability Security by Default); ENG-24143

## Summary

Ibex will replace its current string-based capability policy plane with the
effect-oriented model developed in Oden. The existing enforcement substrate
remains: runtime-instance isolation, per-package principals, native compartment
globals, lockdown, frame-derived attribution, import gating, and
authority-bearing attenuated handles. The replacement is above that substrate:
typed effects, generated coverage and conformance data, typed policy artifacts,
explicit resource semantics, and a fail-closed armed runtime snapshot.

This is a direct cutover, not a compatibility migration. Ibex has no external
users whose committed policies or CLI workflows need preservation. The project
will therefore not build a frozen legacy oracle, dual-profile runtime, policy
translator, or deprecation period. Current policy files, permissive defaults,
and weakening flags are development-state implementation details that may be
deleted as soon as their replacements work.

The destination has these properties:

1. The unit of mediation is a normalized **effect**, not a capability string
   attached one-to-one to an API. One operation may require several effects,
   and all must authorize before the corresponding effect occurs.
2. Capability definitions, surface-to-effect coverage edges, target
   conformance cells, and policy/classifier rules are generated datasets with
   deterministic drift checks.
3. Policy moves one way through **authored source → canonical review policy →
   armed snapshot**. Only the armed snapshot is consumed by the engine.
4. Canonical positive authority uses explicit actions and typed resources.
   Paths, endpoints, routes, ports, peer classes, executable identities, and
   other resource kinds are not overloaded colon-delimited strings.
5. Policy and runtime semantics are bound by profile, vocabulary, registry,
   policy, and armed-snapshot digests.
6. Every authority-bearing runtime surface is classified and tested. A surface
   is enforced, deliberately closed, absent, unsupported, or explicitly a
   non-capability; there is no unclassified production surface.
7. Normal `ibex` execution enforces the complete supported profile by default.
   Missing policy means empty dependency authority, not permissive execution.
   A target that cannot support the profile refuses before project code.

This plan is complete only when the old matcher and policy format are gone, the
default command cannot silently weaken the posture, and every advertised target
has a generated conformance report proving the profile it claims.

## Motivation

LLP 0013's mechanism work substantially exists and remains the right substrate,
but the policy plane has accumulated ambiguity that the Oden work made
concrete:

- `PolicyFile` accepts unversioned arrays of capability strings. Matching,
  resource grammar, action implication, and future vocabulary growth are
  implicit in handwritten code.
- The current shape encourages one operation to check one capability even when
  the operation discloses, reads, writes, connects, redirects, spawns, or
  delegates through several independently meaningful effects.
- Generated import-site policy is reviewable, but the artifact does not
  cryptographically bind the exact vocabulary, normalization semantics,
  surface classification, target support, or runtime bindings it relies on.
- Filesystem and network authorization can be separated from the OS object or
  final peer used after the check. String-level authorization alone cannot
  express retained-object, redirect, DNS rebinding, proxy-route, or staged
  authorization semantics cleanly.
- Enforcement completeness depends heavily on remembering to classify each new
  native, loader, builtin, callback, inspector, process-global, or resource-use
  surface. Oden demonstrated that this should be a generated inventory and CI
  invariant.
- The current CLI makes permissive execution the implicit no-policy default and
  exposes public weakening paths. That is the wrong long-term identity for a
  runtime whose defining distinction is package-level capability security.

Because Ibex has no external consumers yet, the usual reason to preserve these
semantics—migration cost—does not apply. The lowest-risk long-term choice is to
change direction now, before examples, embedders, and policies harden around the
intermediate model.

## Decision boundary

### Retained from LLP 0013 and LLP 0014

- Runtime instances remain the outer trust-domain boundary.
- Integrity-bound package principals remain the package-layer subjects.
- Hermes frame attribution and schedule-time principal capture remain the
  unforgeable source of acting-principal identity.
- Native per-package compartment globals and lockdown remain the reachability
  and shared-intrinsic integrity layer.
- Import gating and compartment endowments remain defense in depth; making an
  API unreachable never substitutes for checking its effect when reachable.
- Passed, attenuated handles remain the primary voluntary delegation channel.
- Import-site grants in root-principal code remain the concise grant-authoring
  surface, with package-authored declarations treated as requests rather than
  grants.
- Root and runtime-internal principals remain explicit identities rather than
  attribution fallbacks. Missing attribution continues to deny.

### Replaced

- `PolicyFile` as an unversioned bag of string lists.
- A single handwritten capability manifest serving simultaneously as public
  vocabulary, matcher input, implementation inventory, and conformance claim.
- Colon-delimited capability strings as the canonical review or engine format.
- Implicit action derivations and positive wildcards whose meaning can grow as
  the vocabulary grows.
- One-operation/one-check reasoning.
- Check-then-reopen filesystem and check-requested-host-only network semantics.
- A committed durable `audit` or `permissive` policy mode.
- Default permissive execution, `--allow-all`, public permissive execution,
  advisory-attribution execution, environment-selected weakening, and
  enforce-without-required-lockdown behavior on the normal production command.

### Deferred above the core

The following Oden work is not required to complete this migration: AI-assisted
grant proposal conversations, protected authorization receipt workflows,
isolated candidate publication, daemon migration, and report-artifact privacy.
The core must expose authenticated typed evidence those systems could consume,
but Ibex does not need to copy Oden's complete product workflow.

## Target model

### Effects and decision sets

A **surface** is a JavaScript API, loader path, builtin, native op, startup
route, callback, or other entry point. A generated **coverage edge** maps a
surface to one or more normalized effects and identifies the enforcement gate,
principal source, normalization rule, authorization stage, and fixture set.

An **effect occurrence** contains the runtime facts needed to decide one
authority-bearing action. A policy row contains an **authority selector** over
such occurrences. Runtime observations such as a selected DNS candidate or file
identity never become reusable authored authority.

All effects in one decision set are conjunctive. An operation may proceed to a
stage only after every effect knowable at that stage is allowed for every
non-transparent constrained principal. Later discoveries—symlink targets, DNS
candidates, redirects, proxy routes, accepted peers—pause the operation and
authorize the next stage before committing it. Missing required facts,
unclassified surfaces, missing attribution, unknown definitions, and unsupported
target cells deny or refuse arming.

### Generated semantic datasets

The implementation has four generated inputs:

1. **Capability definitions** — action identity, selector and occurrence
   schemas, normalization, authoring disposition, delegation/dynamic behavior,
   and risk metadata.
2. **Coverage edges** — surface inventory, effects, principal/effect-owner
   source, gate, stages, lifetime/recheck obligations, and stable identifiers.
3. **Backend/target conformance cells** — implemented disposition and required
   fixtures for each coverage edge on each supported target/profile.
4. **Policy and classifier rules** — derivations, non-capability rationales,
   decision precedence, protected resources, risk promotion, route/address
   classes, and other decision-affecting data.

Generated Rust, C++, JavaScript/TypeScript, JSON schemas, documentation tables,
and fixtures consume these sources. Handwritten duplicate matcher tables are
not authoritative. Drift is a build/CI failure.

Coverage edges contain semantic data only. A separately generated
`implementation-manifest.json` joins each edge to source-derived definitions,
stubs, or security-relevant references, the later work package that owns its
gate, fixture obligations, and content digests for generated outputs. Those
references are inventory evidence, not conformance evidence; only executed
fixtures can promote a target cell.

An effect edge is normally `conjunctive`. WP1 may record a known
parameter/provenance-dependent surface as `conditional-unrefined` only while
every corresponding target cell remains `unsupported`; the edge names its
refinement owner and why its possible effect set is not yet executable. Such an
edge cannot be promoted or armed. The owning filesystem, network, process, or
device work package must replace it with exact conjunctive logical branches
before conformance.

An exact conditional edge carries a canonical `logicalBranches` set. Each
branch names the normalized operation facts that select it and either its
complete conjunctive effect set, principal/effect-owner sources, lifetime, and
barriers, or a deny-only closed disposition with its closed action and
rationale. This permits a dispatcher to retain narrow object-bound operations
without misclassifying adjacent unbound mutations as effects. Immutable target
facts may participate in selection only when they come from the exact
digest-bound target profile; they are never caller-supplied runtime input.
Selection facts are produced only after argument/resource normalization and
must select exactly one branch; missing, unknown, or overlapping facts deny.
Fixture obligations are derived independently for every logical branch,
including branch selection, explicit no-effect branches, and a physical
pre-effect refusal for every closed branch, so a union of possible effects
cannot masquerade as executed conditional semantics.

### Policy forms and digests

Policy has three forms:

1. **Authored source** may use import-site syntax, aliases, macros, logical
   paths, and package selectors.
2. **Canonical review policy** contains explicit actions, typed resources,
   integrity-bound principals, explicit derivations, and reproducible logical
   bindings. It is the artifact a human reviews and may commit.
3. **Armed snapshot** binds the canonical policy to one execution: engine
   target, generated registry, effective mode, canonical host objects and paths,
   final route constraints, process-wide ceiling, protected guards, package
   graph, root identity, and immutable runtime generations. It is the only form
   the decision engine consumes.

The profile is `ibex/capsec/1`; this is Ibex's first public contract. Oden's
`/2` suffix belongs to Oden's own profile lineage, while the shared ancestry is
expressed by the effect/registry semantics and `capsec/semantics/1` core
contract. Digest encoding and domains are frozen below. A stale or mismatched
digest refuses arming. Duplicate keys, unknown positive actions, unresolved
selectors, aliases, macros, and machine-specific unbound paths may not reach
the armed snapshot.

`runtimeExtensions`, when present, is a closed
`ibex/runtime-extension-authority-capsule/1` projection. Its
`extensionSetDigest` uses domain `ibex:runtime-extension-set:1` over the sorted
selection tuple `(id, version, sdkVersion, manifestDigest)`. Its complete
`authorityCapsuleDigest` uses domain
`ibex:runtime-extension-authority-capsule:1` and omits only the digest field
itself. Both use the existing canonical `sha256-` plus unpadded-base64url
encoding. The capsule binds required SDK feature bits; full operation entry
paths and flags; callback producer affinity, owner-thread delivery, and queue
bounds; selected provider ABI version, size, and identity; and optional
source/Hermes-bytecode bootstrap content digests, lengths, source URLs, and
the closed `script-global` evaluation mode. Absence is the canonical empty
extension projection.

### Default execution contract

Normal project-code execution uses enforce mode. Absence of authored grants
produces empty package floors and closed dynamic ceilings; it does not select a
weaker mode. Lockdown, per-package attribution, compartment globals, and full
deputy intersection are required structural posture rather than independently
disableable policy preferences.

Audit is the separately named, ephemeral `ibex capsec audit` foreground
workflow governed by LLP 0030. It uses
`ForegroundAuditGraphSnapshotV1`/`ForegroundAuditDecisionContextV1`, not an
`ArmedSnapshot`; the historical armed-schema `diagnostic-audit` value is
decode-only until the next schema major removes it and no new instance may
arm. Permissive behavior exists only inside isolated tests. The
`contract-fixture` armed workflow is schema-only, must use the synthetic
`capsec-contract-fixture` target, and is never executable. None of these is a
mode of ordinary `ibex run`. Embedders must select an explicit supported profile
and successfully arm it; the legacy host constructor must not silently create a
production runtime that claims package security while running permissively.

### Module initialization and trusted source acquisition

LLP 0026 adds one explicit boundary to full deputy intersection. A module
factory's once-per-execution-generation initialization is an autonomous,
record-owned task: it executes in the defining principal's authenticated
compartment, and the constrained-principal set begins at that initialization
task boundary. Importer frames physically above a synchronous `require()` do
not join initialization-time decisions. This preserves deterministic module
state across cold/warm, synchronous/asynchronous, and competing-importer
orders. It does not widen the module's own grants. Calls through exports after
initialization continue to intersect the complete live caller and scheduler
chain exactly as before.

Module source acquisition is classified as a narrow trusted-loader operation,
not as `fs:list`/`fs:read` authority borrowed from the importer. It may occur
only after the exact authenticated import edge authorizes and is bound to that
edge's `SourceId`, source binding, locator, integrity, requesting record, and
graph generation. It is non-delegable and conveys no general filesystem
authority. The generated coverage registry rows for module-source acquisition
must use this classification before the ModuleRunner security integration can
claim conformance; denial, no-probe, cache-hit, prepared-carrier, and
wrong-principal fixtures are mandatory.

First-party and package source reads pin the authenticated root directory
object and open every descendant component relative to the retained parent
without following links. Unix uses descriptor-relative `openat`; Windows uses
`NtCreateFile` with the retained directory handle as `RootDirectory` and
`FILE_OPEN_REPARSE_POINT` at every step. Package reads additionally compare two
complete integrity inventories and retain source bytes from the same opened
handle that supplied their digest record. Both paths validate the armed root
object before accepting source bytes, so a path rename or reparse substitution
cannot redirect trusted-loader acquisition.

ENG-25062 implements that boundary as a typed `GraphDecisionSet` over the
exact requesting and target `SourceId`, resolution kind, conditions,
attributes, actor, effect owner, schedule-time identity, canonical constrained
set, stage, atomicity group, graph generation, and coverage edge. Successful
authorization returns an opaque receipt bound to the armed snapshot digest and
all four authority generations. The graph linker produces and retains those
receipts. The production native-graph builder now separates metadata resolution
from executable-source acquisition for every authored dependency. It
authorizes the exact typed edge before the Host may enter the retained-object
source read, keeps that read inside an opaque acquisition closure, computes the
authenticated byte digest, finalizes the source-access receipt, and retains the
receipt for the graph lifetime before releasing bytes to the producer. The
entry read remains joined to its separate authenticated launch request. Armed
transpilation is fresh and in-memory, so it has no persistent `CacheRead` path
to authorize. When a prepared carrier contains an authored dependency, its read
derives an exact `PreparedCarrierRead` receipt from that dependency's retained
source-acquisition continuation, binds the expected source integrity and
deterministic carrier digest, reads the manifest/payload only inside the
receipt-revalidated closure, and retains the resulting receipt for the prepared
graph lifetime. Prepared-cache loading additionally requires an opaque,
non-serializable entry-join token minted only after the structured file
request's VFS identity, principal, snapshot digest, source integrity, goal,
dialect, role, and main-entry status match the graph. The token is rejoined to
the current graph before `index.json` is read. A carrier with no dependency
receipt is admissible only when it contains that joined launch entry, rather
than inventing an import edge for the entry.
Module factories remain reachability-only at the graph boundary; host effects
they perform still enter ordinary typed semantic-core `DecisionSet`s at their
native effect gates. Generated target cells remain unsupported until executed
conformance evidence promotes them.

## WP0 semantic contract

ENG-24144 freezes the following contract for WP1–WP11. The machine-readable
authority is under `capsec/`; this section records the design decisions that
those artifacts implement.

### Ownership and profile identity

Ibex owns the initial canonical contract under `capsec/`. WP2 places the
runtime-neutral Rust implementation behind the neutral crate boundary
`crates/capsec-semantics` in this repository. A second runtime consumes that
exact source or makes an explicit ownership move; it must not copy the schemas,
canonicalizer, precedence implementation, or matcher into a second authority.
Product capability definitions, coverage edges, principal attribution adapters,
and target cells remain Ibex-local.

The product profile is `ibex/capsec/1`; the neutral semantic-core contract is
`capsec/semantics/1`. Profile suffixes are product-local compatibility versions,
not cross-runtime marketing generations.

An authenticated native runtime-extension capsule may add only namespaced data:
extension/operation IDs, authority classes, trusted-bootstrap surface names,
callback identities and bounded delivery facts, provider ABI identities, and
protected bootstrap/native linked-artifact identities. The neutral crate owns the single
`runtime-extension:invoke` definition and
`runtime-extension.identity.v1` exact normalization behavior. Extension
fragments are closed data objects and cannot provide matchers, normalizers,
precedence, action definitions, target predicates, or executable semantic
logic. Their authority exists only while the complete capsule is digest-bound
into the armed snapshot.

### Typed resources and initial vocabulary

Canonical positive rows contain one explicit two-part action and one typed
resource object. No `*`, bare family, family prefix, alias, comma list, or
colon-delimited resource can survive source ingestion. Authoring macros may
expand only against the pinned vocabulary and their expansions appear as
explicit canonical rows.

Initial authorable resource kinds are:

- logical-root `path-exact` and `path-tree`. Exact matches the entire decoded
  component sequence; tree is a component-boundary prefix including its base.
  Package roots additionally require the same package-root binding owner.
  Valid UTF-8 uses UTF-8 form and other byte components use canonical unpadded
  base64url. Target-neutral identity rejects only empty, dot, dot-dot, NUL, and
  slash components; a backslash or Windows-reserved name remains representable
  for Unix. At arming, Unix/Android accepts all remaining byte names, Windows
  additionally requires valid UTF-8 ASCII, rejects controls, forbidden characters,
  trailing dot/space, DOS device names, tilde spellings, and adapter-reported
  aliases, and binds ASCII case-folding as its current candidate identity. A
  case-sensitive Windows directory refuses rather than collapsing distinct names.
  Retained relative opens additionally stage the exact long/short directory-entry
  names and file ID, refuse selection through any 8.3 name, and repeat the entry
  after opening without delete sharing. The Apple bound-volume adapter supplies
  its actual case/normalization alias key.
  Alias collisions are compared only within the same bound-root/volume
  namespace; two packages' separate package-root bindings do not alias.
  Absolute paths are explicitly host-bound, and execution still requires a
  retained or verified platform object identity;
- separate fetch, raw/bidirectional connect, Unix connect, internet/Unix
  listen, and standalone DNS-query resources. Fetch never implies connect.
  Network selectors bind the exact scheme or transport, canonical DNS/IP/CIDR,
  remote or listen port, direct route, and peer classes. Runtime occurrences
  additionally materialize the concrete port, selected candidate, verified
  peer, and connection/listener identity applicable at each stage; those facts
  never become reusable authored selectors. Non-direct routes are discovered
  and refused before DNS, connect, or request bytes in this profile; typed
  proxies require a future profile;
- exact environment names: `env:read` accepts broker-base and
  principal-overlay, while `env:write` accepts principal-overlay and one
  child-launch. Read and write never imply one another;
- executable identity binding logical name, path, content, platform object,
  and, when present, interpreter path/content/platform object. Spawn composes
  `process:spawn`, child working-directory, child environment, and inherited
  stdio effects into one conjunctive decision set; closed stdio and unexported
  anonymous-pipe creation carry no external authority, while every exported
  endpoint has an exact owner-bound identity;
- independent stdio resources with stream and exact source identity:
  `stdio:query` accepts stdin/stdout/stderr, `stdio:read` only stdin,
  `stdio:write` only stdout/stderr, and `stdio:raw` only terminal-backed stdin;
  plus explicit system-information kinds, typed location/camera/microphone
  acquisition, and native system clipboard formats.

The optional native runtime-extension profile adds one product-neutral,
equality-only resource:
`{"kind":"runtime-extension","extensionId":...,"authorityClass":...}`.
It has no wildcard, family, prefix, or manifest-defined containment. The
authenticated capsule separately proves that an exact operation ID belongs to
that extension and authority class; opaque operation resource data contributes
only a canonical digest to the occurrence/lease identity. Every constrained
principal must already hold the exact selector in its immutable static floor,
so ambient-root fallback cannot manufacture extension authority.

`fs:list`, `fs:read`, `fs:write`, and `fs:watch` are independent. A matcher
never derives one action from another. SQLite file operations decompose into
the corresponding filesystem effects for the main database, parent, and
journal/WAL/SHM objects; `sqlite:*` is not canonical authority. Unix sockets
decompose `network:local` into connect or listen plus the applicable filesystem
effects. Ordinary randomness, pure in-memory cryptography, ordinary/high-
resolution clocks, and status-only attenuations are reasoned non-capabilities.
Exact SQLite `:memory:` databases are likewise computation because the host
authorizer denies attach/detach and extension loading. URI-looking or empty
filenames are not covered by that exemption and remain file-backed effects.

Location, camera, microphone, and clipboard are authorable target-specific
definitions. Their cells remain unsupported until native gates and broker/
lifetime fixtures prove them (`device:microphone` is known ungated today).
Storage remains deny-only until principal/shared namespace and native isolation
are proven. Shared process mutation, ambient IPC, inspector/runtime inspection,
VM, workers, WASI, and FFI remain deny-only or absent. The generated
reconciliation table joins every one of the 57 current bit names to its exact
destination disposition across 38 typed action definitions; the Rust bit source
remains the sole bit-number authority.

A package principal is the exact package locator plus integrity digest (with
its review name), not a package name alone. Root-only sources author positive
grants. Canonical provenance may merge several non-authorizing source records,
while definition lifecycle and channel restrictions still determine whether a
row may become static, dynamic, handle-mediated, or terminal authority.

### Decision, staging, and principal semantics

For one normalized effect and one constrained principal, precedence is:

1. arm validity and authenticated profile/digest agreement;
2. attribution (`NoUser`, missing, or ambiguous denies);
3. definition lifecycle and exact target-cell closure;
4. built-in protected-resource guards;
5. process-wide ceiling;
6. root-only authority ceiling for an authenticated root principal;
7. principal-specific denial;
8. revocation and negative generation;
9. quarantine denial;
10. definition/edge positive predicates;
11. static floor;
12. an explicit unforgeable bearer handle;
13. a typed dynamic session grant within the static ceiling;
14. generated implicit package-self access;
15. ambient root for the root dimension only; and
16. the effective mode's missing-authority result.

Every deny stratum precedes every positive authority source. The direct cutover
has no runtime legacy-oracle or compatibility-mask stratum; the 57-bit table is
build-time reconciliation evidence only. An unbounded process ceiling
continues; a bounded ceiling requires containment, and an empty bounded ceiling
denies everything.
The root ceiling is independently bounded or unbounded, applies only to an
authenticated root principal, and constrains `AmbientRoot` without narrowing a
package floor. It is immutable publication identity and therefore cannot be
widened through a live-generation update.
Every filesystem occurrence is projected separately through each constrained
principal's authenticated root binding before any principal-indexed authority
stratum runs. That rule applies to protected resources, process ceilings,
principal denials, revocations, static floors, handles, dynamic grants, and
implicit package-self authority; an actor-projected package path is never reused
as another package's resource. An unprojected multi-principal path occurrence
fails closed. A deeper foreign package binding shadows an owned package
ancestor, so an outer package sees a nested dependency through the best
ownerless root rather than as part of its own package tree; equal package host
bindings and package principals without bindings refuse arming. Other
path-bearing resource kinds (executables and Unix sockets) refuse a
multi-principal package-root decision until their adapters supply complete
projections. The host, ABI, and semantic core all use the same JCS principal
ordering. No later source, including ambient root, can override an earlier
ceiling or denial.

The exact reserved `runtime/ibex-runtime-internal` frame stamp is transparent;
other runtime identities are not, and the reserved identity is never an
attribution fallback. `NoUser`, missing, or ambiguous attribution denies. Live
user frames plus authenticated schedule-time and owner/deputy identities form
a deduplicated constrained set. Each non-transparent dimension must allow;
dimensions intersect and never union. All effects known at a stage are
conjunctive and authorize before that stage's first visible or irreversible
action. Later object, DNS candidate, redirect, route, accepted-peer, or resource
discovery re-enters the same precedence before the next effect. Missing facts
deny, speculative effects are forbidden, and a late denial releases provisional
resources without pretending earlier discovery was reversible.

An armed snapshot has exactly one authority row matching `rootIdentity`. Every
package-graph node has a unique locator-and-integrity principal, an exact
authority row, and its own package-root binding; package authority rows may not
exist outside the graph. Import allowlists exactly equal authenticated graph
edges, and every logical path resolves through a root binding. Exact protected
objects cover armed policy, engine binary, package graph, and registry. In
addition, arming derives `fs:write` path-tree guards for every authenticated
package binding in every principal's projected view. Authenticated package
source cannot be written through any registered package spelling, even when two
such spellings share an inode; writable package scratch space requires a
separate future binding. A pre-existing filesystem alias outside every
authenticated package binding is not covered by this lexical guarantee and
requires a future commit-time identity/integrity guard. Network posture binds
direct-only routing and always denies metadata and unspecified peers.

Compiled arming may satisfy a protected role with an authenticated embedded
range instead of a host pathname. An embedded protected artifact binds one
mapped executable object, a nonempty safe-integer byte range, the exact section
role, and the admitted content digest. Host and embedded artifacts together
must fill every protected role exactly once; embedded ranges on one executable
cannot overlap. Several ranges in one mapped executable collapse to one
filesystem write guard for that executable object, while their role/range/
digest identities remain distinct immutable arming facts.

### Handles, dynamic authority, and generations

Ibex deliberately retains LLP 0013's possession-based delegation within one
authenticated runtime. A handle is an unforgeable bearer object whose exact
action/resource grant, source owner, ancestry, and snapshot identity are fixed
at mint. Passing the object is voluntary delegation; frame/schedule attribution
still records the holder and actor chain. Handle use re-enters every negative
stratum at every effect stage, can attenuate only to the same action and a
strict resource subset, and is invalidated by ancestor revocation. A temporary
operation lease is native, operation-bound, non-transferable, and cannot turn
mode fallback into reusable authority. This is an explicit Ibex adaptation of
the Oden model, not an accidental omission of delegatee identity.

Authority containment is meaningful only within the same armed snapshot. Any
authority containing a package logical root also requires the same package-root
binding owner. Different actions are always incomparable even when their
resource shapes coincide.

Dynamic grants use typed resources and cannot cross the canonical static
escalation ceiling. Deny-only, planned, terminal, and static-only definitions
cannot enter the dynamic overlay. Mode fallback can never mint a grant or
handle. Revocation advances a negative generation before any later positive
decision.

Arm-time ceilings, protected-object/resource guards, and principal policies
retain an identity-preserving copy-on-write backing after validation. A live
publication must present those exact four immutable identities and then fully
validates only the changed generations, revocations, handles, and dynamic
grants. Cloning and publishing live authority is therefore constant-time in
the size of the static policy; attempting to mutate any immutable component
creates a new backing identity and refuses publication `[observed]`
(ENG-24280).

Decision caches key at least action, canonical resource bytes, constrained
principal set, effect owner, stage, vocabulary/registry/policy/armed-snapshot
digests, and negative/dynamic/handle generations. Repeated and live operations
must still obey their coverage edge's lifetime recheck contract.
Authority-reducing release, reset, shutdown, and cancellation have no positive
effect stage: they validate the retained object's runtime and principal owner
but remain possible after its positive grant is revoked. Requiring a live
positive lease to relinquish an owned resource can leak authority and violates
the registry's `authority-release` non-capability classification.

### Canonicalization and digest domains

All digest inputs are valid UTF-8 containing only Unicode scalar values and are
strict I-JSON serialized with RFC 8785 JCS. Duplicate keys are rejected before
canonicalization, and integers outside the I-JSON safe range use a tagged
canonical string. Arrays named by `digestContract.setKeys` are semantic sets
sorted and deduplicated by canonical JCS bytes. Composite-row sets use the exact
`(schema, path, orderBy)` declarations in `digestContract.keyedSets`; other
arrays retain sequence meaning. The hash frame is:

```text
SHA-256(UTF8(domain) || 0x00 || canonical-payload)
```

Digest text is lowercase `sha256-` followed by unpadded base64url. Domains are:

- `ibex:capsec:vocab:1` — definitions, selector/occurrence schemas,
  decision-affecting coverage/classifier rules, and non-capability rationales;
- `ibex:capsec:registry:1` — the source-derived generated registry,
  implementation references, and fixtures. Report-promoted target-cell bytes
  are bound separately so publishing a report cannot change the registry or
  implementation digest that the same report attests;
- `ibex:capsec:policy:2` — canonical review policy with its own digest omitted;
- `ibex:capsec:armed:1` — policy/registry identities plus resolved host objects,
  engine target, routes, graph, ceilings, generations, run nonce, and channel
  epoch; and
- `ibex:capsec:conformance:1` — one observed result for every target cell and
  the exact engine/fixture/report provenance.

Vocabulary and registry aggregates use `ibex/capsec-digest-bundle/1`, with
members ordered lexically by logical name and exact member lists frozen in
`digestContract.projections`. Policy, armed-snapshot, and conformance
projections omit only their own digest fields. The checked vocabulary bundle is
assembled from the exact WP0 definition/rule/schema files plus normative
coverage and containment vectors. The registry fixture content-addresses every
semantic and invalid fixture body as well as its closed file inventory; digest
payloads and the fixed digest-vector oracle are explicitly excluded where
including their raw bytes would create a cycle, and are checked independently.
The generated production registry is available after WP1. Its target cells are
all unsupported and its source references are explicitly non-conformance
inventory evidence. A tiny authored attestation catalog may name only a
content-addressed report; generation revalidates that report against the exact
source-derived implementation manifest and derives both target cells and the
advertisement list. Target cells, their matrix, and advertisements are excluded
from `implementationManifestDigest`, breaking the otherwise circular
report-promotes-cells-that-change-the-report-input dependency. The armed
snapshot remains a `contract-fixture`, and conformance remains unavailable
until WP10. Canonical policy and armed examples carry
recomputed self-digests and exact cross-digests. One checked golden vector
freezes each of the five domains, and the domain-to-payload mapping is fixed.

Production handle, dynamic-permission, and denial evidence carry all four
loaded vocabulary, registry, policy, and armed-snapshot digests from the
immutable engine decision context rather than expected wrapper values.
Foreground-audit evidence instead carries vocabulary, registry, the compiled
diagnostic-baseline digest, and the foreground graph digest; it never fills a
policy or armed-snapshot slot with a lookalike value.

### Default and target claim

Durable canonical policy accepts only enforce. Audit is a separately named,
ephemeral foreground workflow; production permissive/off are not profile
members. Missing policy canonicalizes to enforce with empty dependency floors
and empty escalation ceilings. Full deputy intersection, lockdown, frame
attribution, native compartments, and immutable arming are structural.

WP1 advertises no targets and records one candidate exact target,
`aarch64-apple-darwin` with structural `hermes-frame-attribution`,
`native-compartments`, and `native-lockdown` features. These are security
properties, not Cargo feature names. An executable production snapshot may arm
only when its exact target triple and canonical feature set
are advertised and every coverage edge has a matching `enforced`, `closed`, or
`absent` cell; a missing or `unsupported` cell refuses before project code.
Foreground source audit does not arm, but uses this same verified target and
feature-set authority before capture; the OS/architecture allowlist alone is
not an advertisement.
Public-address classification remains closed until pinned IANA IPv4 and IPv6
special-purpose snapshots enter the registry. IPv4-mapped IPv6 is classified
through its embedded IPv4 address, unmatched addresses fall back to `reserved`,
and classifier activation gates the first target advertisement.

WP9 flips the ordinary command once at least one exact advertised target has a
complete generated conformance report. The repository does not wait for every
conceivable build triple, but a build on any incomplete target refuses before
project code rather than degrading or selecting the legacy plane. Public claims
remain exact-target claims. Internal unit/integration fixtures are sufficient
for permissive compatibility investigation; the production CLI gains no raw
developer harness.

Exact embedding does not create a second or weaker target-claim plane. The
dedicated `exact.invokeHostAsync` ABI removes the generic string bridge from
app and agent traffic, with separate canonical numeric endowment sets and no
UI-worklet installation, but the same target-advertisement rule still governs
production construction. Before Exact may consume an armed artifact through
the public embedding ABI, the normal Ibex package flow must supply the generic
snapshot/expected-identity inputs plus Exact's single-source operation manifest;
the target-local producer then publishes a final pair bound to the loaded
engine, this registry, the exact package graph, and the protected manifest.
Its target row
must be promoted only from the checked conformance report. Missing artifacts,
wrong targets, identity or registry mismatches, fixed/stale nonces, replayed
input, and unadvertised rows all remain startup refusals.

Implementation status (2026-07-17): the dedicated binary app/agent ingress and
single-use completion path exist and are usable by an armed runtime without
making `__hostCall` reachable. Its setter publishes an immutable method on the
stable pre-captured `exact` object and atomically completes the one-shot package
baseline finalization, so package compartments cannot intercept or replace the
capability. Armed snapshots now conditionally authenticate the Exact manifest
as a fifth protected artifact and carry exact app, agent-isolate, and empty
UI-worklet ID sets. The setter validates that three-way binding before any JSI
or callback-state mutation. The public artifact-preparation ABI authenticates
an already-built pair against the checked registry, loaded engine, package
graph/root objects, and protected artifacts, then replaces its construction
nonce and digest; it cannot advertise a target. A second target-local preparer
now strictly validates Exact's raw operation manifest, derives the complete
three-context projection without a caller allowlist, materializes those bytes
as the fifth protected artifact, and re-authenticates the fresh pair. Exact's
Apple and Windows consumers use this seam. The normal target-local producer now
builds the complete pair directly from the installed app root, loaded engine,
checked registry, canonical empty package policy/graph, and strict Exact
manifest; it therefore does not package stale filesystem identities. Exact's
protected-artifact publisher uses the target's real durability boundary after
the content-addressed hard link is installed: Unix syncs the parent directory,
while Windows re-flushes the still-pinned file object because Rust's ordinary
file API cannot open a directory for `sync_all`. Both paths validate the
read-only file and its exact bytes before publication; this portability split
does not relax artifact identity or immutability. Exact's bundled-root producer
is complete. The former additive `exactGpuProvider` builder/profile path was a
WebGPU-specific one-off and was removed by LLP 0040. Selected runtime
extensions now enter through the generic, product-neutral authority
template/capsule projection: the launcher binds the complete descriptor,
linked-artifact, provider-ABI, global/module, operation, callback, and
loaded-executable facts before arming. An unselected build has no
runtime-extension capsule or extension library. Package-bearing policy input
remains a separate future contract. Apple/Windows conformance reports and target
advertisements remain incomplete. The merge reconciles both per-target
catalogs from the source registry before retaining evidence; point counts from
either pre-merge catalog are not publication authority. Windows differences
remain explicit target-applicability or unauthored-path facts, and none is
credited as a pass. The latest source-bound tranches add 322 armed shared-runtime global
absence recipes, nine armed direct-native global absence recipes, 18 physical
no-debugger ABI closure recipes, 106
terminal-builtin closure recipes, four public SQLite extension-load and
cr-sqlite enablement closure recipes, four
loader/source-acquisition recipes, 19 native module-runner ABI
lifecycle recipes, one armed namespace-inspection closure, two armed
whole-environment zero-decision branch recipes, 14 asymmetric/EVP
crypto recipes, eight
owner-authenticated timer-control recipes, nine bounded authority-control
refusals, six retained HTTP/process owner refusals, two owned filesystem-close
executions, three incomplete/invalid authority-control refusals, one loader-private
post-capture absence, five cached
system-information authorization scenarios and twelve asynchronous path-operation scenarios for
the `readdir` and `realpath` branches, twelve retained-file `chmod`/`utime`
scenarios, five retained-target direct `statfs` scenarios, twelve complete
malformed/attribution/principal scenarios for retained metadata and whole-file
reads, thirty-six complete malformed/attribution/principal scenarios for system
information, environment, and stdout, three complete adversarial loopback TCP
connect scenarios, plus five zlib stream lifecycle recipes, eleven TLS lifecycle
recipes, and a principal-owned network stamp recipe. Ten internal locale and
accessibility state-object surfaces no longer exist: normalized mutable state is
held in module singletons while host snapshot inputs and update hooks remain
explicit globals. Thirteen memory-debug implementation surfaces likewise no
longer exist: the timer, samples, counters, and options are captured behind the
deliberate `__exactMemoryDebug` diagnostic API. Six `__OriginalPromise`
surfaces likewise no longer exist: rejection tracking
retains the unwrapped constructor in its install closure instead of publishing
a project-visible bypass around the wrapped global constructor. Eleven
write-only process-compatibility diagnostics likewise no longer publish
bootstrap progress, fallback objects, or exception strings to project code;
the sole control predicate is local to the compatibility IIFE. The
decompression unhandled-rejection filter sentinel is module-local as well,
rather than a project-writable global. Bundled-entry remap consumption is now
tracked by exact host entry-path value in the trusted module-loader closure
while the host entry-path input remains explicit. The libuv EOF value is now an
immutable constant at both internal consumers rather than a project-writable
transport sentinel. Readable-stream compatibility retry scheduling is likewise
captured inside bootstrap rather than exposed as a mutable global. The resource
recipes create, exercise, and release their runtime/principal-owned
native state in one bounded invocation. Fourteen Linux/Android-only
`node:constants` exports now carry source-bound Apple absence evidence from the
real public module path rather than remaining generic availability residuals.
Async evidence remains open through a bounded event-loop quiescence drain and
binds both the dispatch edge and the worker edge actually observed at runtime.
The armed `mkdtemp` family remains unresolved: its returned generated path is
not yet retained and authenticated strongly enough for the executor to remove
the created directory, so it cannot claim safe public execution or cleanup.
Both candidate matrices therefore remain unsupported;
this partial implementation is not grounds to promote a target or retain
production benchmark evidence.

The source-bound native-read harness admits inherited members only for 57
static data constants whose descriptors prove the exact property path. Runtime
evidence records the owner depth for every path segment and requires a positive
final depth; own-property substitution, inherited callables/accessors, instance
members, and dynamic tables remain rejected.

The builtin route analyzer now admits module bindings only when their source
initializer is recursively proven intrinsic and the binding is never
reassigned. This reduces `ambiguous-static-enforcement-route` from 7,496 to
7,092: an opaque reassignment still fails closed, and removing false route
ambiguity is not itself public execution evidence. The later terminal-builtin
denial tranche resolves 106 exact source and alias facets before module evaluation,
including 49 otherwise ambiguous call graphs, so the current residual counts
are 7,043 ambiguous routes. The current Apple catalog has 23,815 required,
2,469 executable, and 21,346 unresolved fixtures; Windows has 23,700 required,
2,327 executable, and 21,373 unresolved fixtures. Nine direct native
compatibility, diagnostic, IPC, signal, process, and working-directory globals
are now deleted after lazy installation on the armed lockdown path, and their
exact source-derived JSI cells prove physical absence. The armed runtime also
deletes the configurable `Exact.accessibility` and `Bun.accessibility`
application-state namespaces after trusted shared-runtime installation and
before the compartment baseline is finalized. Accessibility snapshots,
notification hooks, and module-local state remain available to trusted web and
React Native compatibility modules, while all 28 source-derived public
namespace/member cells prove physical absence. Change-listener registration is
closed with the rest of the namespace because future callback payloads cross
the same ambient embedder channel; it is not merely attribution plumbing. The
armed runtime further deletes `BroadcastChannel`, `MessageChannel`, and
`MessagePort` after trusted bootstrap captures any internal constructors. All
29 inventoried constructor/member cells prove physical absence without
breaking the unarmed diagnostic compatibility runtime. The physical
no-debugger tranche also executes all nine debugger ABI functions on both exact
candidates and binds their nine corresponding native-operation facets to the
same zero, null-pointer, or no-event results; the Windows `get_scripts` stub
returns no debugger data. Together with the other closed families, the
preceding messaging checkpoint carried 386 closed fixtures per exact target,
and the loaded Apple engine passed all 386 with zero typed or legacy decisions.
Cache Storage, Web Storage, and IndexedDB now follow the same physical-absence
rule. The armed runtime deletes all 13 ambient storage roots while diagnostic
runtimes retain them. Sixty-three helper, callback, and release members that
were previously labeled non-capability are now closed with the object graph
that would mint them; this removes 180 inapplicable callback-invariant
obligations instead of pretending those unreachable members are independent
APIs. The 232 source-derived storage cells raise each exact target to 618
closed fixtures; the loaded Apple engine passes the complete batch with zero
typed or legacy decisions. Its 2,800-fixture callback-invariant batch binds the
current source-derived shape: 507 fixtures for each of four target-wide
scenarios, 382 for each of two authority scenarios, and eight non-capability
controls. The application runtime
does not install the worklet-only `worklet`, `measure`, or
`scheduleOnAppRuntime` namespaces. Eleven exact source facets now prove that
runtime-variant boundary through physical absence, including `worklet.clamp`
and `worklet.lerp`, which are closed with their absent namespace rather than
misreported as independently reachable pure helpers. This raises the exact
closed batch to 629 fixtures without treating worklet-runtime reachability as
application-runtime authority. The exact SQLite refusal tranche then executes
both `loadExtension` and `enableCrSqlite` through the `Database` and default
exports, using in-memory databases through both public module aliases. Each
exact target now carries 633 closed fixtures without constructing filesystem
authority or loading native code.

Six retained TCP metadata/control operations (`__exactTcpLocalAddr`,
`__exactTcpRead`, `__exactTcpRemoteAddr`, `__exactTcpSetKeepAlive`,
`__exactTcpSetNoDelay`, and `__exactTcpWrite`) have two actionless logical
`metadata` fixtures apiece. A physical loaded-engine audit drove each family
through a harness-owned loopback client and found that the native operation
emits the retained socket's `repeat` decision. The evidence validator therefore
correctly rejects a zero-decision recipe: those twelve cells remain residual
until the semantic registry binds the retained lease action/resource/owner to
the logical fixtures (or explicitly reclassifies the branches). UDP address and
WebSocket release require their own retained-owner setup and were not inferred
from the TCP result.

### WP0 artifacts and gate

The schemas, registry inputs, examples, invalid goldens, and generated legacy
table live under `capsec/`. `contract-files.json` is a closed inventory of every
schema, registry, example, invalid fixture, and generated artifact; an unlisted
or missing file fails validation, and every registered invalid fixture must be
executed and rejected.

`capsec-contract.mjs` rejects duplicate keys, validates Draft 2020-12 schemas,
checks cross-file action/resource references, requires selector and occurrence
examples for every authorable resource kind, requires containment vectors for
every handle/dynamic resource kind, and joins definitions to normalizers and
coverage edges exactly. It also checks all five digest vectors, keyed canonical
sets, target cells, armed graph/root/binding/protected-object invariants, and an
exact one-to-one reconciliation with live rows inside
`CAPABILITY_BIT_DEFINITIONS`; commented or outside-constant Rust lookalikes are
not authority. `--check` is non-writing and participates in the repository's
single generated-drift gate.

## Implementation plan

The work is organized around stable work packages so Linear tickets can remain
connected to this document even if ticket titles or implementation details
change. Each package lands tests and generated outputs with its code; a later
phase does not postpone testing an earlier one.

### WP0 — Freeze the target semantics and registry contract

Define the Ibex destination vocabulary and the schemas for capability
definitions, effects, authority selectors, effect occurrences, coverage edges,
target cells, policy rules, canonical policy, and armed snapshots. Adapt Oden's
semantics deliberately rather than copying Oden/Deno-only surface rows.

Decide the initial disposition of every existing Ibex capability: authorable,
deny-only/closed, absent, unsupported, or non-capability. Settle exact versus
tree path semantics; fetch/connect/listen/resolve endpoint resources; process,
stdio, inspector, storage, device, crypto, and runtime-internal categories; and
which rows are terminal, static-only, handle-delegable, or dynamically
acquirable.

Acceptance:

- Schemas and canonical examples cover every initial authorable resource kind.
- Every current capability bit has an explicit destination disposition.
- Positive action wildcards and untyped canonical strings are impossible.
- Decision precedence, principal intersection, staged effects, handles,
  revocation, caching generations, and digest domains are specified.

Implementation: frozen by ENG-24144 in `capsec/`; validation is
`bun run check:capsec-contract` plus
`bun test packages/ibex-devtools/src/scripts/capsec-contract.test.mjs`.

### WP1 — Generate the registry and completeness inventory

Implement the four generated datasets, code generation, drift checking, and the
surface inventory. Seed the inventory from native host calls, loader branches,
builtin exports, startup/inspector paths, callback queues, and resource families.

Acceptance:

- Every inventoried surface has exactly one coverage edge or explicit
  non-capability/closed classification.
- Adding an unclassified surface or unknown capability fails generation/CI.
- Generated bindings and documentation are byte-reproducible.
- Target cells begin honestly as unsupported/closed until fixtures prove more.

Implementation: ENG-24145 generates the production coverage registry, exact
candidate-target product, source-surface/fixture-obligation manifest, stable-ID
schema, review tables, and Rust/C++/JavaScript/TypeScript bindings. Discovery is
source-derived across native globals, public host/embedder/worklet ABI,
builtin exports, installed globals, loader branches, callback producers,
startup installers/scripts, inspector operations, and CLI commands. Unknown
surfaces/actions/normalizers fail generation; source filenames never choose a
semantic classification. `bun run check:capsec-registry`,
`bun run check:capsec-contract`, their focused tests, and the repository drift
gate are non-writing checks.

Implementation alternatives retain their source-derived target variant,
normalized applicability, backend/stub disposition, and a globally unique
branch ID. Every target cell lists the exact applicable branch IDs even while
unsupported; fixture obligations are scoped to those branch IDs. Promotion
must execute the complete obligation union for exactly that source-derived
branch set. Unknown, wrong-target, omitted, or invented branch evidence fails
validation, while a branchless target can advance only to target-proved
`absent`. A known `unsupported-stub` branch cannot promote. Weak-fallback and
source-uncertain provenance are resolved only by the WP10 report's executed
obligations bound to the exact target binary; they are not conformance evidence
by themselves.

The ENG-24145 baseline contains 6,804 logical surfaces and coverage edges,
6,984 implementation-branch rows, and 11,048 source references. It includes
2,823 builtin surfaces: 2,696 export/prototype/inherited-shape APIs plus 127
specifier aliases. Inherited CommonJS and authored shared-runtime class shapes
are traversed exactly when their base is source-resolvable; otherwise a
review-bound dynamic-table sentinel closes the entire inherited property domain.
Builtin enforcement-route discovery likewise follows only immutable source
provenance: direct calls, constructor bodies, locally authored callable
alternatives, and literal CommonJS dependencies joined to the exact manifest
source key and export. Reassigned or computed dependency receivers, opaque
callable alternatives, intrinsic mutation, and unresolved cross-source exports
routinely remain explicit ambiguities. The bounded `dns/promises` exception
projects exactly 42 callable carrier rows from the structurally reviewed
`node_dns` provider plus three provider Resolver `_handle` instance rows. Both
complete source ASTs, their exact source keys and paths, and the projection
schema are bound to a pinned inventory digest; the semantic classifier carries
an independent hardcoded digest and exact 45-name review set. Any one-sided
source, scanner, metadata, or classifier drift therefore fails closed. The
projection does not invent a call route: every row retains one explicit
carrier/provider or constructor-instance ambiguity and no terminal. Multiple
source-proven terminals are retained
rather than guessed away; WP10 still requires bounded public arguments to show
which route the bound engine actually executes.
It also includes 178 host-ABI surfaces: the complete 84/36/10
`ex_host_*`/`ex_hermes_*`/`ex_worklet_*` families, one `ex_android_*` entry,
and 39 Java plus 8 JNI Android bridge routes. All 6,804 candidate-target cells
are unsupported; 760 known
parameter/provenance-dependent effect edges are explicitly
`conditional-unrefined` and therefore unpromotable.

Generator hardening now makes the reviewed/discovered join bidirectional,
rejects overlapping logical-branch predicates (including subset and
cross-fact overlaps), fails on unrouted fixed rows and Android provider
overloads, understands adjacent C++ literals and digit separators, and derives
implementation branch identity from the target variant rather than mutable
source-reference paths. Provenance remains digest-bound without becoming the
semantic identifier.

### WP2 — Implement the typed policy and decision core

Replace string parsing and matching with the typed Rust semantic core. Implement
canonicalization, deterministic serialization, digest computation, decision
precedence, conjunctive decision sets, staged decisions, principal
intersection, negative generations, and cache keys.

Acceptance:

- Property and differential tests cover canonicalization and matcher behavior.
- Unknown/malformed definitions fail in every mode.
- Adding a future vocabulary action cannot widen an existing positive policy.
- The decision core consumes normalized typed effects, never authored strings.

Implementation: ENG-24146 adds the product-neutral `crates/capsec-semantics`
workspace member. It strictly ingests the frozen WP0 definitions/rules, uses
RFC 8785 canonical bytes and domain-bound digests, validates typed selector and
occurrence semantics, evaluates every deny stratum before positive authority,
intersects constrained principals, conjoins effects, rejects speculative stage
facts, binds revocation/dynamic/handle generations, and keys decisions by the
complete frozen semantic identity. Rust golden and property tests consume the
same WP0 fixtures as the JavaScript/schema validator; CI runs the focused Rust
test and clippy gates without requiring a Hermes build.

The action-definition `selectorConstraints` fields are executable semantics in
the Rust core, not schema commentary: the same validator now governs armed
floors, denials, process/escalation ceilings, handles, dynamic grants, and
normalized occurrence requests. A corpus test routes every declared invalid
fixture through the corresponding strict JSON, selector, or occurrence ingress.
Principal and every other semantic set now use one JCS-byte order at engine,
host, and core boundaries. IPv4-mapped IPv6 values canonicalize to their
embedded IPv4 identity, RFC 8785 number bytes use ECMAScript tie-breaking, late
listen/device facts are required only when their stage produces them, and the
decision cache is bounded and generation-evictable.

### WP3 — Rebuild policy generation and import-site authoring

Adapt LLP 0014's import-site generator to emit authored-source inputs and the
typed canonical review policy. Preserve provenance, root-only grant authority,
request/delegation intersection, union across authorized root import sites, and
explicit import/endowment surfaces.

Acceptance:

- Generated policy contains every package in the integrity-bound graph.
- Every grant has source/delegation provenance.
- Package code cannot self-grant through import attributes or manifests.
- Drift reporting distinguishes authority expansion, narrowing, and semantic
  vocabulary changes.

Implementation update (2026-07-12): policy authoring reuses the contract's
action-specific selector validator. Drift review performs containment-aware
diffs for floors, denials, ceilings, package/builtin imports, endowments, and
principal identities, classifying expansion, narrowing, mixed, identity, and
vocabulary changes. Every semantic set uses canonical UTF-8/JCS byte order.

### WP4 — Arm immutable snapshots through the CLI, host, and engine

Build the trusted arming pipeline that binds canonical policy to an execution
and hands the authenticated immutable snapshot to the host/engine. Report the
actually loaded profile and digests from the decision context.

Production runtime construction owns `runNonce`. After authenticating any
supplied snapshot template, it discards the artifact/caller nonce, generates a
fresh 128-bit value with the operating-system CSPRNG, and finalizes the armed
digest before handing the snapshot to the host and engine. Fixed nonces remain
valid only in contract fixtures; RNG failure refuses construction.

The same construction boundary owns every compatibility input that may affect
trusted bootstrap shape. It reads an admitted launcher control at most once
before arming, normalizes it into the closed, sorted
`bootstrapCompatibilityModes` set, and includes that set in the final snapshot
digest. After arming, native bootstrap receives only the authenticated fixed
projection: it does not reread the launcher environment, and its temporary
carrier is sealed before project code. These modes grant no authority and are
not environment entries.

The snapshot separately requires `environmentBase: []`. An armed runtime never
copies the host process environment into JavaScript or falls through to it.
Values created during execution live only in a runtime-scoped map keyed by the
authenticated principal; exact-name read, write, and non-empty enumeration are
independently authorized at their requested and commit stages.

Acceptance:

- The runtime refuses before project code on stale/mismatched policy, registry,
  engine target, package graph, or required target cell.
- Mutable authored files and environment variables are not consulted after
  arming.
- The environment base is explicitly empty, and compatibility shape is a
  digest-bound fixed-mode projection rather than an environment backchannel.
- Audit, denial, handle, and dynamic-permission records carry the loaded
  semantic identity and snapshot generation.

Implementation status (2026-07-12): Rust ingestion checks the WP0 root,
authority/graph-edge, root-binding, and four protected-object invariants and
uses the checked digest contract's semantic-set canonicalization. Production
derives exact target cells from authenticated registry data; because every
current cell is unsupported and no target is advertised, ordinary execution
refuses before project code. Arming measures the artifact containing the loaded
Hermes factory, requires structural lockdown/compartments/frame attribution,
uses per-run nonces, rejects every generated closed startup control, and binds
an immutable Host context to each runtime. The old unarmed constructor is
non-executable. Package principals are stamped only after exact locator,
resolved root, and whole-tree integrity verification; package-to-root imports
require an exact authenticated graph edge. Default project-root discovery
selects only a canonical ancestor containing `package.json`; a manifestless
entry must receive an explicit trusted `--project-root` and otherwise refuses
before policy construction or project evaluation.

Implementation update (2026-07-12): canonical policy now carries the exact
registry digest as well as vocabulary identity. Production strictly
deserializes the complete typed artifact, recomputes its self-digest, validates
every authority against current definitions, and refuses independently
recomputed stale vocabulary or registry policies before projection. Bounded
process ceilings containing package logical roots expand into one bound row per
authenticated package principal rather than losing their owner identity.

Implementation update (2026-07-17): the semantic decision set now carries a
distinct root-authority-ceiling stratum before principal denials. Canonical
policy v2 root-ceiling rows populate it only for the authenticated root;
fixtures prove an empty bounded root ceiling denies `AmbientRoot`, a matching
row permits it, and package floors are unaffected. `ArmedSnapshot` also admits
strict embedded protected-artifact facts, enforces the host/embedded role union
and per-object range non-overlap, and cross-binds role, object, range, and
digest in `ExpectedArmingIdentity`. The arming ABI is
`ibex-capsec-arming-2-root-ceiling-embedded-ranges-bootstrap-seal`.
`ArmedSnapshot` also binds a strict immutable root-only bootstrap authority
floor. Its positive stratum requires an evaluator-owned one-way token and
bootstrap matches cannot fall through to `AmbientRoot`; retained context clones
therefore deny the same effect after sealing. Hermes requires the active Host
to consume the token exactly once after armed-posture verification and before
application attribution. Production boot construction intentionally publishes
an empty bootstrap floor: the current bootstrap performs no root-attributed
capability effect, and its authenticated runtime inputs execute under the
transparent runtime principal. Inventing a positive selector would widen
authority rather than complete the mechanism. The one-shot token,
seal-before-application transition, nonempty-floor semantics, and
retained-context denial remain covered by mechanism tests; any future
root-attributed bootstrap effect must add its exact selector and a real
application-level retained-callback fixture in the same change.

Implementation update (2026-07-25): `ArmedSnapshot` strictly ingests the
optional runtime-extension authority capsule and requires a
`runtime-extension-authority-capsule` protected role. `ExpectedArmingIdentity`
independently binds the capsule digest and the launcher's actual sorted linked
object/range/content identities; descriptor or linked-artifact substitution
therefore refuses even when an attacker recomputes the outer armed digest. The
protected artifact's `contentDigest` is the ordinary SHA-256 of the exact
materialized capsule bytes; it is intentionally distinct from the
domain-separated semantic `authorityCapsuleDigest`, which is independently
recomputed after strict parsing.
Legacy armed construction may claim only the empty projection. Extension-aware
construction supplies the exact snapshot and authority digests, and the Host
rechecks the latter against the claimed context before any operation. Before
Hermes allocation, the structurally validated C registry must also serialize
its closed identity/surface projection; the Host strictly parses and
exact-compares it with the capsule, so attaching the correct authority digest
to a changed operation, callback, provider, module, global, feature, or
bootstrap table still refuses construction. A
successful generic typed decision mints a random nonzero context-local opaque
lease bound to capsule, namespace, operation, class, canonical resource
digest, and constrained principals; check/revoke and context release cannot
transfer it across constructions. Diagnostic/unarmed Host construction does
not authenticate extensions. Each copied nonempty bootstrap payload is
SHA-256 checked against its capsule-bound canonical digest through a bounded
generic Host ABI before Hermes allocation; invalid, oversized, or mismatched
inputs refuse. Conformance fixtures use an armed test profile through this
same path rather than a permissive bypass.

### WP5 — Convert filesystem effects and checked-object execution

Map all filesystem surfaces to explicit list/read/write/watch effects and typed
exact/tree resources. Replace check-then-reopen paths with retained handles or
verified post-open identities, including symlink, hard-link, rename, metadata,
special-file, and platform alias behavior.

Acceptance:

- Multi-effect operations authorize every disclosure/read/write stage.
- Symlink/hard-link/TOCTOU fixtures operate on the object actually used.
- File descriptors and handles retain owner, authority source, revocation
  generation, and resource identity for repeated operations.

Implementation status (2026-07-11): synchronous and worker-backed async native
`fs.open` now have an
armed-only staged adapter for read, write, create, and truncate. It authorizes
the requested logical path, retains and verifies the resolved parent directory
inside the authenticated logical root, distinguishes existing from
absent-create discovery, and authorizes the operation effects before `openat`.
Final symlinks are closed with `O_NOFOLLOW`; parent symlinks that resolve outside
the authenticated binding are refused. Truncation is deferred until commit has
authorized the actual `fstat` identity and retained descriptor ID, so a denial
cannot mutate an existing or absent target. An explicitly presented typed
bearer ID participates in every stage. Legacy hosts retain their existing gate;
armed refusal never falls back to it. The fd registry retains the parent
descriptor and presented bearer ID, and every armed read or write re-authorizes
at `repeat` against fresh identities and current authority generations. Async
commit runs on the worker before the descriptor is delivered to JavaScript;
registry publication remains on the attributed runtime thread. The remaining
descriptor metadata/disclosure operations (`fstat`, truncate, sync, ownership,
mode, and times, including their worker-backed forms) reuse the retained
descriptor and typed repeat checks. Synchronous and worker-backed whole-file
reads use their own conjunctive registry edges: `fs:list` authorizes requested
path lookup and retained-object discovery, then `fs:read` authorizes commit
immediately before the first byte can be observed and every repeat lease. The
private descriptor open between discovery and commit discloses no file bytes
and does not add a redundant read-discovery decision. Public `Cargo.toml`
allow/deny recipes prove the six-decision component-walk, commit, and repeat
sequence and fail closed at the
first list decision when lookup authority is absent. Whole-file reads accept
only retained regular files. They perform one full repeat decision per
descriptor lease and cheaply compare
negative, dynamic, and handle generations before each chunk; any change
re-enters the full evaluator before more bytes are observed. Leases are local
to the exact operation and retained descriptors, so operation/gate/principal/
object facts cannot collide and descriptor reuse starts a new lease. `stat` and directory
enumeration likewise use retained no-follow targets and their own `fs:list`
edges; enumeration rechecks before every disclosed entry. Worker-backed path
and descriptor stat use the async stat edge and recheck on the worker before
serialization. Sync and async lstat retain the link object itself with
`no-follow-final` semantics. Realpath returns the canonical path of the retained
no-follow descriptor under its own list edge. Whole-file replace,
append, and worker-backed write use their own edges, authorize absent-create or
existing state before `openat`, commit the actual regular file before delayed
truncation, and recheck before each write/flush. The registry's ordinary
`fs:list` lifecycle remains requested/discovery; retained-object Repeat checks
are separately bound to exact native filesystem terminals by the source-authored
internal-observer stage contract. Non-recursive synchronous and worker-backed
directory creation use the `mkdir` edge: they authorize the requested path,
retain and verify the parent, preauthorize absent creation, and create exactly
once with `mkdirat`. A failed post-create check leaves the new, still-empty
directory in place: reopening the name to verify and then calling `unlinkat`
would permit a replacement race, so armed code deliberately performs no
name-bound rollback. Worker-backed single-path `chmod` and `utime` are the
narrow metadata-mutation exception: both retain the target, authorize commit,
and repeat authorization on the worker immediately before `fchmod`/`futimes`.
Their synchronous, link, ownership, and descriptor variants remain closed.
`mkdtemp` also remains closed at the armed public entry point. Recursive
creation remains closed until every created component can run the full
object-bound sequence independently. Path removal
also remains closed in armed execution: retaining a target descriptor and then
calling name-based `unlinkat` would still permit a swap between identity check
and deletion, so sync and async denial fixtures require the original file or
directory to survive until a genuinely race-safe removal strategy is adopted.
The same armed denial fixture covers unported sync and async rename, copy,
symlink, and hard-link paths, proving they cannot mutate either source or
destination through the legacy oracle while their typed staged adapters remain
pending.

Post-review hardening (2026-07-12) preserves ENOENT/ENOTDIR and Node-shaped
denials, avoids read-opening metadata targets and blocking FIFO lstat, shares a
bounded runtime-scoped parent-directory descriptor cache, and rechecks regular
whole-file reads per chunk. Open/create rollback ownership is established only
by successful `O_CREAT|O_EXCL`; state races rediscover and reauthorize before
retry, so a competitor's file is never treated as ours to unlink or truncate.
FD, IPC, and transferable registries bind runtime nonce plus device/inode and
evict stale rows on descriptor-number reuse. Async worker exceptions and result
delivery failures reject instead of aborting or hanging, completed closures
release descriptor captures eagerly, and callback attribution intersects live,
captured, owner, and scheduler principals. Async directory traversal, realpath,
watch polling, recursive-readdir spelling, and non-recursive `rm` parity now use
worker-backed paths; that worker plumbing does not reopen the armed `mkdtemp`,
watch, recursive, or removal entry points described above. Windows preserves
distinct errno values and implements recursive-mkdir results, exclusive copy,
truncate, utimes, and statfs through the portable host ABI.

The first Windows mutation slice is deliberately smaller than the flag's
legacy meaning. Armed `__exactFsOpen(path, "a")` accepts only an **existing**
regular file. It submits `fs:write` Requested before lookup, uses
requested/discovery `fs:list` to authenticate the existing leaf, opens that
leaf with native append-only access and no delete sharing, object-matches it,
then submits `fs:write` Commit with the retained identity and authenticated
package-source generation. An absent leaf returns `ENOENT`; `O_CREAT` is never
exercised. The descriptor registry retains the opaque append-only file,
runtime, owner, principals, bearer, namespace, object identities, and handle
ID. Armed scalar `__exactFsWrite` validates that registry entry before
inspecting caller bytes, submits one `fs:write` Repeat, performs one
short-write-preserving append through the same file, and rechecks identity
after I/O. The JavaScript position argument cannot weaken append semantics.
Requested denial happens before lookup and leaves bytes unchanged; Repeat
denial happens before mutation; a hard-link alias to authenticated package
source refuses at Commit when its retained object/generation joins the
package-source guard. Numeric flags, `"as"`, `"ax"`, read/write modes,
truncate/create modes, positional non-append writes, synchronous vector writes,
and the remaining write-capable descriptor families
remain closed or residual. Worker-backed append writes and synchronous
durability are the bounded exceptions described below.

Armed Windows `__exactReadFile`, `__exactStat`, `__exactLstat`,
`__exactReaddir`, retained `__exactFsOpen`, `__exactFsRead`,
`__exactFsReadv`, `__exactFsWrite`, `__exactFsFstatSync`, and
`__exactFsReadFileAsync`, `__exactFsReadAsync`, `__exactFsReadvAsync`,
`__exactFsWriteAsync`, `__exactFsWritevAsync`, `__exactFsFsyncSync`, and
`__exactFsFdatasyncSync` are the first
installed Windows filesystem effects to leave the legacy path oracle.
Their private
native bridges derive the runtime generation, actor, and canonical
constrained-principal stack from engine provenance, resolve only virtual
syntax, and delegate to the cross-platform `RuntimeVfsSession` retained-object
operations. Whole-file read emits requested/discovery `fs:list` followed by
commit/repeat `fs:read` for the selected object and deliberately inherits the
VFS bounded whole-file input limit. Stat opens the selected object for metadata
only and emits requested/discovery/repeat `fs:list`; the list lifecycle has no
Commit observation, and Repeat runs immediately before Node-shaped metadata
serialization. Stat also handles the authenticated mount root without
inventing a namespace parent. Lstat uses the same three-stage list lifecycle
with `no-follow-final`, stops traversal at a final reparse object, reopens that
object relative to its retained parent for metadata only, and object-matches it
before Repeat and disclosure. Unlike the POSIX adapter's additional root-walk
observations, the retained authenticated mount handle is structural session
state on these routes, so no synthetic observations are claimed.
`VirtualFileSystem::readdir_authenticated` emits requested/discovery `fs:list`,
reopens a nested final directory relative to its retained parent with
`FILE_LIST_DIRECTORY` access and without delete sharing, and object-matches
that handle before enumeration. It queries `FileIdExtdBothDirectoryInformation`
on the retained handle, uses the long name as the sole output coordinate,
validates but never emits the associated 8.3 short name, preserves malformed
UTF-16 as an explicit byte marker, sorts deterministically, and authorizes
Repeat once for each member immediately before adding that name to the returned
listing. The authenticated mount root is already retained and therefore has no
fabricated parent; the synthetic namespace root `/` exposes only mount names
and requires no filesystem authorization. Refused or malformed typed calls
return the VFS error and never fall through to
`exactResolveVfsPath`, `requireReadCapability`, `ex_host_fs_read_file`,
`ex_host_fs_stat`, `ex_host_fs_lstat`, or `ex_host_fs_readdir`.

Read-only `__exactFsOpen` uses the same contained discovery protocol, then
opens and object-matches a regular file for read at Commit. The private Host
ABI returns the exact `File` plus its namespace, retained parent/final object
identities, retained handle ID, canonical virtual path, and presented bearer.
The Windows engine keeps that opaque file behind its existing monotonically
allocated numeric descriptor table together with the engine-derived runtime
and principal owner; JavaScript cannot forge a handle or move it between
owners by guessing an integer. `__exactFsFstatSync` first enforces that registry
ownership, then authorizes one `fs:list` Repeat against the stored parent,
final object, handle ID, and bearer and obtains metadata from the same retained
file. It performs no pathname lookup and cannot fall back to `ex_host_fs_fstat`.
`__exactFsRead` and synchronous `__exactFsReadv` apply the same owner/runtime
and readable-open checks, then authorize one `fs:read` Repeat against those
stored occurrence facts before reading the retained file itself. The vector
route validates at most 1,024 destinations and a `uint32` aggregate length,
acquires one owned aggregate result, and scatters into JavaScript buffers only
after the Repeat and retained-identity postcheck succeed. Sequential reads
advance that file's cursor; positional scalar and vector reads restore it
before returning. The VFS checks the retained object identity before
authorization and after I/O, and the armed engine cannot fall back to the
pathname-based legacy read oracle.
Armed write/create/truncate/append open flags and unsupported numeric flag bits
return `EPERM` before virtual resolution, legacy authorization, or host file
creation. Unarmed compatibility continues to use the existing host path.

Armed `__exactFsReadFileAsync` captures the runtime nonce, canonical
constrained-principal stack, actor, virtual input, and optional bearer on the
runtime thread, and uses that same immutable stack for its native-worker
operation lease and private typed ABI call. The path branch does not resolve or
authorize before dispatch: on the worker, `VirtualFileSystem::read_authenticated`
performs Requested/Discovery `fs:list`, Commit `fs:read`, and a generation-aware
Repeat before each bounded read chunk. Requested denial therefore happens on
the worker before lookup. The descriptor branch retains the owner/runtime-bound
opaque file entry for the operation, holds its per-file I/O mutex from the
current cursor through EOF, and calls
`read_descriptor_authenticated` once per 64 KiB chunk plus EOF. Each call
submits a fresh exact-object `fs:read` Repeat and advances the cursor only after
that decision succeeds. Neither branch can reopen the legacy pathname oracle,
and Promise settlement still occurs on the attributed runtime thread.

Armed scalar `__exactFsReadAsync` and aggregate `__exactFsReadvAsync` use a
separate single-acquisition protocol on both installed filesystem backends.
The runtime thread first validates the owner/runtime-bound readable descriptor,
safe position, and bounded byte count; vector validation inspects at most 1,024
actual ArrayBuffer views and records only their lengths before authorization.
The worker operation lease installs the exact captured principal stack. On
POSIX, one `fs:read` Repeat against the retained parent, duplicated file object,
stored path, owner, and bearer executes immediately before the single
`read`/`pread` or `readv`/`preadv`; vector destination storage is allocated only
after that decision. On Windows, the worker holds the retained file's I/O mutex
and invokes an async-surface-specific typed VFS bridge, which performs the same
exact-object Repeat immediately before acquisition. Both backends return owned
bytes and publish them to JavaScript only after success; the vector facade
validates all destinations before scattering that aggregate. Empty requests
perform no acquisition and emit no decision. Positioned requests preserve the
retained cursor, while a sequential request advances it.

Armed scalar `__exactFsWriteAsync` and aggregate `__exactFsWritevAsync` use the
corresponding worker-side retained-object protocol. The runtime thread first
validates the owner/runtime-bound writable descriptor and snapshots no more
than 1,024 actual ArrayBuffer views with an aggregate host-I/O bound. On POSIX,
the worker submits one surface-specific exact-object `fs:write` Repeat against
the duplicated retained descriptor immediately before `write`/`pwrite` or
`writev`/`pwritev`. On Windows, the route accepts only an existing retained
append-only descriptor, holds its I/O mutex, and passes either the scalar bytes
or one flattened vector aggregate to a surface-specific typed VFS bridge. That
bridge object-matches before the Repeat, appends once, and object-matches again
before returning. Flattening preserves one logical `writev` mutation and
prevents partial authorization across component buffers. Empty scalar and
all-empty vector requests return zero without a typed decision.

Synchronous descriptor durability now has the same exact-object boundary on
both installed backends. `__exactFsFsyncSync` and
`__exactFsFdatasyncSync` validate a retained writable descriptor and submit one
`fs:write` Repeat attributed to their own distinct public surface edge
immediately before `fsync`/`fdatasync` or `sync_all`/`sync_data`. Windows holds
the retained file's I/O mutex while the private VFS bridge object-matches,
authorizes, flushes, and rechecks. POSIX uses the retained parent plus the live
descriptor identity immediately before its syscall. Durability does not borrow
the prerequisite open edge, and cleanup remains outside the decision window.

This is a bounded slice, not Windows filesystem promotion. Unsupported
write-capable open modes, synchronous vector/positional mutation, and the other
installed Windows filesystem routes remain residual until their own
retained-object contracts are implemented.
Those residual routes are nevertheless closed in armed execution. The
installed `__exactWriteFile`, `__exactMkdir`, `__exactRealpath`,
`__exactReadlink`, `__exactAccess`, `__exactTruncate`, `__exactStatfs`,
path and descriptor forms of `__exactFsWriteFileAsync`, every operation
selected through `__exactFsPathAsync`, and every target kind selected through
`__exactFsStatAsync` return structured `EPERM` before path conversion,
descriptor lookup, caller-buffer acquisition, worker dispatch, or legacy
capability probing. On a target without a typed synchronous
`__exactFsWritev`, the JavaScript `writevSync` fallback invokes the
bootstrap-captured armed mutation guard before decomposing the vector into
scalar writes. Unarmed compatibility and the typed retained-object Windows
routes listed above are unchanged.
Exact-target recipe generation now
schedules the five `__exactReadFile`, five `__exactStat`, and five
`__exactLstat`, five `__exactReaddir`, six read-only `__exactFsOpen`, and four
`__exactFsRead`, four `__exactFsReadv`, plus four `__exactFsFstatSync`
scenarios on Windows. It also schedules eleven executable
`__exactFsReadFileAsync` rows: all six path scenarios and five descriptor
scenarios; descriptor denial remains residual because the same denied floor
cannot create its required retained setup handle. It additionally schedules
four executable retained-descriptor rows apiece for `__exactFsReadAsync` and
`__exactFsReadvAsync` on both targets; each deny row remains residual for the
same source-setup reason. It also schedules four executable rows apiece for
`__exactFsWriteAsync` and `__exactFsWritevAsync` on both targets, plus four
apiece for `__exactFsFsyncSync` and `__exactFsFdatasyncSync` on both targets.
Each deny row remains residual because the denied `fs:write` floor cannot
construct its prerequisite writable descriptor. The generator continues to
classify the remaining 142 callable Windows filesystem
recipes under
`public-surface-filesystem-not-typed-on-target`; five `__exactAppendFile`
recipes remain under the more exact
`native-public-operation-not-installed-on-target` build-source boundary. The
corrected Windows catalog is 23,505 required / 2,453 fully executable / 3,122
internally verified / 17,930 unresolved with digest
`sha256-Pc_rPPo2gn0lrqXTz6uXaz_x-lpoHBLXPUpeIKmUU4M`. It no longer promotes
19 private native module-runner lifecycle ABI rows while LLP 0026 keeps
Windows compatibility-only. Apple is independently shaped at 23,846 / 2,799 /
3,136 / 17,911 with digest
`sha256-hzFaFp6ca8rOPfB-aswmofNj87HnLQAhzJZgbDPfvg0`. The six new required
rows on each target are the landed `compat --probe` CLI surfaces; they remain
honestly unresolved until an exact public invocation is authored.

Integrating the lockdown error-prototype override repair changed the
source-derived taming digest to
`sha256-db554fcb6c9c245527ee92fc34988671b3797dfa15676ad75e72a3734ffd6c5c`
and the reviewed evaluator identity to
`hermes-evaluators.3e6954de6300cf7cbd32f27af9077c4a0a55dc951e106a44a991791846e9971f`.
The reachable evaluator family and all three reviewed engine profiles remain
unchanged. The identity composition changes catalog digests but not semantic
counts; the six landed CLI surfaces account for the count increase above.

The Windows TCP connect path now uses the typed network adapter. `Requested`
authorizes the caller's host/port before DNS, `Candidate` authorizes every
member of the complete canonical resolver set before its connect attempt, and
`Commit` binds the selected candidate to the actual peer returned by
`getpeername`. The retained socket records a monotonically allocated socket
identity, runtime/owner identity, selected candidate, verified peer, and exact
connection id. Every armed read or write obtains a stable generation bracket,
rechecks the current peer, submits a full `Repeat`, revalidates the same
registry entry and connection id, and holds the registry lock through the
WinSock operation so close and numeric-socket reuse cannot race the effect.
Release remains authority reducing and checks ownership without requiring live
policy authority. The five staged `__exactTcpConnect` scenarios and the three
zero-decision close/reset/shutdown lifecycle scenarios are now executable on
Windows. Target-aware recipe binding selects the installed Windows JSI source
descriptor rather than borrowing the default POSIX translation unit.

The non-capability `__exactTcpClose`, `__exactTcpReset`, and
`__exactTcpShutdown` probes execute against an exact loopback socket produced
by that typed Windows connect path. They remain zero-decision observations:
setup supplies the required authority, while lifecycle release cannot mint or
widen it. The sole remaining
`native-public-prerequisite-not-typed-on-target` row is the unrelated Windows
filesystem close setup.

The Windows network translation unit registers `__exactUdpSocket` and
`__exactUdpClose` as explicit throwing placeholders; their real operations
exist only in the default Unix network source. Both non-capability recipes
therefore remain residual under
`native-public-operation-not-installed-on-target`. A callable placeholder is
not execution evidence for a returning operation, and close must not borrow a
socket from a producer that the target explicitly refuses.

Windows also substitutes eight platform-specific translation units for the
default filesystem, crypto, DNS, process, network, OS-info, debugger, and
process-setup backends. Source inventory retains both sides of that build graph,
so a source-discovered default registration alone cannot authorize a Windows
public invocation. Recipe generation intersects native installation branches
with the sources `build.rs` actually compiles and keeps 37 recipes across 33
default-only globals residual under
`native-public-operation-not-installed-on-target`. This includes
`__exactGetProcessRSS`, the first physical mismatch, plus the default-only
asymmetric crypto, performance, signal, Brotli, and async-close surfaces later
in the same batch. Duplicated globals with a real Windows installation branch
remain scheduled. These residuals are neither target-absence passes nor
evidence for an uncompiled enforcement branch.

Exact-target conformance snapshots, including startup-environment and callback
package-root overrides, now derive test root-binding components and object
identity through the production host helpers on every platform. The
previous test helper retained only `Normal` path components and refreshed
object identity only on Unix; on Windows that dropped the drive prefix from a
canonical temporary project root, so authenticated module-graph capture could
not match the bound logical root. Reusing the production encoding preserves the
Windows prefix and pinned file identity without introducing a test-only path
model. Conversely, reconstruction of a Windows host-bound logical path seeds
the native path from that volume or namespace prefix plus its root separator;
pushing the prefix into an already separator-rooted `PathBuf` collapses the
drive and leaves module resolution rooted at `\\`. Module-specifier query and
fragment stripping likewise begins after the Windows verbatim namespace prefix
(`\\?\`), so the prefix's question mark cannot truncate an authenticated entry
path before resolution. At Oxc and external JavaScript-tool compatibility
boundaries only, canonical verbatim drive and UNC spellings are projected to
their ordinary Windows equivalents. Oxc results are canonicalized immediately
after resolution, and tool scripts are selected and authenticated before
projection, so authenticated paths and identities remain canonical and
unchanged outside those compatibility boundaries. Checked-in module-runner and computed-candidate
fixtures whose bytes or canonical JSON text are authenticated are explicitly
LF-normalized by Git, keeping those authority and golden comparisons identical
on Windows and Unix checkouts.

The Windows Oxc boundary is now backed by retained-handle traversal rather than
ambient pathname queries. It retains the authenticated project/package root,
opens every ordinary component relative to that handle without following
reparse points, and object-matches each directory witness/reopen pair. For a
Microsoft symlink or mount-point reparse, it reads the payload through the
witnessed no-follow handle, reopens and object-matches the same component,
requires an identical second payload, normalizes the complete target plus
pending tail beneath the retained root, checks denied principal subtrees before
lookup, and restarts traversal from the root handle. Oxc `read_link` receives
only an ordinary drive/UNC or relative spelling whose destination has already
passed those boundary checks. Unsupported provider tags, malformed or changing
payloads, outside targets, and excessive depth remain refusals.

Package manifest semantics still come only from strict VFS-captured bytes or
explicit absence, and `NODE_PATH` remains disabled. This makes authenticated
entry, relative, `#imports`, package-export, and contained symlink/junction
resolution executable on Windows and lets the closed module-runner fixture use
the same graph builder and authorized linker as Unix. It does not promote the
target. Windows now binds the digest-identified `windows-ascii-casefold-v1`
function into authored selectors and occurrences; the resolver compares captured
manifests, absences, and denied subtrees in the same coordinate while retaining
lexical display and SourceId. Non-ASCII and tilde components refuse before lookup,
and every retained traversal directory must successfully prove that its
per-directory case-sensitive flag is clear. This closes ordinary ASCII case
aliases without collapsing hard-link entries. Administrator-assigned 8.3 aliases
that omit `~` are closed by the retained relative-open protocol: stage the
parent entry's long name, short name, and 128-bit file ID; refuse a short-name
selection; open no-follow without delete sharing; then repeat and object-match
the entry. Query failure and replacement refuse. Installed Windows
`node:fs`/native filesystem effects still lack the typed retained-object adapter,
and the exact target public-evidence catalog remains incomplete.

Filesystem path occurrences now retain a non-wire projection for every
constrained principal, keyed exactly to the constrained set and effect index.
Every authority stratum uses that principal's projection, so two packages with
the same package-relative tail cannot borrow one another's self grants. Arming
also derives hard-deny `fs:write` path-tree guards for every package binding in
every authenticated principal's view, including nested package layouts. These
lexical guards make installed package source immutable without attempting to
enumerate inodes or assuming that hard-linked files have distinct identities;
first-party project paths outside package bindings remain writable. A foreign
nested package is a shadow boundary rather than part of its ancestor's package
tree, and colliding physical package bindings refuse. Aliases outside all
registered package spellings remain a distinct integrity problem rather than a
claim made by the lexical guard.

### WP6 — Convert network effects and protected peers

Map fetch, raw/bidirectional connect, listen, and standalone resolve to separate
typed resources. Authorize requested endpoint, selected candidates, redirects,
reconnects, routes/proxies, listeners, and final verified peers at their stages.
Add an engine-level protected metadata-peer guard with only an exact loud
exception if Ibex needs one.

Implementation status (2026-07-11): the armed host now constructs typed
`network:fetch` decision sets for requested and candidate stages using the
authenticated principal stack, concrete scheme/host/port, resolved candidate
set, selected candidate, and optional verified peer/connection facts. Candidate
authorization applies selector peer classes, while an independent host guard
unconditionally rejects metadata-service and unspecified selected or verified
peers. Live fetch remains closed until the transport adapter can report and
recheck the actual connected peer; requested-host authorization alone is not
treated as sufficient enforcement. The host also evaluates staged typed TCP
connect occurrences under the distinct `network:connect` action and retained
verified-peer/connection facts. A package fixture proves a fetch-only floor
cannot yield raw TCP authority, while a matching connect floor commits the
verified public peer.
The C ABI accepts the complete staged network fact set for fetch and connect,
maps authenticated numeric frame stacks to typed principals, and rejects
noncanonical host/IP text, duplicate-key or ill-typed candidate JSON, invalid
ports/stages/transports, and unsafe redirect counters before host evaluation.
The synchronous POSIX TCP adapter now uses that ABI end to end: it authorizes
the request before resolution, submits the canonically sorted complete
`getaddrinfo` candidate set, authorizes each attempted address, verifies
`getpeername` at commit, retains the candidate/peer/connection facts with the
socket handle. The first later I/O, and each generation-lease renewal, verifies
the immutable connected peer with `getpeername`; stable later I/O pins the exact
socket registry identity through the syscall without copying the retained
candidate/peer strings. Retained socket use reuses a full repeat decision only
for the exact peer and principal set while all mutable authority generations
remain unchanged; a generation or deputy-set change forces a stable
before/after redecision and another peer verification. The nonblocking POSIX path applies the same request and
candidate gates, registers only a pending handle, and withholds read/write
authority until poll observes successful `SO_ERROR`, verifies `getpeername`,
and commits the peer. Pending handles may only be polled or closed. Armed
local-bind options remain closed pending their own typed effects. Windows, TLS,
WebSocket, and the remaining UDP adapters are not yet migrated. POSIX unconnected UDP sends
are gated under their own registry edge: only canonical literal IPv4/IPv6
destinations are accepted, and the first datagram authorizes requested,
candidate, and committed destination facts immediately before `sendto` through
one parsed and attributed ABI call. Repeated datagrams reuse that complete
decision only for the same socket identity, literal host/port, canonical
principal set, and unchanged negative/dynamic/handle generations. Endpoint,
principal, revocation, or handle-generation changes force a stable
before/after three-stage redecision; the registry lock pins the fd through
`sendto`, so close/reuse cannot consume the lease. A bounded live fixture proves
sixteen identical datagrams require only one three-stage decision, revocation
forces exactly one renewal, and a metadata destination is rejected before
transmission. UDP bind/receive/listen authority remains
unmigrated and closed in armed execution.
One live armed closure fixture exercises the remaining transport families at
their native boundaries: fetch, standalone DNS, WebSocket, TCP listen, HTTP
serve, Unix connect/listen, and UDP bind all refuse before an external effect;
the Unix socket path remains absent. Together with the positive TCP-connect
and per-datagram UDP fixtures, the initial advertised network profile is thus
either typed end to end or explicitly closed rather than falling back to the
legacy capability oracle.

Acceptance:

- DNS rebinding, mixed answers, numeric aliases, redirects, WebSocket/raw
  transport, proxy, reconnect, and private/metadata peer fixtures pass.
- A fetch grant never yields raw transport authority.
- A hostname grant cannot silently reach a denied address class or port.

### WP7 — Close loader, process, inspector, stdio, and escape surfaces

Classify and gate typed local imports, dynamic imports, builtin loading,
subprocesses, executable identity, child environment/stdio, inspector routes,
process-global mutation, workers, VM/eval, WASI, FFI/native addons, storage, and
runtime inspection. Unsupported authority is closed rather than represented by
a token the runtime cannot enforce.

Acceptance:

- Static, literal-dynamic, computed, text/JSON/bytes, and CJS loader paths have
  explicit coverage.
- Inspector and runtime-memory surfaces cannot bypass package isolation.
- Terminal capabilities cannot be dynamically granted or delegated through an
  ordinary handle.
- Closed rows have denial/absence fixtures on every advertised target.

Implementation status (2026-07-11): the armed host decodes explicit builtin
and package import axes from the authenticated snapshot. Numeric engine module
IDs bind only to a matching package name plus locator from that snapshot;
unknown or mismatched registrations fail closed. Root and package import checks
therefore no longer consult `PolicyFile` once armed.
Armed runtime construction also rejects every inspector activation and
configuration flag (`inspect`, wait/open/pause, host, and port), including the
duplicate `run`-subcommand spellings, before reading arming artifacts or
allocating the engine. Ambient compatibility switches do not survive that
boundary as mutable controls. The trusted launcher may instead capture the
closed fixed compatibility set into the snapshot before its digest is
finalized; native bootstrap consumes only that authenticated projection and
seals its temporary carrier. The Bun facade is absent by default. When, and
only when, the snapshot includes `bun`, bootstrap installs `Bun` as the same
object as `Exact`; that identity adds no effect authority and cannot be toggled
by a later `process.env` write. Hidden compatibility-fidelity controls that
expose internals or alter process-wide stack/HTTP-parser configuration remain
rejected before armed artifact I/O.
Ad-hoc eval/print, explicit or implicit REPL entry, and debug-registry commands
are likewise rejected at the production dispatcher/runtime boundary before
arming artifact I/O, engine allocation, or evaluation of supplied code.
At runtime armed `process.env` has no broker-base branch. It begins at the
snapshot's explicit empty base and projects only the current authenticated
principal's runtime-scoped overlay. Scalar read, mutation, and each non-empty
enumeration member take exact-name typed decisions at requested and commit;
`env:read` and `env:write` remain independent. A write changes neither the host
process environment nor another principal's overlay, and a fresh runtime starts
empty. Process cwd disclosure uses its distinct `path:cwd-observe` action over
the exact `session-state` / `cwd` selector: requested and commit authorize the
read before `getcwd`, while denial occurs before disclosure. The armed root
realm exposes only `process.cwd`; that public function has captured the sealed
private `__exactGetCwd` bridge, whose own root property remains absent. The
source-derived facade path and both root-global disposition identities are
digest-bound in the loaded-engine fixture. Cwd mutation remains denied without
changing the host process directory. Live armed fixtures cover these
boundaries.
The same live fixture invokes shell exec, synchronous spawn, and asynchronous
spawn with a real marker-file command. All three are denied at the armed native
boundary and the marker remains absent, so executable selection, child
environment, stdio, and IPC option parsing cannot reach process creation via
the legacy `process:spawn` oracle.
Diagnostic audit keeps the child-process compatibility suite executable without
widening that production boundary. Its low-descriptor regression uses a plain
POSIX child to exercise IPC and extra-stdio `dup2` mapping directly; it does not
grant a nested Ibex runtime ambient ownership of inherited numeric descriptors.
A diagnostic nested Ibex child may adopt exactly one inherited POSIX IPC socket,
but only through a process-wide, construction-captured, one-shot lease released
to the first claimed unarmed Host context. The socket is validated and bound to
the runtime plus device/inode identity, its close-on-exec flag is restored before
project code, both startup markers stay absent from the principal environment,
and the temporary bootstrap carrier is removed after trusted runtime capture.
The captured carrier exposes only a frozen zero-argument close hook bound to
that runtime and socket identity. Trusted `process.disconnect()` consumes the
hook once; runtime teardown is the exact-once fallback. Each close revalidates
the native socket identity, so a stale or reused descriptor number revokes the
old lease without ever closing the replacement object.
Armed contexts, later runtimes, invalid descriptors, Windows, and unrelated
grandchildren cannot consume or inherit that lease. This is diagnostic
compatibility plumbing, not `ipc:channel` authority or target-conformance
evidence; every armed IPC cell remains closed and unsupported until a typed,
attributed channel design and its exact-target fixtures exist.
Parent-side extra stdio is a bounded, backpressure-aware full-duplex stream:
`end` half-closes writes, readable EOF gates the child `close` event, and
`destroy` releases both directions. Production child environment and inherited
stdio effects remain closed pending their typed conjunctive spawn implementation.
The armed import gate also carries an artifact-independent terminal-builtin
deny set for `async_hooks`, `diagnostics_channel`, `domain`, `inspector`, `vm`,
`wasi`, and `worker_threads` (including `node:` aliases and subpaths). A
deliberately overbroad but otherwise authenticated snapshot cannot re-enable
those runtime-inspection, process-wide publication/context, VM, WASI, or worker
escape surfaces; ordinary typed builtins such as `node:fs` remain governed by
the snapshot import policy. This module-wide closure is limited to source
families whose root and every export are closed. A mixed module with supported
operations is not terminal-denied merely because some of its import-time or
export routes remain closed.
For a terminal builtin with no downstream static call-graph terminal, the
authenticated import gate is itself the runtime terminal. Its closure recipe
therefore may have one exact surface key and zero route alternatives. Evidence
accepts that direct route only for the terminal-builtin import operation, only
when the recipe is the closed scenario, and only when the runtime-derived key
equals that sole bound surface. The original complete Apple run at `510ba04e`
executed all 106 facets in the first five source families before exposing the
former validator contradiction. Current exact-target batches execute 137
facets across all seven families. A missing surface binding still fails
closed rather than turning an empty alternative set into wildcard authority.
On-disk `.node` native-addon and `.wasm` module candidates now refuse in the
native resolver before their bytes are read into the JavaScript compilation
path. The authenticated VFS import path used by loaded-engine conformance does
not execute the legacy `resolve_with_oxc` facet named by those inventory rows,
and its normalized public error cannot identify which private rejection branch
fired. The public loader-kind and compatibility-module facets therefore remain
residual even though the underlying resolver refusal is implemented. Promotion
requires a future authenticated, source-bound executor that reaches and
distinguishes each legacy branch without treating a generic failed import as
branch evidence.
The eight native OS-information functions used by public `node:os` now enter
the same exact typed plane on every implementation target. Hostname, CPU,
memory, uptime, user, load-average, and network-interface reads authorize both
their generated requested and commit stages before invoking POSIX, Apple, or
Windows APIs. Loaded-Hermes fixtures exercise all 18 public exports in every
effect scenario. Allow, malformed, missing-attribution, and wrong-principal
fixtures independently observe the public requested/commit route under its
exact floor while their typed adapter cases exercise the scenario-specific
semantic branch; principal-deny fixtures observe the public requested-stage
denial. Neither path consults the legacy string oracle (ENG-24450).
The same exact-engine batch now exercises `node:fs` `statSync`, `lstatSync`, and
`readdirSync` against harness-owned file and directory fixtures beneath an
authenticated, canonical logical-root binding. Metadata calls must return after
emitting requested, discovery, and repeat decisions. Directory enumeration must
also emit the repeat decision that establishes its generation lease before any
entry is returned. Denial fixtures stop at requested. For these exact
source/setup/argument recipes, a noisy static dynamic-call list is diagnostic
rather than residual: promotion still requires the runtime-observed gate to
belong to the source-derived terminal allow-list.
Direct global `print()` writes now authorize the exact stdout console-broker
identity (`broker` / `ibex:console:stdout`) at requested, commit, and repeat
before enqueuing a line. Denial therefore cannot leak output through the
best-effort mirror, and this public path no longer bypasses typed
`stdio:write` authority.
The initial profile therefore has no debugger protocol or compatibility-facade
route that bypasses package attribution or typed authority. Snapshot-enabled
`Bun` is only an identity alias of the already-governed `Exact` object.

### WP8 — Port handles, dynamic authority, and audit evidence

Rebase attenuated handles, revocation cascades, dynamic permission ceilings,
change signals, deputy intersection, and audit output onto typed effects and the
armed snapshot. Distinguish effect actor, effect owner, authority source, and
constrained principal set.

Acceptance:

- Possession-based delegation remains usable without becoming ambient authority.
- Revocation invalidates caches, derived handles, and live/repeated operations.
- Dynamic grants cannot exceed the canonical static ceiling or apply to
  static-only/closed definitions.
- Evidence groups denials without losing loaded-policy or effect provenance.

Implementation status (2026-07-11): armed hosts now decode the immutable
snapshot into a validated `VerifiedDecisionContext`, accept strict typed
decision-set/effect-gate input, classify final peers, and retain bounded
structured evidence. Every legacy string check, import check, handle mint, and
dynamic grant fails closed once that typed context is installed; production
call sites must migrate to the typed ingress before a target can advertise.
Typed dynamic grant publication now validates the canonical ceiling before
advancing its generation; revocation advances negative and dynamic generations
before publishing the replacement context, invalidating prior decisions. Typed
bearer handles use OS-random identifiers, can be minted only from an owner's
static floor or re-attenuated from a handle currently held by the actor, and
revoke descendants as one negative/handle-generation publication.

The live Hermes surface also exposes typed dynamic grant and revocation as
`Ibex.permissions.requestTyped(request)` and `revokeTyped(grantId)`. Requests
cross the native boundary as strict typed JSON and therefore use the same
ceiling, lifecycle, digest, and generation validation as embedder calls;
legacy colon strings are rejected by the typed method rather than reinterpreted.
Both the private bridge and public methods are exact registry surfaces.
Typed bearer mint and cascade revocation are likewise reachable as
`Ibex.authority.mintHandle(request)` and `revokeHandle(handleId)`. Handle IDs
remain opaque strings; the live bridge exposes no numeric conversion or legacy
capability-string minting path.
The live native ABI authenticates both authority surfaces from the executing
Hermes principal rather than trusting the principal or actor supplied in JSON.
Dynamic grants must name that authenticated principal and may be revoked only
by it; handle mint actors must match it, and handle revocation is limited to the
authenticated owner or current holder. Forged package identities and unknown
grant or handle IDs therefore refuse at the bridge instead of becoming ambient
authority or cross-principal revocation.
For a new handle, the bridge also carries the canonical full Hermes principal
stack into the host. The requested selector must be covered by every
constrained principal's static floor, so an authorized inner actor cannot use
an ungranted caller as a deputy to mint authority. Re-attenuation remains bound
to an explicitly presented parent held by the authenticated actor.
Successful typed grant, revocation, mint, and cascade-revocation publications
wake the runtime. Each event-loop poll compares the authenticated negative,
dynamic, and handle generations; changes emit a frozen generation tuple through
`Ibex.authority.onChange`, including mutations initiated by an embedder rather
than JavaScript itself.
Every typed decision context carries a canonical sorted `presentedHandleIds`
set. The bearer stratum considers only those IDs, and rejects duplicate,
unsorted, unknown, or wrong-holder presentation as invalid attribution. Merely
minting a handle for a principal therefore never turns possession into ambient
principal authority.
Armed root bindings are decoded into typed values and host paths normalize
through the longest authenticated binding. Package roots match only their exact
package owner, project roots do not borrow package identity, absolute bindings
remain exact, and paths outside every armed binding refuse before a decision.
For filesystem effects the host computes that normalization once per
constrained principal, preserves the complete principal set for attribution and
evidence, and refuses a missing, extra, or noncanonical projection before any
authority match.
Live typed filesystem decisions now carry the canonical full Hermes principal
stack, including the captured schedule-time owner. Worker dispatch snapshots
that stack on the runtime thread and installs a scoped immutable copy on the
worker, so commit/repeat checks cannot lose an outer caller or detached
scheduler. The evaluator intersects every constrained principal; an ungranted
outer principal therefore denies even when the innermost actor has authority.
Timers and next-tick queues likewise retain the complete schedule-time stack
and restore it only for their callback invocation, so a later
authority-bearing operation cannot shed an outer constrained deputy;
generation checks still occur at the operation and observe intervening
revocation rather than caching the schedule-time allow.
A retained-operation fixture publishes ceiling-bounded dynamic filesystem
authority, commits a descriptor use, revokes the grant, observes both negative
and dynamic generation advances, and proves the immediately following repeat
check denies.
Distinct live dynamic grants are now restamped atomically to one published
generation on every add/revoke/regrant transition, with failed publication
leaving both rows and clocks unchanged. The typed decision ABI returns the
decision and its exact structured evidence from one evaluation; bounded
history receives a clone of that same record and is no longer queried to build
the response.

Implementation update (2026-07-16): a diagnostic harness executes six
callback/control-plane invariants against the loaded armed Hermes engine through
production `process.env` and public authority-control operations:
missing attribution denies, scheduled decisions recheck authority after
generation changes, callback principals restore after delivery, bearer handles
cannot cross snapshot identities, public grant requests cannot widen the static
ceiling, and lockdown remains structurally immutable. A feature-gated one-shot
observer records only the actual principal and runtime nonce; it cannot evaluate
or authorize an operation, and the harness deletes its global before the public
invariant operation runs. These six generic invariant runs are suite-prerequisite
diagnostics only. Async attribution remains channel-by-channel rather than
structurally forced through one chokepoint (LLP 0016 §W2), so a rationale ID and
static source reference do not prove that an arbitrary carrier entered its body
or used the checked mechanism. The 2,976 carrier-specific invariant recipes
therefore remain residual pending exact carrier execution or an independently
proved carrier-to-mechanism relation with its own non-terminal evidence contract.
Only nine Exact embedder rows currently have source-bound exact-mechanism public
executions; those carry runtime-derived lifecycle results and zero legacy
observations. No diagnostic run may manufacture a `terminalObservedKey` or close
an enforcement-branch fixture for a carrier it did not execute.

### WP9 — Make complete enforcement the default and remove weakening paths

Flip ordinary CLI execution and embedding defaults only after WP4–WP8 cover the
required initial profile. Remove or quarantine legacy policy parsing, public
permissive execution, `--allow-all`, advisory attribution, environment-selected
weakening, durable audit mode, optional lockdown under enforce, and permissive
legacy host construction.

Implementation status (2026-07-11): `Auto` and explicit `enforce` now resolve
to the same enforce posture even when no policy is present. Durable audit or
permissive policy modes, `--allow-all`, explicit permissive mode, legacy
allow/deny overrides, environment-endowment widening, and advisory-attribution
flags/environment inputs refuse instead of weakening production. Lockdown is
installed structurally for both the ordinary CLI and direct `Runtime`
construction, and missing lockdown, frame attribution, or package isolation is
a hard enforce failure with no advisory override. Inspector and runtime-fidelity
controls refuse at ordinary host construction. Compatibility inputs cannot
remain ambient controls: the only admitted armed forms are launcher-captured,
fixed modes bound into the finalized snapshot, and they grant no authority. The
ordinary no-policy path now constructs an execution-bound immutable typed
snapshot instead of the legacy host: it binds the actual project directory
object, patched-Hermes binary digest, exact advertised target/features, empty
package graph, empty dependency floors and dynamic ceilings, and the current
semantic/registry identity. Auto and explicit enforce produce identical policy
and authority state. Each runtime construction injects a fresh run nonce before
finalizing the armed digest, so complete snapshot bytes and handshake digests
intentionally differ. The trusted module loader may read
only source that canonicalizes under the authenticated project binding after
the typed import gate succeeds. A project-local `ibex-policy.json` (or explicit
`--policy`) is now accepted only as strict, digest-valid canonical typed policy;
its package principals, typed floor/denial/ceiling rows, import axes,
endowments, graph nodes, root and package import edges, and authenticated package-root
bindings are projected one way into that same snapshot. Environment-selected
policy paths and stale/tampered policy digests refuse. Production builds always
enable enforce isolation and cannot persist audit or permissive posture.
Diagnostic audit is a separately named foreground command,
`ibex capsec audit <file>`; it accepts no durable policy or ambient endowment
input and never becomes an armed production profile. In the candidate registry,
that canonical file-execution dispatch route is conservatively closed under
`vm:evaluate` until authenticated code ingress and its fixtures exist; parser
and positional metadata remain structural rows and claim no ingress authority.

Acceptance:

- Plain `ibex run` and an explicit enforce affirmation arm identical policy and
  make identical authority decisions.
- Missing policy yields empty dependency authority under enforce.
- Missing/incomplete prerequisites refuse before project code.
- Audit is a visibly separate diagnostic workflow and cannot become durable
  production posture.

### WP10 — Prove targets and publish the conformance report

Build the generated cross-target conformance report and run the red-team suite
for each advertised target. Exercise the real Exact/Snapback graphs and the npm
compatibility corpus as product-quality evidence, not as a reason to preserve
the old policy format.

Implementation status (2026-07-12): no target is advertised complete. The
former runner incorrectly converted a handful of broad suite successes into
21,597 synthetic per-obligation passes. The runner now executes the full
default Rust/integration/red-team matrix, all-feature executable
library/binary/test/example coverage plus compile-only all-target coverage,
complete devtools and runtime-JS tests, Hermes transform/loader corpora,
all generated drift gates, contract/registry checks, and `ref-check` from a
clean revision. It launches an executable Hermes probe, but records that probe
identity separately from the actual runtime engine artifact whose digest enters
the binding; the probe can never promote a different embedded library. Those
broad results remain prerequisite suite evidence only, and command logs are
streamed to files with full digests plus bounded tails rather than retained
unbounded in the report.
Command-evidence directories must be real on every host and owned whenever the
runtime exposes a numeric user identity. POSIX additionally requires no group
or other permission bits; Windows does not expose authoritative POSIX mode
bits, so its synthetic mode is not used as a security decision.
The same runner is now the arm64 macOS and x64 Windows CI gate. CI invokes
`verify:capsec-conformance --target <triple> --expect-incomplete`, which still
runs the entire matrix and emits exact command, adapter, public-surface,
execution, and report artifacts. That mode succeeds only after the report is generated, remains
`incomplete`, independently fails the recipe/public/report promotion checks,
and has no matching committed target attestation. It fails automatically once
the target becomes conformant, forcing CI to remove the expectation and adopt
the ordinary promotion gate rather than silently retaining a stale
"incomplete" posture. On Windows, the full Rust product gate still passes
through the fail-on-zero wrapper; that wrapper binds Cargo to the configured
absolute MSVC linker before Git Bash can prepend its unrelated Coreutils
`link.exe`, and binds vendored OpenSSL to a validated native Perl from the
original Windows developer path rather than Git's incomplete Perl.
Target-selected replacement translation units still provide any cross-target
integration-test C ABI whose runtime contract reports that the physical target
or profile is unsupported; target absence is a test result, not a link error.
An obligation can pass only with fixture-specific command evidence carrying
its exact fixture ID, result marker, exit status, recomputed evidence digest,
and exact execution binding. Missing, generic, duplicated, stale, or synthetic
records keep the report incomplete. Promotion remains closed until real
executable evidence exists for every required fixture and the full matrix is
green.

Implementation status (2026-07-24): after `insecure` entered Cargo's default
feature set, the recipe and runner commands still used default features and
therefore exercised the deliberate no-sandbox bypass while naming their output
as CapSec evidence. All promotion-facing Rust executors now share an explicit
`--no-default-features` command with
`standard,capsec-conformance-observer,openssl-crypto`, and catalog tests reject
any generated Cargo executor that regresses. Re-executing the callback
mechanism smoke under that profile exposed and repaired an Exact endowment
ordering defect in the harness: the one-shot authenticated endowment is
published before the first session submission can add the runtime-owned `$_`
root and close the bootstrap disposition. The smoke passes in secure mode.
The broader callback batch remains incomplete for a separate reason: only
eight exact public mechanisms are executable while the report currently
auto-credits 2,800 rationale-wide internal rows. That accounting must be
replaced by executed internal proof rather than weakening the command profile.

Implementation status (2026-07-25): Cargo defaults no longer include
`insecure`. Plain `ibex` uses the secure production posture and, while the
advertisement set is empty, refuses before project code. Secure development
without an advertisement requires the compile-time
`unadvertised-dev-arming` feature; the ambient no-sandbox posture requires the
separately named `insecure` feature. Neither weakening is a runtime flag or a
silent default.

Implementation status (2026-07-25): the internal accounting is now
evidence-backed. The proof audit retained exactly six closed-vocabulary
runtime-owned scenarios. A later input-ownership audit removed
`malformed-branch-facts` from fixture obligations entirely: branch predicates
are authenticated registry metadata rather than caller-supplied runtime facts,
so per-surface execution could never prove a malformed input path. This is no
credit or reclassification; registry contract validation owns malformed
predicate refusal. Every retained internal recipe carries
a source-bound proof plan naming its mechanism, source location, secure Cargo
command, and proof-plan digest. The secure internal batch executes each of the
six mechanisms once and expands that scenario-class observation into exact
fixture records carrying the fixture plan, common execution binding, engine
digest, result marker, and artifact digest. Report generation validates those
records independently; catalog status alone leaves the fixtures missing.
Apple now has 2,666 fully executable rows, 3,114 internally verified rows, and
18,260 unresolved rows;
Windows has 2,240 fully executable rows, 3,102 internally verified rows, and
18,583 unresolved rows. The
public callback batch is correspondingly pinned to its eight exact authored
mechanisms. Portable recipe projection preserves internal rows under their
dedicated executor and excludes them from public-surface execution; portable
mapped-process production for the internal executor remains a separate
promotion integration step.

Implementation status (2026-07-25): invocation-time activation changed the
module-runner graph's public evidence window. A CommonJS lifecycle fixture can
execute zero decisions for its selected non-capability ABI while the surrounding
graph legitimately authorizes exact `require` resolution and authenticated
source reads. The native harness now permits only those two reviewed auxiliary
coverage edges, requires allowed outcomes and the exact observer session, and
still reports zero decisions for the selected ABI surface. The authenticated
graph exercises all 19 production-reachable lifecycle ABIs. Six eager
dynamic/require-link functions are not invoked by the deferred call-time
production route and therefore remain residual instead of borrowing the
generic graph command. The refreshed Apple catalog has 24,654 required, 2,596
fully executable, 3,092 internally verified, and 18,966 unresolved fixtures;
Windows has 24,539 required, 2,230 fully executable, 3,080 internally verified,
and 19,229 unresolved fixtures.

Implementation status (2026-07-16): the report-crediting fixture pilot reruns
exactly nine source-bound Exact embedder mechanisms independently of the public
catalog/adapter batches. The set covers the single-use host-call route,
endowment and exact-set authorization, unendowed-operation closure, and all three
artifact-bound preparation/materialization ABIs; generic callback/control-plane
rows are not credited by analogy. Every
`ibex/capsec-fixture-evidence/2` record carries the committed revision/tree,
exact target and mapped engine identity, full fixture plan, recipe/public
digests, producer command and exit status, and the fresh runtime observation.
The runner validates the artifact through its `--fixture-evidence` path and
credits exactly nine passes; all other obligations remain missing or residual, so
the report remains `incomplete` and the target remains unadvertised. Missing,
duplicate, stale, mismatched-plan/engine, or mechanism-invalid pilot evidence
fails closed rather than reverting to zero credited rows.

Builtin public-surface evidence follows the same rule at value granularity.
The source scanner records whether an export is data, a readable accessor, a
callable, or unresolved, plus source-derived platform availability where the
builtin authors conditional tables. It also distinguishes manifest-importable
aliases from bootstrap-internal names that preempt a same-named manifest
source. Registry-only names remain executable when an authenticated import
policy grants their exact spelling, even when they are neither advertised nor
bundler-external. Bootstrap-shadowed and unaliased manifest exports remain in
the completeness inventory, but receive an explicit reachability residual
rather than a public invocation recipe. A generic read recipe is valid only for
a publicly reachable root data property or readable root accessor on the
selected target; the loaded runtime must match the authored property
descriptor, and accessor evidence actually invokes the getter. Retrieving a
function, constructor, or prototype method is presence evidence rather than
execution evidence, so those surfaces remain residual until a bounded
call/setup recipe is authored.
Import-only aliases are not generically executable. An effect-bearing alias is
eligible only when an authored source-bound template identifies its exact
first-load effect and each public spelling executes in a fresh armed engine
whose observer opens before the first `require`. The reviewed `NODE_DEBUG`
initialization family uses that path. Platform-classified filesystem,
constants, and OS aliases remain residual because a bare import emits no typed
decision. The current DNS sources are different from their former eager
implementation: resolver configuration is loaded lazily only when an exported
operation asks for it. Therefore exactly `dns`, `node:dns`, `dns/promises`, and
`node:dns/promises` are classified as `module-reachability-only` and each is
executed in its own fresh armed engine with the observer open before the first
`require` and through event-loop quiescence. Evidence must contain zero legacy
or typed decisions and must bind the exact alias source metadata and carrier
edge. Each accepted receipt must prove exactly one authenticated module-cache
miss, the exact VFS builtin `SourceId`, completed builtin-body evaluation, and
the exact requested alias. The four receipts must also carry pairwise-distinct
tagged runtime nonces, so neither a cache hit nor shared-engine alias reuse can
stand in for an independent first load. In particular, the two promises
spellings fall through `loadInternal` to
their declared `node_dns_promises` manifest source; a synthesized
`dns.promises` cache would not be source-bound evidence for that manifest
alias. The two scanner-produced DNS `default` namespace rows share the corrected
non-capability classification, but remain output-shape residuals while their
value shape is unresolved. This import evidence does not execute or credit
`getServers`, `Resolver`, or any other export; those calls remain separate
obligations. The reviewed two-source shape makes 42 `node_dns_promises`
callables and three `node_dns` Resolver `_handle` callables inventory-visible,
but all 45 remain route residuals and are explicitly excluded from generic
effect, closed, and non-capability probe authors. `getServers` and `Resolver`
are effect-bearing conditional rows. The same `node_dns_promises` source also
authors 24 error-code exports by loop-copying string values onto the public
module. Those rows are data reads, not callable projections, but the scanner
conservatively records their `valueShape` as `unknown`. They are executable
only through an exact, independently duplicated allowlist of the 24 export
names whose descriptors also bind `node_dns_promises`, the two public
`dns/promises` spellings, the member-assignment idiom, a single-segment access
path, and `expectedValueType: "string"`. The physical executor and independent
evidence validator both require the loaded value to be a string. This
exception does not make generic unknown-shape reads executable and does not
credit any of the 42 callable projections or three Resolver `_handle`
callables.

The `node_cluster`, `node_http`, and `node_os` modules remain excluded from
generic export-read authoring because their initialization can perform
capability-bearing work. Exactly 15 later scalar reads are separately
executable: the module is first loaded and driven to quiescence before the
export observer opens, then the invocation performs an authenticated public
`require` against that cache and resolves the exact source-derived export.
This proves only the read; it neither observes nor credits module
initialization. Independent authoring, physical execution, and evidence
validation bind each exact source key, export name, source ref, public alias
set, export idiom, access path, static shape, and expected runtime type. All
other exports from those modules remain behind the generic exclusion.

`getServers` and `Resolver` remain effect-bearing conditional rows:
uncached system-server discovery uses the native `network:resolve` gate and may
fall back to `fs:list` plus `fs:read`; cached or explicitly configured server
state is the no-effect branch. A reviewed decision-free root cohort uses the
same exact fresh-engine receipt for
30 additional spellings: the bare/`node:` pairs for `buffer`, `console`,
`module`, `path`, `path/posix`, `path/win32`, `punycode`, `querystring`,
`string_decoder`, `timers`, `timers/promises`, `trace_events`, and `v8`, plus
`exact:clipboard`, `exact:http`, and the shared `exact:sqlite`/`bun:sqlite`
source. The SQLite and string-decoder roots must return a function; every other
root in this set must return an object. The root type is descriptor-bound
presence evidence only and does not credit any export or lazy installer edge.
Both `stream/consumers` spellings remain residual because `loadInternal()`
returns the compatibility `stream.consumers` value before the declared
`node_stream_consumers` manifest body can execute; `internal/fs/utils` remains
bootstrap-shadowed for the same evidence reason. All other non-capability
aliases remain residual: a shared-engine zero-decision result cannot establish
that each spelling has an effect-free first load because later aliases reuse
the module cache. Cache order is not independent execution evidence. Export
reads and calls remain separate
obligations: their exact public module is loaded and driven to
event-loop quiescence before the per-export observer opens, then the invocation
still performs the authenticated public `require` and resolves the
source-derived export from that cache. This isolates both synchronous and
deferred module initialization from the export body without claiming that
initialization was zero-effect. The closed generated builtin manifest may
authenticate, source-materialize, compile, and link exact private builtin
dependencies as runtime build metadata before a builtin body executes. That
operation has no package/path resolver route and no ambient filesystem probe,
so it does not create a package import edge. Activation of one of those links
is nevertheless confined to the exact builtin record at the top of synchronous
initialization: the exemption does not suppress capability terminal checks,
survive after initialization, or re-enter through an exported `require`
closure while another record is active.

Bounded non-capability callable recipes are grouped by exact source template,
not inferred from `typeof value === "function"`. The first authored families
cover `assert`, `buffer`, `events`, `path`, `perf_hooks`, `punycode`,
`querystring`, `zlib`, `stream`, `string_decoder`, `url`, and `util`: each
recipe fixes its setup, receiver, arguments, dispatch mode, and expected return
type. Direct member-to-member aliases inherit a callable shape only from the
already observed source member, and reuse that member family's bounded
arguments rather than weakening the template allowlist. Prototype
recipes construct the declared owner (with dedicated bounded Buffer,
CallTracker, zlib-transform, string-decoder, and configured
readable/writable/duplex stream fixtures), then dispatch the exact
source-inventoried prototype function. Zlib decoder probes derive a valid
compressed input with the matching one-shot encoder, and every zlib receiver
closes native stream state in a `finally` path. Stream recipes use inert
read/write/transform callbacks; standalone `destroy` receives an explicit
non-error value so it cannot leave an asynchronous `AbortError`, and `compose`
remains residual because its normal return still owns a live pipeline.
Performance observer `observe` likewise remains residual because it retains a
callback; constructor, query, mutation, and explicitly disconnected observer
recipes have bounded lifetimes. Evidence requires a normal return from the
selected dispatch; an argument/receiver binding error or any other throw fails
the recipe and cannot stand in for body entry. Normal return is not completion
evidence on its own: the observer remains open while the harness drives the
loaded engine to event-loop quiescence under the recipe's fixed one-second
bound. A timeout or event-loop error stops the batch before another fixture can
inherit its work, and the runtime completion marker is independently checked
against the authored mode and bound. A later tranche adds exact bounded
templates for in-memory crypto hash/HMAC/sign/verify, KDF, random-buffer,
prime, key, DH, and ECDH operations; pure module/path, IP/block-list, URL, and
version helpers; and unbound server metadata operations. Promise-returning
stream consumers, pipelines, `wrap`, and Hash/HMAC readable-side finalization
remain residual;
their one-shot recipes do not own enough state to prove completion even with a
quiescence drain. All accepted calls and data/accessor reads execute against
the same mapped Hermes
identity; there are no promoted cache-dependent module imports.
Loaded execution also exposed lazy builtin assignments that were swallowed by
locked inherited primordial properties; those Buffer, AssertionError, and
StringDecoder prototype members
are now installed as explicit writable/configurable own properties without
weakening primordial lockdown. Source inventory also preserves own prototype
overrides when an inherited member of the same name was propagated into a
concrete constructor.

Windows installs a reduced `node:crypto` implementation directly from the
bootstrap module loader instead of loading `src/builtins/crypto.js`. Exact
target generation therefore keeps every public recipe whose source descriptor
names that default file residual under
`builtin-export-source-replaced-on-target`, including overlapping export names:
executing a same-named replacement function is not evidence that the
source-bound default implementation ran. Those recipes become executable on
Windows only after inventory and recipe generation bind the replacement's own
source surface (or the target stops replacing the module).

The Windows zlib bridge installs `__exactDeflateSync` and
`__exactInflateSync`, but not the `__exactBrotli*` codec globals. Source-bound
`Brotli*`, `brotli*`, and `createBrotli*` call recipes therefore remain
residual on that target under
`builtin-export-native-prerequisite-not-installed-on-target`; a callable
JavaScript wrapper that can only throw for its absent native prerequisite is
not normal-return execution evidence. Source-defined scalar `BROTLI_*`
constants remain executable because reading them does not claim codec
execution.

Closed and conditional evidence remains branch-executed rather than
classification-derived. A closed CLI facet is executable only when the harness
first reconciles its source-discovered spelling, action, arity, defaults, and
parser against the live Clap command and then observes the production entry
reject that selected control before artifact or project execution. The four
Hermes evaluator identities additionally bind the reviewed engine identity and
lockdown-taming digest, resolve their exact intrinsic access path, and must
actually throw the exact native lockdown error when invoked on the loaded
engine. Their public fixture is an authenticated direct-file program admitted
through the native module graph: persistent-session lowering intentionally
closes evaluator syntax before runtime and is never bypassed for this evidence.

Production startup evidence now covers ten curated structural stages against a
fresh armed runtime from the exact mapped Hermes artifact: runtime creation,
global/module-loader/shared-runtime installation, capability-hatch sealing,
eager lazy-installer sealing, lockdown, freeze-hatch sealing, compartment
registry installation, and explicitly enabled Web Streams installation. Each
stage has one fixed source descriptor and an independently validated
postcondition; the probe then executes a project marker and requires zero
legacy or typed decisions. The lockdown-stage self-check uses authenticated
direct-file native-graph admission so it can inspect the tamed evaluator
without bypassing the persistent-session syntax closure; its startup,
admission, and execution observation windows are independently empty.
Scanner-only script URLs, evaluation/call-site
facets, installer definitions, skipped legacy bootstraps, and platform-only
routes remain residual rather than inheriting these stage results.
Direct `__exactReadFile` now has five Windows exact-target recipes as well as
the existing Apple evidence. The Windows invocation passes a null typed handle
to the public global and requires the target-specific four-stage sequence:
requested/discovery `fs:list`, then commit/repeat `fs:read`. Success and
negative-attribution scenarios bind returned bytes or typed refusal to that
sequence; denial stops at requested. Physical engine tests prove successful
bytes, pre-lookup denial, and zero legacy decisions. The lower retained VFS
fixture separately replaces the selected leaf between discovery and commit and
requires a stale-object refusal. The asynchronous Windows read remains
residual because it still lacks per-chunk typed generation rechecks.
Direct non-recursive `__exactMkdir` now uses a separate harness-owned path under
`target/`, an exact `fs:list` and `fs:write` floor, and source-authored boolean
arguments. Successful public execution must emit the complete seven-decision
component walk: requested full spelling, authenticated-root discovery,
requested/repeat authorization for the retained `target` directory, requested
leaf lookup, requested dangling spelling, and absent-create discovery. The
authorized `mkdirat` is deliberately the terminal mutation and emits no
name-bound post-create commit; the harness must remove the created directory before
the fixture can pass. Denial occurs at requested before creation. This closes
the direct Apple and Windows surface cells independently from the asynchronous
dispatcher route; recursive creation remains closed under armed startup.
Direct `__exactWriteFile` similarly receives bytes from the source-bound
`__exactStringToUtf8Bytes` native producer and a null typed-handle argument. It
can create only one exact harness-owned target file under the joint `fs:list`
and `fs:write` floor. Passing evidence requires requested, retained-parent and
created-target discovery through the complete nine-decision component walk,
commit, and repeat sequence, exact written bytes, and removal of the file after the
call; denial stops at requested before creation.
Direct `__exactAppendFile` uses the same typed retained-object route against a
pre-seeded exact harness-owned file. Passing evidence must preserve the known
prefix, append all source-derived suffix bytes, observe the eight-decision
existing-path sequence (full-spelling request, authenticated-root discovery,
requested/repeat checks for both components, commit, and write repeat), and
then remove the file. Denial stops
at requested, leaves the prefix byte-identical, and still removes the harness
fixture outside the observation.
Direct `__exactFsOpen` covers its read, write, and read-write logical branches
with non-mutating `r`, `a`, and `r+` flags against three exact pre-seeded files.
Successful and branch-selection evidence must emit an access-class request,
the six-decision existing-path component walk, and commit (eight decisions),
then close the returned descriptor through
`__exactFsClose`, prove the fixture bytes unchanged, and remove the file.
Denial stops at requested and still proves unchanged bytes before harness
cleanup. Standalone `__exactFsClose` evidence also requires a descriptor staged
before observation. It remains residual on Windows because the installed
`__exactFsOpen` prerequisite still uses the legacy capability oracle there;
executing close after a denied setup would fabricate evidence for an
unavailable retained object.
The POSIX `__exactFsOpenAsync` surface mirrors those three exact owned fixtures
through event-loop quiescence. Successful and branch-selection evidence binds
the seven-decision component-walk-and-commit sequence to the asynchronous
surface plus its synchronous descriptor-cleanup terminal,
closes the returned descriptor, proves unchanged bytes, and removes the file;
denial stops at requested and removes its unchanged fixture. The Windows
backend does not install `__exactFsOpenAsync`, so Windows recipes remain
explicitly residual instead of borrowing the POSIX invocation.
Retained `__exactFsFstatSync` metadata now has four physical Apple recipes. The
harness opens source-bound `Cargo.toml` before observation under exact
`fs:list` and `fs:read` floors, passes only the retained descriptor to the
metadata surface, requires one typed `fs:list` repeat decision, and closes the
descriptor after collecting observations. Cleanup therefore cannot contribute
an unrelated decision to the recipe it proves. The deny recipe remains
residual: denying the same principal's `fs:list` authority would prevent the
prerequisite descriptor from being opened, so the harness cannot honestly
stage that retained-object scenario. Windows now executes the same four
retained-object scenarios through its typed descriptor-metadata gate.
Retained `__exactFsFsyncSync` and `__exactFsFdatasyncSync` durability each add
four physical recipes on both exact targets. Before observation, the harness
creates a distinct exact file under `target/` and opens an append descriptor
through the source-bound native surface under joint `fs:list` and `fs:write`
floors. Each durability invocation must emit one typed `fs:write` repeat
decision on its own public edge, preserve the fixture bytes, and then close the
descriptor and remove the owned file outside the decision window. Windows
performs the flush through the same retained typed VFS file while holding its
I/O mutex; POSIX authorizes the live retained descriptor immediately before the
syscall. Denial remains residual because denying the descriptor's required
`fs:write` authority would prevent the prerequisite writable descriptor from
being opened.
The same owned-descriptor harness now physically executes
`__exactFsFtruncateSync` on Apple. Four recipes require one typed `fs:write`
repeat decision, then independently verify the exact two-byte length before
closing the descriptor and removing the file. The global is not installed by
the Windows filesystem backend, so its exact Windows cell is an executable
target-absence obligation; the
Apple deny recipe also remains residual because its required writable-descriptor
setup cannot survive the same principal's `fs:write` denial. Descriptor mode
and timestamp mutation remain unresolved: LLP 0023 keeps `fchmod` and `futimes`
closed pending object-bound mutation work, so physical execution alone would
overclaim the governing contract.
Direct `__exactTruncate` now uses the same object-bound shape on armed Apple
runtimes: the six-decision existing-path component walk precedes a
non-truncating `openat`, commit binds the actual regular-file descriptor, and a
repeat decision immediately precedes `ftruncate`. Five public recipes operate
only on an exact harness-owned file, verify its two-byte result or unchanged
denial bytes, and remove it. The legacy Windows backend remains residual until
it can provide the same retained-object execution contract.
The conditional `__exactFsFdAsync` registry now matches that retained-object
contract instead of claiming an unreachable `durability-read` branch. LLP 0023
places `fsync`, `fdatasync`, and their `FileHandle` aliases in the open-write
family because they act on a descriptor already authorized to write; the
runtime likewise requires a writable owned descriptor and emits `fs:write`.
Apple public evidence selects `durability-write` with `fsync`, awaits event-loop
quiescence, requires exactly one typed repeat decision, then closes the
descriptor and verifies the unchanged owned file before removal. Its deny case
remains residual because the setup itself requires the authority being denied,
and the Windows backend does not install this dispatcher; source inventory now
labels `hermes_runtime_fs.cc` as POSIX, so Windows receives one exact absence
fixture rather than inheriting a fictitious fallback implementation.
The former aggregate `metadata-write` branch is split exactly. `ftruncate`
selects its own open-family `fs:write` branch, while `fchmod`, `fchown`, and
`futimes` each select a deny-only `fs:unbound-mutation` branch. The same
branch-local closure models every unbound operation spelling in
`__exactFsPathAsync` and the recursive branch of `__exactMkdir`; the public
closed harness invokes each spelling, requires exact `EPERM`, zero legacy and
typed decisions, and recursively compares the entire filesystem fixture before
and after. Apple has 17 such dispatcher closures and Windows has 16; the
Windows-only path `chmod`/`utime` closures replace the three descriptor
closures whose dispatcher is absent there.
Direct `__exactReaddir` now enumerates a separate exact directory containing one
harness-owned file. Passing evidence must select the six-decision existing-path
component walk and three later repeat decisions: retained-target open,
pre-enumeration reauthorization, and the generation-bound lease for the one
disclosed entry. The harness removes the entry and directory after both
success and denial, and successful evidence records that cleanup explicitly.
The runtime-create descriptor binds `ex_hermes_create_armed`, not the historical
`ex_hermes_create` symbol that production deliberately leaves non-executable.

A zero-effect conditional branch may pass without a typed decision only when a
source-bound public invocation itself selects the registry's exact branch facts,
returns normally, emits zero legacy and typed observations, and releases every
harness-owned resource. The first such family covers the seven native JSI and
seven Rust host-ABI SQLite operations on exact in-memory handles; each proves
both branch selection and the no-effect result while the file-backed branches
remain independent obligations. A valid public API cannot inject malformed
internal branch facts, so malformed-branch-fact fixtures remain residual rather
than reusing a generic malformed adapter result or a hand-labelled terminal.

The macOS/aarch64
candidate has exact loaded-Hermes adapter-probe evidence, but probe coverage is
deliberately non-promotable and is not represented as fixture pass claims.
The physical Release candidate is a universal MinSizeRel Hermes build with the
debugger disabled, the pinned Exact patch set applied, and the expected patched
package-attribution export. Its loaded arm64 identity is recorded independently
from the executable probe. The first whole-report run against that artifact
failed closed when the native public batch reached an Apple OpenSSL-backed ECDH
fixture without the `openssl-crypto` build profile. All executable-recipe,
fixture-evidence, public-surface, callback, closed, startup, startup-environment,
and target-absence commands now bind that profile explicitly alongside the
observer. A focused rerun against the same loaded Release artifact passes all
470 native, host-ABI, and module-loader public fixtures, including the ECDH
fixture that exposed the omission. The regenerated catalog retains 23,126
required, 4,845 executable, and 18,281 unresolved fixtures. This corrects the
evidence producer contract but does not promote the candidate or turn the
remaining residuals into passes.
The complete physical Apple Release run now succeeds at source revision
`9329a9123a10e379d6253afb6a90a33de5de928e` with all 24 exact prerequisite
commands passing. The execution artifact is bound to source-tree digest
`sha256-37oyAHa_E6_FdVqKjL51CEVsmjQrmfp4QZSLePRTP6s`, the loaded arm64 engine
digest `sha256-TI61ftuk_AoTSSNEjQOOuOEopGFCsAH38C7Qu9yxYuw`, and recipe-catalog
digest `sha256-ocEiwJu5McEiGcypMkUBhB0q47sT8-47nTm4PYxJO_8`. The resulting
report is intentionally `incomplete`: one of 7,108 target cells is conformant,
7,107 remain incomplete, nine of 23,126 required fixtures pass, 23,117 are
missing, and none fail. Its conformance digest is
`sha256-pX31WIshSle8F2DnydGKCn_AeMw8npRyIhDtX2SG1LM`. This supplies the missing
physical Release report without weakening the promotion rule: the target stays
unadvertised until every required fixture and target cell conforms.
The artifact workflow now reproduces that no-debugger Darwin Release profile
as a separately named, checksummed bundle and rejects either a missing patch
export or any exported debugger API. `download-hermes.sh` installs that exact
profile into the same content-addressed build cache used by local source builds.
The conformance workflow uses a separately versioned no-debugger cache key and
rechecks the attribution export and debugger-symbol absence after every cache
restore, so an older debugger-enabled framework cannot enter the matrix merely
because it shares the source pin and patch digest. The job explicitly exports
`HERMES_ENABLE_DEBUGGER=false`, binding both prebuilt artifact selection and the
compiled Exact wrapper to that profile. Symbol checks capture the complete
`nm` output before matching, so `grep -q` cannot terminate the producer with
SIGPIPE and turn a present debugger symbol into a false absence result.
Windows no longer has to rely on the historical unpatched NuGet artifact. Its
installer now fetches the exact commit-plus-patch-digest Release bundle and
falls back to the same source build; the artifact manifest binds commit, patch
digest, architecture, configuration, debugger state, and DLL digest. At
runtime, the C++ bridge snapshots the loader module set, requires exactly one
loaded module with the authored `hermesvm.dll` basename, pins that module by
its mapped base address, and obtains its loader-reported pathname. This avoids
both an executable-side MSVC import thunk and ambiguous basename lookup. Rust
reopens that pathname and compares its Windows volume serial/file index with
the pinned file used for hashing.
That detects ordinary named-file substitution, but it does not authenticate
the already mapped image section: a post-load replacement can make both file
handles identify different bytes from the code supplying the running process.
The release workflow has now built and inspected the DLL on a Windows runner
and published the exact checksummed Release bundle; its DLL digest is
`6f5190b9f8bf943b073e62dc5dbc2e297b77b7becbac3ca0c209b12d92828b6a`.
The artifact manifest and installer continue to hash the PowerShell builder's
raw platform-native checkout bytes. Evaluator discovery has a distinct source
review domain: it canonicalizes CRLF to LF for the Windows builder and installer
before hashing, so semantically identical Git checkouts retain one reviewed
Function-family reachability claim without weakening the release bundle's
byte-exact provenance check. Any non-line-ending source mutation still changes
the evaluator review identity and fails closed pending review.
Windows x64 is now a declared but unadvertised candidate alongside Apple arm64.
The complete-matrix workflow installs the checked Release DLL, revalidates its
manifest, digest, patched export, and debugger-free profile, then explicitly
selects `x86_64-pc-windows-msvc` for recipe generation and report execution.
Deterministic registry, contract, generated-policy, aggregate-generated, and
LLP-reference drift checks run as an evidence-retained preflight before engine
attestation or physical fixture execution, so stale source artifacts cannot
consume an authoritative matrix run before refusing the report.
Its current catalog has 2,327 executable and 21,373 unresolved fixtures. The
first authoritative Windows attempt physically rejected the published DLL:
although its manifest claimed the no-debugger Release profile, its PE export
table still contained the full `AsyncDebuggerAPI`/CDP implementation. The
Windows builder now passes a quoted, typed `HERMES_ENABLE_DEBUGGER:BOOL=OFF`
argument (the prior unquoted PowerShell token preserved `$debugger` literally),
checks the configured CMake cache, and rejects the implementation-only
`CDPAgent`/`CDPDebugAPI` exports before writing a manifest. Install and
publication paths independently enforce the same implementation-symbol check.
A rebuilt physical artifact must still close both the independent source-build
authority and mapped-image provenance blockers, and a complete report must
finish and be inspected, before any Windows target cell or advertisement can
change. Incomplete evidence is retained as a refusal artifact, not promotion
authority.
`bun run verify:capsec-conformance` must publish a conformant revision-, tree-,
full loaded-engine identity-, vocabulary-, registry-, source-implementation-,
target-, and fixture-catalog-bound report. Promotion then requires a checked
content-addressed attestation; the generator reopens and validates the report,
the complete executable-recipe catalog, and a separate public-surface execution
artifact, plus the loaded-engine output-disposition evidence. All four are
immutable regular files addressed by their raw content, and the report and
attestation bind the catalog and public-execution semantic digests together
with the exact output-disposition evidence bytes. Adapter-probe evidence is a
distinct diagnostic schema and is rejected at publication.
`IBEX_CAPSEC_PUBLIC_BATCH_EVIDENCE_OUTPUT` only selects the
harness-owned diagnostic artifact destination; it never supplies authority,
policy, a principal, a target claim, or production runtime input. The generator
re-derives the exact required fixture set and
requires one passing authored public-surface invocation (or target-absence
probe) with the selected terminal observation for every recipe, with zero
residual, missing, duplicate, or failed rows. It then derives every cell and
advertisement and permits no source changes after the reported revision except
those four evidence files, the attestation, and generated publication
artifacts. Until every required fixture genuinely passes, production startup
refuses before project code on every target.

Source-derived global reads are executable evidence only when the authored
runtime graph proves a concrete access path, every path segment has an actual
registration rather than a synthesized namespace prefix, and the final value
is unambiguously data or an accessor. The loaded-engine probe resolves the
source-proven property path, checks the final descriptor shape, performs the
read, and requires zero legacy or typed authorization observations. Merely
retrieving a function is never call evidence. Conditional namespace aliases,
multi-installer globals, receiver-dependent prototype members, and lazy getters
that may already have materialized a callable remain residual until they have a
bounded call/setup recipe. This keeps inventory facts from becoming synthetic
execution claims while permitting exact non-capability data reads to close.

Bounded native-call recipes likewise use only harness-owned literals,
callbacks, listeners, handles, or results of source-bound native producers.
When two arguments need the same generated key pair, the loaded-engine harness
caches the exact producer invocation and projects only an own `privateKey` or
`publicKey` property; independently generated keys are not interchangeable
evidence. Timer callbacks are inert and their returned timers are cancelled
before the fixture completes. Resource-consuming calls receive a handle minted
inside that invocation. Compile-guarded globals absent from the attested engine
remain residual even when source discovery finds their registration text.
Every non-capability recipe requires zero legacy and zero typed authorization
observations; in particular, ordinary random bytes cannot retain the retired
always-allowed `crypto:random` legacy check.

Promise-returning public builtin calls require a stronger receipt than a
synchronous function return. The readable-stream consumer family is executable
only for an already-ended, empty stream created by the harness, with the exact
returned Promise awaited inside the same observation and event-loop quiescence
proved afterward. The recipe author, evidence validator, and Rust executor each
repeat the closed owner, method, arguments, and settled result type. A Promise
object returned to a synchronous harness is not completion evidence. Stream
composition, wrapping, and pipeline operations retain delegated sources or
pipelines and remain residual until a recipe owns and drains those resources.

The base `node:stream` constructor is the module value itself. It has no nested
`default` property, so its reviewed lifecycle calls resolve through
`["prototype", method]`. That correction is executable only for the separately
enumerated `_close`, `_emitClose`, `_undestroy`, `constructor`, `destroy`, and
`unpipe` set on a harness-created plain Stream; generic default-owner prototype
authoring remains unavailable. In particular, `pipe` retains listener and
pipeline ownership after returning and remains residual.

Explicit-parameter Diffie-Hellman construction and state-only accessors are
executable only with the independently repeated evidence vector: prime 23 as
one harness-owned byte, generator 5, and private/public setter input 3.
Supplying the prime avoids lazy prime generation, and the reviewed getters and
setters only project or replace bounded in-memory byte arrays. The recipe
author, evidence validator, and Rust executor separately enumerate the exact
constructor, factory, four getters, two setters, setup kinds, arguments, and
result types. `generateKeys` and `computeSecret` remain residual because this
receipt does not own random-key generation or broaden bounded state evidence
into modular key-agreement evidence.

Idle zlib destruction is executable only for a closed owner allowlist. Each
constructor establishes its principal-bound native selector before the
invocation, the public `destroy` source path authenticates that selector before
delegating to the stream lifecycle, and `_destroy` closes it. The harness then
performs idempotent cleanup and requires event-loop quiescence; no input is
submitted to a codec. The recipe author, independent evidence validator, and
Rust executor separately enumerate the exact owners, empty argument list,
object result, cleanup, and zero-decision contract. Apple installs and executes
`BrotliCompress`, `BrotliDecompress`, `Deflate`, `DeflateRaw`, `Gunzip`, `Gzip`,
`Inflate`, `InflateRaw`, `Unzip`, `ZstdCompress`, and `ZstdDecompress`.
Windows executes the same set except the two Brotli owners, whose absent native
codec prerequisite remains explicit residual evidence rather than a throwing
wrapper being credited as normal execution.

Three one-shot zlib encoders have a separate isolated receipt:
`deflateRawSync`, `deflateSync`, and `gzipSync`. Each exact public root call
receives one harness-owned Buffer containing bytes `[105, 98, 101, 120]`; the
loaded engine requires a nonempty byte-view result before recording normal
return and event-loop quiescence. No incremental codec selector, callback,
listener, or deferred stream survives the call. The recipe author, independent
evidence validator, Rust validator, and loaded-engine JavaScript boundary each
repeat the same three-name allowlist, source descriptor, argument, dispatch,
result type, and byte-view proof. This receipt does not cover callback codecs,
`_processChunk`, `flush`, `params`, `write`, or any other stream-processing
method; direct `write` and `_processChunk` use the separately bounded receipts
below rather than borrowing this synchronous one-shot proof.

Four one-shot zlib decoders have their own isolated receipt: `gunzipSync`,
`inflateRawSync`, `inflateSync`, and `unzipSync`. Their harness-owned inputs are
fixed complete deflate, raw-deflate, or gzip encodings of `[105, 98, 101, 120]`.
The loaded engine credits normal return only when the result is a byte view
whose length and every byte exactly reproduce that payload, then requires
event-loop quiescence and zero decisions. The recipe author, independent
evidence validator, Rust validator, and loaded-engine JavaScript boundary each
repeat the exact four-name allowlist, source descriptor, compressed bytes,
root-call dispatch, object result, and decoded-byte proof. Brotli, zstd,
callback codecs, retained codec objects, multi-member variants beyond the
single fixed gzip member, and every incremental stream method remain residual
except for the separately bounded Apple-only Brotli routes below.

Seven one-shot callback wrappers have a distinct deferred-delivery receipt:
`deflate`, `deflateRaw`, `gzip`, `gunzip`, `inflate`, `inflateRaw`, and
`unzip`. The harness passes the fixed encoder or decoder Buffer followed by a
dedicated callback credential, requires the public source call itself to return
`undefined`, awaits exactly one later callback, rejects any error, and accepts
only a nonempty encoder byte view or the exact decoded bytes
`[105, 98, 101, 120]`. Completion then requires event-loop quiescence and zero
decisions. The author, independent evidence validator, Rust validator, and
loaded-engine boundary each repeat the exact seven-name allowlist, source
descriptor, input, callback-result contract, dispatch, return type, and
delivery proof. This does not admit Brotli or zstd wrappers, `info` engines,
arbitrary callbacks, multiple delivery, or any retained codec stream through
this seven-name receipt; the separately bounded Apple-only Brotli callbacks
follow below.

Four Apple-only one-shot Brotli routes have a platform-bounded receipt:
`brotliCompressSync`, `brotliDecompressSync`, `brotliCompress`, and
`brotliDecompress`. Compression receives the fixed Buffer bytes
`[105, 98, 101, 120]` and must produce a nonempty byte view. Decompression
receives the fixed complete Brotli member `[139, 1, 128, 105, 98, 101, 120, 3]`
and must reproduce exactly `[105, 98, 101, 120]`. The callback variants must
return `undefined`, deliver exactly once without error, satisfy the matching
output proof, and then reach event-loop quiescence. The recipe author,
independent evidence validator, Rust validator, and loaded-engine JavaScript
boundary each repeat the exact four-name vocabulary, source descriptor, fixed
bytes, root dispatch, return contract, and output proof. Windows continues to
leave all four rows residual because that target does not install the native
Brotli bridge; zstd one-shot wrappers, `info` engines, arbitrary callbacks,
multiple delivery, retained codec objects, and incremental stream methods other
than the separately bounded terminal `end` lifecycles below remain residual.

Terminal zlib `end(Buffer)` has a separate stream-lifecycle receipt for exactly
nine Apple owners: `BrotliCompress`, `BrotliDecompress`, `Deflate`,
`DeflateRaw`, `Gunzip`, `Gzip`, `Inflate`, `InflateRaw`, and `Unzip`. Windows
executes the same set without the two target-unavailable Brotli owners.
Compression receives `[105, 98, 101, 120]` and must emit a nonempty byte view;
each decoder receives its fixed complete Brotli, deflate, raw-deflate, or gzip
member and must emit exactly `[105, 98, 101, 120]`. The selected source call
must return the receiver object, emit exactly one `finish`, set terminal
writable state, leave no native selector live, and reach event-loop quiescence
with zero decisions; owners without a native stream still pass the same
idempotent cleanup proof. The author, independent evidence validator, Rust
validator, and loaded-engine JavaScript boundary separately repeat the exact
owner set, inherited prototype descriptor, input, output contract, dispatch,
finish, cleanup, and quiescence proof. `ZstdCompress.end` and
`ZstdDecompress.end` remain residual because the runtime deliberately exposes
no native zstd bridge. Parameter changes, flushes, transforms, and direct
writes or synchronous `_processChunk` calls are not credited by this receipt;
the latter two have separate contracts below.

Direct incremental zlib `write(Buffer, callback)` has a terminal-write receipt
for the same nine Apple owners and seven non-Brotli Windows owners as
`end(Buffer)`. Compression receives `[105, 98, 101, 120]`; each decoder
receives its fixed complete Brotli, deflate, raw-deflate, or gzip member. The
selected source call must return a boolean and invoke the dedicated callback
exactly once without error. Only after that callback does the harness supply a
separate empty `end()` to release retained input, wait for exactly one
`finish`, and require a nonempty encoded byte view or exact decoded bytes
`[105, 98, 101, 120]`. It then destroys the receiver and proves flushed and
ended writable state, `destroyed === true`, a null native handle, event-loop
quiescence, and zero decisions. The separate terminal step is required for the
Apple Brotli wrappers because their stream fallback buffers incremental writes
until finalization; it does not turn `end`'s return into evidence for the
selected `write` return or callback. The author, independent evidence
validator, Rust validator, and loaded-engine JavaScript boundary each repeat
the exact owner, inherited-prototype descriptor, fixed input, dedicated
callback, terminal method, output, and cleanup contract. Both zstd owners
remain residual because the runtime deliberately exposes no native zstd
bridge, and `_writeNative`, `_transform`, `_flush`, `flush`, and `params`
remain outside this receipt.

Public zlib `flush(callback)` has a separate non-terminal lifecycle receipt for
all nine non-zstd Apple owners, the seven non-Brotli Windows owners, and both
zstd wrappers on either target. The harness passes its dedicated callback as
the first argument, fixing the source branch to the default `Z_FULL_FLUSH`,
and requires the source call to return the fresh receiver. The callback must
run exactly once without error while the receiver still has
`_flushed === false` and `writableEnded === false`; the harness then destroys
the receiver, closes any native handle, drains byte-view output, quiesces, and
observes zero decisions. The two zstd entries prove only the source-defined
control write: with no native zstd bridge, their flush marker is a safe no-op
and does not constitute zstd compression or decompression evidence. The
author, independent evidence validator, Rust validator, and loaded-engine
JavaScript boundary each repeat the exact owner vocabulary, inherited
prototype descriptor, first-argument callback form, default flush selection,
receiver return, non-terminal state, and cleanup contract. `_flush`,
`_writeNative`, `_transform`, and `params` remain outside this receipt.

Public zlib `params(1, 0, callback)` has its own selected-state receipt over the
same eleven Apple and nine Windows owners as public `flush`. The fixed numeric
arguments choose compression level 1 and default strategy 0; the source call
must return the fresh receiver and deliver its dedicated callback exactly once
without error. Before cleanup, the harness proves `_level === 1`,
`_strategy === 0`, `_flushed === false`, and `writableEnded === false`; it then
destroys the receiver, closes any native handle, drains byte-view output,
quiesces, and observes zero decisions. Native deflate-family compressors enter
the installed parameter bridge, while decoder, Brotli, and no-bridge zstd
wrappers prove only their source-defined retained-state control path. This
does not claim Brotli or zstd codec execution. The author, independent evidence
validator, Rust validator, and loaded-engine JavaScript boundary each repeat
the exact owner vocabulary, inherited descriptor, arguments, callback,
selected state, receiver return, and cleanup contract. `_flush`,
`_writeNative`, and `_transform` remain outside this receipt.

Direct zlib `_transform(Buffer, "buffer", callback)` has a bounded
accepted-input receipt over the same eleven Apple and nine Windows owners. Each
encoder receives `[105, 98, 101, 120]`; the nine established decoders receive
their fixed complete Brotli, deflate, raw-deflate, or gzip member. The direct
source call must return undefined, deliver its callback exactly once without
error, and set both byte counters to the exact input length while leaving
`_flushed` and `writableEnded` false. The harness drains byte-view output,
destroys the receiver, closes any native handle, quiesces, and observes zero
decisions. The two zstd wrappers receive fixed bytes only on the current
no-bridge retained-input branch, so this receipt makes no zstd codec claim.
The author, independent evidence validator, Rust validator, and loaded-engine
boundary repeat the exact owner, input, encoding, callback, accepted-state,
undefined-return, and cleanup contract. `_flush` and `_writeNative` remain
outside this receipt.

Direct synchronous zlib `_processChunk(Buffer, Z_FINISH)` has a distinct
one-shot receipt for the same nine Apple owners and seven non-Brotli Windows
owners as terminal `end`. Compression receives `[105, 98, 101, 120]` and must
return a nonempty byte view; each decoder receives its fixed complete Brotli,
deflate, raw-deflate, or gzip member and must return exactly
`[105, 98, 101, 120]`. The flush flag is fixed to `Z_FINISH` (`4`), even though
the compatibility method currently delegates directly to its stored one-shot
function. Construction may establish an idle native selector, so the harness
must close it in every return or throw path before quiescence. The author,
independent evidence validator, Rust validator, and loaded-engine JavaScript
boundary separately repeat the exact owner set, inherited prototype
descriptor, input, numeric flag, result contract, cleanup, and zero-decision
proof. This receipt does not credit `_writeNative`, `_transform`, `flush`,
`_flush`, `_final`, or `params`; `write` uses the distinct terminal-write
receipt above. It leaves both zstd owners
residual because their one-shot function deliberately reports `ENOSYS`.

The seven reviewed `node:stream` `closed` projections require a constructed
receiver even though the source inventory exposes them as inherited or direct
prototype rows. `Stream()` installs an own accessor backed by `_closed`; the
value does not live on the exported prototype. Authoring therefore cannot reuse
generic prototype reads. It constructs exactly one fresh idle `default`,
`Duplex`, `PassThrough`, `Readable`, `Stream`, `Transform`, or `Writable`,
requires the final property to be an own getter, reads its inert boolean, and
then proves event-loop quiescence with zero decisions. The author, independent
validator, and Rust executor separately repeat that owner/access/result
contract. `readableState` and `writableState` remain residual because their
mutable object graphs are not justified by this scalar receipt.

Fresh HTTP lifecycle evidence is limited to nine independently repeated
contracts: `Agent.destroy`; construction through `Server`,
`Server.constructor`, or `createServer`; and `Server.close`,
`Server.closeAllConnections`, `Server.closeIdleConnections`, `Server.ref`, and
`Server.unref`. Every receiver is constructed by the harness with empty
arguments and owns no listener, socket, or native selector. The recipe author,
independent evidence validator, Rust validator, and loaded-engine JavaScript
harness each repeat the complete `node_http` source descriptor, canonical
`node:http` invocation, exact receiver setup, empty argument list, result type,
and normal-return proof. `Server.close` may schedule its terminal close event;
the receipt is valid only after that event drains and event-loop quiescence is
observed with zero typed decisions. This exception does not admit arbitrary
HTTP calls: client-request operations, `Agent.addRequest`, `Server.listen`,
`Server.getConnections`, and every route requiring or retaining live transport
state remain residual.

Four source-only HTTP validators use separate exact root-call contracts rather
than inheriting the generic captured-output route:
`_checkInvalidHeaderChar("ibex")`, `_checkIsHttpToken("x-ibex")`,
`validateHeaderName("x-ibex")`, and
`validateHeaderValue("x-ibex", "ibex")`. The recipe author, independent
evidence validator, Rust validator, and loaded-engine JavaScript harness each
repeat the literal arguments, direct call dispatch, boolean or undefined
result, event-loop quiescence, and zero-decision contract. These four rows were
already executable through the generic captured-output mechanism, so the
stronger proof changes neither target's executable total nor its unresolved
total; it removes them from the generic captured set and from the
descriptor-only residual manifest. This closed proof does not admit malformed
input, thrown validation results, arbitrary header data, or other HTTP
exports.

Fresh net terminal evidence is limited to five independently repeated
contracts: `Server.close`, `Socket.close`, `Socket.resetAndDestroy`,
`Stream.close`, and `Stream.resetAndDestroy`. The dedicated setup constructs
each receiver with empty arguments and attaches one close observer before
dispatch. A fresh `Server` owns no listener, native handle, accept timer,
connection, or Unix path; a fresh `Socket` or legacy `Stream` owns no native
handle, pending connect, write queue, poll timer, or peer route. The loaded
harness still requires exactly one close event and verifies the final
in-memory state: a server is non-listening with a null handle, while sockets
are destroyed, closed, and have a null handle. The recipe author, independent
evidence validator, Rust validator, and loaded-engine JavaScript harness
separately repeat the exact five-name vocabulary, canonical `node:net`
invocation, source descriptor, owner setup, empty arguments, object result,
cleanup fields, quiescence, and zero-decision contract. This receipt does not
admit `listen`, `connect`, accepted sockets, writes, reset of a live transport,
or any other operation requiring a native handle or peer lifecycle.

Transport-free TLS socket evidence is limited to five independently repeated
contracts: construction through `TLSSocket`, plus `close`, `destroy`, `ref`,
and `unref` on a fresh harness-created `TLSSocket`. The constructor receives no
underlying transport, so it does not capture a native TLS owner token, create a
TLS engine, bind a selector, install transport listeners, or schedule a timer.
`ref` and `unref` consequently return the wrapper without delegating, while
`close` and `destroy` update only wrapper state and queue the terminal close
event; the receipt is valid only after that timer drains and event-loop
quiescence is observed. The recipe author, independent evidence validator,
Rust validator, and loaded-engine JavaScript harness separately repeat the
complete `node_tls` descriptor, canonical `node:tls` invocation, empty
transport/argument setup, object result, and zero-decision contract. This
closed proof does not admit `connect`, `write`, `end`, server construction, or
any call that binds or operates on a transport.

The TLS `SecureContext.context` read uses a separate constructed-instance
contract. A fresh `SecureContext()` normalizes only the harness-owned empty
options object and installs `context` as an own enumerable, non-writable,
non-configurable data property whose value is a frozen opaque object. No TLS
engine is allocated and no native trust or certificate state is consulted.
The recipe author, independent evidence validator, Rust validator, and
loaded-engine JavaScript harness separately repeat the exact `node_tls`
descriptor, empty constructor, `["context"]` instance access, object result,
quiescence, and zero-decision proof. This scalar-shaped receipt does not expose
the constructor's private WeakMap state or admit certificate, key, cipher, or
server operations.

Fresh TLS Server construction is executable only through a separate retirement
contract for `Server`, `Server.constructor`, and `createServer`. Each source
call creates an idle `net.Server` with no bound transport, native listener,
accept timer, or connection, but `_decorateServer` still mints one private
runtime/principal TLS owner token and installs its `listening` and `close`
registry hooks. The loaded harness therefore attaches exactly one close
observer, invokes the guarded `close`, awaits the internal close hook and the
subsequent retirement timer, and requires one close event plus a later guarded
`address()` call failing with `ERR_TLS_SERVER_CLOSED`. Reaching that terminal
state proves native token release completed before the private state was
scrubbed; a close failure instead escapes the timer and fails the fixture. The
recipe author, independent evidence validator, Rust validator, and loaded
engine separately repeat the exact constructor surface, dispatch kind, empty
arguments, object source result, cleanup fields, quiescence, and zero-decision
contract. This receipt does not admit `listen`, accepted connections,
handshakes, credentials, ticket keys, or any other transport-bearing server
operation.

Fresh HTTPS Server construction uses the same retirement mechanism but retains
its distinct source contract. `Server`, `Server.constructor`, and
`createServer` construct an HTTP wrapper with one private principal stamp and
no HTTP native selector, then install one fresh idle TLS server as its net
server. Neither layer binds a transport; the inner TLS layer owns the single
retirable token. The loaded harness closes the outer HTTP wrapper, observes its
close event only after the inner TLS close event propagates, waits one later
timer turn, and calls the outer `address()`. That call delegates to the guarded
inner server and must fail with `ERR_TLS_SERVER_CLOSED`, proving its token was
released and private TLS state scrubbed before the fixture completed. The
recipe author, independent evidence validator, Rust validator, and loaded
engine separately repeat the exact `node:https` module identity,
`member-assignment` export provenance, empty construction arguments, dispatch,
cleanup fields, quiescence, and zero-decision contract. This does not admit
`listen`, requests, accepted connections, handshakes, credentials, agents, or
client transports.

Fresh UDP lifecycle evidence is similarly limited to `Socket`,
`Socket.constructor`, `createSocket`, `Socket.close`, `Socket.ref`,
`Socket.unref`, and `Socket.dropMembership("224.0.0.1")`, all with the exact
`udp4` constructor argument. Construction creates the authenticated principal
stamp but no native handle, binding, poll timer, or peer route. `ref` and
`unref` therefore update only wrapper state, while `close` marks the wrapper
closed and schedules its terminal event; the receipt requires that event to
drain before quiescence. On that same fresh receiver `dropMembership` returns
`undefined` before consulting the native membership hook because the private
handle remains `-1`; the literal group address does not widen the contract to
other membership calls or receiver states.

The separate `Socket._closed` read constructs the same fresh udp4 receiver and
accesses only its own non-enumerable, non-configurable getter/setter pair. The
getter authenticates the retained owner state and returns its boolean close
bit; it does not expose `_handle`, the private WeakMap state, a binding, or a
route. The author, independent evidence validator, Rust validator, and
loaded-engine JavaScript harness each repeat the real
`src/builtins/dgram.js` descriptor, two public module aliases, canonical
`node:dgram` invocation, exact constructed receiver, access/call shape, literal
argument, result type, and zero-decision proof. The closed set still excludes
bind, connect, disconnect, send, address, add-membership,
source-specific-membership, buffer-size, socket-option, and every operation
that requires a bound handle, peer route, throwing result, or separately owned
network lifecycle.

X509 instance evidence is limited to two bounded operations on a fresh
harness-owned `X509Certificate("ibex-x509-fixture")`. The `raw` row requires
the own constructed-instance accessor and returns only its bounded byte object.
The `toString` row calls the source-defined certificate formatter and requires
a string result. Lockdown makes the inherited primordial
`Object.prototype.toString` non-writable, so ordinary assignment previously
failed silently instead of installing the intended X509 override. The builtin
now defines that own method explicitly with the reviewed descriptor, analogous
to other compatibility methods that must survive primordial locking. The
recipe author, independent evidence validator, Rust validator, and
loaded-engine JavaScript harness separately repeat the exact constructor,
access or call kind, result type, quiescence, and zero-decision contract. This
receipt does not admit certificate verification, hostname/email/IP checks,
public-key export, or other X509 operations whose inputs or outputs require a
separate bounded proof.

Three source-only compatibility helpers have a similarly closed receipt.
`exact_crypto.createPrivateKey("ibex-key")` and
`exact_crypto.createPublicKey("ibex-key")` construct only the source-defined
in-memory key wrappers; these compatibility functions do not parse or import
the bytes and do not consult a native key store. `node_readline.CSI(["31m"])`
only concatenates the harness-owned string array into an escape sequence; it
does not open a terminal or retain a stream. The author, independent evidence
validator, Rust validator, and loaded-engine JavaScript harness separately
repeat the exact source descriptor, root-call setup, literal argument, result
type, quiescence, and zero-decision contract. This closed list does not admit
other crypto or readline calls. In particular,
`dns/promises.getDefaultResultOrder` remains residual because its public export
is an explicitly marked cross-source projection rather than a locally authored
callable.

`exact_crypto.KeyObject.equals` has a separate pair-owner receipt. The harness
constructs two distinct secret `KeyObject` instances from the same fixed four
bytes (`ibex`) and passes the second only through a named setup binding to the
first instance's exact prototype method. The returned boolean proves the
source-defined in-memory byte comparison. The four validators repeat the
complete descriptor, bytes, key type, receiver, peer binding, result,
quiescence, and zero-decision contract. The setup kind is specific to this
route; it does not expose a generic nested-constructor argument that another
crypto callable could inherit.

`node_readline.Interface.close` and `node_readline.Interface.pause` have
separate lifecycle-owner receipts. Each harness constructs a fresh
non-terminal `Interface` over an inert input shim that accepts only the exact
data, error, end, and close listeners and records exactly one constructor
resume. The close receipt proves the selected call detaches every listener,
pauses exactly once, closes the receiver, emits one close event, returns
`undefined`, and reaches event-loop quiescence with zero legacy or typed
decisions. The pause receipt first proves the selected call returns the
receiver object while leaving it open but paused, preserves all four
constructor listeners, records exactly one pause, and emits no close event.
The harness then invokes exact `Interface.close` as auxiliary cleanup and
proves every listener detached, two total pauses, one close event, quiescence,
and zero decisions. Cleanup runs even when the pre-cleanup pause-state check
fails. The recipe author, independent evidence validator, Rust validator, and
loaded-engine JavaScript harness separately repeat each complete descriptor,
owner, terminal mode, listener lifecycle, result, cleanup, and zero-decision
contract. This closed list does not admit the constructor-instance
`_onAbortSignal`, `_onClose`, or `_onError` closures.

Acceptance:

- Every authorable edge has positive, negative, wrong-principal, malformed,
  missing-attribution, and target-specific fixtures.
- Multi-effect, lifetime, revocation, loader, filesystem, network, process, and
  escape-surface suites pass on every advertised target.
- The report binds source revision, engine identity, target, profile, semantic
  and registry digests, fixture catalog, and observed results.
- Unsupported targets do not advertise or silently degrade the complete profile.

### WP11 — Reconcile the corpus and remove the legacy plane

Update LLP 0013 and LLP 0014 to describe the final mechanism and artifact,
revise LLP 0016's assessment, update LLP 0002/0004/0005 where their contracts
change, refresh demos and documentation, and delete dead code/generators/tests
for the legacy plane.

Implementation status (2026-07-25): the `PolicyFile` parser and public module,
the `HostConfig` policy/path/allow/deny seams, and the policy-string mode parser
have been deleted. Foreground audit deliberately constructs a policyless
diagnostic Host under LLP 0030; no durable string-policy value is representable
at that boundary. Historical compatibility-manager import/deputy/dynamic
algebra remains covered only through private test setup, not a parser or
embedder configuration surface. LLP 0013, LLP 0014, and LLP 0016 identify their
old mode, flag, and string-policy passages as superseded. The canonical typed
artifact, armed snapshot, and target-bound conformance report are the current
contracts. ENG-24263 retired LLP 0013's executable string-policy corpus and its
127 legacy fixtures. A checked 69-case retirement join names the current typed,
armed-engine, production-closure, or migrated diagnostic coverage for every
former test; the live callback harness also proves package-global withholding
and native-freeze hatch removal, while process signaling is covered inside the
authenticated armed process-closure test.

Acceptance:

- `./ref-check` passes and all capsec `@ref`s point to current semantics.
- No documentation teaches permissive-by-default or the legacy string format.
- No production path parses or executes the legacy `PolicyFile` model.
- The root LLP and implementation-status sections identify the supported
  profile and current target conformance honestly.

## Dependency order

The executable dependency graph is:

```text
WP0 ─┬─> WP1 ────────────────┐
     └─> WP2 ─> WP3 ─> WP4 ─┼─> WP5 ─┐
                            ├─> WP6 ─┤
                            ├─> WP7 ─┼─> WP9 ─┐
                            └─> WP8 ─┘        ├─> WP11
WP1 ────────────────────────────────> WP10 ───┘
WP5, WP6, WP7, WP8 ─────────────────> WP10
```

WP5–WP8 are intentionally parallel once the typed core and armed-snapshot seam
exist. WP10 begins with registry/fixture infrastructure during WP1 and closes
only after every enforcement workstream lands. WP9 is the product cutover, not
the point at which enforcement work starts. WP11 removes the old plane only
after both cutover and conformance are green.

## Linear execution contract

Each WP maps to one child issue beneath an umbrella issue. Issues use Linear's
blocking relations to encode the graph above and belong to the Exact project.
Every issue description must include:

- this LLP and its WP anchor;
- the exact in-scope surfaces and explicit exclusions;
- acceptance criteria copied or strengthened from the WP;
- required tests and generated artifacts;
- the LLPs and existing `@ref`s that govern its files;
- a rule that semantic/code changes update the governing LLP in the same commit.

The umbrella issue tracks the overall completion gate but is not a substitute
for dependency relations. The created issue set is:

| Work package | Linear issue | Blocked by                                            |
| ------------ | ------------ | ----------------------------------------------------- |
| Program      | ENG-24143    | completion is defined by the child graph              |
| WP0          | ENG-24144    | —                                                     |
| WP1          | ENG-24145    | ENG-24144                                             |
| WP2          | ENG-24146    | ENG-24144                                             |
| WP3          | ENG-24147    | ENG-24146                                             |
| WP4          | ENG-24148    | ENG-24145, ENG-24147                                  |
| WP5          | ENG-24149    | ENG-24148                                             |
| WP6          | ENG-24150    | ENG-24148                                             |
| WP7          | ENG-24151    | ENG-24148                                             |
| WP8          | ENG-24152    | ENG-24148                                             |
| WP9          | ENG-24153    | ENG-24149, ENG-24150, ENG-24151, ENG-24152            |
| WP10         | ENG-24154    | ENG-24145, ENG-24149, ENG-24150, ENG-24151, ENG-24152 |
| WP11         | ENG-24155    | ENG-24153, ENG-24154                                  |

## Risks and controls

### Scope expansion

The Oden corpus contains product workflows far beyond Ibex's core needs.
Deferring grant-assistant, publication, daemon, and privacy systems keeps this
plan focused. New product surfaces must justify themselves independently.

### A typed model that remains incomplete

Schemas alone do not create security. Generated surface inventory and target
cells land before broad conversion work, and target claims stay closed until
fixtures prove each edge.

### Big-bang cutover instability

The external cutover is direct, but implementation is staged behind internal
seams. The typed decision core, generator, and armed snapshot land before
surface conversions; filesystem/network/escape/handle work then proceeds in
parallel. The legacy plane is deleted only at the end.

### Cross-project drift with Oden

Ibex should reuse runtime-neutral schemas, canonicalizers, property fixtures,
and Rust decision logic where practical, but not force Deno-specific vocabulary
or product workflow into Hermes. Shared components need one source of truth and
cross-repo fixture parity; target-specific coverage edges remain local.

### Default enforcement before evidence

Having no external users removes migration constraints, not the need for
correctness. WP9 remains gated on complete initial enforcement and WP10 remains
the release/claim gate. Development can exercise the new default earlier, but
unsupported targets may not silently claim completion.

## Completion criteria

This plan is complete when:

1. The typed effect model is the only production policy and decision plane.
2. Every production surface has a generated classification and target cell.
3. Canonical policy and armed snapshots are deterministic, typed, digest-bound,
   and fail closed on mismatch.
4. Filesystem and network checks bind the object/peer actually used, with
   staged multi-effect authorization.
5. Handles, dynamic authority, deputy intersection, import gating, and audit
   evidence operate on the same immutable effect semantics.
6. Plain `ibex` execution enforces the supported profile and offers no silent
   weakening path.
7. Every advertised target has a passing generated conformance report.
8. Legacy policy code, docs, demos, and stale LLP claims are removed or revised.

## Resolved WP0 questions

1. Ibex owns the canonical contract and neutral crate boundary initially;
   another consumer reuses it or explicitly moves ownership, never copies it.
2. The profile is `ibex/capsec/1`; the neutral core is
   `capsec/semantics/1`.
3. Location, camera, microphone, and clipboard are target-specific authorable
   definitions; storage and unproved device families stay closed, absent, or
   unsupported exactly as the generated reconciliation records.
4. Production gets no raw/permissive developer harness; isolated fixtures and
   the explicit ephemeral audit workflow cover compatibility work.
5. WP9 may flip after one exact target is complete, but every incomplete build
   target refuses before project code. No target silently inherits another
   target's conformance or falls back to the legacy plane.
