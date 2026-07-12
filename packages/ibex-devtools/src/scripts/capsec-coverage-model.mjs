/**
 * Turn mechanically observed runtime surfaces into the semantic coverage
 * registry and its separate implementation inventory.
 *
 * This module is intentionally pure: discovery owns source parsing, while this
 * file owns the closed classification vocabulary and the join to the frozen
 * capability definitions. It emits no target claims and performs no I/O.
 *
 * @ref LLP 0021#wp1--generate-the-registry-and-completeness-inventory — every
 * observed production surface receives one deterministic semantic edge or
 * generation fails closed.
 */

import { fixtureObligationsForBranch } from "./capsec-fixture-obligations.mjs";
import { targetApplicabilityForVariant } from "./capsec-target-branches.mjs";

const PROFILE = "ibex/capsec/1";
const COVERAGE_SCHEMA = "ibex/capsec-coverage/1";
const STABLE_ID_RE = /^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/u;
const SURFACE_KINDS = new Set([
  "builtin",
  "callback",
  "cli",
  "host-abi",
  "loader",
  "native-op",
  "startup",
]);
// This is semantic approval, not discovery authority: the source scanner owns
// the inventory and a test requires an exact stale/missing join. The broad
// matchers later in this module run only for these reviewed native operations,
// so suggestive suffixes such as `Ensure`, `Close`, `Callback`, or `Network`
// cannot grant an unknown callable an inherited classification.
const REVIEWED_NATIVE_OPERATION_NAMES = new Set([
  "__StringBuffer",
  "__compartments",
  "__ex_p",
  "__exact",
  "__exactAccess",
  "__exactAccessibilitySnapshot",
  "__exactAesCbcDecrypt",
  "__exactAesCbcEncrypt",
  "__exactAesCtrEncrypt",
  "__exactAesGcmDecrypt",
  "__exactAesGcmEncrypt",
  "__exactAndroidCameraHostCall",
  "__exactAndroidCameraMetadata",
  "__exactAndroidDispatchPlatformEvent",
  "__exactAndroidDrainPlatformEvents",
  "__exactAndroidGetPlatformState",
  "__exactAndroidLocation",
  "__exactAndroidLocation.getCurrentLocation",
  "__exactAndroidStoragePaths",
  "__exactAppState",
  "__exactAppearanceState",
  "__exactAppendFile",
  "__exactArch",
  "__exactBrotliCompressSync",
  "__exactBrotliDecompressSync",
  "__exactBytesToUtf8String",
  "__exactCancel",
  "__exactCapabilityCheck",
  "__exactCheckImport",
  "__exactChmod",
  "__exactChown",
  "__exactClipboardRead",
  "__exactClipboardWrite",
  "__exactCopyFile",
  "__exactCreateHandle",
  "__exactDeepFreeze",
  "__exactDeflateSync",
  "__exactDispatchEvent",
  "__exactDispatchPendingSignals",
  "__exactDnsGetServers",
  "__exactDnsLookup",
  "__exactDnsLookupAsync",
  "__exactDnsResolve",
  "__exactDnsResolveAsync",
  "__exactDnsReverse",
  "__exactDnsReverseAsync",
  "__exactEcdhDeriveBits",
  "__exactEcdsaSign",
  "__exactEcdsaVerify",
  "__exactEd25519Sign",
  "__exactEd25519Verify",
  "__exactEnsureChildProcess",
  "__exactEnsureDns",
  "__exactEnsureFormData",
  "__exactEnsureFs",
  "__exactEnsureHttp",
  "__exactEnsureNet",
  "__exactEnsureSqlite",
  "__exactEnsureStreamEnhance",
  "__exactEnsureWebCrypto",
  "__exactEnsureWebStorage",
  "__exactEvpCipherDecrypt",
  "__exactEvpCipherEncrypt",
  "__exactExecSync",
  "__exactExit",
  "__exactExportKeyPkcs8",
  "__exactExportKeySpki",
  "__exactFdPollHup",
  "__exactFsClose",
  "__exactFsCloseAsync",
  "__exactFsFchmod",
  "__exactFsFchmodSync",
  "__exactFsFchown",
  "__exactFsFchownSync",
  "__exactFsFdAsync",
  "__exactFsFdatasyncSync",
  "__exactFsFstatSync",
  "__exactFsFsyncSync",
  "__exactFsFtruncateSync",
  "__exactFsFutimesSync",
  "__exactFsOpen",
  "__exactFsOpenAsync",
  "__exactFsPathAsync",
  "__exactFsRead",
  "__exactFsReadAsync",
  "__exactFsReadFileAsync",
  "__exactFsReadv",
  "__exactFsReadvAsync",
  "__exactFsStatAsync",
  "__exactFsWrite",
  "__exactFsWriteAsync",
  "__exactFsWriteFileAsync",
  "__exactFsWritev",
  "__exactFsWritevAsync",
  "__exactGenerateKeyPairSync",
  "__exactGetAllEnv",
  "__exactGetCpuCount",
  "__exactGetCwd",
  "__exactGetEnv",
  "__exactGetFreeMem",
  "__exactGetGCStats",
  "__exactGetHeapInfo",
  "__exactGetHostname",
  "__exactGetLoadAvg",
  "__exactGetNetworkInterfaces",
  "__exactGetProcessRSS",
  "__exactGetScreenInfo",
  "__exactGetSourceCacheStats",
  "__exactGetTotalMem",
  "__exactGetUptime",
  "__exactGetUserInfo",
  "__exactGrantCapability",
  "__exactHandleReadFileSync",
  "__exactHandleScoped",
  "__exactHasSharedRuntimeBundle",
  "__exactHashRaw",
  "__exactHashSync",
  "__exactHkdf",
  "__exactHmacSync",
  "__exactHostExit",
  "__exactHttpAddress",
  "__exactHttpAwaitWritable",
  "__exactHttpAwaitWritableExecutor",
  "__exactHttpClose",
  "__exactHttpDrain",
  "__exactHttpPoll",
  "__exactHttpReadBody",
  "__exactHttpRespond",
  "__exactHttpRespondAbort",
  "__exactHttpRespondChunk",
  "__exactHttpRespondChunkTry",
  "__exactHttpRespondEnd",
  "__exactHttpRespondEndTry",
  "__exactHttpRespondJson",
  "__exactHttpRespondStream",
  "__exactHttpRespondString",
  "__exactHttpRespondText",
  "__exactHttpServe",
  "__exactHttpSetRef",
  "__exactHttpWait",
  "__exactHttpWaitExecutor",
  "__exactImportKeyPkcs8",
  "__exactImportKeySpki",
  "__exactInflateSync",
  "__exactInitialURL",
  "__exactIpcRecvMsg",
  "__exactIpcSendMsg",
  "__exactLanguage",
  "__exactLchmod",
  "__exactLchmodSync",
  "__exactLchown",
  "__exactLink",
  "__exactLocale",
  "__exactLocaleSnapshot",
  "__exactLstat",
  "__exactLutimes",
  "__exactLutimesSync",
  "__exactMkdir",
  "__exactMkdtemp",
  "__exactModuleEvent",
  "__exactModuleResolve",
  "__exactModuleResolveMeta",
  "__exactNativeDialog",
  "__exactNativeFreeze",
  "__exactNativeModuleResolve",
  "__exactNativeModuleResolveMeta",
  "__exactNotifyTypedAuthorityChange",
  "__exactOSRelease",
  "__exactOSVersion",
  "__exactOpendir",
  "__exactPbkdf2",
  "__exactPerformanceNow",
  "__exactPerformanceTimeOrigin",
  "__exactPermissionRequest",
  "__exactPermissionRevoke",
  "__exactPermissionStatus",
  "__exactTypedHandleMint",
  "__exactTypedHandleRevoke",
  "__exactTypedPermissionRequest",
  "__exactTypedPermissionRevoke",
  "__exactPlatform",
  "__exactPlatformVersion",
  "__exactPollSignal",
  "__exactRandomBytes",
  "__exactReadFile",
  "__exactReaddir",
  "__exactReadlink",
  "__exactRealpath",
  "__exactRegisterPackage",
  "__exactRename",
  "__exactRequestAnimationFrame",
  "__exactResetSignal",
  "__exactRevokeHandle",
  "__exactRmdir",
  "__exactRsaOaepDecrypt",
  "__exactRsaOaepEncrypt",
  "__exactRuntimeLoaded",
  "__exactScryptSync",
  "__exactSetActiveModuleId",
  "__exactSetCompartmentFor",
  "__exactSetCwd",
  "__exactSetPendingPackageId",
  "__exactSignSync",
  "__exactSignalNumbers",
  "__exactSpawn",
  "__exactSpawnCloseStdin",
  "__exactSpawnDispose",
  "__exactSpawnGetFd",
  "__exactSpawnKill",
  "__exactSpawnPoll",
  "__exactSpawnRead",
  "__exactSpawnRecvMsg",
  "__exactSpawnSendMsg",
  "__exactSpawnSync",
  "__exactSpawnWrite",
  "__exactSqliteAll",
  "__exactSqliteClose",
  "__exactSqliteExec",
  "__exactSqliteExpandedSql",
  "__exactSqliteFinalize",
  "__exactSqliteGet",
  "__exactSqliteInTransaction",
  "__exactSqliteOpen",
  "__exactSqlitePrepare",
  "__exactSqliteRun",
  "__exactSqliteValues",
  "__exactStat",
  "__exactStatfs",
  "__exactStdinRead",
  "__exactStringToUtf8Bytes",
  "__exactSuppressRuntimeBanner",
  "__exactSymlink",
  "__exactTcpAccept",
  "__exactTcpClose",
  "__exactTcpConnect",
  "__exactTcpConnectPoll",
  "__exactTcpConnectStart",
  "__exactTcpFromFd",
  "__exactTcpGetFd",
  "__exactTcpListen",
  "__exactTcpLocalAddr",
  "__exactTcpRead",
  "__exactTcpRemoteAddr",
  "__exactTcpReset",
  "__exactTcpSetKeepAlive",
  "__exactTcpSetNoDelay",
  "__exactTcpShutdown",
  "__exactTcpWrite",
  "__exactTimerRef",
  "__exactTimerUnref",
  "__exactTlsEngineClose",
  "__exactTlsEngineNew",
  "__exactTlsEnginePeerCerts",
  "__exactTlsEngineReadPlain",
  "__exactTlsEngineReadTls",
  "__exactTlsEngineShutdown",
  "__exactTlsEngineStatus",
  "__exactTlsEngineTransportEof",
  "__exactTlsEngineWritePlain",
  "__exactTlsEngineWriteTls",
  "__exactTrapSignal",
  "__exactTruncate",
  "__exactUdpAddress",
  "__exactUdpBind",
  "__exactUdpClose",
  "__exactUdpFromFd",
  "__exactUdpGetFd",
  "__exactUdpRecv",
  "__exactUdpSend",
  "__exactUdpSocket",
  "__exactUncaughtExceptionHandler",
  "__exactUnixAccept",
  "__exactUnixConnect",
  "__exactUnixListen",
  "__exactUnlink",
  "__exactUtimes",
  "__exactVerifySync",
  "__exactWhich",
  "__exactWriteFile",
  "__exactWsClose",
  "__exactWsConnect",
  "__exactWsPause",
  "__exactWsResume",
  "__exactWsSend",
  "__exactWsSetFlowControlled",
  "__exactX25519DeriveBits",
  "__exactZlibClose",
  "__exactZlibCreate",
  "__exactZlibParams",
  "__exactZlibWrite",
  "__hostCall",
  "__hostCallAsync",
  "__ibex",
  "__ibexBarePackageName",
  "__ibexEndowRaw",
  "__ibexLockedDown",
  "__ibexNativeLockdown",
  "__ibexTamed",
  "__nativeFetch",
  "__nativeFetchSync",
  "__svGet",
  "__svSet",
  "native_fetch_cancel",
  "native_fetch_perform",
  "native_ws_close",
  "native_ws_connect",
  "native_ws_destroy",
  "native_ws_has_active",
  "native_ws_pause",
  "native_ws_resume",
  "native_ws_send",
  "native_ws_set_flow_controlled",
]);

const REVIEWED_CALLBACK_PRODUCER_NAMES = new Set([
  "producer:src/engine/hermes_runtime.cc:ex_hermes_resolve_host_call:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime.cc:ex_hermes_schedule_watchdog_heartbeat:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime.cc:native_ws_release_context:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime_android.cc:android_animation_frame_callback:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime_android.cc:android_platform_event_available:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime_crypto.cc:signalWatcherThreadMain:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime_dns.cc:startDnsAsync:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime_fetch.cc:installFetchGlobals:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime_fs.cc:startFsAsync:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime_fs_windows.cc:startFsAsync:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime_http.cc:WaitWorkerPool::spawnWorkerIfNeededLocked:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime_http.cc:WritableWorkerPool::spawnWorkerIfNeededLocked:pushRuntimeCallback",
  "producer:src/engine/hermes_runtime_websocket.cc:installWebSocketGlobals:pushRuntimeCallback",
]);

// Authored builtin specifier roots are reviewed independently from their
// exported methods because module initialization may itself have effects.
const REVIEWED_BUILTIN_ROOT_NAMES = new Set([
  "_http_agent",
  "_http_common",
  "_http_incoming",
  "_http_outgoing",
  "_http_server",
  "_stream_duplex",
  "_stream_passthrough",
  "_stream_readable",
  "_stream_transform",
  "_stream_writable",
  "assert",
  "assert/strict",
  "async_hooks",
  "buffer",
  "bun:fs",
  "bun:fs/promises",
  "bun:sqlite",
  "child_process",
  "cluster",
  "console",
  "constants",
  "crypto",
  "dgram",
  "diagnostics_channel",
  "dns",
  "dns/promises",
  "domain",
  "events",
  "exact:clipboard",
  "exact:crypto",
  "exact:http",
  "exact:process",
  "exact:sqlite",
  "fs",
  "fs/promises",
  "http",
  "http2",
  "https",
  "inspector",
  "inspector/promises",
  "internal/fs/promises",
  "internal/fs/utils",
  "module",
  "net",
  "node:assert",
  "node:assert/strict",
  "node:async_hooks",
  "node:buffer",
  "node:child_process",
  "node:cluster",
  "node:console",
  "node:constants",
  "node:crypto",
  "node:dgram",
  "node:diagnostics_channel",
  "node:dns",
  "node:dns/promises",
  "node:domain",
  "node:events",
  "node:fs",
  "node:fs/promises",
  "node:http",
  "node:http2",
  "node:https",
  "node:inspector",
  "node:inspector/promises",
  "node:module",
  "node:net",
  "node:os",
  "node:path",
  "node:path/posix",
  "node:path/win32",
  "node:perf_hooks",
  "node:process",
  "node:punycode",
  "node:querystring",
  "node:readline",
  "node:readline/promises",
  "node:stream",
  "node:stream/consumers",
  "node:stream/promises",
  "node:stream/web",
  "node:string_decoder",
  "node:sys",
  "node:timers",
  "node:timers/promises",
  "node:tls",
  "node:trace_events",
  "node:tty",
  "node:url",
  "node:util",
  "node:util/types",
  "node:v8",
  "node:vm",
  "node:wasi",
  "node:worker_threads",
  "node:zlib",
  "os",
  "path",
  "path/posix",
  "path/win32",
  "perf_hooks",
  "process",
  "punycode",
  "querystring",
  "readline",
  "readline/promises",
  "stream",
  "stream/consumers",
  "stream/promises",
  "stream/web",
  "string_decoder",
  "sys",
  "timers",
  "timers/promises",
  "tls",
  "trace_events",
  "tty",
  "url",
  "util",
  "util/types",
  "v8",
  "vm",
  "wasi",
  "worker_threads",
  "ws",
  "zlib",
]);

// Export and prototype keys are approved exactly. Semantic source families
// below may share a classification only after every concrete key appears here;
// a newly added export therefore fails generation until it is reviewed.
const REVIEWED_BUILTIN_EXPORT_NAMES = new Set([
  "export:exact_clipboard:default",
  "export:exact_clipboard:readText",
  "export:exact_clipboard:writeText",
  "export:exact_crypto:Certificate",
  "export:exact_crypto:Certificate.exportChallenge",
  "export:exact_crypto:Certificate.exportPublicKey",
  "export:exact_crypto:Certificate.verifySpkac",
  "export:exact_crypto:Cipher",
  "export:exact_crypto:Cipher._final",
  "export:exact_crypto:Cipher._flush",
  "export:exact_crypto:Cipher._flushStreamResult",
  "export:exact_crypto:Cipher._transform",
  "export:exact_crypto:Cipher.constructor",
  "export:exact_crypto:Cipher.end",
  "export:exact_crypto:Cipher.final",
  "export:exact_crypto:Cipher.getAuthTag",
  "export:exact_crypto:Cipher.setAAD",
  "export:exact_crypto:Cipher.setAutoPadding",
  "export:exact_crypto:Cipher.update",
  "export:exact_crypto:Cipheriv",
  "export:exact_crypto:Cipheriv._final",
  "export:exact_crypto:Cipheriv._flush",
  "export:exact_crypto:Cipheriv._flushStreamResult",
  "export:exact_crypto:Cipheriv._transform",
  "export:exact_crypto:Cipheriv.constructor",
  "export:exact_crypto:Cipheriv.end",
  "export:exact_crypto:Cipheriv.final",
  "export:exact_crypto:Cipheriv.getAuthTag",
  "export:exact_crypto:Cipheriv.setAAD",
  "export:exact_crypto:Cipheriv.setAutoPadding",
  "export:exact_crypto:Cipheriv.update",
  "export:exact_crypto:Decipher",
  "export:exact_crypto:Decipher._final",
  "export:exact_crypto:Decipher._flush",
  "export:exact_crypto:Decipher._flushStreamResult",
  "export:exact_crypto:Decipher._transform",
  "export:exact_crypto:Decipher.constructor",
  "export:exact_crypto:Decipher.end",
  "export:exact_crypto:Decipher.final",
  "export:exact_crypto:Decipher.setAAD",
  "export:exact_crypto:Decipher.setAuthTag",
  "export:exact_crypto:Decipher.setAutoPadding",
  "export:exact_crypto:Decipher.update",
  "export:exact_crypto:Decipheriv",
  "export:exact_crypto:Decipheriv._final",
  "export:exact_crypto:Decipheriv._flush",
  "export:exact_crypto:Decipheriv._flushStreamResult",
  "export:exact_crypto:Decipheriv._transform",
  "export:exact_crypto:Decipheriv.constructor",
  "export:exact_crypto:Decipheriv.end",
  "export:exact_crypto:Decipheriv.final",
  "export:exact_crypto:Decipheriv.setAAD",
  "export:exact_crypto:Decipheriv.setAuthTag",
  "export:exact_crypto:Decipheriv.setAutoPadding",
  "export:exact_crypto:Decipheriv.update",
  "export:exact_crypto:DiffieHellman",
  "export:exact_crypto:DiffieHellman.computeSecret",
  "export:exact_crypto:DiffieHellman.generateKeys",
  "export:exact_crypto:DiffieHellman.getGenerator",
  "export:exact_crypto:DiffieHellman.getPrime",
  "export:exact_crypto:DiffieHellman.getPrivateKey",
  "export:exact_crypto:DiffieHellman.getPublicKey",
  "export:exact_crypto:DiffieHellman.setPrivateKey",
  "export:exact_crypto:DiffieHellman.setPublicKey",
  "export:exact_crypto:DiffieHellmanGroup",
  "export:exact_crypto:DiffieHellmanGroup.computeSecret",
  "export:exact_crypto:DiffieHellmanGroup.generateKeys",
  "export:exact_crypto:DiffieHellmanGroup.getGenerator",
  "export:exact_crypto:DiffieHellmanGroup.getPrime",
  "export:exact_crypto:DiffieHellmanGroup.getPrivateKey",
  "export:exact_crypto:DiffieHellmanGroup.getPublicKey",
  "export:exact_crypto:ECDH",
  "export:exact_crypto:ECDH.computeSecret",
  "export:exact_crypto:ECDH.generateKeys",
  "export:exact_crypto:ECDH.getPrivateKey",
  "export:exact_crypto:ECDH.getPublicKey",
  "export:exact_crypto:ECDH.setPrivateKey",
  "export:exact_crypto:ECDH.setPublicKey",
  "export:exact_crypto:Hash",
  "export:exact_crypto:Hash._flush",
  "export:exact_crypto:Hash._transform",
  "export:exact_crypto:Hash.constructor",
  "export:exact_crypto:Hash.copy",
  "export:exact_crypto:Hash.digest",
  "export:exact_crypto:Hash.end",
  "export:exact_crypto:Hash.update",
  "export:exact_crypto:Hmac",
  "export:exact_crypto:Hmac._flush",
  "export:exact_crypto:Hmac._transform",
  "export:exact_crypto:Hmac.constructor",
  "export:exact_crypto:Hmac.digest",
  "export:exact_crypto:Hmac.end",
  "export:exact_crypto:Hmac.update",
  "export:exact_crypto:KeyObject",
  "export:exact_crypto:KeyObject.asymmetricKeyDetails",
  "export:exact_crypto:KeyObject.asymmetricKeyType",
  "export:exact_crypto:KeyObject.equals",
  "export:exact_crypto:KeyObject.export",
  "export:exact_crypto:KeyObject.symmetricKeySize",
  "export:exact_crypto:KeyObject.type",
  "export:exact_crypto:Sign",
  "export:exact_crypto:Sign.constructor",
  "export:exact_crypto:Sign.end",
  "export:exact_crypto:Sign.sign",
  "export:exact_crypto:Sign.update",
  "export:exact_crypto:Verify",
  "export:exact_crypto:Verify.constructor",
  "export:exact_crypto:Verify.end",
  "export:exact_crypto:Verify.update",
  "export:exact_crypto:Verify.verify",
  "export:exact_crypto:X509Certificate",
  "export:exact_crypto:X509Certificate.checkEmail",
  "export:exact_crypto:X509Certificate.checkHost",
  "export:exact_crypto:X509Certificate.checkIP",
  "export:exact_crypto:X509Certificate.checkIssued",
  "export:exact_crypto:X509Certificate.checkPrivateKey",
  "export:exact_crypto:X509Certificate.fingerprint",
  "export:exact_crypto:X509Certificate.fingerprint256",
  "export:exact_crypto:X509Certificate.infoAccess",
  "export:exact_crypto:X509Certificate.issuer",
  "export:exact_crypto:X509Certificate.issuerCertificate",
  "export:exact_crypto:X509Certificate.keyUsage",
  "export:exact_crypto:X509Certificate.publicKey",
  "export:exact_crypto:X509Certificate.raw",
  "export:exact_crypto:X509Certificate.serialNumber",
  "export:exact_crypto:X509Certificate.subject",
  "export:exact_crypto:X509Certificate.subjectAltName",
  "export:exact_crypto:X509Certificate.toJSON",
  "export:exact_crypto:X509Certificate.toLegacyObject",
  "export:exact_crypto:X509Certificate.toString",
  "export:exact_crypto:X509Certificate.validFrom",
  "export:exact_crypto:X509Certificate.validTo",
  "export:exact_crypto:X509Certificate.verify",
  "export:exact_crypto:argon2",
  "export:exact_crypto:checkPrime",
  "export:exact_crypto:checkPrimeSync",
  "export:exact_crypto:constants",
  "export:exact_crypto:createCipher",
  "export:exact_crypto:createCipheriv",
  "export:exact_crypto:createDecipher",
  "export:exact_crypto:createDecipheriv",
  "export:exact_crypto:createDiffieHellman",
  "export:exact_crypto:createDiffieHellmanGroup",
  "export:exact_crypto:createECDH",
  "export:exact_crypto:createHash",
  "export:exact_crypto:createHmac",
  "export:exact_crypto:createPrivateKey",
  "export:exact_crypto:createPublicKey",
  "export:exact_crypto:createSecretKey",
  "export:exact_crypto:createSign",
  "export:exact_crypto:createVerify",
  "export:exact_crypto:decapsulate",
  "export:exact_crypto:default",
  "export:exact_crypto:diffieHellman",
  "export:exact_crypto:encapsulate",
  "export:exact_crypto:fips",
  "export:exact_crypto:generateKey",
  "export:exact_crypto:generateKeyPair",
  "export:exact_crypto:generateKeyPairSync",
  "export:exact_crypto:generateKeySync",
  "export:exact_crypto:generatePrime",
  "export:exact_crypto:generatePrimeSync",
  "export:exact_crypto:getCipherInfo",
  "export:exact_crypto:getCiphers",
  "export:exact_crypto:getCurves",
  "export:exact_crypto:getDiffieHellman",
  "export:exact_crypto:getFips",
  "export:exact_crypto:getHashes",
  "export:exact_crypto:getRandomValues",
  "export:exact_crypto:hash",
  "export:exact_crypto:hkdf",
  "export:exact_crypto:hkdfSync",
  "export:exact_crypto:pbkdf2",
  "export:exact_crypto:pbkdf2Sync",
  "export:exact_crypto:privateDecrypt",
  "export:exact_crypto:privateEncrypt",
  "export:exact_crypto:prng",
  "export:exact_crypto:pseudoRandomBytes",
  "export:exact_crypto:publicDecrypt",
  "export:exact_crypto:publicEncrypt",
  "export:exact_crypto:randomBytes",
  "export:exact_crypto:randomFill",
  "export:exact_crypto:randomFillSync",
  "export:exact_crypto:randomInt",
  "export:exact_crypto:randomUUID",
  "export:exact_crypto:rng",
  "export:exact_crypto:scrypt",
  "export:exact_crypto:scryptSync",
  "export:exact_crypto:secureHeapUsed",
  "export:exact_crypto:setEngine",
  "export:exact_crypto:setFips",
  "export:exact_crypto:sign",
  "export:exact_crypto:subtle",
  "export:exact_crypto:timingSafeEqual",
  "export:exact_crypto:verify",
  "export:exact_crypto:webcrypto",
  "export:exact_http:serve",
  "export:exact_process:_umask",
  "export:exact_process:_uncaughtCaptureCb",
  "export:exact_process:addListener",
  "export:exact_process:argv",
  "export:exact_process:binding",
  "export:exact_process:channel",
  "export:exact_process:chdir",
  "export:exact_process:cwd",
  "export:exact_process:default",
  "export:exact_process:emitWarning",
  "export:exact_process:env",
  "export:exact_process:execArgv",
  "export:exact_process:execve",
  "export:exact_process:getegid",
  "export:exact_process:geteuid",
  "export:exact_process:getgid",
  "export:exact_process:getgroups",
  "export:exact_process:getuid",
  "export:exact_process:hasUncaughtExceptionCaptureCallback",
  "export:exact_process:hrtime",
  "export:exact_process:kill",
  "export:exact_process:off",
  "export:exact_process:release",
  "export:exact_process:setSourceMapsEnabled",
  "export:exact_process:setUncaughtExceptionCaptureCallback",
  "export:exact_process:stdin",
  "export:exact_process:umask",
  "export:exact_process:version",
  "export:exact_sqlite:Database",
  "export:exact_sqlite:Database._checkClosed",
  "export:exact_sqlite:Database.applyChanges",
  "export:exact_sqlite:Database.close",
  "export:exact_sqlite:Database.enableCrSqlite",
  "export:exact_sqlite:Database.exec",
  "export:exact_sqlite:Database.fileControl",
  "export:exact_sqlite:Database.getChanges",
  "export:exact_sqlite:Database.getDbVersion",
  "export:exact_sqlite:Database.getSiteId",
  "export:exact_sqlite:Database.handle",
  "export:exact_sqlite:Database.inTransaction",
  "export:exact_sqlite:Database.loadExtension",
  "export:exact_sqlite:Database.markAsCrr",
  "export:exact_sqlite:Database.prepare",
  "export:exact_sqlite:Database.query",
  "export:exact_sqlite:Database.run",
  "export:exact_sqlite:Database.serialize",
  "export:exact_sqlite:Database.transaction",
  "export:exact_sqlite:SQLiteError",
  "export:exact_sqlite:SQLiteError.constructor",
  "export:exact_sqlite:Statement",
  "export:exact_sqlite:Statement._checkFinalized",
  "export:exact_sqlite:Statement._normalizeParams",
  "export:exact_sqlite:Statement._recordExecution",
  "export:exact_sqlite:Statement.all",
  "export:exact_sqlite:Statement.as",
  "export:exact_sqlite:Statement.columnTypes",
  "export:exact_sqlite:Statement.declaredTypes",
  "export:exact_sqlite:Statement.finalize",
  "export:exact_sqlite:Statement.get",
  "export:exact_sqlite:Statement.native",
  "export:exact_sqlite:Statement.run",
  "export:exact_sqlite:Statement.toString",
  "export:exact_sqlite:Statement.values",
  "export:exact_sqlite:constants",
  "export:exact_sqlite:default",
  "export:exact_sqlite:default._checkClosed",
  "export:exact_sqlite:default.applyChanges",
  "export:exact_sqlite:default.close",
  "export:exact_sqlite:default.enableCrSqlite",
  "export:exact_sqlite:default.exec",
  "export:exact_sqlite:default.fileControl",
  "export:exact_sqlite:default.getChanges",
  "export:exact_sqlite:default.getDbVersion",
  "export:exact_sqlite:default.getSiteId",
  "export:exact_sqlite:default.handle",
  "export:exact_sqlite:default.inTransaction",
  "export:exact_sqlite:default.loadExtension",
  "export:exact_sqlite:default.markAsCrr",
  "export:exact_sqlite:default.prepare",
  "export:exact_sqlite:default.query",
  "export:exact_sqlite:default.run",
  "export:exact_sqlite:default.serialize",
  "export:exact_sqlite:default.transaction",
  "export:exact_sqlite:deserialize",
  "export:exact_sqlite:open",
  "export:internal_fs_utils:BigIntStats",
  "export:internal_fs_utils:BigIntStats.isBlockDevice",
  "export:internal_fs_utils:BigIntStats.isCharacterDevice",
  "export:internal_fs_utils:BigIntStats.isDirectory",
  "export:internal_fs_utils:BigIntStats.isFIFO",
  "export:internal_fs_utils:BigIntStats.isFile",
  "export:internal_fs_utils:BigIntStats.isSocket",
  "export:internal_fs_utils:BigIntStats.isSymbolicLink",
  "export:internal_fs_utils:SyncWriteStream",
  "export:internal_fs_utils:SyncWriteStream._write",
  "export:internal_fs_utils:default",
  "export:internal_fs_utils:getDirent",
  "export:internal_fs_utils:getDirents",
  "export:internal_fs_utils:isFd",
  "export:internal_fs_utils:isFileMode",
  "export:internal_fs_utils:kMinPoolSpace",
  "export:internal_fs_utils:stringToFlags",
  "export:internal_fs_utils:toPathIfFileURL",
  "export:internal_fs_utils:validateFd",
  "export:internal_fs_utils:validateOffsetLengthRead",
  "export:internal_fs_utils:validateOffsetLengthWrite",
  "export:internal_fs_utils:validateRmOptionsSync",
  "export:internal_fs_utils:validateRmdirOptions",
  "export:legacy_stream_duplex:default",
  "export:legacy_stream_passthrough:default",
  "export:legacy_stream_readable:default",
  "export:legacy_stream_transform:default",
  "export:legacy_stream_writable:default",
  "export:node_assert:AssertionError",
  "export:node_assert:AssertionError.constructor",
  "export:node_assert:CallTracker",
  "export:node_assert:CallTracker._getContext",
  "export:node_assert:CallTracker.calls",
  "export:node_assert:CallTracker.getCalls",
  "export:node_assert:CallTracker.report",
  "export:node_assert:CallTracker.reset",
  "export:node_assert:CallTracker.verify",
  "export:node_assert:_isDeepStrictEqual",
  "export:node_assert:deepEqual",
  "export:node_assert:deepStrictEqual",
  "export:node_assert:default",
  "export:node_assert:doesNotMatch",
  "export:node_assert:doesNotReject",
  "export:node_assert:doesNotThrow",
  "export:node_assert:equal",
  "export:node_assert:fail",
  "export:node_assert:ifError",
  "export:node_assert:match",
  "export:node_assert:notDeepEqual",
  "export:node_assert:notDeepStrictEqual",
  "export:node_assert:notEqual",
  "export:node_assert:notStrictEqual",
  "export:node_assert:ok",
  "export:node_assert:partialDeepStrictEqual",
  "export:node_assert:rejects",
  "export:node_assert:strict",
  "export:node_assert:strictEqual",
  "export:node_assert:throws",
  "export:node_async_hooks:AsyncLocalStorage",
  "export:node_async_hooks:AsyncLocalStorage.disable",
  "export:node_async_hooks:AsyncLocalStorage.enable",
  "export:node_async_hooks:AsyncLocalStorage.enterWith",
  "export:node_async_hooks:AsyncLocalStorage.exit",
  "export:node_async_hooks:AsyncLocalStorage.getStore",
  "export:node_async_hooks:AsyncLocalStorage.run",
  "export:node_async_hooks:AsyncLocalStorage.snapshot",
  "export:node_async_hooks:AsyncResource",
  "export:node_async_hooks:AsyncResource.asyncId",
  "export:node_async_hooks:AsyncResource.bind",
  "export:node_async_hooks:AsyncResource.emitAfter",
  "export:node_async_hooks:AsyncResource.emitBefore",
  "export:node_async_hooks:AsyncResource.emitDestroy",
  "export:node_async_hooks:AsyncResource.runInAsyncScope",
  "export:node_async_hooks:AsyncResource.triggerAsyncId",
  "export:node_async_hooks:__emitInit",
  "export:node_async_hooks:__getHooksEnabled",
  "export:node_async_hooks:__nextAsyncId",
  "export:node_async_hooks:createHook",
  "export:node_async_hooks:default",
  "export:node_async_hooks:executionAsyncId",
  "export:node_async_hooks:triggerAsyncId",
  "export:node_buffer:Blob",
  "export:node_buffer:Buffer",
  "export:node_buffer:Buffer.__isExactBuffer",
  "export:node_buffer:Buffer._toByteString",
  "export:node_buffer:Buffer.asciiSlice",
  "export:node_buffer:Buffer.asciiWrite",
  "export:node_buffer:Buffer.base64Slice",
  "export:node_buffer:Buffer.base64Write",
  "export:node_buffer:Buffer.base64urlSlice",
  "export:node_buffer:Buffer.base64urlWrite",
  "export:node_buffer:Buffer.compare",
  "export:node_buffer:Buffer.copy",
  "export:node_buffer:Buffer.equals",
  "export:node_buffer:Buffer.fill",
  "export:node_buffer:Buffer.hexSlice",
  "export:node_buffer:Buffer.hexWrite",
  "export:node_buffer:Buffer.includes",
  "export:node_buffer:Buffer.indexOf",
  "export:node_buffer:Buffer.inspect",
  "export:node_buffer:Buffer.lastIndexOf",
  "export:node_buffer:Buffer.latin1Slice",
  "export:node_buffer:Buffer.latin1Write",
  "export:node_buffer:Buffer.offset",
  "export:node_buffer:Buffer.parent",
  "export:node_buffer:Buffer.readBigInt64BE",
  "export:node_buffer:Buffer.readBigInt64LE",
  "export:node_buffer:Buffer.readBigUInt64BE",
  "export:node_buffer:Buffer.readBigUInt64LE",
  "export:node_buffer:Buffer.readBigUint64BE",
  "export:node_buffer:Buffer.readBigUint64LE",
  "export:node_buffer:Buffer.readDoubleBE",
  "export:node_buffer:Buffer.readDoubleLE",
  "export:node_buffer:Buffer.readFloatBE",
  "export:node_buffer:Buffer.readFloatLE",
  "export:node_buffer:Buffer.readInt16BE",
  "export:node_buffer:Buffer.readInt16LE",
  "export:node_buffer:Buffer.readInt32BE",
  "export:node_buffer:Buffer.readInt32LE",
  "export:node_buffer:Buffer.readInt8",
  "export:node_buffer:Buffer.readIntBE",
  "export:node_buffer:Buffer.readIntLE",
  "export:node_buffer:Buffer.readUInt16BE",
  "export:node_buffer:Buffer.readUInt16LE",
  "export:node_buffer:Buffer.readUInt32BE",
  "export:node_buffer:Buffer.readUInt32LE",
  "export:node_buffer:Buffer.readUInt8",
  "export:node_buffer:Buffer.readUIntBE",
  "export:node_buffer:Buffer.readUIntLE",
  "export:node_buffer:Buffer.readUint16BE",
  "export:node_buffer:Buffer.readUint16LE",
  "export:node_buffer:Buffer.readUint32BE",
  "export:node_buffer:Buffer.readUint32LE",
  "export:node_buffer:Buffer.readUint8",
  "export:node_buffer:Buffer.readUintBE",
  "export:node_buffer:Buffer.readUintLE",
  "export:node_buffer:Buffer.slice",
  "export:node_buffer:Buffer.subarray",
  "export:node_buffer:Buffer.swap16",
  "export:node_buffer:Buffer.swap32",
  "export:node_buffer:Buffer.swap64",
  "export:node_buffer:Buffer.toJSON",
  "export:node_buffer:Buffer.toLocaleString",
  "export:node_buffer:Buffer.toString",
  "export:node_buffer:Buffer.ucs2Slice",
  "export:node_buffer:Buffer.ucs2Write",
  "export:node_buffer:Buffer.utf16beWrite",
  "export:node_buffer:Buffer.utf16leWrite",
  "export:node_buffer:Buffer.utf8Slice",
  "export:node_buffer:Buffer.utf8Write",
  "export:node_buffer:Buffer.write",
  "export:node_buffer:Buffer.writeBigInt64BE",
  "export:node_buffer:Buffer.writeBigInt64LE",
  "export:node_buffer:Buffer.writeBigUInt64BE",
  "export:node_buffer:Buffer.writeBigUInt64LE",
  "export:node_buffer:Buffer.writeBigUint64BE",
  "export:node_buffer:Buffer.writeBigUint64LE",
  "export:node_buffer:Buffer.writeDoubleBE",
  "export:node_buffer:Buffer.writeDoubleLE",
  "export:node_buffer:Buffer.writeFloatBE",
  "export:node_buffer:Buffer.writeFloatLE",
  "export:node_buffer:Buffer.writeInt16BE",
  "export:node_buffer:Buffer.writeInt16LE",
  "export:node_buffer:Buffer.writeInt32BE",
  "export:node_buffer:Buffer.writeInt32LE",
  "export:node_buffer:Buffer.writeInt8",
  "export:node_buffer:Buffer.writeIntBE",
  "export:node_buffer:Buffer.writeIntLE",
  "export:node_buffer:Buffer.writeUInt16BE",
  "export:node_buffer:Buffer.writeUInt16LE",
  "export:node_buffer:Buffer.writeUInt32BE",
  "export:node_buffer:Buffer.writeUInt32LE",
  "export:node_buffer:Buffer.writeUInt8",
  "export:node_buffer:Buffer.writeUIntBE",
  "export:node_buffer:Buffer.writeUIntLE",
  "export:node_buffer:Buffer.writeUint16BE",
  "export:node_buffer:Buffer.writeUint16LE",
  "export:node_buffer:Buffer.writeUint32BE",
  "export:node_buffer:Buffer.writeUint32LE",
  "export:node_buffer:Buffer.writeUint8",
  "export:node_buffer:Buffer.writeUintBE",
  "export:node_buffer:Buffer.writeUintLE",
  "export:node_buffer:File",
  "export:node_buffer:INSPECT_MAX_BYTES",
  "export:node_buffer:SlowBuffer",
  "export:node_buffer:SlowBuffer.__isExactBuffer",
  "export:node_buffer:SlowBuffer._toByteString",
  "export:node_buffer:SlowBuffer.asciiSlice",
  "export:node_buffer:SlowBuffer.asciiWrite",
  "export:node_buffer:SlowBuffer.base64Slice",
  "export:node_buffer:SlowBuffer.base64Write",
  "export:node_buffer:SlowBuffer.base64urlSlice",
  "export:node_buffer:SlowBuffer.base64urlWrite",
  "export:node_buffer:SlowBuffer.compare",
  "export:node_buffer:SlowBuffer.copy",
  "export:node_buffer:SlowBuffer.equals",
  "export:node_buffer:SlowBuffer.fill",
  "export:node_buffer:SlowBuffer.hexSlice",
  "export:node_buffer:SlowBuffer.hexWrite",
  "export:node_buffer:SlowBuffer.includes",
  "export:node_buffer:SlowBuffer.indexOf",
  "export:node_buffer:SlowBuffer.inspect",
  "export:node_buffer:SlowBuffer.lastIndexOf",
  "export:node_buffer:SlowBuffer.latin1Slice",
  "export:node_buffer:SlowBuffer.latin1Write",
  "export:node_buffer:SlowBuffer.offset",
  "export:node_buffer:SlowBuffer.parent",
  "export:node_buffer:SlowBuffer.readBigInt64BE",
  "export:node_buffer:SlowBuffer.readBigInt64LE",
  "export:node_buffer:SlowBuffer.readBigUInt64BE",
  "export:node_buffer:SlowBuffer.readBigUInt64LE",
  "export:node_buffer:SlowBuffer.readBigUint64BE",
  "export:node_buffer:SlowBuffer.readBigUint64LE",
  "export:node_buffer:SlowBuffer.readDoubleBE",
  "export:node_buffer:SlowBuffer.readDoubleLE",
  "export:node_buffer:SlowBuffer.readFloatBE",
  "export:node_buffer:SlowBuffer.readFloatLE",
  "export:node_buffer:SlowBuffer.readInt16BE",
  "export:node_buffer:SlowBuffer.readInt16LE",
  "export:node_buffer:SlowBuffer.readInt32BE",
  "export:node_buffer:SlowBuffer.readInt32LE",
  "export:node_buffer:SlowBuffer.readInt8",
  "export:node_buffer:SlowBuffer.readIntBE",
  "export:node_buffer:SlowBuffer.readIntLE",
  "export:node_buffer:SlowBuffer.readUInt16BE",
  "export:node_buffer:SlowBuffer.readUInt16LE",
  "export:node_buffer:SlowBuffer.readUInt32BE",
  "export:node_buffer:SlowBuffer.readUInt32LE",
  "export:node_buffer:SlowBuffer.readUInt8",
  "export:node_buffer:SlowBuffer.readUIntBE",
  "export:node_buffer:SlowBuffer.readUIntLE",
  "export:node_buffer:SlowBuffer.readUint16BE",
  "export:node_buffer:SlowBuffer.readUint16LE",
  "export:node_buffer:SlowBuffer.readUint32BE",
  "export:node_buffer:SlowBuffer.readUint32LE",
  "export:node_buffer:SlowBuffer.readUint8",
  "export:node_buffer:SlowBuffer.readUintBE",
  "export:node_buffer:SlowBuffer.readUintLE",
  "export:node_buffer:SlowBuffer.slice",
  "export:node_buffer:SlowBuffer.subarray",
  "export:node_buffer:SlowBuffer.swap16",
  "export:node_buffer:SlowBuffer.swap32",
  "export:node_buffer:SlowBuffer.swap64",
  "export:node_buffer:SlowBuffer.toJSON",
  "export:node_buffer:SlowBuffer.toLocaleString",
  "export:node_buffer:SlowBuffer.toString",
  "export:node_buffer:SlowBuffer.ucs2Slice",
  "export:node_buffer:SlowBuffer.ucs2Write",
  "export:node_buffer:SlowBuffer.utf16beWrite",
  "export:node_buffer:SlowBuffer.utf16leWrite",
  "export:node_buffer:SlowBuffer.utf8Slice",
  "export:node_buffer:SlowBuffer.utf8Write",
  "export:node_buffer:SlowBuffer.write",
  "export:node_buffer:SlowBuffer.writeBigInt64BE",
  "export:node_buffer:SlowBuffer.writeBigInt64LE",
  "export:node_buffer:SlowBuffer.writeBigUInt64BE",
  "export:node_buffer:SlowBuffer.writeBigUInt64LE",
  "export:node_buffer:SlowBuffer.writeBigUint64BE",
  "export:node_buffer:SlowBuffer.writeBigUint64LE",
  "export:node_buffer:SlowBuffer.writeDoubleBE",
  "export:node_buffer:SlowBuffer.writeDoubleLE",
  "export:node_buffer:SlowBuffer.writeFloatBE",
  "export:node_buffer:SlowBuffer.writeFloatLE",
  "export:node_buffer:SlowBuffer.writeInt16BE",
  "export:node_buffer:SlowBuffer.writeInt16LE",
  "export:node_buffer:SlowBuffer.writeInt32BE",
  "export:node_buffer:SlowBuffer.writeInt32LE",
  "export:node_buffer:SlowBuffer.writeInt8",
  "export:node_buffer:SlowBuffer.writeIntBE",
  "export:node_buffer:SlowBuffer.writeIntLE",
  "export:node_buffer:SlowBuffer.writeUInt16BE",
  "export:node_buffer:SlowBuffer.writeUInt16LE",
  "export:node_buffer:SlowBuffer.writeUInt32BE",
  "export:node_buffer:SlowBuffer.writeUInt32LE",
  "export:node_buffer:SlowBuffer.writeUInt8",
  "export:node_buffer:SlowBuffer.writeUIntBE",
  "export:node_buffer:SlowBuffer.writeUIntLE",
  "export:node_buffer:SlowBuffer.writeUint16BE",
  "export:node_buffer:SlowBuffer.writeUint16LE",
  "export:node_buffer:SlowBuffer.writeUint32BE",
  "export:node_buffer:SlowBuffer.writeUint32LE",
  "export:node_buffer:SlowBuffer.writeUint8",
  "export:node_buffer:SlowBuffer.writeUintBE",
  "export:node_buffer:SlowBuffer.writeUintLE",
  "export:node_buffer:atob",
  "export:node_buffer:btoa",
  "export:node_buffer:constants",
  "export:node_buffer:default",
  "export:node_buffer:isAscii",
  "export:node_buffer:isUtf8",
  "export:node_buffer:kMaxLength",
  "export:node_child_process:ChildProcess",
  "export:node_child_process:ChildProcess._completeIpcSendEntry",
  "export:node_child_process:ChildProcess._enqueueIpcPacket",
  "export:node_child_process:ChildProcess._failPendingIpcSends",
  "export:node_child_process:ChildProcess._finalizeDisconnect",
  "export:node_child_process:ChildProcess._flushIpcSendQueue",
  "export:node_child_process:ChildProcess._ipcWriteChunk",
  "export:node_child_process:ChildProcess._scheduleIpcFlush",
  "export:node_child_process:ChildProcess.disconnect",
  "export:node_child_process:ChildProcess.kill",
  "export:node_child_process:ChildProcess.ref",
  "export:node_child_process:ChildProcess.send",
  "export:node_child_process:ChildProcess.spawn",
  "export:node_child_process:ChildProcess.unref",
  "export:node_child_process:default",
  "export:node_child_process:exec",
  "export:node_child_process:execFile",
  "export:node_child_process:execFileSync",
  "export:node_child_process:execSync",
  "export:node_child_process:fork",
  "export:node_child_process:spawn",
  "export:node_child_process:spawnSync",
  "export:node_cluster:SCHED_NONE",
  "export:node_cluster:SCHED_RR",
  "export:node_cluster:_nextWorkerId",
  "export:node_cluster:default",
  "export:node_cluster:disconnect",
  "export:node_cluster:fork",
  "export:node_cluster:isMaster",
  "export:node_cluster:isPrimary",
  "export:node_cluster:isWorker",
  "export:node_cluster:schedulingPolicy",
  "export:node_cluster:settings",
  "export:node_cluster:setupMaster",
  "export:node_cluster:setupPrimary",
  "export:node_cluster:worker",
  "export:node_cluster:workers",
  "export:node_console:Console",
  "export:node_console:default",
  "export:node_constants:E2BIG",
  "export:node_constants:EACCES",
  "export:node_constants:EADDRINUSE",
  "export:node_constants:EADDRNOTAVAIL",
  "export:node_constants:EAFNOSUPPORT",
  "export:node_constants:EAGAIN",
  "export:node_constants:EALREADY",
  "export:node_constants:EBADF",
  "export:node_constants:EBADMSG",
  "export:node_constants:EBUSY",
  "export:node_constants:ECANCELED",
  "export:node_constants:ECHILD",
  "export:node_constants:ECONNABORTED",
  "export:node_constants:ECONNREFUSED",
  "export:node_constants:ECONNRESET",
  "export:node_constants:EDEADLK",
  "export:node_constants:EDESTADDRREQ",
  "export:node_constants:EDOM",
  "export:node_constants:EDQUOT",
  "export:node_constants:EEXIST",
  "export:node_constants:EFAULT",
  "export:node_constants:EFBIG",
  "export:node_constants:EHOSTUNREACH",
  "export:node_constants:EIDRM",
  "export:node_constants:EILSEQ",
  "export:node_constants:EINPROGRESS",
  "export:node_constants:EINTR",
  "export:node_constants:EINVAL",
  "export:node_constants:EIO",
  "export:node_constants:EISCONN",
  "export:node_constants:EISDIR",
  "export:node_constants:ELOOP",
  "export:node_constants:EMFILE",
  "export:node_constants:EMLINK",
  "export:node_constants:EMSGSIZE",
  "export:node_constants:EMULTIHOP",
  "export:node_constants:ENAMETOOLONG",
  "export:node_constants:ENETDOWN",
  "export:node_constants:ENETRESET",
  "export:node_constants:ENETUNREACH",
  "export:node_constants:ENFILE",
  "export:node_constants:ENOBUFS",
  "export:node_constants:ENODATA",
  "export:node_constants:ENODEV",
  "export:node_constants:ENOENT",
  "export:node_constants:ENOLINK",
  "export:node_constants:ENOMEM",
  "export:node_constants:ENOPROTOOPT",
  "export:node_constants:ENOSPC",
  "export:node_constants:ENOSR",
  "export:node_constants:ENOSTR",
  "export:node_constants:ENOSYS",
  "export:node_constants:ENOTCONN",
  "export:node_constants:ENOTDIR",
  "export:node_constants:ENOTEMPTY",
  "export:node_constants:ENOTSOCK",
  "export:node_constants:ENOTSUP",
  "export:node_constants:ENOTTY",
  "export:node_constants:ENXIO",
  "export:node_constants:EOPNOTSUPP",
  "export:node_constants:EOVERFLOW",
  "export:node_constants:EPERM",
  "export:node_constants:EPIPE",
  "export:node_constants:EPROTO",
  "export:node_constants:EPROTONOSUPPORT",
  "export:node_constants:EPROTOTYPE",
  "export:node_constants:ERANGE",
  "export:node_constants:EROFS",
  "export:node_constants:ESPIPE",
  "export:node_constants:ESRCH",
  "export:node_constants:ESTALE",
  "export:node_constants:ETIME",
  "export:node_constants:ETIMEDOUT",
  "export:node_constants:ETXTBSY",
  "export:node_constants:EWOULDBLOCK",
  "export:node_constants:EXDEV",
  "export:node_constants:F_OK",
  "export:node_constants:O_APPEND",
  "export:node_constants:O_CREAT",
  "export:node_constants:O_DIRECT",
  "export:node_constants:O_DIRECTORY",
  "export:node_constants:O_DSYNC",
  "export:node_constants:O_EXCL",
  "export:node_constants:O_NOATIME",
  "export:node_constants:O_NOCTTY",
  "export:node_constants:O_NOFOLLOW",
  "export:node_constants:O_NONBLOCK",
  "export:node_constants:O_RDONLY",
  "export:node_constants:O_RDWR",
  "export:node_constants:O_SYMLINK",
  "export:node_constants:O_SYNC",
  "export:node_constants:O_TRUNC",
  "export:node_constants:O_WRONLY",
  "export:node_constants:R_OK",
  "export:node_constants:SIGABRT",
  "export:node_constants:SIGALRM",
  "export:node_constants:SIGBUS",
  "export:node_constants:SIGCHLD",
  "export:node_constants:SIGCONT",
  "export:node_constants:SIGFPE",
  "export:node_constants:SIGHUP",
  "export:node_constants:SIGILL",
  "export:node_constants:SIGINFO",
  "export:node_constants:SIGINT",
  "export:node_constants:SIGIO",
  "export:node_constants:SIGIOT",
  "export:node_constants:SIGKILL",
  "export:node_constants:SIGPIPE",
  "export:node_constants:SIGPOLL",
  "export:node_constants:SIGPROF",
  "export:node_constants:SIGPWR",
  "export:node_constants:SIGQUIT",
  "export:node_constants:SIGSEGV",
  "export:node_constants:SIGSTKFLT",
  "export:node_constants:SIGSTOP",
  "export:node_constants:SIGSYS",
  "export:node_constants:SIGTERM",
  "export:node_constants:SIGTRAP",
  "export:node_constants:SIGTSTP",
  "export:node_constants:SIGTTIN",
  "export:node_constants:SIGTTOU",
  "export:node_constants:SIGURG",
  "export:node_constants:SIGUSR1",
  "export:node_constants:SIGUSR2",
  "export:node_constants:SIGVTALRM",
  "export:node_constants:SIGWINCH",
  "export:node_constants:SIGXCPU",
  "export:node_constants:SIGXFSZ",
  "export:node_constants:S_IFBLK",
  "export:node_constants:S_IFCHR",
  "export:node_constants:S_IFDIR",
  "export:node_constants:S_IFIFO",
  "export:node_constants:S_IFLNK",
  "export:node_constants:S_IFMT",
  "export:node_constants:S_IFREG",
  "export:node_constants:S_IFSOCK",
  "export:node_constants:S_IRGRP",
  "export:node_constants:S_IROTH",
  "export:node_constants:S_IRUSR",
  "export:node_constants:S_IRWXG",
  "export:node_constants:S_IRWXO",
  "export:node_constants:S_IRWXU",
  "export:node_constants:S_IWGRP",
  "export:node_constants:S_IWOTH",
  "export:node_constants:S_IWUSR",
  "export:node_constants:S_IXGRP",
  "export:node_constants:S_IXOTH",
  "export:node_constants:S_IXUSR",
  "export:node_constants:UV_UDP_REUSEADDR",
  "export:node_constants:W_OK",
  "export:node_constants:X_OK",
  "export:node_constants:[[dynamic-table:signal-number-overlay]]",
  "export:node_constants:default",
  "export:node_dgram:Socket",
  "export:node_dgram:Socket._fromFd",
  "export:node_dgram:Socket._getFd",
  "export:node_dgram:Socket._startRecv",
  "export:node_dgram:Socket.addMembership",
  "export:node_dgram:Socket.addSourceSpecificMembership",
  "export:node_dgram:Socket.address",
  "export:node_dgram:Socket.bind",
  "export:node_dgram:Socket.close",
  "export:node_dgram:Socket.connect",
  "export:node_dgram:Socket.constructor",
  "export:node_dgram:Socket.disconnect",
  "export:node_dgram:Socket.dropMembership",
  "export:node_dgram:Socket.dropSourceSpecificMembership",
  "export:node_dgram:Socket.getRecvBufferSize",
  "export:node_dgram:Socket.getSendBufferSize",
  "export:node_dgram:Socket.ref",
  "export:node_dgram:Socket.remoteAddress",
  "export:node_dgram:Socket.send",
  "export:node_dgram:Socket.sendto",
  "export:node_dgram:Socket.setBroadcast",
  "export:node_dgram:Socket.setMulticastInterface",
  "export:node_dgram:Socket.setMulticastLoopback",
  "export:node_dgram:Socket.setMulticastTTL",
  "export:node_dgram:Socket.setRecvBufferSize",
  "export:node_dgram:Socket.setSendBufferSize",
  "export:node_dgram:Socket.setTTL",
  "export:node_dgram:Socket.unref",
  "export:node_dgram:createSocket",
  "export:node_dgram:default",
  "export:node_diagnostics_channel:Channel",
  "export:node_diagnostics_channel:Channel.hasSubscribers",
  "export:node_diagnostics_channel:Channel.publish",
  "export:node_diagnostics_channel:Channel.subscribe",
  "export:node_diagnostics_channel:Channel.unsubscribe",
  "export:node_diagnostics_channel:TracingChannel",
  "export:node_diagnostics_channel:TracingChannel.subscribe",
  "export:node_diagnostics_channel:TracingChannel.traceSync",
  "export:node_diagnostics_channel:TracingChannel.unsubscribe",
  "export:node_diagnostics_channel:channel",
  "export:node_diagnostics_channel:default",
  "export:node_diagnostics_channel:hasSubscribers",
  "export:node_diagnostics_channel:tracingChannel",
  "export:node_dns:ADDRGETNETWORKPARAMS",
  "export:node_dns:BADFAMILY",
  "export:node_dns:BADFLAGS",
  "export:node_dns:BADHINTS",
  "export:node_dns:BADNAME",
  "export:node_dns:BADQUERY",
  "export:node_dns:BADRESP",
  "export:node_dns:BADSTR",
  "export:node_dns:CANCELLED",
  "export:node_dns:CONNREFUSED",
  "export:node_dns:DESTRUCTION",
  "export:node_dns:EOF",
  "export:node_dns:FILE",
  "export:node_dns:FORMERR",
  "export:node_dns:LOADIPHLPAPI",
  "export:node_dns:NODATA",
  "export:node_dns:NOMEM",
  "export:node_dns:NONAME",
  "export:node_dns:NOTFOUND",
  "export:node_dns:NOTIMP",
  "export:node_dns:NOTINITIALIZED",
  "export:node_dns:REFUSED",
  "export:node_dns:Resolver",
  "export:node_dns:Resolver.cancel",
  "export:node_dns:Resolver.getServers",
  "export:node_dns:Resolver.resolve",
  "export:node_dns:Resolver.resolve4",
  "export:node_dns:Resolver.resolve6",
  "export:node_dns:Resolver.resolveAny",
  "export:node_dns:Resolver.resolveCaa",
  "export:node_dns:Resolver.resolveCname",
  "export:node_dns:Resolver.resolveMx",
  "export:node_dns:Resolver.resolveNaptr",
  "export:node_dns:Resolver.resolveNs",
  "export:node_dns:Resolver.resolvePtr",
  "export:node_dns:Resolver.resolveSoa",
  "export:node_dns:Resolver.resolveSrv",
  "export:node_dns:Resolver.resolveTxt",
  "export:node_dns:Resolver.reverse",
  "export:node_dns:Resolver.setLocalAddress",
  "export:node_dns:Resolver.setServers",
  "export:node_dns:SERVFAIL",
  "export:node_dns:TIMEOUT",
  "export:node_dns:default",
  "export:node_dns:getDefaultResultOrder",
  "export:node_dns:getServers",
  "export:node_dns:lookup",
  "export:node_dns:lookupService",
  "export:node_dns:promises",
  "export:node_dns:resolve",
  "export:node_dns:resolve4",
  "export:node_dns:resolve6",
  "export:node_dns:resolveAny",
  "export:node_dns:resolveCaa",
  "export:node_dns:resolveCname",
  "export:node_dns:resolveMx",
  "export:node_dns:resolveNaptr",
  "export:node_dns:resolveNs",
  "export:node_dns:resolvePtr",
  "export:node_dns:resolveSoa",
  "export:node_dns:resolveSrv",
  "export:node_dns:resolveTxt",
  "export:node_dns:reverse",
  "export:node_dns:setDefaultResultOrder",
  "export:node_dns:setServers",
  "export:node_dns_promises:ADDRGETNETWORKPARAMS",
  "export:node_dns_promises:BADFAMILY",
  "export:node_dns_promises:BADFLAGS",
  "export:node_dns_promises:BADHINTS",
  "export:node_dns_promises:BADNAME",
  "export:node_dns_promises:BADQUERY",
  "export:node_dns_promises:BADRESP",
  "export:node_dns_promises:BADSTR",
  "export:node_dns_promises:CANCELLED",
  "export:node_dns_promises:CONNREFUSED",
  "export:node_dns_promises:DESTRUCTION",
  "export:node_dns_promises:EOF",
  "export:node_dns_promises:FILE",
  "export:node_dns_promises:FORMERR",
  "export:node_dns_promises:LOADIPHLPAPI",
  "export:node_dns_promises:NODATA",
  "export:node_dns_promises:NOMEM",
  "export:node_dns_promises:NONAME",
  "export:node_dns_promises:NOTFOUND",
  "export:node_dns_promises:NOTIMP",
  "export:node_dns_promises:NOTINITIALIZED",
  "export:node_dns_promises:REFUSED",
  "export:node_dns_promises:SERVFAIL",
  "export:node_dns_promises:TIMEOUT",
  "export:node_dns_promises:default",
  "export:node_domain:Domain",
  "export:node_domain:Domain.add",
  "export:node_domain:Domain.bind",
  "export:node_domain:Domain.constructor",
  "export:node_domain:Domain.dispose",
  "export:node_domain:Domain.enter",
  "export:node_domain:Domain.exit",
  "export:node_domain:Domain.intercept",
  "export:node_domain:Domain.remove",
  "export:node_domain:Domain.run",
  "export:node_domain:create",
  "export:node_domain:createDomain",
  "export:node_domain:default",
  "export:node_events:EventEmitter",
  "export:node_events:EventEmitter._events",
  "export:node_events:EventEmitter._maxListeners",
  "export:node_events:EventEmitter.addListener",
  "export:node_events:EventEmitter.emit",
  "export:node_events:EventEmitter.eventNames",
  "export:node_events:EventEmitter.getMaxListeners",
  "export:node_events:EventEmitter.listenerCount",
  "export:node_events:EventEmitter.listeners",
  "export:node_events:EventEmitter.off",
  "export:node_events:EventEmitter.on",
  "export:node_events:EventEmitter.once",
  "export:node_events:EventEmitter.prependListener",
  "export:node_events:EventEmitter.prependOnceListener",
  "export:node_events:EventEmitter.rawListeners",
  "export:node_events:EventEmitter.removeAllListeners",
  "export:node_events:EventEmitter.removeListener",
  "export:node_events:EventEmitter.setMaxListeners",
  "export:node_events:EventEmitterAsyncResource",
  "export:node_events:EventEmitterAsyncResource.constructor",
  "export:node_events:EventEmitterAsyncResource.emit",
  "export:node_events:__esModule",
  "export:node_events:captureRejectionSymbol",
  "export:node_events:captureRejections",
  "export:node_events:default",
  "export:node_events:default._events",
  "export:node_events:default._maxListeners",
  "export:node_events:default.addListener",
  "export:node_events:default.emit",
  "export:node_events:default.eventNames",
  "export:node_events:default.getMaxListeners",
  "export:node_events:default.listenerCount",
  "export:node_events:default.listeners",
  "export:node_events:default.off",
  "export:node_events:default.on",
  "export:node_events:default.once",
  "export:node_events:default.prependListener",
  "export:node_events:default.prependOnceListener",
  "export:node_events:default.rawListeners",
  "export:node_events:default.removeAllListeners",
  "export:node_events:default.removeListener",
  "export:node_events:default.setMaxListeners",
  "export:node_events:defaultMaxListeners",
  "export:node_events:errorMonitor",
  "export:node_events:getEventListeners",
  "export:node_events:getMaxListeners",
  "export:node_events:init",
  "export:node_events:listenerCount",
  "export:node_events:on",
  "export:node_events:once",
  "export:node_events:setMaxListeners",
  "export:node_fs:Dir",
  "export:node_fs:Dir._nextEntry",
  "export:node_fs:Dir.close",
  "export:node_fs:Dir.closeSync",
  "export:node_fs:Dir.path",
  "export:node_fs:Dir.read",
  "export:node_fs:Dir.readSync",
  "export:node_fs:Dirent",
  "export:node_fs:Dirent.isBlockDevice",
  "export:node_fs:Dirent.isCharacterDevice",
  "export:node_fs:Dirent.isDirectory",
  "export:node_fs:Dirent.isFIFO",
  "export:node_fs:Dirent.isFile",
  "export:node_fs:Dirent.isSocket",
  "export:node_fs:Dirent.isSymbolicLink",
  "export:node_fs:FSWatcher",
  "export:node_fs:FSWatcher.addListener",
  "export:node_fs:FSWatcher.close",
  "export:node_fs:FSWatcher.emit",
  "export:node_fs:FSWatcher.listenerCount",
  "export:node_fs:FSWatcher.off",
  "export:node_fs:FSWatcher.on",
  "export:node_fs:FSWatcher.once",
  "export:node_fs:FSWatcher.ref",
  "export:node_fs:FSWatcher.removeListener",
  "export:node_fs:FSWatcher.stop",
  "export:node_fs:FSWatcher.unref",
  "export:node_fs:F_OK",
  "export:node_fs:R_OK",
  "export:node_fs:ReadStream",
  "export:node_fs:ReadStream._read",
  "export:node_fs:ReadStream.close",
  "export:node_fs:ReadStream.constructor",
  "export:node_fs:ReadStream.destroy",
  "export:node_fs:ReadStream.open",
  "export:node_fs:Stats",
  "export:node_fs:Stats.isBlockDevice",
  "export:node_fs:Stats.isCharacterDevice",
  "export:node_fs:Stats.isDirectory",
  "export:node_fs:Stats.isFIFO",
  "export:node_fs:Stats.isFile",
  "export:node_fs:Stats.isSocket",
  "export:node_fs:Stats.isSymbolicLink",
  "export:node_fs:W_OK",
  "export:node_fs:WriteStream",
  "export:node_fs:WriteStream._emitClose",
  "export:node_fs:WriteStream._final",
  "export:node_fs:WriteStream._write",
  "export:node_fs:WriteStream._writev",
  "export:node_fs:WriteStream.autoClose",
  "export:node_fs:WriteStream.close",
  "export:node_fs:WriteStream.constructor",
  "export:node_fs:WriteStream.destroy",
  "export:node_fs:WriteStream.open",
  "export:node_fs:X_OK",
  "export:node_fs:_toUnixTimestamp",
  "export:node_fs:access",
  "export:node_fs:accessSync",
  "export:node_fs:appendFile",
  "export:node_fs:appendFileSync",
  "export:node_fs:chmod",
  "export:node_fs:chmodSync",
  "export:node_fs:chown",
  "export:node_fs:chownSync",
  "export:node_fs:close",
  "export:node_fs:closeSync",
  "export:node_fs:constants",
  "export:node_fs:copyFile",
  "export:node_fs:copyFileSync",
  "export:node_fs:cp",
  "export:node_fs:cpSync",
  "export:node_fs:createReadStream",
  "export:node_fs:createWriteStream",
  "export:node_fs:default",
  "export:node_fs:exists",
  "export:node_fs:existsSync",
  "export:node_fs:fchmod",
  "export:node_fs:fchmodSync",
  "export:node_fs:fchown",
  "export:node_fs:fchownSync",
  "export:node_fs:fdatasync",
  "export:node_fs:fdatasyncSync",
  "export:node_fs:fstat",
  "export:node_fs:fstatSync",
  "export:node_fs:fsync",
  "export:node_fs:fsyncSync",
  "export:node_fs:ftruncate",
  "export:node_fs:ftruncateSync",
  "export:node_fs:futimes",
  "export:node_fs:futimesSync",
  "export:node_fs:glob",
  "export:node_fs:globSync",
  "export:node_fs:lchmod",
  "export:node_fs:lchmodSync",
  "export:node_fs:lchown",
  "export:node_fs:lchownSync",
  "export:node_fs:link",
  "export:node_fs:linkSync",
  "export:node_fs:lstat",
  "export:node_fs:lstatSync",
  "export:node_fs:lutimes",
  "export:node_fs:lutimesSync",
  "export:node_fs:mkdir",
  "export:node_fs:mkdirSync",
  "export:node_fs:mkdtemp",
  "export:node_fs:mkdtempDisposable",
  "export:node_fs:mkdtempDisposableSync",
  "export:node_fs:mkdtempSync",
  "export:node_fs:open",
  "export:node_fs:openSync",
  "export:node_fs:opendir",
  "export:node_fs:opendirSync",
  "export:node_fs:promises",
  "export:node_fs:read",
  "export:node_fs:readFile",
  "export:node_fs:readFileSync",
  "export:node_fs:readSync",
  "export:node_fs:readdir",
  "export:node_fs:readdirSync",
  "export:node_fs:readlink",
  "export:node_fs:readlinkSync",
  "export:node_fs:readv",
  "export:node_fs:readvSync",
  "export:node_fs:realpath",
  "export:node_fs:realpathSync",
  "export:node_fs:rename",
  "export:node_fs:renameSync",
  "export:node_fs:rm",
  "export:node_fs:rmSync",
  "export:node_fs:rmdir",
  "export:node_fs:rmdirSync",
  "export:node_fs:stat",
  "export:node_fs:statSync",
  "export:node_fs:statfs",
  "export:node_fs:statfsSync",
  "export:node_fs:symlink",
  "export:node_fs:symlinkSync",
  "export:node_fs:truncate",
  "export:node_fs:truncateSync",
  "export:node_fs:unlink",
  "export:node_fs:unlinkSync",
  "export:node_fs:unwatchFile",
  "export:node_fs:utimes",
  "export:node_fs:utimesSync",
  "export:node_fs:watch",
  "export:node_fs:watchFile",
  "export:node_fs:write",
  "export:node_fs:writeFile",
  "export:node_fs:writeFileSync",
  "export:node_fs:writeSync",
  "export:node_fs:writev",
  "export:node_fs:writevSync",
  "export:node_fs_promises:FileHandle",
  "export:node_fs_promises:FileHandle.chmod",
  "export:node_fs_promises:FileHandle.chown",
  "export:node_fs_promises:FileHandle.close",
  "export:node_fs_promises:FileHandle.emit",
  "export:node_fs_promises:FileHandle.fd",
  "export:node_fs_promises:FileHandle.on",
  "export:node_fs_promises:FileHandle.read",
  "export:node_fs_promises:FileHandle.readFile",
  "export:node_fs_promises:FileHandle.readv",
  "export:node_fs_promises:FileHandle.stat",
  "export:node_fs_promises:FileHandle.truncate",
  "export:node_fs_promises:FileHandle.write",
  "export:node_fs_promises:FileHandle.writeFile",
  "export:node_fs_promises:FileHandle.writev",
  "export:node_fs_promises:access",
  "export:node_fs_promises:appendFile",
  "export:node_fs_promises:chmod",
  "export:node_fs_promises:chown",
  "export:node_fs_promises:constants",
  "export:node_fs_promises:copyFile",
  "export:node_fs_promises:default",
  "export:node_fs_promises:fdatasync",
  "export:node_fs_promises:fsync",
  "export:node_fs_promises:lchmod",
  "export:node_fs_promises:lchown",
  "export:node_fs_promises:link",
  "export:node_fs_promises:lstat",
  "export:node_fs_promises:lutimes",
  "export:node_fs_promises:mkdir",
  "export:node_fs_promises:mkdtemp",
  "export:node_fs_promises:open",
  "export:node_fs_promises:opendir",
  "export:node_fs_promises:readFile",
  "export:node_fs_promises:readFileSync",
  "export:node_fs_promises:readdir",
  "export:node_fs_promises:readlink",
  "export:node_fs_promises:readv",
  "export:node_fs_promises:realpath",
  "export:node_fs_promises:rename",
  "export:node_fs_promises:rm",
  "export:node_fs_promises:rmdir",
  "export:node_fs_promises:sendFile",
  "export:node_fs_promises:stat",
  "export:node_fs_promises:statfs",
  "export:node_fs_promises:symlink",
  "export:node_fs_promises:truncate",
  "export:node_fs_promises:unlink",
  "export:node_fs_promises:utimes",
  "export:node_fs_promises:writeFile",
  "export:node_fs_promises:writev",
  "export:node_http2:Http2ServerRequest",
  "export:node_http2:Http2ServerRequest.destroy",
  "export:node_http2:Http2ServerRequest.pause",
  "export:node_http2:Http2ServerRequest.resume",
  "export:node_http2:Http2ServerRequest.setTimeout",
  "export:node_http2:Http2ServerResponse",
  "export:node_http2:Http2ServerResponse.createPushResponse",
  "export:node_http2:Http2ServerResponse.end",
  "export:node_http2:Http2ServerResponse.flushHeaders",
  "export:node_http2:Http2ServerResponse.getHeader",
  "export:node_http2:Http2ServerResponse.getHeaderNames",
  "export:node_http2:Http2ServerResponse.hasHeader",
  "export:node_http2:Http2ServerResponse.removeHeader",
  "export:node_http2:Http2ServerResponse.setHeader",
  "export:node_http2:Http2ServerResponse.write",
  "export:node_http2:Http2ServerResponse.writeHead",
  "export:node_http2:connect",
  "export:node_http2:constants",
  "export:node_http2:createSecureServer",
  "export:node_http2:createServer",
  "export:node_http2:default",
  "export:node_http2:getDefaultSettings",
  "export:node_http2:getPackedSettings",
  "export:node_http2:getUnpackedSettings",
  "export:node_http2:performServerHandshake",
  "export:node_http2:sensitiveHeaders",
  "export:node_http:Agent",
  "export:node_http:Agent.addRequest",
  "export:node_http:Agent.constructor",
  "export:node_http:Agent.createConnection",
  "export:node_http:Agent.createSocket",
  "export:node_http:Agent.destroy",
  "export:node_http:Agent.getName",
  "export:node_http:Agent.keepSocketAlive",
  "export:node_http:Agent.removeSocket",
  "export:node_http:Agent.reuseSocket",
  "export:node_http:ClientRequest",
  "export:node_http:ClientRequest._abortSignalListener",
  "export:node_http:ClientRequest._attachToSocket",
  "export:node_http:ClientRequest._deferToConnect",
  "export:node_http:ClientRequest._ensureSocketAssigned",
  "export:node_http:ClientRequest._implicitHeader",
  "export:node_http:ClientRequest._maybeEmitFetchContinue",
  "export:node_http:ClientRequest._queueStreamingRequestBody",
  "export:node_http:ClientRequest._resolveConnectionOptions",
  "export:node_http:ClientRequest._send",
  "export:node_http:ClientRequest._sendViaFetch",
  "export:node_http:ClientRequest._sendViaTcp",
  "export:node_http:ClientRequest._startStreamingRequest",
  "export:node_http:ClientRequest.abort",
  "export:node_http:ClientRequest.appendHeader",
  "export:node_http:ClientRequest.clearTimeout",
  "export:node_http:ClientRequest.constructor",
  "export:node_http:ClientRequest.destroy",
  "export:node_http:ClientRequest.end",
  "export:node_http:ClientRequest.flushHeaders",
  "export:node_http:ClientRequest.getHeader",
  "export:node_http:ClientRequest.getHeaderNames",
  "export:node_http:ClientRequest.getHeaders",
  "export:node_http:ClientRequest.getRawHeaderNames",
  "export:node_http:ClientRequest.hasHeader",
  "export:node_http:ClientRequest.onSocket",
  "export:node_http:ClientRequest.parser",
  "export:node_http:ClientRequest.removeHeader",
  "export:node_http:ClientRequest.setHeader",
  "export:node_http:ClientRequest.setNoDelay",
  "export:node_http:ClientRequest.setSocketKeepAlive",
  "export:node_http:ClientRequest.setTimeout",
  "export:node_http:ClientRequest.write",
  "export:node_http:CloseEvent",
  "export:node_http:HTTPParser",
  "export:node_http:IncomingMessage",
  "export:node_http:IncomingMessage._addHeaderLine",
  "export:node_http:IncomingMessage._consumeBody",
  "export:node_http:IncomingMessage._read",
  "export:node_http:IncomingMessage.connection",
  "export:node_http:IncomingMessage.constructor",
  "export:node_http:IncomingMessage.destroy",
  "export:node_http:IncomingMessage.pause",
  "export:node_http:IncomingMessage.push",
  "export:node_http:IncomingMessage.read",
  "export:node_http:IncomingMessage.resume",
  "export:node_http:IncomingMessage.setEncoding",
  "export:node_http:IncomingMessage.setTimeout",
  "export:node_http:METHODS",
  "export:node_http:MessageEvent",
  "export:node_http:OutgoingMessage",
  "export:node_http:OutgoingMessage._implicitHeader",
  "export:node_http:OutgoingMessage._renderHeaders",
  "export:node_http:OutgoingMessage.addTrailers",
  "export:node_http:OutgoingMessage.appendHeader",
  "export:node_http:OutgoingMessage.connection",
  "export:node_http:OutgoingMessage.constructor",
  "export:node_http:OutgoingMessage.cork",
  "export:node_http:OutgoingMessage.destroy",
  "export:node_http:OutgoingMessage.end",
  "export:node_http:OutgoingMessage.flushHeaders",
  "export:node_http:OutgoingMessage.getHeader",
  "export:node_http:OutgoingMessage.getHeaderNames",
  "export:node_http:OutgoingMessage.getHeaders",
  "export:node_http:OutgoingMessage.getRawHeaderNames",
  "export:node_http:OutgoingMessage.hasHeader",
  "export:node_http:OutgoingMessage.headersSent",
  "export:node_http:OutgoingMessage.pipe",
  "export:node_http:OutgoingMessage.removeHeader",
  "export:node_http:OutgoingMessage.setHeader",
  "export:node_http:OutgoingMessage.setHeaders",
  "export:node_http:OutgoingMessage.setTimeout",
  "export:node_http:OutgoingMessage.uncork",
  "export:node_http:OutgoingMessage.writableHighWaterMark",
  "export:node_http:OutgoingMessage.writableLength",
  "export:node_http:OutgoingMessage.writableNeedDrain",
  "export:node_http:OutgoingMessage.writableObjectMode",
  "export:node_http:OutgoingMessage.write",
  "export:node_http:STATUS_CODES",
  "export:node_http:Server",
  "export:node_http:Server._handleNativeRequest",
  "export:node_http:Server._onConnection",
  "export:node_http:Server._pollLoop",
  "export:node_http:Server.address",
  "export:node_http:Server.close",
  "export:node_http:Server.closeAllConnections",
  "export:node_http:Server.closeIdleConnections",
  "export:node_http:Server.constructor",
  "export:node_http:Server.getConnections",
  "export:node_http:Server.listen",
  "export:node_http:Server.listening",
  "export:node_http:Server.maxConnections",
  "export:node_http:Server.ref",
  "export:node_http:Server.setTimeout",
  "export:node_http:Server.unref",
  "export:node_http:ServerIncomingMessage",
  "export:node_http:ServerIncomingMessage._dump",
  "export:node_http:ServerIncomingMessage._emitHttpClose",
  "export:node_http:ServerIncomingMessage._emitManualEnd",
  "export:node_http:ServerIncomingMessage._finishBody",
  "export:node_http:ServerIncomingMessage._flushManualData",
  "export:node_http:ServerIncomingMessage._maybeResumePausedSocket",
  "export:node_http:ServerIncomingMessage._pushBodyChunk",
  "export:node_http:ServerIncomingMessage._scheduleManualReadable",
  "export:node_http:ServerIncomingMessage.addListener",
  "export:node_http:ServerIncomingMessage.connection",
  "export:node_http:ServerIncomingMessage.constructor",
  "export:node_http:ServerIncomingMessage.destroy",
  "export:node_http:ServerIncomingMessage.isPaused",
  "export:node_http:ServerIncomingMessage.on",
  "export:node_http:ServerIncomingMessage.pause",
  "export:node_http:ServerIncomingMessage.pipe",
  "export:node_http:ServerIncomingMessage.read",
  "export:node_http:ServerIncomingMessage.resume",
  "export:node_http:ServerIncomingMessage.setEncoding",
  "export:node_http:ServerIncomingMessage.setTimeout",
  "export:node_http:ServerResponse",
  "export:node_http:ServerResponse._enqueueNativeStreamItem",
  "export:node_http:ServerResponse._ensureImplicitHeaders",
  "export:node_http:ServerResponse._ensureStreaming",
  "export:node_http:ServerResponse._failNativeStream",
  "export:node_http:ServerResponse._finishNativeStream",
  "export:node_http:ServerResponse._implicitHeader",
  "export:node_http:ServerResponse._issueNativeStreamItem",
  "export:node_http:ServerResponse._processNativeWriteQueue",
  "export:node_http:ServerResponse._renderHeaders",
  "export:node_http:ServerResponse._send",
  "export:node_http:ServerResponse._sendChunk",
  "export:node_http:ServerResponse._sendNativeResponse",
  "export:node_http:ServerResponse._sendNativeStreamEnd",
  "export:node_http:ServerResponse._sendSocketResponse",
  "export:node_http:ServerResponse._streamChunk",
  "export:node_http:ServerResponse._writeRaw",
  "export:node_http:ServerResponse.addTrailers",
  "export:node_http:ServerResponse.assignSocket",
  "export:node_http:ServerResponse.connection",
  "export:node_http:ServerResponse.constructor",
  "export:node_http:ServerResponse.cork",
  "export:node_http:ServerResponse.destroy",
  "export:node_http:ServerResponse.detachSocket",
  "export:node_http:ServerResponse.end",
  "export:node_http:ServerResponse.flushHeaders",
  "export:node_http:ServerResponse.getHeader",
  "export:node_http:ServerResponse.getHeaderNames",
  "export:node_http:ServerResponse.getHeaders",
  "export:node_http:ServerResponse.getRawHeaderNames",
  "export:node_http:ServerResponse.hasHeader",
  "export:node_http:ServerResponse.headersSent",
  "export:node_http:ServerResponse.removeHeader",
  "export:node_http:ServerResponse.setHeader",
  "export:node_http:ServerResponse.setTimeout",
  "export:node_http:ServerResponse.uncork",
  "export:node_http:ServerResponse.writableHighWaterMark",
  "export:node_http:ServerResponse.writableNeedDrain",
  "export:node_http:ServerResponse.write",
  "export:node_http:ServerResponse.writeContinue",
  "export:node_http:ServerResponse.writeEarlyHints",
  "export:node_http:ServerResponse.writeHead",
  "export:node_http:ServerResponse.writeProcessing",
  "export:node_http:WebSocket",
  "export:node_http:_checkInvalidHeaderChar",
  "export:node_http:_checkIsHttpToken",
  "export:node_http:createServer",
  "export:node_http:default",
  "export:node_http:get",
  "export:node_http:globalAgent",
  "export:node_http:kConnectionsCheckingInterval",
  "export:node_http:kHighWaterMark",
  "export:node_http:kTimeout",
  "export:node_http:maxHeaderSize",
  "export:node_http:methods",
  "export:node_http:parsers",
  "export:node_http:request",
  "export:node_http:setMaxIdleHTTPParsers",
  "export:node_http:validateHeaderName",
  "export:node_http:validateHeaderValue",
  "export:node_https:Agent",
  "export:node_https:Agent.constructor",
  "export:node_https:Agent.createConnection",
  "export:node_https:Server",
  "export:node_https:Server.constructor",
  "export:node_https:createServer",
  "export:node_https:default",
  "export:node_https:get",
  "export:node_https:globalAgent",
  "export:node_https:request",
  "export:node_inspector:Session",
  "export:node_inspector:Session.connect",
  "export:node_inspector:Session.connectToMainThread",
  "export:node_inspector:Session.constructor",
  "export:node_inspector:Session.disconnect",
  "export:node_inspector:Session.post",
  "export:node_inspector:close",
  "export:node_inspector:default",
  "export:node_inspector:open",
  "export:node_inspector:url",
  "export:node_inspector:waitForDebugger",
  "export:node_module:Module",
  "export:node_module:_cache",
  "export:node_module:_extensions",
  "export:node_module:_nodeModulePaths",
  "export:node_module:_pathCache",
  "export:node_module:builtinModules",
  "export:node_module:createRequire",
  "export:node_module:default",
  "export:node_module:globalPaths",
  "export:node_module:isBuiltin",
  "export:node_module:wrap",
  "export:node_net:BlockList",
  "export:node_net:BlockList.addAddress",
  "export:node_net:BlockList.addRange",
  "export:node_net:BlockList.addSubnet",
  "export:node_net:BlockList.check",
  "export:node_net:Server",
  "export:node_net:Server._startAccepting",
  "export:node_net:Server.address",
  "export:node_net:Server.close",
  "export:node_net:Server.getConnections",
  "export:node_net:Server.listen",
  "export:node_net:Server.ref",
  "export:node_net:Server.unref",
  "export:node_net:Socket",
  "export:node_net:Socket._abortListener",
  "export:node_net:Socket._appendToReadBuffer",
  "export:node_net:Socket._connecting",
  "export:node_net:Socket._consumeReadBuffer",
  "export:node_net:Socket._deliverInboundData",
  "export:node_net:Socket._drainWriteQueue",
  "export:node_net:Socket._emitFlowingData",
  "export:node_net:Socket._isFlowing",
  "export:node_net:Socket._isReadBufferOverHighWaterMark",
  "export:node_net:Socket._notifyOnreadEOF",
  "export:node_net:Socket._processOnreadBuffer",
  "export:node_net:Socket._resolveOnreadBuffer",
  "export:node_net:Socket._startPolling",
  "export:node_net:Socket._updateAddressInfo",
  "export:node_net:Socket.addListener",
  "export:node_net:Socket.address",
  "export:node_net:Socket.bufferSize",
  "export:node_net:Socket.bytesWritten",
  "export:node_net:Socket.close",
  "export:node_net:Socket.connect",
  "export:node_net:Socket.cork",
  "export:node_net:Socket.destroy",
  "export:node_net:Socket.end",
  "export:node_net:Socket.on",
  "export:node_net:Socket.pause",
  "export:node_net:Socket.pipe",
  "export:node_net:Socket.prependListener",
  "export:node_net:Socket.push",
  "export:node_net:Socket.read",
  "export:node_net:Socket.readableHighWaterMark",
  "export:node_net:Socket.ref",
  "export:node_net:Socket.resetAndDestroy",
  "export:node_net:Socket.resume",
  "export:node_net:Socket.setEncoding",
  "export:node_net:Socket.setKeepAlive",
  "export:node_net:Socket.setNoDelay",
  "export:node_net:Socket.setTimeout",
  "export:node_net:Socket.uncork",
  "export:node_net:Socket.unref",
  "export:node_net:Socket.unshift",
  "export:node_net:Socket.writableCorked",
  "export:node_net:Socket.writableEnded",
  "export:node_net:Socket.writableHighWaterMark",
  "export:node_net:Socket.writableLength",
  "export:node_net:Socket.writableNeedDrain",
  "export:node_net:Socket.write",
  "export:node_net:SocketAddress",
  "export:node_net:Stream",
  "export:node_net:Stream._abortListener",
  "export:node_net:Stream._appendToReadBuffer",
  "export:node_net:Stream._connecting",
  "export:node_net:Stream._consumeReadBuffer",
  "export:node_net:Stream._deliverInboundData",
  "export:node_net:Stream._drainWriteQueue",
  "export:node_net:Stream._emitFlowingData",
  "export:node_net:Stream._isFlowing",
  "export:node_net:Stream._isReadBufferOverHighWaterMark",
  "export:node_net:Stream._notifyOnreadEOF",
  "export:node_net:Stream._processOnreadBuffer",
  "export:node_net:Stream._resolveOnreadBuffer",
  "export:node_net:Stream._startPolling",
  "export:node_net:Stream._updateAddressInfo",
  "export:node_net:Stream.addListener",
  "export:node_net:Stream.address",
  "export:node_net:Stream.bufferSize",
  "export:node_net:Stream.bytesWritten",
  "export:node_net:Stream.close",
  "export:node_net:Stream.connect",
  "export:node_net:Stream.cork",
  "export:node_net:Stream.destroy",
  "export:node_net:Stream.end",
  "export:node_net:Stream.on",
  "export:node_net:Stream.pause",
  "export:node_net:Stream.pipe",
  "export:node_net:Stream.prependListener",
  "export:node_net:Stream.push",
  "export:node_net:Stream.read",
  "export:node_net:Stream.readableHighWaterMark",
  "export:node_net:Stream.ref",
  "export:node_net:Stream.resetAndDestroy",
  "export:node_net:Stream.resume",
  "export:node_net:Stream.setEncoding",
  "export:node_net:Stream.setKeepAlive",
  "export:node_net:Stream.setNoDelay",
  "export:node_net:Stream.setTimeout",
  "export:node_net:Stream.uncork",
  "export:node_net:Stream.unref",
  "export:node_net:Stream.unshift",
  "export:node_net:Stream.writableCorked",
  "export:node_net:Stream.writableEnded",
  "export:node_net:Stream.writableHighWaterMark",
  "export:node_net:Stream.writableLength",
  "export:node_net:Stream.writableNeedDrain",
  "export:node_net:Stream.write",
  "export:node_net:_normalizeArgs",
  "export:node_net:connect",
  "export:node_net:createConnection",
  "export:node_net:createServer",
  "export:node_net:default",
  "export:node_net:getDefaultAutoSelectFamily",
  "export:node_net:getDefaultAutoSelectFamilyAttemptTimeout",
  "export:node_net:isIP",
  "export:node_net:isIPv4",
  "export:node_net:isIPv6",
  "export:node_net:setDefaultAutoSelectFamily",
  "export:node_net:setDefaultAutoSelectFamilyAttemptTimeout",
  "export:node_os:EOL",
  "export:node_os:arch",
  "export:node_os:availableParallelism",
  "export:node_os:constants",
  "export:node_os:cpus",
  "export:node_os:default",
  "export:node_os:devNull",
  "export:node_os:endianness",
  "export:node_os:freemem",
  "export:node_os:getPriority",
  "export:node_os:homedir",
  "export:node_os:hostname",
  "export:node_os:loadavg",
  "export:node_os:machine",
  "export:node_os:networkInterfaces",
  "export:node_os:platform",
  "export:node_os:release",
  "export:node_os:setPriority",
  "export:node_os:tmpdir",
  "export:node_os:totalmem",
  "export:node_os:type",
  "export:node_os:uptime",
  "export:node_os:userInfo",
  "export:node_os:version",
  "export:node_path:_makeLong",
  "export:node_path:basename",
  "export:node_path:default",
  "export:node_path:delimiter",
  "export:node_path:dirname",
  "export:node_path:extname",
  "export:node_path:format",
  "export:node_path:isAbsolute",
  "export:node_path:join",
  "export:node_path:normalize",
  "export:node_path:parse",
  "export:node_path:posix",
  "export:node_path:relative",
  "export:node_path:resolve",
  "export:node_path:sep",
  "export:node_path:toNamespacedPath",
  "export:node_path:win32",
  "export:node_perf_hooks:Performance",
  "export:node_perf_hooks:Performance.clearMarks",
  "export:node_perf_hooks:Performance.clearMeasures",
  "export:node_perf_hooks:Performance.clearResourceTimings",
  "export:node_perf_hooks:Performance.getEntries",
  "export:node_perf_hooks:Performance.getEntriesByName",
  "export:node_perf_hooks:Performance.getEntriesByType",
  "export:node_perf_hooks:Performance.mark",
  "export:node_perf_hooks:Performance.markResourceTiming",
  "export:node_perf_hooks:Performance.measure",
  "export:node_perf_hooks:Performance.now",
  "export:node_perf_hooks:Performance.timeOrigin",
  "export:node_perf_hooks:Performance.toJSON",
  "export:node_perf_hooks:PerformanceEntry",
  "export:node_perf_hooks:PerformanceEntry.toJSON",
  "export:node_perf_hooks:PerformanceMark",
  "export:node_perf_hooks:PerformanceMark.constructor",
  "export:node_perf_hooks:PerformanceMark.detail",
  "export:node_perf_hooks:PerformanceMeasure",
  "export:node_perf_hooks:PerformanceMeasure.constructor",
  "export:node_perf_hooks:PerformanceMeasure.detail",
  "export:node_perf_hooks:PerformanceObserver",
  "export:node_perf_hooks:PerformanceObserver.disconnect",
  "export:node_perf_hooks:PerformanceObserver.observe",
  "export:node_perf_hooks:PerformanceObserver.takeRecords",
  "export:node_perf_hooks:PerformanceResourceTiming",
  "export:node_perf_hooks:PerformanceResourceTiming.constructor",
  "export:node_perf_hooks:PerformanceResourceTiming.toJSON",
  "export:node_perf_hooks:constants",
  "export:node_perf_hooks:createHistogram",
  "export:node_perf_hooks:default",
  "export:node_perf_hooks:eventLoopUtilization",
  "export:node_perf_hooks:monitorEventLoopDelay",
  "export:node_perf_hooks:performance",
  "export:node_perf_hooks:timerify",
  "export:node_punycode:decode",
  "export:node_punycode:default",
  "export:node_punycode:encode",
  "export:node_punycode:toASCII",
  "export:node_punycode:toUnicode",
  "export:node_punycode:ucs2",
  "export:node_punycode:version",
  "export:node_querystring:decode",
  "export:node_querystring:default",
  "export:node_querystring:encode",
  "export:node_querystring:escape",
  "export:node_querystring:parse",
  "export:node_querystring:stringify",
  "export:node_querystring:unescape",
  "export:node_readline:CSI",
  "export:node_readline:Interface",
  "export:node_readline:Interface._addHistory",
  "export:node_readline:Interface._deleteLeft",
  "export:node_readline:Interface._deleteLineLeft",
  "export:node_readline:Interface._deleteLineRight",
  "export:node_readline:Interface._deleteRight",
  "export:node_readline:Interface._deleteWordLeft",
  "export:node_readline:Interface._deleteWordRight",
  "export:node_readline:Interface._finishLine",
  "export:node_readline:Interface._getColumns",
  "export:node_readline:Interface._getDisplayPos",
  "export:node_readline:Interface._getPromptText",
  "export:node_readline:Interface._historyStep",
  "export:node_readline:Interface._insertString",
  "export:node_readline:Interface._moveCursor",
  "export:node_readline:Interface._moveCursorTo",
  "export:node_readline:Interface._normalWrite",
  "export:node_readline:Interface._onAbortSignal",
  "export:node_readline:Interface._onClose",
  "export:node_readline:Interface._onData",
  "export:node_readline:Interface._onEnd",
  "export:node_readline:Interface._onError",
  "export:node_readline:Interface._onKeypress",
  "export:node_readline:Interface._pushUndoSnapshot",
  "export:node_readline:Interface._redoEdit",
  "export:node_readline:Interface._refreshLine",
  "export:node_readline:Interface._rememberKill",
  "export:node_readline:Interface._replaceLine",
  "export:node_readline:Interface._resetHistorySearch",
  "export:node_readline:Interface._resolveCompletion",
  "export:node_readline:Interface._showCompletionError",
  "export:node_readline:Interface._showCompletions",
  "export:node_readline:Interface._tabComplete",
  "export:node_readline:Interface._ttyWrite",
  "export:node_readline:Interface._undoEdit",
  "export:node_readline:Interface._wordLeftIndex",
  "export:node_readline:Interface._wordRightIndex",
  "export:node_readline:Interface._writeToOutput",
  "export:node_readline:Interface._yank",
  "export:node_readline:Interface._yankPop",
  "export:node_readline:Interface.close",
  "export:node_readline:Interface.constructor",
  "export:node_readline:Interface.getCursorPos",
  "export:node_readline:Interface.getPrompt",
  "export:node_readline:Interface.pause",
  "export:node_readline:Interface.prompt",
  "export:node_readline:Interface.question",
  "export:node_readline:Interface.resume",
  "export:node_readline:Interface.setPrompt",
  "export:node_readline:Interface.write",
  "export:node_readline:clearLine",
  "export:node_readline:clearScreenDown",
  "export:node_readline:createInterface",
  "export:node_readline:cursorTo",
  "export:node_readline:default",
  "export:node_readline:emitKeypressEvents",
  "export:node_readline:moveCursor",
  "export:node_readline:promises",
  "export:node_stream:Duplex",
  "export:node_stream:Duplex.0",
  "export:node_stream:Duplex.constructor",
  "export:node_stream:Duplex.pipe",
  "export:node_stream:PassThrough",
  "export:node_stream:PassThrough._transform",
  "export:node_stream:PassThrough.constructor",
  "export:node_stream:Readable",
  "export:node_stream:Readable._emitReadableIfNeeded",
  "export:node_stream:Readable._read",
  "export:node_stream:Readable._readFromSource",
  "export:node_stream:Readable._syncReadableState",
  "export:node_stream:Readable._updateReadableLength",
  "export:node_stream:Readable.addListener",
  "export:node_stream:Readable.compose",
  "export:node_stream:Readable.constructor",
  "export:node_stream:Readable.drop",
  "export:node_stream:Readable.emit",
  "export:node_stream:Readable.every",
  "export:node_stream:Readable.filter",
  "export:node_stream:Readable.find",
  "export:node_stream:Readable.flatMap",
  "export:node_stream:Readable.forEach",
  "export:node_stream:Readable.isPaused",
  "export:node_stream:Readable.iterator",
  "export:node_stream:Readable.map",
  "export:node_stream:Readable.on",
  "export:node_stream:Readable.pause",
  "export:node_stream:Readable.push",
  "export:node_stream:Readable.read",
  "export:node_stream:Readable.readableAborted",
  "export:node_stream:Readable.readableDidRead",
  "export:node_stream:Readable.readableEncoding",
  "export:node_stream:Readable.readableEnded",
  "export:node_stream:Readable.readableFlowing",
  "export:node_stream:Readable.readableHighWaterMark",
  "export:node_stream:Readable.readableLength",
  "export:node_stream:Readable.readableObjectMode",
  "export:node_stream:Readable.readableState",
  "export:node_stream:Readable.reduce",
  "export:node_stream:Readable.resume",
  "export:node_stream:Readable.setEncoding",
  "export:node_stream:Readable.some",
  "export:node_stream:Readable.take",
  "export:node_stream:Readable.toArray",
  "export:node_stream:Readable.unshift",
  "export:node_stream:Readable.wrap",
  "export:node_stream:Stream",
  "export:node_stream:Stream._close",
  "export:node_stream:Stream._emitClose",
  "export:node_stream:Stream._undestroy",
  "export:node_stream:Stream.closed",
  "export:node_stream:Stream.constructor",
  "export:node_stream:Stream.destroy",
  "export:node_stream:Stream.destroyed",
  "export:node_stream:Stream.pipe",
  "export:node_stream:Stream.unpipe",
  "export:node_stream:Transform",
  "export:node_stream:Transform._transform",
  "export:node_stream:Transform._write",
  "export:node_stream:Transform.constructor",
  "export:node_stream:Transform.push",
  "export:node_stream:Writable",
  "export:node_stream:Writable.__exactWritableProtoPatched",
  "export:node_stream:Writable._flushWriteQueue",
  "export:node_stream:Writable._undestroy",
  "export:node_stream:Writable._write",
  "export:node_stream:Writable.constructor",
  "export:node_stream:Writable.cork",
  "export:node_stream:Writable.end",
  "export:node_stream:Writable.pipe",
  "export:node_stream:Writable.setDefaultEncoding",
  "export:node_stream:Writable.uncork",
  "export:node_stream:Writable.writableAborted",
  "export:node_stream:Writable.writableBuffer",
  "export:node_stream:Writable.writableCorked",
  "export:node_stream:Writable.writableEnded",
  "export:node_stream:Writable.writableFinished",
  "export:node_stream:Writable.writableHighWaterMark",
  "export:node_stream:Writable.writableLength",
  "export:node_stream:Writable.writableNeedDrain",
  "export:node_stream:Writable.writableObjectMode",
  "export:node_stream:Writable.writableState",
  "export:node_stream:Writable.write",
  "export:node_stream:addAbortSignal",
  "export:node_stream:addAbortSignalNoValidate",
  "export:node_stream:compose",
  "export:node_stream:consumers",
  "export:node_stream:default",
  "export:node_stream:default._close",
  "export:node_stream:default._emitClose",
  "export:node_stream:default._undestroy",
  "export:node_stream:default.closed",
  "export:node_stream:default.constructor",
  "export:node_stream:default.destroy",
  "export:node_stream:default.destroyed",
  "export:node_stream:default.pipe",
  "export:node_stream:default.unpipe",
  "export:node_stream:destroy",
  "export:node_stream:duplexPair",
  "export:node_stream:finished",
  "export:node_stream:getDefaultHighWaterMark",
  "export:node_stream:isDisturbed",
  "export:node_stream:isErrored",
  "export:node_stream:isReadable",
  "export:node_stream:isWritable",
  "export:node_stream:pipeline",
  "export:node_stream:promises",
  "export:node_stream:setDefaultHighWaterMark",
  "export:node_stream_consumers:arrayBuffer",
  "export:node_stream_consumers:blob",
  "export:node_stream_consumers:buffer",
  "export:node_stream_consumers:default",
  "export:node_stream_consumers:json",
  "export:node_stream_consumers:text",
  "export:node_stream_promises:default",
  "export:node_stream_promises:finished",
  "export:node_stream_promises:pipeline",
  "export:node_stream_web:ByteLengthQueuingStrategy",
  "export:node_stream_web:CountQueuingStrategy",
  "export:node_stream_web:ReadableStream",
  "export:node_stream_web:ReadableStreamBYOBReader",
  "export:node_stream_web:ReadableStreamDefaultReader",
  "export:node_stream_web:TransformStream",
  "export:node_stream_web:WritableStream",
  "export:node_stream_web:WritableStreamDefaultWriter",
  "export:node_stream_web:default",
  "export:node_stream_web:fromWeb",
  "export:node_stream_web:isReadableStream",
  "export:node_stream_web:isWritableStream",
  "export:node_stream_web:toWeb",
  "export:node_string_decoder:StringDecoder",
  "export:node_string_decoder:StringDecoder.end",
  "export:node_string_decoder:StringDecoder.fillLast",
  "export:node_string_decoder:StringDecoder.text",
  "export:node_string_decoder:StringDecoder.toString",
  "export:node_string_decoder:StringDecoder.write",
  "export:node_string_decoder:default",
  "export:node_string_decoder:default.end",
  "export:node_string_decoder:default.fillLast",
  "export:node_string_decoder:default.text",
  "export:node_string_decoder:default.toString",
  "export:node_string_decoder:default.write",
  "export:node_timers:Immediate",
  "export:node_timers:Immediate.close",
  "export:node_timers:Immediate.hasRef",
  "export:node_timers:Immediate.ref",
  "export:node_timers:Immediate.unref",
  "export:node_timers:Timeout",
  "export:node_timers:Timeout._scheduleNative",
  "export:node_timers:Timeout.close",
  "export:node_timers:Timeout.hasRef",
  "export:node_timers:Timeout.ref",
  "export:node_timers:Timeout.refresh",
  "export:node_timers:Timeout.unref",
  "export:node_timers:_unrefActive",
  "export:node_timers:active",
  "export:node_timers:clearImmediate",
  "export:node_timers:clearInterval",
  "export:node_timers:clearTimeout",
  "export:node_timers:default",
  "export:node_timers:enroll",
  "export:node_timers:promises",
  "export:node_timers:setImmediate",
  "export:node_timers:setInterval",
  "export:node_timers:setTimeout",
  "export:node_timers:unenroll",
  "export:node_timers_promises:default",
  "export:node_timers_promises:scheduler",
  "export:node_timers_promises:setImmediate",
  "export:node_timers_promises:setInterval",
  "export:node_timers_promises:setTimeout",
  "export:node_tls:CLIENT_RENEG_LIMIT",
  "export:node_tls:CLIENT_RENEG_WINDOW",
  "export:node_tls:DEFAULT_CIPHERS",
  "export:node_tls:DEFAULT_ECDH_CURVE",
  "export:node_tls:DEFAULT_MAX_VERSION",
  "export:node_tls:DEFAULT_MIN_VERSION",
  "export:node_tls:SecureContext",
  "export:node_tls:Server",
  "export:node_tls:Server.constructor",
  "export:node_tls:TLSSocket",
  "export:node_tls:TLSSocket._setSocket",
  "export:node_tls:TLSSocket.addListener",
  "export:node_tls:TLSSocket.address",
  "export:node_tls:TLSSocket.bytesRead",
  "export:node_tls:TLSSocket.bytesWritten",
  "export:node_tls:TLSSocket.close",
  "export:node_tls:TLSSocket.connect",
  "export:node_tls:TLSSocket.connecting",
  "export:node_tls:TLSSocket.constructor",
  "export:node_tls:TLSSocket.cork",
  "export:node_tls:TLSSocket.destroy",
  "export:node_tls:TLSSocket.destroyed",
  "export:node_tls:TLSSocket.disableRenegotiation",
  "export:node_tls:TLSSocket.enableTrace",
  "export:node_tls:TLSSocket.end",
  "export:node_tls:TLSSocket.getCertificate",
  "export:node_tls:TLSSocket.getCipher",
  "export:node_tls:TLSSocket.getFinished",
  "export:node_tls:TLSSocket.getPeerCertificate",
  "export:node_tls:TLSSocket.getPeerX509Certificate",
  "export:node_tls:TLSSocket.getProtocol",
  "export:node_tls:TLSSocket.getSession",
  "export:node_tls:TLSSocket.getSharedSigalgs",
  "export:node_tls:TLSSocket.getTLSTicket",
  "export:node_tls:TLSSocket.getX509Certificate",
  "export:node_tls:TLSSocket.isSessionReused",
  "export:node_tls:TLSSocket.localAddress",
  "export:node_tls:TLSSocket.localFamily",
  "export:node_tls:TLSSocket.localPort",
  "export:node_tls:TLSSocket.on",
  "export:node_tls:TLSSocket.pause",
  "export:node_tls:TLSSocket.pending",
  "export:node_tls:TLSSocket.pipe",
  "export:node_tls:TLSSocket.push",
  "export:node_tls:TLSSocket.read",
  "export:node_tls:TLSSocket.readable",
  "export:node_tls:TLSSocket.readyState",
  "export:node_tls:TLSSocket.ref",
  "export:node_tls:TLSSocket.remoteAddress",
  "export:node_tls:TLSSocket.remoteFamily",
  "export:node_tls:TLSSocket.remotePort",
  "export:node_tls:TLSSocket.renegotiate",
  "export:node_tls:TLSSocket.resume",
  "export:node_tls:TLSSocket.setEncoding",
  "export:node_tls:TLSSocket.setKeepAlive",
  "export:node_tls:TLSSocket.setMaxSendFragment",
  "export:node_tls:TLSSocket.setNoDelay",
  "export:node_tls:TLSSocket.setSession",
  "export:node_tls:TLSSocket.setTimeout",
  "export:node_tls:TLSSocket.uncork",
  "export:node_tls:TLSSocket.unref",
  "export:node_tls:TLSSocket.unshift",
  "export:node_tls:TLSSocket.writable",
  "export:node_tls:TLSSocket.write",
  "export:node_tls:checkServerIdentity",
  "export:node_tls:connect",
  "export:node_tls:convertALPNProtocols",
  "export:node_tls:createSecureContext",
  "export:node_tls:createServer",
  "export:node_tls:default",
  "export:node_tls:getCACertificates",
  "export:node_tls:getCiphers",
  "export:node_tls:rootCertificates",
  "export:node_tls:setDefaultCACertificates",
  "export:node_tls:translatePeerCertificate",
  "export:node_trace_events:createTracing",
  "export:node_trace_events:default",
  "export:node_trace_events:getEnabledCategories",
  "export:node_tty:ReadStream",
  "export:node_tty:ReadStream.constructor",
  "export:node_tty:ReadStream.setRawMode",
  "export:node_tty:WriteStream",
  "export:node_tty:WriteStream._refreshSize",
  "export:node_tty:WriteStream.clearLine",
  "export:node_tty:WriteStream.clearScreenDown",
  "export:node_tty:WriteStream.constructor",
  "export:node_tty:WriteStream.cursorTo",
  "export:node_tty:WriteStream.getColorDepth",
  "export:node_tty:WriteStream.getWindowSize",
  "export:node_tty:WriteStream.hasColors",
  "export:node_tty:WriteStream.isTTY",
  "export:node_tty:WriteStream.moveCursor",
  "export:node_tty:default",
  "export:node_tty:isatty",
  "export:node_url:URL",
  "export:node_url:URLSearchParams",
  "export:node_url:Url",
  "export:node_url:Url.resolveObject",
  "export:node_url:canParse",
  "export:node_url:createObjectURL",
  "export:node_url:default",
  "export:node_url:domainToASCII",
  "export:node_url:domainToUnicode",
  "export:node_url:fileURLToPath",
  "export:node_url:format",
  "export:node_url:parse",
  "export:node_url:pathToFileURL",
  "export:node_url:resolve",
  "export:node_url:resolveObject",
  "export:node_url:revokeObjectURL",
  "export:node_url:urlToHttpOptions",
  "export:node_util:TextDecoder",
  "export:node_util:TextEncoder",
  "export:node_util:_errnoMap",
  "export:node_util:_extend",
  "export:node_util:callbackify",
  "export:node_util:debuglog",
  "export:node_util:default",
  "export:node_util:deprecate",
  "export:node_util:format",
  "export:node_util:formatWithOptions",
  "export:node_util:getSystemErrorName",
  "export:node_util:inherits",
  "export:node_util:inspect",
  "export:node_util:isDeepStrictEqual",
  "export:node_util:log",
  "export:node_util:parseArgs",
  "export:node_util:promisify",
  "export:node_util:types",
  "export:node_util_types_alias:default",
  "export:node_v8:cachedDataVersionTag",
  "export:node_v8:default",
  "export:node_v8:deserialize",
  "export:node_v8:getHeapCodeStatistics",
  "export:node_v8:getHeapSnapshot",
  "export:node_v8:getHeapSpaceStatistics",
  "export:node_v8:getHeapStatistics",
  "export:node_v8:serialize",
  "export:node_v8:setFlagsFromString",
  "export:node_v8:writeHeapSnapshot",
  "export:node_vm:Script",
  "export:node_vm:Script.runInNewContext",
  "export:node_vm:Script.runInThisContext",
  "export:node_vm:compileFunction",
  "export:node_vm:createContext",
  "export:node_vm:default",
  "export:node_vm:isContext",
  "export:node_vm:runInNewContext",
  "export:node_vm:runInThisContext",
  "export:node_wasi:WASI",
  "export:node_wasi:WASI.getImportObject",
  "export:node_wasi:WASI.initialize",
  "export:node_wasi:WASI.start",
  "export:node_wasi:default",
  "export:node_worker_threads:BroadcastChannel",
  "export:node_worker_threads:BroadcastChannel.addEventListener",
  "export:node_worker_threads:BroadcastChannel.close",
  "export:node_worker_threads:BroadcastChannel.dispatchEvent",
  "export:node_worker_threads:BroadcastChannel.onmessage",
  "export:node_worker_threads:BroadcastChannel.onmessageerror",
  "export:node_worker_threads:BroadcastChannel.postMessage",
  "export:node_worker_threads:BroadcastChannel.removeEventListener",
  "export:node_worker_threads:MessageChannel",
  "export:node_worker_threads:MessagePort",
  "export:node_worker_threads:MessagePort._dispatchMessage",
  "export:node_worker_threads:MessagePort._dispatchMessageError",
  "export:node_worker_threads:MessagePort.addEventListener",
  "export:node_worker_threads:MessagePort.close",
  "export:node_worker_threads:MessagePort.dispatchEvent",
  "export:node_worker_threads:MessagePort.hasRef",
  "export:node_worker_threads:MessagePort.off",
  "export:node_worker_threads:MessagePort.on",
  "export:node_worker_threads:MessagePort.onmessage",
  "export:node_worker_threads:MessagePort.onmessageerror",
  "export:node_worker_threads:MessagePort.postMessage",
  "export:node_worker_threads:MessagePort.ref",
  "export:node_worker_threads:MessagePort.removeEventListener",
  "export:node_worker_threads:MessagePort.start",
  "export:node_worker_threads:MessagePort.unref",
  "export:node_worker_threads:SHARE_ENV",
  "export:node_worker_threads:Worker",
  "export:node_worker_threads:default",
  "export:node_worker_threads:getEnvironmentData",
  "export:node_worker_threads:isMainThread",
  "export:node_worker_threads:isMarkedAsUntransferable",
  "export:node_worker_threads:markAsUntransferable",
  "export:node_worker_threads:moveMessagePortToContext",
  "export:node_worker_threads:parentPort",
  "export:node_worker_threads:receiveMessageOnPort",
  "export:node_worker_threads:resourceLimits",
  "export:node_worker_threads:setEnvironmentData",
  "export:node_worker_threads:threadId",
  "export:node_worker_threads:workerData",
  "export:node_zlib:BROTLI_DECODER_RESULT_ERROR",
  "export:node_zlib:BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT",
  "export:node_zlib:BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT",
  "export:node_zlib:BROTLI_DECODER_RESULT_SUCCESS",
  "export:node_zlib:BROTLI_DEFAULT_QUALITY",
  "export:node_zlib:BROTLI_DEFAULT_WINDOW",
  "export:node_zlib:BROTLI_MAX_INPUT_BLOCK_BITS",
  "export:node_zlib:BROTLI_MAX_QUALITY",
  "export:node_zlib:BROTLI_MAX_WINDOW_BITS",
  "export:node_zlib:BROTLI_MIN_INPUT_BLOCK_BITS",
  "export:node_zlib:BROTLI_MIN_QUALITY",
  "export:node_zlib:BROTLI_MIN_WINDOW_BITS",
  "export:node_zlib:BROTLI_MODE_FONT",
  "export:node_zlib:BROTLI_MODE_GENERIC",
  "export:node_zlib:BROTLI_MODE_TEXT",
  "export:node_zlib:BROTLI_OPERATION_FINISH",
  "export:node_zlib:BROTLI_OPERATION_FLUSH",
  "export:node_zlib:BROTLI_OPERATION_PROCESS",
  "export:node_zlib:BROTLI_PARAM_DISABLE_LITERAL_CONTEXT_MODELING",
  "export:node_zlib:BROTLI_PARAM_LARGE_WINDOW",
  "export:node_zlib:BROTLI_PARAM_LGBLOCK",
  "export:node_zlib:BROTLI_PARAM_LGWIN",
  "export:node_zlib:BROTLI_PARAM_MODE",
  "export:node_zlib:BROTLI_PARAM_NDIRECT",
  "export:node_zlib:BROTLI_PARAM_NPOSTFIX",
  "export:node_zlib:BROTLI_PARAM_QUALITY",
  "export:node_zlib:BROTLI_PARAM_SIZE_HINT",
  "export:node_zlib:BrotliCompress",
  "export:node_zlib:BrotliCompress.constructor",
  "export:node_zlib:BrotliDecompress",
  "export:node_zlib:BrotliDecompress.constructor",
  "export:node_zlib:Deflate",
  "export:node_zlib:Deflate.constructor",
  "export:node_zlib:DeflateRaw",
  "export:node_zlib:DeflateRaw.constructor",
  "export:node_zlib:Gunzip",
  "export:node_zlib:Gunzip.constructor",
  "export:node_zlib:Gzip",
  "export:node_zlib:Gzip.constructor",
  "export:node_zlib:Inflate",
  "export:node_zlib:Inflate.constructor",
  "export:node_zlib:InflateRaw",
  "export:node_zlib:InflateRaw.constructor",
  "export:node_zlib:Unzip",
  "export:node_zlib:Unzip.constructor",
  "export:node_zlib:ZSTD_CLEVEL_DEFAULT",
  "export:node_zlib:ZSTD_COMPRESS",
  "export:node_zlib:ZSTD_DECOMPRESS",
  "export:node_zlib:ZSTD_btlazy2",
  "export:node_zlib:ZSTD_btopt",
  "export:node_zlib:ZSTD_btultra",
  "export:node_zlib:ZSTD_btultra2",
  "export:node_zlib:ZSTD_c_chainLog",
  "export:node_zlib:ZSTD_c_checksumFlag",
  "export:node_zlib:ZSTD_c_compressionLevel",
  "export:node_zlib:ZSTD_c_contentSizeFlag",
  "export:node_zlib:ZSTD_c_dictIDFlag",
  "export:node_zlib:ZSTD_c_enableLongDistanceMatching",
  "export:node_zlib:ZSTD_c_hashLog",
  "export:node_zlib:ZSTD_c_jobSize",
  "export:node_zlib:ZSTD_c_ldmBucketSizeLog",
  "export:node_zlib:ZSTD_c_ldmHashLog",
  "export:node_zlib:ZSTD_c_ldmHashRateLog",
  "export:node_zlib:ZSTD_c_ldmMinMatch",
  "export:node_zlib:ZSTD_c_minMatch",
  "export:node_zlib:ZSTD_c_nbWorkers",
  "export:node_zlib:ZSTD_c_overlapLog",
  "export:node_zlib:ZSTD_c_searchLog",
  "export:node_zlib:ZSTD_c_strategy",
  "export:node_zlib:ZSTD_c_targetLength",
  "export:node_zlib:ZSTD_c_windowLog",
  "export:node_zlib:ZSTD_d_windowLogMax",
  "export:node_zlib:ZSTD_dfast",
  "export:node_zlib:ZSTD_e_continue",
  "export:node_zlib:ZSTD_e_end",
  "export:node_zlib:ZSTD_e_flush",
  "export:node_zlib:ZSTD_error_GENERIC",
  "export:node_zlib:ZSTD_error_checksum_wrong",
  "export:node_zlib:ZSTD_error_corruption_detected",
  "export:node_zlib:ZSTD_error_dictionaryCreation_failed",
  "export:node_zlib:ZSTD_error_dictionary_corrupted",
  "export:node_zlib:ZSTD_error_dictionary_wrong",
  "export:node_zlib:ZSTD_error_dstBuffer_null",
  "export:node_zlib:ZSTD_error_dstSize_tooSmall",
  "export:node_zlib:ZSTD_error_frameParameter_unsupported",
  "export:node_zlib:ZSTD_error_frameParameter_windowTooLarge",
  "export:node_zlib:ZSTD_error_init_missing",
  "export:node_zlib:ZSTD_error_literals_headerWrong",
  "export:node_zlib:ZSTD_error_maxSymbolValue_tooLarge",
  "export:node_zlib:ZSTD_error_maxSymbolValue_tooSmall",
  "export:node_zlib:ZSTD_error_memory_allocation",
  "export:node_zlib:ZSTD_error_noForwardProgress_destFull",
  "export:node_zlib:ZSTD_error_noForwardProgress_inputEmpty",
  "export:node_zlib:ZSTD_error_no_error",
  "export:node_zlib:ZSTD_error_parameter_combination_unsupported",
  "export:node_zlib:ZSTD_error_parameter_outOfBound",
  "export:node_zlib:ZSTD_error_parameter_unsupported",
  "export:node_zlib:ZSTD_error_prefix_unknown",
  "export:node_zlib:ZSTD_error_srcSize_wrong",
  "export:node_zlib:ZSTD_error_stabilityCondition_notRespected",
  "export:node_zlib:ZSTD_error_stage_wrong",
  "export:node_zlib:ZSTD_error_tableLog_tooLarge",
  "export:node_zlib:ZSTD_error_version_unsupported",
  "export:node_zlib:ZSTD_error_workSpace_tooSmall",
  "export:node_zlib:ZSTD_fast",
  "export:node_zlib:ZSTD_greedy",
  "export:node_zlib:ZSTD_lazy",
  "export:node_zlib:ZSTD_lazy2",
  "export:node_zlib:Z_BEST_COMPRESSION",
  "export:node_zlib:Z_BEST_SPEED",
  "export:node_zlib:Z_BLOCK",
  "export:node_zlib:Z_BUF_ERROR",
  "export:node_zlib:Z_DATA_ERROR",
  "export:node_zlib:Z_DEFAULT_COMPRESSION",
  "export:node_zlib:Z_DEFAULT_STRATEGY",
  "export:node_zlib:Z_ERRNO",
  "export:node_zlib:Z_FILTERED",
  "export:node_zlib:Z_FINISH",
  "export:node_zlib:Z_FIXED",
  "export:node_zlib:Z_FULL_FLUSH",
  "export:node_zlib:Z_HUFFMAN_ONLY",
  "export:node_zlib:Z_MAX_CHUNK",
  "export:node_zlib:Z_MEM_ERROR",
  "export:node_zlib:Z_NEED_DICT",
  "export:node_zlib:Z_NO_COMPRESSION",
  "export:node_zlib:Z_NO_FLUSH",
  "export:node_zlib:Z_OK",
  "export:node_zlib:Z_PARTIAL_FLUSH",
  "export:node_zlib:Z_RLE",
  "export:node_zlib:Z_STREAM_END",
  "export:node_zlib:Z_STREAM_ERROR",
  "export:node_zlib:Z_SYNC_FLUSH",
  "export:node_zlib:Z_TREES",
  "export:node_zlib:Z_VERSION_ERROR",
  "export:node_zlib:ZstdCompress",
  "export:node_zlib:ZstdCompress.constructor",
  "export:node_zlib:ZstdDecompress",
  "export:node_zlib:ZstdDecompress.constructor",
  "export:node_zlib:brotliCompress",
  "export:node_zlib:brotliCompressSync",
  "export:node_zlib:brotliDecompress",
  "export:node_zlib:brotliDecompressSync",
  "export:node_zlib:codes",
  "export:node_zlib:constants",
  "export:node_zlib:crc32",
  "export:node_zlib:createBrotliCompress",
  "export:node_zlib:createBrotliDecompress",
  "export:node_zlib:createDeflate",
  "export:node_zlib:createDeflateRaw",
  "export:node_zlib:createGunzip",
  "export:node_zlib:createGzip",
  "export:node_zlib:createInflate",
  "export:node_zlib:createInflateRaw",
  "export:node_zlib:createUnzip",
  "export:node_zlib:createZstdCompress",
  "export:node_zlib:createZstdDecompress",
  "export:node_zlib:default",
  "export:node_zlib:deflate",
  "export:node_zlib:deflateRaw",
  "export:node_zlib:deflateRawSync",
  "export:node_zlib:deflateSync",
  "export:node_zlib:gunzip",
  "export:node_zlib:gunzipSync",
  "export:node_zlib:gzip",
  "export:node_zlib:gzipSync",
  "export:node_zlib:inflate",
  "export:node_zlib:inflateRaw",
  "export:node_zlib:inflateRawSync",
  "export:node_zlib:inflateSync",
  "export:node_zlib:unzip",
  "export:node_zlib:unzipSync",
  "export:node_zlib:zstdCompress",
  "export:node_zlib:zstdCompressSync",
  "export:node_zlib:zstdDecompress",
  "export:node_zlib:zstdDecompressSync",
  "export:path_posix_alias:default",
  "export:path_win32_alias:default",
  "export:url_alias:default",
  "export:util_types_alias:default",
  "export:ws:CLOSED",
  "export:ws:CLOSING",
  "export:ws:CONNECTING",
  "export:ws:OPEN",
  "export:ws:Server",
  "export:ws:Server._completeUpgrade",
  "export:ws:Server._handleRawConnection",
  "export:ws:Server._startAccepting",
  "export:ws:Server.address",
  "export:ws:Server.close",
  "export:ws:Server.handleUpgrade",
  "export:ws:WebSocket",
  "export:ws:WebSocket.CLOSED",
  "export:ws:WebSocket.CLOSING",
  "export:ws:WebSocket.CONNECTING",
  "export:ws:WebSocket.OPEN",
  "export:ws:WebSocket._appendData",
  "export:ws:WebSocket._deliverMessage",
  "export:ws:WebSocket._exceedMaxPayload",
  "export:ws:WebSocket._handleFrame",
  "export:ws:WebSocket._handleTransportClose",
  "export:ws:WebSocket._processBuffer",
  "export:ws:WebSocket._sendFrame",
  "export:ws:WebSocket._startReading",
  "export:ws:WebSocket.binaryType",
  "export:ws:WebSocket.close",
  "export:ws:WebSocket.ping",
  "export:ws:WebSocket.pong",
  "export:ws:WebSocket.readyState",
  "export:ws:WebSocket.send",
  "export:ws:WebSocket.terminate",
  "export:ws:WebSocketServer",
  "export:ws:WebSocketServer._completeUpgrade",
  "export:ws:WebSocketServer._handleRawConnection",
  "export:ws:WebSocketServer._startAccepting",
  "export:ws:WebSocketServer.address",
  "export:ws:WebSocketServer.close",
  "export:ws:WebSocketServer.handleUpgrade",
  "export:ws:createWebSocketStream",
  "export:ws:default",
]);

// Semantic approval for discovered global call/property surfaces. Discovery
// remains source-derived and the live test requires an exact stale/missing
// join; this list prevents a reviewed constructor family from blessing a new
// member with a suggestive or effectful name.
const REVIEWED_NON_GLOBAL_NATIVE_OPERATION_NAMES = new Set([
  "__exact",
  "__exactCancel",
  "__exactDeepFreeze",
  "__exactDispatchEvent",
  "__exactHostExit",
  "__exactHttpAwaitWritableExecutor",
  "__exactHttpWaitExecutor",
  "__exactModuleEvent",
  "__exactNativeFreeze",
  "__exactOSRelease",
  "__exactOSVersion",
  "__exactSetCompartmentFor",
  "__ibex",
  "__ibexLockedDown",
  "__ibexTamed",
  "native_fetch_cancel",
  "native_fetch_perform",
  "native_ws_close",
  "native_ws_connect",
  "native_ws_destroy",
  "native_ws_has_active",
  "native_ws_pause",
  "native_ws_resume",
  "native_ws_send",
  "native_ws_set_flow_controlled",
]);

// Keep this approval independent from inventory discovery. Changing a Hermes
// pin or its source patch stack changes the source-derived review ID; the
// classifier must then fail until evaluator reachability is reviewed here too.
// @ref LLP 0013#mechanism-1-lockdown — every reachable
// Function-family evaluator must remain closed by the initial profile.
const REVIEWED_HERMES_EVALUATOR_REVIEW_ID =
  "hermes-evaluators.30d158ff776c29d55fee650ca956cc4ba0d34c480344b451f80670cdcbd6c601";
const REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST =
  "sha256-8e6f277ae960175a3b0d16dd2276576f3be5e17c4e5a8d9cb9da47dc239096f8";
const REVIEWED_HERMES_EVALUATOR_PROFILE_IDS = Object.freeze([
  "android-maven",
  "source-patched",
  "windows-nuget",
]);
const REVIEWED_HERMES_EVALUATOR_BRANCHES = Object.freeze([
  Object.freeze({
    authorityRef: "scripts/hermes-version.sh#IBEX_HERMES_ANDROID_VERSION",
    profileId: "android-maven",
    routePrefix: "hermes-intrinsic-android-maven-",
    targetVariant: "android",
  }),
  Object.freeze({
    authorityRef: "scripts/apply-hermes-patches.sh#patches",
    profileId: "source-patched",
    routePrefix: "hermes-intrinsic-source-patched-",
    targetVariant: "default",
  }),
  Object.freeze({
    authorityRef: "scripts/install-windows-hermes.ps1#Version",
    profileId: "windows-nuget",
    routePrefix: "hermes-intrinsic-windows-nuget-",
    targetVariant: "windows",
  }),
]);
const REVIEWED_HERMES_EVALUATORS = Object.freeze({
  AsyncFunction: Object.freeze({
    reachability: "intrinsic-constructor",
    sourceKey: "hermes_intrinsic_evaluators",
    sourceKeys: Object.freeze(["hermes_intrinsic_evaluators"]),
  }),
  Function: Object.freeze({
    reachability: "inherited-global",
    sourceKey: "hermes_intrinsic_evaluators",
    sourceKeys: Object.freeze(["hermes_intrinsic_evaluators"]),
  }),
  GeneratorFunction: Object.freeze({
    reachability: "intrinsic-constructor",
    sourceKey: "hermes_intrinsic_evaluators",
    sourceKeys: Object.freeze(["hermes_intrinsic_evaluators"]),
  }),
  eval: Object.freeze({
    reachability: "inherited-global",
    sourceKey: "global_compat_polyfills",
    sourceKeys: Object.freeze([
      "global_compat_polyfills",
      "global_process_compat_fix",
      "hermes_intrinsic_evaluators",
    ]),
  }),
});

function hasReviewedHermesEvaluatorBranches(metadata) {
  if (
    !Array.isArray(metadata.branches) ||
    !Array.isArray(metadata.installationBranches) ||
    JSON.stringify(metadata.installationBranches) !==
      JSON.stringify(metadata.branches) ||
    metadata.branches.length !== REVIEWED_HERMES_EVALUATOR_BRANCHES.length
  ) {
    return false;
  }
  const lockdownRef = `src/engine/hermes_runtime.cc#lockdown-taming:${REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST}`;
  return REVIEWED_HERMES_EVALUATOR_BRANCHES.every((reviewedBranch, index) => {
    const branch = metadata.branches[index];
    const routes = branch?.routes ?? [branch?.route];
    return (
      branch?.targetVariant === reviewedBranch.targetVariant &&
      branch?.stubDisposition === "not-structurally-proven" &&
      Array.isArray(routes) &&
      routes.some(
        (route) =>
          typeof route === "string" &&
          route.startsWith(reviewedBranch.routePrefix),
      ) &&
      Array.isArray(branch?.sourceRefs) &&
      branch.sourceRefs.includes(reviewedBranch.authorityRef) &&
      branch.sourceRefs.includes(lockdownRef)
    );
  });
}

// Frozen semantic approval by exact global root/member pair. This table is a
// reviewed snapshot, independent of discovery; the live inventory test rejects
// both newly observed members and stale approvals.
const REVIEWED_GLOBAL_API_MEMBER_NAMES = Object.freeze({
  AbortController: ["", "abort", "signal"],
  AbortSignal: [
    "",
    "_abort",
    "abort",
    "aborted",
    "addEventListener",
    "any",
    "dispatchEvent",
    "onabort",
    "reason",
    "removeEventListener",
    "throwIfAborted",
    "timeout",
  ],
  ArrayBuffer: [""],
  AsyncFunction: [""],
  Atomics: [
    "",
    "[[Symbol.toStringTag]]",
    "add",
    "and",
    "compareExchange",
    "exchange",
    "isLockFree",
    "load",
    "notify",
    "or",
    "store",
    "sub",
    "wait",
    "xor",
  ],
  BigInt64Array: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  BigUint64Array: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  Blob: [
    "",
    "[[Symbol.toStringTag]]",
    "_getBytes",
    "arrayBuffer",
    "bytes",
    "formData",
    "json",
    "size",
    "slice",
    "stream",
    "text",
    "type",
  ],
  BroadcastChannel: [
    "",
    "[[Symbol.toStringTag]]",
    "_deliverMessage",
    "_getChannelCount",
    "_getChannelNames",
    "close",
    "name",
    "onmessage",
    "onmessageerror",
    "postMessage",
  ],
  Buffer: [
    "",
    "[[Symbol.for:nodejs.util.inspect.custom]]",
    "[[Symbol.iterator]]",
    "[[Symbol.toStringTag]]",
    "alloc",
    "allocUnsafe",
    "allocUnsafeSlow",
    "byteLength",
    "compare",
    "concat",
    "constants",
    "copy",
    "entries",
    "equals",
    "fill",
    "from",
    "includes",
    "indexOf",
    "isBuffer",
    "isEncoding",
    "keys",
    "lastIndexOf",
    "offset",
    "parent",
    "poolSize",
    "readBigInt64BE",
    "readBigInt64LE",
    "readBigUInt64BE",
    "readBigUInt64LE",
    "readBigUint64BE",
    "readBigUint64LE",
    "readDoubleBE",
    "readDoubleLE",
    "readFloatBE",
    "readFloatLE",
    "readInt16BE",
    "readInt16LE",
    "readInt32BE",
    "readInt32LE",
    "readInt8",
    "readIntBE",
    "readIntLE",
    "readUInt16BE",
    "readUInt16LE",
    "readUInt32BE",
    "readUInt32LE",
    "readUInt8",
    "readUIntBE",
    "readUIntLE",
    "readUint16BE",
    "readUint16LE",
    "readUint32BE",
    "readUint32LE",
    "readUint8",
    "readUintBE",
    "readUintLE",
    "slice",
    "subarray",
    "swap16",
    "swap32",
    "swap64",
    "toJSON",
    "toString",
    "values",
    "write",
    "writeBigInt64BE",
    "writeBigInt64LE",
    "writeBigUInt64BE",
    "writeBigUInt64LE",
    "writeBigUint64BE",
    "writeBigUint64LE",
    "writeDoubleBE",
    "writeDoubleLE",
    "writeFloatBE",
    "writeFloatLE",
    "writeInt16BE",
    "writeInt16LE",
    "writeInt32BE",
    "writeInt32LE",
    "writeInt8",
    "writeIntBE",
    "writeIntLE",
    "writeUInt16BE",
    "writeUInt16LE",
    "writeUInt32BE",
    "writeUInt32LE",
    "writeUInt8",
    "writeUIntBE",
    "writeUIntLE",
    "writeUint16BE",
    "writeUint16LE",
    "writeUint32BE",
    "writeUint32LE",
    "writeUint8",
    "writeUintBE",
    "writeUintLE",
  ],
  Bun: [
    "",
    "$",
    "CryptoHasher",
    "CryptoHasher.algorithms",
    "CryptoHasher.digest",
    "CryptoHasher.update",
    "MD5",
    "MD5.digest",
    "MD5.update",
    "SHA1",
    "SHA1.digest",
    "SHA1.update",
    "SHA224",
    "SHA224.digest",
    "SHA224.update",
    "SHA256",
    "SHA256.digest",
    "SHA256.update",
    "SHA384",
    "SHA384.digest",
    "SHA384.update",
    "SHA512",
    "SHA512.digest",
    "SHA512.update",
    "Transpiler",
    "accessibility",
    "accessibility.addEventListener",
    "accessibility.announce",
    "accessibility.colorScheme",
    "accessibility.dynamicTypeSize",
    "accessibility.fontScale",
    "accessibility.get",
    "accessibility.isBoldTextEnabled",
    "accessibility.isGrayscaleEnabled",
    "accessibility.isInvertColorsEnabled",
    "accessibility.isScreenReaderEnabled",
    "accessibility.prefersHighContrast",
    "accessibility.prefersReducedMotion",
    "accessibility.prefersReducedTransparency",
    "argv",
    "color",
    "concatArrayBuffers",
    "connect",
    "deepEquals",
    "deepMatch",
    "deflateSync",
    "dns",
    "dns.lookup",
    "dns.resolve",
    "enableANSIColors",
    "env",
    "escapeHTML",
    "fetch",
    "file",
    "fileURLToPath",
    "gc",
    "gunzipSync",
    "gzipSync",
    "hash",
    "hash.adler32",
    "hash.crc32",
    "hash.wyhash",
    "inflateSync",
    "inspect",
    "isMainThread",
    "listen",
    "locale",
    "locale.addListener",
    "locale.direction",
    "locale.language",
    "locale.region",
    "locale.tag",
    "locale.tags",
    "locale.uses24Hour",
    "main",
    "nanoseconds",
    "origin",
    "password",
    "password.hash",
    "password.hashSync",
    "password.verify",
    "password.verifySync",
    "pathToFileURL",
    "peek",
    "peek.status",
    "platform",
    "readableStreamToArray",
    "readableStreamToArrayBuffer",
    "readableStreamToBlob",
    "readableStreamToFormData",
    "readableStreamToJSON",
    "readableStreamToText",
    "resolve",
    "resolveSync",
    "revision",
    "semver",
    "semver.order",
    "semver.satisfies",
    "serve",
    "setModuleCapabilities",
    "sha",
    "sleep",
    "sleepSync",
    "spawn",
    "spawnSync",
    "stderr",
    "stdin",
    "stdout",
    "stringWidth",
    "unsafe",
    "unsafe.arrayBufferToString",
    "unsafe.gcAggressionLevel",
    "unsafe.segfault",
    "version",
    "which",
    "write",
  ],
  ByteLengthQueuingStrategy: [
    "",
    "[[Symbol.toStringTag]]",
    "highWaterMark",
    "size",
  ],
  Cache: ["", "add", "addAll", "delete", "keys", "match", "matchAll", "put"],
  CacheStorage: ["", "delete", "has", "keys", "match", "open"],
  ClipboardItem: ["", "[[Symbol.toStringTag]]", "getType", "types"],
  CloseEvent: [
    "",
    "[[Symbol.toStringTag]]",
    "_code",
    "_reason",
    "_wasClean",
    "code",
    "length",
    "reason",
    "wasClean",
  ],
  CompressionStream: ["", "readable", "writable"],
  CountQueuingStrategy: [
    "",
    "[[Symbol.toStringTag]]",
    "__exactUnrestrictedDoublePatched",
    "highWaterMark",
    "size",
  ],
  Crypto: ["", "getRandomValues", "randomUUID", "subtle"],
  CryptoKey: [
    "",
    "[[Symbol.toStringTag]]",
    "_keyData",
    "algorithm",
    "extractable",
    "type",
    "usages",
  ],
  CustomEvent: ["", "constructor", "detail"],
  DOMException: [
    "",
    "ABORT_ERR",
    "DATA_CLONE_ERR",
    "DOMSTRING_SIZE_ERR",
    "HIERARCHY_REQUEST_ERR",
    "INDEX_SIZE_ERR",
    "INUSE_ATTRIBUTE_ERR",
    "INVALID_ACCESS_ERR",
    "INVALID_CHARACTER_ERR",
    "INVALID_MODIFICATION_ERR",
    "INVALID_NODE_TYPE_ERR",
    "INVALID_STATE_ERR",
    "NAMESPACE_ERR",
    "NETWORK_ERR",
    "NOT_FOUND_ERR",
    "NOT_SUPPORTED_ERR",
    "NO_DATA_ALLOWED_ERR",
    "NO_MODIFICATION_ALLOWED_ERR",
    "QUOTA_EXCEEDED_ERR",
    "SECURITY_ERR",
    "SYNTAX_ERR",
    "TIMEOUT_ERR",
    "TYPE_MISMATCH_ERR",
    "URL_MISMATCH_ERR",
    "VALIDATION_ERR",
    "WRONG_DOCUMENT_ERR",
    "code",
    "message",
    "name",
    "stack",
    "toString",
  ],
  DataView: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
  ],
  Date: ["", "constructor"],
  DecompressionStream: ["", "readable", "writable"],
  ErrorEvent: [
    "",
    "[[Symbol.toStringTag]]",
    "colno",
    "error",
    "filename",
    "lineno",
    "message",
  ],
  Event: [
    "",
    "AT_TARGET",
    "BUBBLING_PHASE",
    "CAPTURING_PHASE",
    "NONE",
    "_isBeingDispatched",
    "_isImmediatePropagationStopped",
    "_isPropagationStopped",
    "_resetFlags",
    "_setCurrentTarget",
    "_setDispatchFlag",
    "_setEventPhase",
    "_setInPassiveListener",
    "_setTarget",
    "bubbles",
    "cancelBubble",
    "cancelable",
    "composed",
    "composedPath",
    "currentTarget",
    "defaultPrevented",
    "eventPhase",
    "initEvent",
    "preventDefault",
    "returnValue",
    "stopImmediatePropagation",
    "stopPropagation",
    "target",
    "timeStamp",
    "type",
  ],
  EventSource: [
    "",
    "CLOSED",
    "CONNECTING",
    "OPEN",
    "[[Symbol.toStringTag]]",
    "close",
    "onerror",
    "onmessage",
    "onopen",
    "readyState",
    "url",
    "withCredentials",
  ],
  EventTarget: ["", "addEventListener", "dispatchEvent", "removeEventListener"],
  Exact: [
    "",
    "$",
    "CryptoHasher",
    "CryptoHasher.algorithms",
    "CryptoHasher.digest",
    "CryptoHasher.update",
    "MD5",
    "MD5.digest",
    "MD5.update",
    "SHA1",
    "SHA1.digest",
    "SHA1.update",
    "SHA224",
    "SHA224.digest",
    "SHA224.update",
    "SHA256",
    "SHA256.digest",
    "SHA256.update",
    "SHA384",
    "SHA384.digest",
    "SHA384.update",
    "SHA512",
    "SHA512.digest",
    "SHA512.update",
    "Transpiler",
    "accessibility",
    "accessibility.addEventListener",
    "accessibility.announce",
    "accessibility.colorScheme",
    "accessibility.dynamicTypeSize",
    "accessibility.fontScale",
    "accessibility.get",
    "accessibility.isBoldTextEnabled",
    "accessibility.isGrayscaleEnabled",
    "accessibility.isInvertColorsEnabled",
    "accessibility.isScreenReaderEnabled",
    "accessibility.prefersHighContrast",
    "accessibility.prefersReducedMotion",
    "accessibility.prefersReducedTransparency",
    "argv",
    "color",
    "concatArrayBuffers",
    "connect",
    "deepEquals",
    "deepMatch",
    "deflateSync",
    "dns",
    "dns.lookup",
    "dns.resolve",
    "enableANSIColors",
    "env",
    "escapeHTML",
    "fetch",
    "file",
    "fileURLToPath",
    "gc",
    "gunzipSync",
    "gzipSync",
    "hash",
    "hash.adler32",
    "hash.crc32",
    "hash.wyhash",
    "inflateSync",
    "inspect",
    "isMainThread",
    "listen",
    "locale",
    "locale.addListener",
    "locale.direction",
    "locale.language",
    "locale.region",
    "locale.tag",
    "locale.tags",
    "locale.uses24Hour",
    "main",
    "nanoseconds",
    "origin",
    "password",
    "password.hash",
    "password.hashSync",
    "password.verify",
    "password.verifySync",
    "pathToFileURL",
    "peek",
    "peek.status",
    "platform",
    "readableStreamToArray",
    "readableStreamToArrayBuffer",
    "readableStreamToBlob",
    "readableStreamToFormData",
    "readableStreamToJSON",
    "readableStreamToText",
    "resolve",
    "resolveSync",
    "revision",
    "semver",
    "semver.order",
    "semver.satisfies",
    "serve",
    "setModuleCapabilities",
    "sha",
    "sleep",
    "sleepSync",
    "spawn",
    "spawnSync",
    "stderr",
    "stdin",
    "stdout",
    "stringWidth",
    "unsafe",
    "unsafe.arrayBufferToString",
    "unsafe.gcAggressionLevel",
    "unsafe.segfault",
    "version",
    "which",
    "write",
  ],
  ExactBundle: [
    "",
    "areGlobalsInstalled",
    "detectEngine",
    "detectPlatform",
    "getRuntimeVersion",
    "installGlobals",
    "runtimeInfo",
    "runtimeInfo.engine",
    "runtimeInfo.platform",
    "runtimeInfo.version",
  ],
  File: [
    "",
    "[[Symbol.toStringTag]]",
    "constructor",
    "lastModified",
    "name",
    "webkitRelativePath",
  ],
  FileReader: [
    "",
    "DONE",
    "EMPTY",
    "LOADING",
    "[[Symbol.toStringTag]]",
    "abort",
    "error",
    "onabort",
    "onerror",
    "onload",
    "onloadend",
    "onloadstart",
    "onprogress",
    "readAsArrayBuffer",
    "readAsBinaryString",
    "readAsDataURL",
    "readAsText",
    "readyState",
    "result",
  ],
  Float16Array: [
    "",
    "BYTES_PER_ELEMENT",
    "[[Symbol.toStringTag]]",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
  ],
  Float32Array: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  Float64Array: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  FocusEvent: ["", "[[Symbol.toStringTag]]", "relatedTarget"],
  FormData: [
    "",
    "[[Symbol.iterator]]",
    "[[Symbol.toStringTag]]",
    "_encode",
    "_getEntries",
    "append",
    "delete",
    "entries",
    "forEach",
    "get",
    "getAll",
    "has",
    "keys",
    "set",
    "values",
  ],
  Function: [""],
  GeneratorFunction: [""],
  Headers: [
    "",
    "[[Symbol.for:nodejs.util.inspect.custom]]",
    "[[Symbol.iterator]]",
    "_guard",
    "append",
    "count",
    "delete",
    "entries",
    "forEach",
    "fromTupleArray",
    "get",
    "getAll",
    "getSetCookie",
    "has",
    "keys",
    "name",
    "set",
    "toJSON",
    "toTupleArray",
    "values",
  ],
  IDBCursor: [
    "",
    "advance",
    "continue",
    "delete",
    "direction",
    "key",
    "primaryKey",
    "request",
    "source",
    "update",
  ],
  IDBCursorWithValue: ["", "value"],
  IDBDatabase: [
    "",
    "_all",
    "_beginTxnSnapshot",
    "_checkClosed",
    "_commitTxnSnapshot",
    "_computeAutoIncrementBase",
    "_deleteIndexMeta",
    "_ensureKeyEnc",
    "_exec",
    "_factory",
    "_fireListeners",
    "_fireVersionChange",
    "_get",
    "_getObjectStore",
    "_indexDataReady",
    "_initMeta",
    "_keyencReady",
    "_loadStoreDefinitions",
    "_nextAutoIncrement",
    "_noteExplicitKey",
    "_rollbackTxnSnapshot",
    "_saveIndexMeta",
    "_saveStoreMeta",
    "_scheduleTransaction",
    "_shared",
    "_sqliteDb",
    "_tableNameClaimed",
    "_transactionFinished",
    "_upgradeTransaction",
    "addEventListener",
    "close",
    "createObjectStore",
    "deleteObjectStore",
    "name",
    "objectStoreNames",
    "onabort",
    "onclose",
    "onerror",
    "onversionchange",
    "removeEventListener",
    "transaction",
    "version",
  ],
  IDBIndex: [
    "",
    "_objectStore",
    "count",
    "get",
    "getAll",
    "getAllKeys",
    "getKey",
    "keyPath",
    "multiEntry",
    "name",
    "objectStore",
    "openCursor",
    "openKeyCursor",
    "unique",
  ],
  IDBKeyRange: [
    "",
    "bound",
    "includes",
    "lower",
    "lowerBound",
    "lowerOpen",
    "only",
    "upper",
    "upperBound",
    "upperOpen",
  ],
  IDBObjectStore: [
    "",
    "_backfillIndex",
    "_clearRecords",
    "_countRecords",
    "_cursorStreamer",
    "_db",
    "_deleteRecord",
    "_ensureIndexData",
    "_ensureTable",
    "_extractInlineKey",
    "_getRecord",
    "_hasRecord",
    "_indexCount",
    "_indexCursorStreamer",
    "_indexEntries",
    "_indexGetKeys",
    "_indexGetValues",
    "_indexTableName",
    "_indexWhere",
    "_indexes",
    "_migrateLegacyTables",
    "_prepareIndexMaintenance",
    "_putRecord",
    "_queryRange",
    "_rangeConds",
    "_resolveKeyAndValue",
    "_selectRange",
    "_tableName",
    "_transaction",
    "_validateQuery",
    "add",
    "autoIncrement",
    "clear",
    "count",
    "createIndex",
    "delete",
    "deleteIndex",
    "get",
    "getAll",
    "getAllKeys",
    "getKey",
    "index",
    "indexNames",
    "keyPath",
    "name",
    "openCursor",
    "openKeyCursor",
    "put",
    "transaction",
  ],
  IDBOpenDBRequest: ["", "onblocked", "onupgradeneeded"],
  IDBRequest: [
    "",
    "_abort",
    "_invokeListeners",
    "_reject",
    "_resolve",
    "_resolveSync",
    "_setResult",
    "addEventListener",
    "error",
    "onerror",
    "onsuccess",
    "readyState",
    "removeEventListener",
    "result",
    "source",
    "transaction",
  ],
  IDBTransaction: [
    "",
    "_abortWith",
    "_addToScope",
    "_assertActive",
    "_assertWritable",
    "_beforeCommit",
    "_beginEventDispatch",
    "_beginVersionChange",
    "_endEventDispatch",
    "_enqueueOp",
    "_onFinished",
    "_onStart",
    "_pending",
    "_release",
    "_removeFromScope",
    "_requestErrored",
    "_retain",
    "_scheduleDeactivation",
    "_start",
    "_started",
    "_state",
    "abort",
    "addEventListener",
    "commit",
    "db",
    "error",
    "mode",
    "objectStore",
    "objectStoreNames",
    "onabort",
    "oncomplete",
    "onerror",
    "removeEventListener",
  ],
  Ibex: [
    "",
    "authority",
    "authority.mintHandle",
    "authority.onChange",
    "authority.revokeHandle",
    "fs",
    "fs.readHandle",
    "fs.readHandle.[[return]].readFileSync",
    "fs.readHandle.[[return]].readTextSync",
    "fs.readHandle.[[return]].revoke",
    "fs.readHandle.[[return]].scoped",
    "permissions",
    "permissions.acquire",
    "permissions.broker",
    "permissions.onChange",
    "permissions.request",
    "permissions.requestTyped",
    "permissions.revoke",
    "permissions.revokeTyped",
    "permissions.status",
  ],
  Int16Array: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  Int32Array: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  Int8Array: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  Intl: [
    "",
    "Collator",
    "Collator.compare",
    "Collator.resolvedOptions",
    "Collator.supportedLocalesOf",
    "DateTimeFormat",
    "DateTimeFormat.prototype",
    "DateTimeFormat.prototype.formatRange",
    "DateTimeFormat.prototype.formatRangeToParts",
    "DateTimeFormat.prototype.formatToParts",
    "DisplayNames",
    "DisplayNames.of",
    "DisplayNames.resolvedOptions",
    "DisplayNames.supportedLocalesOf",
    "DurationFormat",
    "DurationFormat._buildDigitalParts",
    "DurationFormat._buildParts",
    "DurationFormat._buildTextParts",
    "DurationFormat._locale",
    "DurationFormat._style",
    "DurationFormat.format",
    "DurationFormat.formatToParts",
    "DurationFormat.resolvedOptions",
    "DurationFormat.supportedLocalesOf",
    "ListFormat",
    "ListFormat.format",
    "ListFormat.formatToParts",
    "ListFormat.resolvedOptions",
    "ListFormat.supportedLocalesOf",
    "Locale",
    "Locale.baseName",
    "Locale.calendar",
    "Locale.language",
    "Locale.maximize",
    "Locale.minimize",
    "Locale.numberingSystem",
    "Locale.prototype",
    "Locale.prototype.textInfo",
    "Locale.prototype.textInfo.direction",
    "Locale.region",
    "Locale.script",
    "Locale.textInfo",
    "Locale.toJSON",
    "Locale.toString",
    "NumberFormat",
    "NumberFormat.prototype",
    "NumberFormat.prototype.formatRange",
    "NumberFormat.prototype.formatRangeToParts",
    "NumberFormat.prototype.formatToParts",
    "PluralRules",
    "PluralRules.resolvedOptions",
    "PluralRules.select",
    "PluralRules.selectRange",
    "PluralRules.supportedLocalesOf",
    "RelativeTimeFormat",
    "RelativeTimeFormat.format",
    "RelativeTimeFormat.formatToParts",
    "RelativeTimeFormat.resolvedOptions",
    "RelativeTimeFormat.supportedLocalesOf",
    "Segmenter",
    "Segmenter.resolvedOptions",
    "Segmenter.segment",
    "Segmenter.supportedLocalesOf",
    "[[dynamic-table:host-intl-properties]]",
    "getCanonicalLocales",
  ],
  Iterator: [
    "",
    "from",
    "prototype",
    "prototype.[[Symbol.iterator]]",
    "prototype.[[Symbol.toStringTag]]",
    "prototype.constructor",
    "prototype.drop",
    "prototype.every",
    "prototype.filter",
    "prototype.find",
    "prototype.flatMap",
    "prototype.forEach",
    "prototype.map",
    "prototype.reduce",
    "prototype.some",
    "prototype.take",
    "prototype.toArray",
  ],
  KeyboardEvent: [
    "",
    "[[Symbol.toStringTag]]",
    "altKey",
    "code",
    "ctrlKey",
    "key",
    "metaKey",
    "repeat",
    "shiftKey",
  ],
  MediaQueryList: [
    "",
    "_syncFromAppearance",
    "addEventListener",
    "addListener",
    "matches",
    "media",
    "onchange",
    "removeEventListener",
    "removeListener",
  ],
  MediaQueryListEvent: ["", "matches", "media"],
  MessageChannel: ["", "[[Symbol.toStringTag]]", "port1", "port2"],
  MessageEvent: [
    "",
    "[[Symbol.toStringTag]]",
    "data",
    "initMessageEvent",
    "lastEventId",
    "origin",
    "ports",
    "source",
  ],
  MessagePort: [
    "",
    "[[Symbol.toStringTag]]",
    "[[symbol-binding:structuredCloneTransferSymbol]]",
    "_setRemotePort",
    "close",
    "onmessage",
    "onmessageerror",
    "postMessage",
    "start",
  ],
  Performance: [""],
  PerformanceEntry: [
    "",
    "duration",
    "entryType",
    "name",
    "startTime",
    "toJSON",
  ],
  PerformanceMark: ["", "detail"],
  PerformanceMeasure: ["", "detail"],
  PerformanceObserver: [
    "",
    "_notify",
    "disconnect",
    "observe",
    "supportedEntryTypes",
    "takeRecords",
  ],
  PerformanceResourceTiming: [""],
  ProgressEvent: [
    "",
    "[[Symbol.toStringTag]]",
    "lengthComputable",
    "loaded",
    "total",
  ],
  Promise: [
    "",
    "prototype",
    "prototype.catch",
    "prototype.finally",
    "prototype.then",
    "reject",
  ],
  PromiseRejectionEvent: ["", "[[Symbol.toStringTag]]", "promise", "reason"],
  ReadableByteStreamController: [
    "",
    "[[Symbol.toStringTag]]",
    "_autoAllocateChunkSize",
    "_byobRequest",
    "_cancelAlgorithm",
    "_closeRequested",
    "_dequeue",
    "_error",
    "_pendingPullIntos",
    "_processReadIntoRequest",
    "_pullAgain",
    "_pullAlgorithm",
    "_pullIfNeeded",
    "_pulling",
    "_queue",
    "_queueTotalSize",
    "_respondToByobRequest",
    "_respondWithNewViewToByobRequest",
    "_setup",
    "_shouldPull",
    "_started",
    "_strategyHWM",
    "_stream",
    "byobRequest",
    "close",
    "desiredSize",
    "enqueue",
    "error",
  ],
  ReadableStream: [
    "",
    "[[Symbol.asyncIterator]]",
    "[[Symbol.toStringTag]]",
    "[[return]].__exactReadableStreamIteratorPatched",
    "[[return]].getReader",
    "[[return]].tee",
    "[[return]].values",
    "__exactReadableStreamsPatched",
    "_cancelStream",
    "_closeStream",
    "_controller",
    "_disturbed",
    "_errorStream",
    "_isByteStream",
    "_isOwningStream",
    "_reader",
    "_state",
    "_storedError",
    "arrayBuffer",
    "blob",
    "bytes",
    "cancel",
    "from",
    "getReader",
    "json",
    "locked",
    "pipeThrough",
    "pipeTo",
    "prototype.__exactReadableStreamCompatIteratorPatched",
    "prototype.__exactReadableStreamIteratorPatched",
    "prototype.__exactReadableStreamValuesPatched",
    "prototype.getReader",
    "prototype.getReader.__exactReadableStreamCompatGetReaderPatched",
    "prototype.getReader.__exactReadableStreamGetReaderPatched",
    "prototype.tee",
    "prototype.values",
    "prototype.values.__exactReadableStreamValuesPatched",
    "tee",
    "text",
    "values",
  ],
  ReadableStreamBYOBReader: [
    "",
    "[[Symbol.toStringTag]]",
    "_closedPromise",
    "_closedReject",
    "_closedResolve",
    "_initializeClosedPromise",
    "_readIntoRequests",
    "_stream",
    "cancel",
    "closed",
    "read",
    "releaseLock",
  ],
  ReadableStreamBYOBRequest: [
    "",
    "[[Symbol.toStringTag]]",
    "_controller",
    "_view",
    "respond",
    "respondWithNewView",
    "view",
  ],
  ReadableStreamDefaultController: [
    "",
    "[[Symbol.toStringTag]]",
    "_canCloseOrEnqueue",
    "_cancelAlgorithm",
    "_closeRequested",
    "_dequeue",
    "_error",
    "_isOwningStream",
    "_pullAgain",
    "_pullAlgorithm",
    "_pullIfNeeded",
    "_pulling",
    "_queue",
    "_queueTotalSize",
    "_shouldPull",
    "_started",
    "_strategyHWM",
    "_strategySizeAlgorithm",
    "_stream",
    "close",
    "desiredSize",
    "enqueue",
    "error",
  ],
  ReadableStreamDefaultReader: [
    "",
    "[[Symbol.toStringTag]]",
    "_closedPromise",
    "_closedReject",
    "_closedResolve",
    "_initializeClosedPromise",
    "_processReadRequests",
    "_readRequests",
    "_stream",
    "cancel",
    "closed",
    "read",
    "releaseLock",
  ],
  Request: [
    "",
    "body",
    "cache",
    "clone",
    "constructor",
    "credentials",
    "destination",
    "duplex",
    "formData",
    "formData.__exactCompatPatched",
    "getBodyAsUint8Array",
    "getBodyStream",
    "hasExplicitKeepalive",
    "headers",
    "integrity",
    "isBodyStream",
    "isHistoryNavigation",
    "isReloadNavigation",
    "keepalive",
    "markBodyAsUsedForFetch",
    "method",
    "mode",
    "name",
    "priority",
    "prototype.formData",
    "prototype.formData.__exactCompatPatched",
    "redirect",
    "referrer",
    "referrerPolicy",
    "signal",
    "url",
  ],
  Response: [
    "",
    "arrayBuffer",
    "body",
    "clone",
    "constructor",
    "error",
    "formData",
    "formData.__exactCompatPatched",
    "fromNative",
    "fromNativeStreaming",
    "headers",
    "json",
    "name",
    "ok",
    "prototype.formData",
    "prototype.formData.__exactCompatPatched",
    "redirect",
    "redirected",
    "status",
    "statusText",
    "text",
    "type",
    "url",
  ],
  SharedArrayBuffer: [
    "",
    "[[Symbol.toStringTag]]",
    "_buffer",
    "byteLength",
    "constructor",
    "prototype",
    "prototype.constructor",
    "prototype.constructor.constructor",
    "slice",
  ],
  SubtleCrypto: [
    "",
    "constructor",
    "decrypt",
    "deriveBits",
    "deriveKey",
    "digest",
    "encrypt",
    "exportKey",
    "generateKey",
    "importKey",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ],
  TextDecoder: ["", "decode", "encoding", "fatal", "ignoreBOM", "prototype"],
  TextDecoderStream: [
    "",
    "[[Symbol.toStringTag]]",
    "encoding",
    "fatal",
    "ignoreBOM",
    "readable",
    "writable",
  ],
  TextEncoder: ["", "encode", "encodeInto", "encoding"],
  TextEncoderStream: [
    "",
    "[[Symbol.toStringTag]]",
    "encoding",
    "readable",
    "writable",
  ],
  TransformStream: [
    "",
    "[[Symbol.toStringTag]]",
    "_backpressure",
    "_backpressureResolve",
    "_controller",
    "_isTerminated",
    "_pendingWritableError",
    "_readable",
    "_updateBackpressure",
    "_writable",
    "readable",
    "writable",
  ],
  TransformStreamDefaultController: [
    "",
    "[[Symbol.toStringTag]]",
    "_flushAlgorithm",
    "_stream",
    "_transformAlgorithm",
    "desiredSize",
    "enqueue",
    "error",
    "terminate",
  ],
  URL: [
    "",
    "_updateSearch",
    "canParse",
    "createObjectURL",
    "hash",
    "host",
    "hostname",
    "href",
    "origin",
    "parse",
    "password",
    "pathname",
    "port",
    "protocol",
    "prototype.host",
    "prototype.password",
    "prototype.pathname",
    "prototype.protocol",
    "prototype.username",
    "revokeObjectURL",
    "search",
    "searchParams",
    "toJSON",
    "toString",
    "username",
  ],
  URLPattern: [
    "",
    "exec",
    "hash",
    "hostname",
    "password",
    "pathname",
    "port",
    "protocol",
    "search",
    "test",
    "username",
  ],
  URLSearchParams: [
    "",
    "[[Symbol.iterator]]",
    "_resetFromSearch",
    "_setURL",
    "append",
    "delete",
    "entries",
    "forEach",
    "get",
    "getAll",
    "has",
    "keys",
    "length",
    "set",
    "size",
    "sort",
    "toJSON",
    "toString",
    "values",
  ],
  Uint16Array: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  Uint32Array: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  Uint8Array: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  Uint8ClampedArray: [
    "",
    "__exactSharedArrayBufferWrapped",
    "constructor",
    "name",
    "prototype",
    "prototype.subarray",
    "prototype.subarray.__exactZeroLengthWrapped",
  ],
  VideoFrame: [
    "",
    "[[Symbol.toStringTag]]",
    "[[return]].close",
    "[[symbol-binding:structuredCloneCloneSymbol]]",
    "[[symbol-binding:structuredCloneTransferSymbol]]",
    "_exactClosed",
    "_exactData",
    "close",
    "codedHeight",
    "codedWidth",
    "format",
    "timestamp",
  ],
  WebSocket: [
    "",
    "CLOSED",
    "CLOSING",
    "CONNECTING",
    "OPEN",
    "[[Symbol.toStringTag]]",
    "_binaryType",
    "_bufferedAmount",
    "_callEventHandler",
    "_closeEventPending",
    "_connectNative",
    "_enqueueEventTask",
    "_eventQueue",
    "_eventQueueOffset",
    "_eventQueueScheduled",
    "_extensions",
    "_handleBytesSent",
    "_handleClose",
    "_handleCloseInternal",
    "_handleError",
    "_handleErrorInternal",
    "_handleMessage",
    "_handleOpen",
    "_incomingFlowControlled",
    "_incomingPaused",
    "_isSendingQueue",
    "_onclose",
    "_onerror",
    "_onmessage",
    "_onopen",
    "_pauseIncoming",
    "_pendingSendAckOffset",
    "_pendingSendAcks",
    "_protocol",
    "_queueSend",
    "_readyState",
    "_resolvePendingSendAcks",
    "_resumeIncoming",
    "_sendNative",
    "_sendQueue",
    "_sendQueueOffset",
    "_setIncomingFlowControl",
    "_simulateConnection",
    "_socketId",
    "_url",
    "binaryType",
    "bufferedAmount",
    "close",
    "extensions",
    "length",
    "onclose",
    "onerror",
    "onmessage",
    "onopen",
    "protocol",
    "readyState",
    "send",
    "url",
  ],
  WebSocketError: ["", "[[Symbol.toStringTag]]", "closeCode", "reason"],
  WebSocketStream: [
    "",
    "[[Symbol.toStringTag]]",
    "_clearPendingWriteResolveTimer",
    "_closeReadable",
    "_closedDeferred",
    "_closedDuringHandshake",
    "_closedSettled",
    "_connected",
    "_drainResolvedWrites",
    "_errorReadable",
    "_errorWritable",
    "_finishWritableClose",
    "_getWritableInvalidStateError",
    "_handleBytesSent",
    "_handleSocketClose",
    "_ignoredTerminal",
    "_initiateClose",
    "_localCloseInitiated",
    "_openedDeferred",
    "_openedSettled",
    "_pendingWriteRequests",
    "_pendingWriteResolveTimer",
    "_readable",
    "_readableController",
    "_rejectClosed",
    "_rejectOpened",
    "_rejectPendingWrites",
    "_resolveClosed",
    "_resolveOpened",
    "_socket",
    "_syncReadableBackpressure",
    "_writable",
    "_writableInvalidStateError",
    "close",
    "closed",
    "opened",
    "url",
  ],
  WebStreamsPolyfill: [""],
  WritableStream: [
    "",
    "[[Symbol.toStringTag]]",
    "_abortAlgorithm",
    "_abortStream",
    "_advanceQueueIfNeeded",
    "_backpressure",
    "_closeAlgorithm",
    "_closeAlgorithmRunning",
    "_closeStream",
    "_controller",
    "_dealWithRejection",
    "_errorIfNeeded",
    "_errorStream",
    "_finishClose",
    "_finishErroring",
    "_hasOperationInFlight",
    "_inFlightCloseRequest",
    "_inFlightWriteRequest",
    "_inFlightWriteSize",
    "_notifyWriterError",
    "_pendingAbortRequest",
    "_queue",
    "_queueTotalSize",
    "_rejectClosedPromiseIfNeeded",
    "_startErroring",
    "_started",
    "_state",
    "_storedError",
    "_strategyHWM",
    "_strategySizeAlgorithm",
    "_updateBackpressure",
    "_writeAlgorithm",
    "_writeChunk",
    "_writeRequests",
    "_writer",
    "_writing",
    "abort",
    "close",
    "getWriter",
    "locked",
  ],
  WritableStreamDefaultController: [
    "",
    "[[Symbol.toStringTag]]",
    "_abortController",
    "_abortReason",
    "_stream",
    "error",
    "signal",
  ],
  WritableStreamDefaultWriter: [
    "",
    "[[Symbol.toStringTag]]",
    "_closedPromise",
    "_closedPromiseRecord",
    "_closedReject",
    "_closedResolve",
    "_ensureClosedPromiseRejected",
    "_ensureReadyPromiseRejected",
    "_readyPromise",
    "_readyPromiseRecord",
    "_readyReject",
    "_readyResolve",
    "_releasedError",
    "_setClosedPromiseRecord",
    "_setReadyPromiseRecord",
    "_stream",
    "abort",
    "close",
    "closed",
    "desiredSize",
    "ready",
    "releaseLock",
    "write",
  ],
  "[[dynamic-table:native-global-name]]": [""],
  __OriginalPromise: [
    "",
    "prototype",
    "prototype.catch",
    "prototype.finally",
    "prototype.then",
    "reject",
  ],
  __dirname: [""],
  __exactAccessibilityChanged: [""],
  __exactAccessibilitySnapshot: [
    "colorScheme",
    "dynamicTypeSize",
    "fontScale",
    "isBoldTextEnabled",
    "isGrayscaleEnabled",
    "isInvertColorsEnabled",
    "isScreenReaderEnabled",
    "prefersHighContrast",
    "prefersReducedMotion",
    "prefersReducedTransparency",
  ],
  __exactAccessibilityState: [
    "",
    "changeTimer",
    "eventListeners",
    "listeners",
    "snapshot",
  ],
  __exactAllowNativesSyntax: [""],
  __exactAndroidCameraMetadata: [
    "backend",
    "moduleId",
    "stateOffset",
    "stateSize",
    "version",
  ],
  __exactAndroidLocation: ["getPermissionStatus", "isLocationServicesEnabled"],
  __exactAndroidStoragePaths: [
    "cacheDir",
    "codeCacheDir",
    "externalFilesDir",
    "filesDir",
    "noBackupFilesDir",
  ],
  __exactAppearanceState: ["colorScheme", "reducedMotion"],
  __exactCompatEval: [""],
  __exactDebugModuleSource: [""],
  __exactDebugModuleSources: ["", "length"],
  __exactEnsureFilesystemModule: [""],
  __exactEntryFileConsumed: [""],
  __exactFinalVersionsDefineOK: [""],
  __exactFinalVersionsError: [""],
  __exactFinalVersionsFixRan: [""],
  __exactFinalVersionsNewProtoOK: [""],
  __exactFinalVersionsObj: [""],
  __exactFinalVersionsOpenssl: [""],
  __exactFinalVersionsOpensslAfter: [""],
  __exactFinalVersionsProtoOK: [""],
  __exactFinalVersionsSame: [""],
  __exactHasDecompressionUnhandledFilter: [""],
  __exactHostNavigator: ["", "[[dynamic-table:host-navigator-properties]]"],
  __exactInstallAsyncIpcListenerPatch: [""],
  __exactInstallProcessIpcBootstrap: [""],
  __exactInstallReadableStreamIteratorCompat: [""],
  __exactIsReadableStream: [""],
  __exactKChannelHandleKey: [""],
  __exactLoadTimings: ["", "installGlobalsEnd", "installGlobalsStart"],
  __exactLocaleChanged: [""],
  __exactLocaleSnapshot: ["tag", "tags", "uses24Hour"],
  __exactLocaleState: ["", "changeTimer", "listeners", "override", "snapshot"],
  __exactMemoryDebug: [
    "",
    "clearModuleDebugSources",
    "formatBytes",
    "samples",
    "snapshot",
    "start",
    "state",
    "stop",
    "summary",
  ],
  __exactMemoryDebugState: [
    "",
    "lastLoggedHeapUsed",
    "nextSampleId",
    "options",
    "options.includeExpensive",
    "options.includeGCStats",
    "options.intervalMs",
    "options.logEvery",
    "options.logOnGrowthBytes",
    "options.maxSamples",
    "sampleCount",
    "samples",
    "timer",
  ],
  __exactNativeWrapState: [
    "",
    "Pipe",
    "TCP",
    "TCPConnectWrap",
    "UV_EINVAL",
    "byFd",
    "pipeConstants",
    "tcpConstants",
  ],
  __exactProcessCompatFixRan: [""],
  __exactProcessCompatFixSawProcess: [""],
  __exactReadableStreamCompatIteratorPatchScheduled: [""],
  __exactReapplyCompatPolyfills: [""],
  __exactRequire: [""],
  __exactRuntime: [
    "",
    "engine",
    "installed",
    "installedAt",
    "platform",
    "version",
  ],
  __exactSignalNamesMap: [""],
  __exactSignalNumbersMap: [""],
  __exactSignalWatchSync: [""],
  __exactStreamWrapReadBytesOrErrorIndex: [""],
  __exactStreamWrapState: [""],
  __exactSyncTrackedIpcListenersAfterDispatch: [""],
  __exactUnhandledRejectionHandler: [""],
  __exactUvEOFValue: [""],
  __exactWebStreamsPolyfillLoaded: [""],
  __exactWindowNotifyMediaChange: [""],
  __exactWindowNotifyResize: [""],
  __filename: [""],
  addEventListener: [""],
  atob: [""],
  badly: [""],
  btoa: [""],
  caches: [
    "",
    "[[Symbol.toStringTag]]",
    "delete",
    "has",
    "keys",
    "match",
    "open",
  ],
  cancelAnimationFrame: [""],
  cancelIdleCallback: [""],
  clearImmediate: [""],
  clearInterval: [""],
  clearTimeout: [""],
  console: ["", "debug", "dir", "error", "info", "log", "trace", "warn"],
  createExternalizableString: [""],
  createExternalizableTwoByteString: [""],
  crypto: [
    "",
    "getRandomValues",
    "randomUUID",
    "subtle",
    "subtle.__exactFullSubtle",
    "subtle.decrypt",
    "subtle.deriveBits",
    "subtle.deriveKey",
    "subtle.digest",
    "subtle.encrypt",
    "subtle.exportKey",
    "subtle.generateKey",
    "subtle.importKey",
    "subtle.sign",
    "subtle.unwrapKey",
    "subtle.verify",
    "subtle.wrapKey",
  ],
  dispatchEvent: [""],
  eval: [""],
  exact: [
    "",
    "callModuleSync",
    "dispatch",
    "dispatchModule",
    "dispatchWithDebugContext",
    "getAbsoluteLayout",
    "getLayout",
    "getLayoutGeneration",
    "getModuleStateOffset",
    "getRootViewId",
    "getStateMirror",
    "hasKernelInspector",
    "hitTest",
    "nodeExists",
    "runtime",
    "runtime.detectEngine",
    "runtime.detectPlatform",
    "runtime.info",
    "runtime.info.engine",
    "runtime.info.platform",
    "runtime.info.version",
    "runtime.isInstalled",
    "runtime.version",
  ],
  externalizeString: [""],
  failed: [""],
  fetch: [""],
  gc: [""],
  global: [""],
  import: [""],
  importModule: [""],
  indexedDB: ["", "cmp", "databases", "deleteDatabase", "open"],
  isOneByteString: [""],
  localStorage: [
    "",
    "[[Symbol.toStringTag]]",
    "clear",
    "getItem",
    "key",
    "length",
    "persistence",
    "removeItem",
    "setItem",
  ],
  log: [""],
  matchMedia: [""],
  measure: [""],
  navigator: [""],
  ok: [""],
  performance: [
    "",
    "clearMarks",
    "clearMeasures",
    "clearResourceTimings",
    "getEntries",
    "getEntriesByName",
    "getEntriesByType",
    "mark",
    "measure",
    "now",
    "setResourceTimingBufferSize",
    "timeOrigin",
    "toJSON",
  ],
  print: [""],
  process: [
    "",
    "[[Symbol.toStringTag]]",
    "[[dynamic-table:channel-handle-key]]",
    "[[dynamic-table:channel-handle-key]].readStart",
    "[[dynamic-table:channel-handle-key]].readStop",
    "[[dynamic-table:exact-channel-handle-key]]",
    "[[dynamic-table:host-process-own-properties]]",
    "[[dynamic-table:host-process-prototype-properties]]",
    "[[dynamic-table:k-channel-handle]]",
    "[[dynamic-table:k-channel-handle]].readStart",
    "[[dynamic-table:k-channel-handle]].readStop",
    "__exactAsyncIpcListenerPatch",
    "__exactLateIpcListenerPatch",
    "__exactProcessIpcBootstrapInstalled",
    "__exactStreamPinned",
    "__exactStreamStabilityPatched",
    "_exactExiting",
    "_getActiveHandles",
    "_getActiveRequests",
    "_kill",
    "_umask",
    "_uncaughtExceptionHandler",
    "_unhandledRejectionHandler",
    "abort",
    "addListener",
    "allowedNodeEnvironmentFlags",
    "arch",
    "argv",
    "argv0",
    "assert",
    "availableMemory",
    "binding",
    "browser",
    "channel",
    "channel.connected",
    "chdir",
    "config",
    "config.target_defaults",
    "config.variables",
    "connected",
    "constrainedMemory",
    "constructor.prototype",
    "cpuUsage",
    "cwd",
    "debugPort",
    "disconnect",
    "domain",
    "emit",
    "emitWarning",
    "env",
    "env.[[dynamic-table:env-obj-properties]]",
    "env.[[dynamic-table:host-process-env-properties]]",
    "eventNames",
    "execArgv",
    "execPath",
    "execve",
    "exit",
    "exit.__exactHostExit",
    "exitCode",
    "features",
    "features.cached_builtins",
    "features.debug",
    "features.inspector",
    "features.ipv6",
    "features.openssl_is_boringssl",
    "features.require_module",
    "features.tls",
    "features.tls_alpn",
    "features.tls_ocsp",
    "features.tls_sni",
    "features.typescript",
    "features.uv",
    "getActiveResourcesInfo",
    "getMaxListeners",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "getuid",
    "hasUncaughtExceptionCaptureCallback",
    "hrtime",
    "hrtime.bigint",
    "kill",
    "listenerCount",
    "listeners",
    "mainModule",
    "memoryUsage",
    "memoryUsage.rss",
    "nextTick",
    "noDeprecation",
    "off",
    "on",
    "once",
    "openStdin",
    "pid",
    "platform",
    "ppid",
    "prependListener",
    "prependOnceListener",
    "rawListeners",
    "release",
    "release.headersUrl",
    "release.lts",
    "release.name",
    "release.sourceUrl",
    "removeAllListeners",
    "removeListener",
    "report",
    "report.compact",
    "report.directory",
    "report.filename",
    "report.getReport",
    "report.reportOnFatalError",
    "report.reportOnSignal",
    "report.reportOnUncaughtException",
    "report.signal",
    "report.writeReport",
    "resourceUsage",
    "send",
    "setMaxListeners",
    "setUncaughtExceptionCaptureCallback",
    "setegid",
    "seteuid",
    "setgid",
    "setuid",
    "stderr",
    "stderr.addListener",
    "stderr.columns",
    "stderr.cork",
    "stderr.destroyed",
    "stderr.emit",
    "stderr.end",
    "stderr.fd",
    "stderr.isTTY",
    "stderr.on",
    "stderr.once",
    "stderr.pipe",
    "stderr.ref",
    "stderr.removeListener",
    "stderr.rows",
    "stderr.uncork",
    "stderr.unref",
    "stderr.writable",
    "stderr.writableEnded",
    "stderr.writableFinished",
    "stderr.writableHighWaterMark",
    "stderr.writableLength",
    "stderr.writableObjectMode",
    "stderr.write",
    "stdin",
    "stdin._decoder",
    "stdin._encoding",
    "stdin._ended",
    "stdin._paused",
    "stdin._pollTimer",
    "stdin.addListener",
    "stdin.cork",
    "stdin.destroy",
    "stdin.destroyed",
    "stdin.emit",
    "stdin.end",
    "stdin.fd",
    "stdin.isTTY",
    "stdin.on",
    "stdin.once",
    "stdin.pause",
    "stdin.pipe",
    "stdin.read",
    "stdin.readable",
    "stdin.readableEnded",
    "stdin.readableFlowing",
    "stdin.readableLength",
    "stdin.readableObjectMode",
    "stdin.ref",
    "stdin.removeListener",
    "stdin.resume",
    "stdin.setEncoding",
    "stdin.uncork",
    "stdin.unref",
    "stdin.writable",
    "stdin.write",
    "stdout",
    "stdout.addListener",
    "stdout.columns",
    "stdout.cork",
    "stdout.destroyed",
    "stdout.emit",
    "stdout.end",
    "stdout.fd",
    "stdout.isTTY",
    "stdout.on",
    "stdout.once",
    "stdout.pipe",
    "stdout.ref",
    "stdout.removeListener",
    "stdout.rows",
    "stdout.uncork",
    "stdout.unref",
    "stdout.writable",
    "stdout.writableEnded",
    "stdout.writableFinished",
    "stdout.writableHighWaterMark",
    "stdout.writableLength",
    "stdout.writableObjectMode",
    "stdout.write",
    "throwDeprecation",
    "title",
    "traceDeprecation",
    "umask",
    "uptime",
    "version",
    "versions",
  ],
  queueMicrotask: [""],
  removeEventListener: [""],
  requestAnimationFrame: [""],
  requestIdleCallback: [""],
  require: ["", "cache", "main", "resolve", "resolve.paths"],
  scheduleOnAppRuntime: [""],
  self: [""],
  sessionStorage: [
    "",
    "[[Symbol.toStringTag]]",
    "clear",
    "getItem",
    "key",
    "length",
    "removeItem",
    "setItem",
  ],
  setImmediate: [""],
  setInterval: [""],
  setTimeout: [""],
  structuredClone: [""],
  window: [""],
  worklet: ["", "clamp", "lerp", "sharedValue"],
});

function reviewedGlobalSurfaceName(globalName, memberName) {
  const exportName =
    memberName === "" ? globalName : `${globalName}.${memberName}`;
  return globalName.startsWith("__") ? exportName : `global:${exportName}`;
}

function buildReviewedGlobalApiNames() {
  const roots = Object.keys(REVIEWED_GLOBAL_API_MEMBER_NAMES);
  if (JSON.stringify(roots) !== JSON.stringify([...roots].sort(utf8Compare))) {
    throw new Error("reviewed global API roots are not canonical UTF-8 order");
  }

  const names = [
    ...[...REVIEWED_NATIVE_OPERATION_NAMES].filter(
      (name) => !REVIEWED_NON_GLOBAL_NATIVE_OPERATION_NAMES.has(name),
    ),
  ];
  for (const [globalName, memberNames] of Object.entries(
    REVIEWED_GLOBAL_API_MEMBER_NAMES,
  )) {
    if (
      memberNames.length === 0 ||
      memberNames.some((memberName) => typeof memberName !== "string") ||
      JSON.stringify(memberNames) !==
        JSON.stringify([...memberNames].sort(utf8Compare)) ||
      new Set(memberNames).size !== memberNames.length
    ) {
      throw new Error(
        `reviewed global API members for ${globalName} are empty, duplicate, or not canonical UTF-8 order`,
      );
    }
    names.push(
      ...memberNames.map((memberName) =>
        reviewedGlobalSurfaceName(globalName, memberName),
      ),
    );
  }
  if (new Set(names).size !== names.length) {
    throw new Error(
      "reviewed global API approvals overlap native-dual and root/member tables",
    );
  }
  return new Set(names);
}

const REVIEWED_GLOBAL_API_NAMES = buildReviewedGlobalApiNames();

function reviewedNameSet(names, label) {
  if (
    names.length === 0 ||
    names.some((name) => typeof name !== "string" || name.length === 0) ||
    JSON.stringify(names) !== JSON.stringify([...names].sort(utf8Compare)) ||
    new Set(names).size !== names.length
  ) {
    throw new Error(
      `${label} is empty, duplicate, or not canonical UTF-8 order`,
    );
  }
  return new Set(names);
}

// Exact semantic approvals for non-builtin inventory families. Discovery remains
// source-derived; exported reviewed-name helpers are joined to the live rows.
const REVIEWED_HOST_ABI_NAMES = reviewedNameSet(
  [
    "ex_android_initialize",
    "ex_hermes_bytecode_version",
    "ex_hermes_callback_backlog",
    "ex_hermes_create",
    "ex_hermes_create_armed",
    "ex_hermes_create_diagnostic",
    "ex_hermes_current_principal_id",
    "ex_hermes_current_runtime_nonce",
    "ex_hermes_debugger_enable",
    "ex_hermes_debugger_eval",
    "ex_hermes_debugger_get_script_source",
    "ex_hermes_debugger_get_scripts",
    "ex_hermes_debugger_next_event",
    "ex_hermes_debugger_pause",
    "ex_hermes_debugger_remove_breakpoint",
    "ex_hermes_debugger_resume",
    "ex_hermes_debugger_set_breakpoint",
    "ex_hermes_destroy",
    "ex_hermes_dispatch_event",
    "ex_hermes_emit_module_event",
    "ex_hermes_emit_module_view_event",
    "ex_hermes_engine_binary_path",
    "ex_hermes_engine_mapped_object",
    "ex_hermes_eval",
    "ex_hermes_free_string",
    "ex_hermes_gc",
    "ex_hermes_get_gc_stats",
    "ex_hermes_get_heap_info",
    "ex_hermes_has_pending_tasks",
    "ex_hermes_next_timer",
    "ex_hermes_notify_callback",
    "ex_hermes_now_ms",
    "ex_hermes_poll",
    "ex_hermes_resolve_host_call",
    "ex_hermes_schedule_watchdog_heartbeat",
    "ex_hermes_set_dispatch_callback",
    "ex_hermes_set_dispatch_with_debug_context_callback",
    "ex_hermes_set_host_call",
    "ex_hermes_set_host_call_async",
    "ex_hermes_set_host_wake_hook",
    "ex_hermes_set_keep_alive_on_async_error",
    "ex_hermes_set_kernel_handle",
    "ex_hermes_set_module_dispatch_callback",
    "ex_hermes_set_module_sync_callback",
    "ex_host_armed_endowments",
    "ex_host_authorize_typed_fs_stack",
    "ex_host_authorize_typed_network_stack",
    "ex_host_authorize_typed_udp_datagram_stack",
    "ex_host_check_capability",
    "ex_host_check_capability_no_follow_final",
    "ex_host_check_capability_stack",
    "ex_host_check_capability_stack_no_follow_final",
    "ex_host_check_handle_mint",
    "ex_host_check_import",
    "ex_host_claim_armed_context",
    "ex_host_claim_diagnostic_context",
    "ex_host_console_flush",
    "ex_host_console_log",
    "ex_host_enter_context",
    "ex_host_env_get",
    "ex_host_evaluate_typed_decision",
    "ex_host_free_buffer",
    "ex_host_free_string",
    "ex_host_fs_access",
    "ex_host_fs_append",
    "ex_host_fs_chmod",
    "ex_host_fs_close",
    "ex_host_fs_copy",
    "ex_host_fs_copy_exclusive",
    "ex_host_fs_fstat",
    "ex_host_fs_last_error",
    "ex_host_fs_lstat",
    "ex_host_fs_mkdir",
    "ex_host_fs_mkdir_recursive_result",
    "ex_host_fs_mkdtemp",
    "ex_host_fs_open",
    "ex_host_fs_pread",
    "ex_host_fs_pwrite",
    "ex_host_fs_read",
    "ex_host_fs_read_file",
    "ex_host_fs_readdir",
    "ex_host_fs_realpath",
    "ex_host_fs_rename",
    "ex_host_fs_rmdir",
    "ex_host_fs_seek",
    "ex_host_fs_stat",
    "ex_host_fs_statfs",
    "ex_host_fs_sync",
    "ex_host_fs_truncate",
    "ex_host_fs_unlink",
    "ex_host_fs_utimes",
    "ex_host_fs_write",
    "ex_host_grant_capability",
    "ex_host_handle_check",
    "ex_host_handle_create",
    "ex_host_handle_revoke",
    "ex_host_handle_scoped",
    "ex_host_has_deputy_classes",
    "ex_host_http_address",
    "ex_host_http_await_writable",
    "ex_host_http_await_writable_owned",
    "ex_host_http_cleanup_runtime",
    "ex_host_http_close",
    "ex_host_http_drain",
    "ex_host_http_has_pending_requests",
    "ex_host_http_has_referenced",
    "ex_host_http_is_referenced",
    "ex_host_http_poll",
    "ex_host_http_read_body",
    "ex_host_http_respond",
    "ex_host_http_respond_abort",
    "ex_host_http_respond_chunk",
    "ex_host_http_respond_chunk_try",
    "ex_host_http_respond_end",
    "ex_host_http_respond_end_try",
    "ex_host_http_respond_json",
    "ex_host_http_respond_stream",
    "ex_host_http_respond_string",
    "ex_host_http_respond_text",
    "ex_host_http_serve",
    "ex_host_http_set_ref",
    "ex_host_http_wait",
    "ex_host_http_wait_owned",
    "ex_host_init",
    "ex_host_install",
    "ex_host_install_armed",
    "ex_host_is_allow_all",
    "ex_host_is_armed",
    "ex_host_legacy_authorization_cacheable",
    "ex_host_legacy_authorization_generation",
    "ex_host_log_event",
    "ex_host_matches_armed_snapshot_digest",
    "ex_host_module_resolve",
    "ex_host_module_resolve_meta",
    "ex_host_permission_request",
    "ex_host_permission_revoke",
    "ex_host_permission_status",
    "ex_host_random_fill",
    "ex_host_register_module_package",
    "ex_host_release_context",
    "ex_host_restore_context",
    "ex_host_sqlite_all",
    "ex_host_sqlite_close",
    "ex_host_sqlite_exec",
    "ex_host_sqlite_expanded_sql",
    "ex_host_sqlite_finalize",
    "ex_host_sqlite_get",
    "ex_host_sqlite_in_transaction",
    "ex_host_sqlite_open",
    "ex_host_sqlite_prepare",
    "ex_host_sqlite_run",
    "ex_host_sqlite_values",
    "ex_host_time_now_ms",
    "ex_host_typed_dynamic_grant",
    "ex_host_typed_dynamic_revoke",
    "ex_host_typed_generations",
    "ex_host_typed_handle_mint",
    "ex_host_typed_handle_revoke",
    "ex_host_version",
    "ex_worklet_bind_shared_values",
    "ex_worklet_create",
    "ex_worklet_destroy",
    "ex_worklet_drain_logs",
    "ex_worklet_drain_scheduled",
    "ex_worklet_generation",
    "ex_worklet_install",
    "ex_worklet_invoke",
    "ex_worklet_set_generation",
    "ex_worklet_set_measure_callback",
    "java:dev.ibex.runtime.IbexNetworking.CameraHostProvider.cameraHostCall",
    "java:dev.ibex.runtime.IbexNetworking.DialogHostProvider.dialog",
    "java:dev.ibex.runtime.IbexNetworking.accessibilityFlags",
    "java:dev.ibex.runtime.IbexNetworking.appState",
    "java:dev.ibex.runtime.IbexNetworking.cameraHostCall",
    "java:dev.ibex.runtime.IbexNetworking.cancelFetch",
    "java:dev.ibex.runtime.IbexNetworking.clipboardReadText",
    "java:dev.ibex.runtime.IbexNetworking.clipboardWriteText",
    "java:dev.ibex.runtime.IbexNetworking.closeWebSocket",
    "java:dev.ibex.runtime.IbexNetworking.connectWebSocket",
    "java:dev.ibex.runtime.IbexNetworking.dialog",
    "java:dev.ibex.runtime.IbexNetworking.dnsQuery",
    "java:dev.ibex.runtime.IbexNetworking.drainPlatformEvents",
    "java:dev.ibex.runtime.IbexNetworking.fetch",
    "java:dev.ibex.runtime.IbexNetworking.getApplicationContext",
    "java:dev.ibex.runtime.IbexNetworking.getCurrentLocation",
    "java:dev.ibex.runtime.IbexNetworking.initialURL",
    "java:dev.ibex.runtime.IbexNetworking.initialize",
    "java:dev.ibex.runtime.IbexNetworking.isLocationServicesEnabled",
    "java:dev.ibex.runtime.IbexNetworking.localeTags",
    "java:dev.ibex.runtime.IbexNetworking.locationPermissionStatus",
    "java:dev.ibex.runtime.IbexNetworking.notifyActivityPaused",
    "java:dev.ibex.runtime.IbexNetworking.notifyActivityResumed",
    "java:dev.ibex.runtime.IbexNetworking.notifyActivityStarted",
    "java:dev.ibex.runtime.IbexNetworking.notifyActivityStopped",
    "java:dev.ibex.runtime.IbexNetworking.notifyDeepLink",
    "java:dev.ibex.runtime.IbexNetworking.notifyNewIntent",
    "java:dev.ibex.runtime.IbexNetworking.pauseWebSocket",
    "java:dev.ibex.runtime.IbexNetworking.platformVersion",
    "java:dev.ibex.runtime.IbexNetworking.postAnimationFrame",
    "java:dev.ibex.runtime.IbexNetworking.resumeWebSocket",
    "java:dev.ibex.runtime.IbexNetworking.screenInfo",
    "java:dev.ibex.runtime.IbexNetworking.sendWebSocket",
    "java:dev.ibex.runtime.IbexNetworking.setCameraHostProvider",
    "java:dev.ibex.runtime.IbexNetworking.setClient",
    "java:dev.ibex.runtime.IbexNetworking.setDialogHostProvider",
    "java:dev.ibex.runtime.IbexNetworking.setWebSocketFlowControlled",
    "java:dev.ibex.runtime.IbexNetworking.storagePaths",
    "java:dev.ibex.runtime.IbexNetworking.uses24HourClock",
    "jni:dev.ibex.runtime.IbexNetworking.nativeAnimationFrame",
    "jni:dev.ibex.runtime.IbexNetworking.nativeFetchDidComplete",
    "jni:dev.ibex.runtime.IbexNetworking.nativePlatformEventAvailable",
    "jni:dev.ibex.runtime.IbexNetworking.nativeWebSocketDidBytesSent",
    "jni:dev.ibex.runtime.IbexNetworking.nativeWebSocketDidClose",
    "jni:dev.ibex.runtime.IbexNetworking.nativeWebSocketDidError",
    "jni:dev.ibex.runtime.IbexNetworking.nativeWebSocketDidMessage",
    "jni:dev.ibex.runtime.IbexNetworking.nativeWebSocketDidOpen",
  ],
  "REVIEWED_HOST_ABI_NAMES",
);

const REVIEWED_INSPECTOR_NATIVE_NAMES = reviewedNameSet(
  [
    "inspector.cdp-http:/json",
    "inspector.cdp-http:/json/list",
    "inspector.cdp-http:/json/version",
    "inspector.cdp-listener",
    "inspector.cdp-request-fallback:json-rpc-error--32601",
    "inspector.cdp-request:Debugger.enable",
    "inspector.cdp-request:Debugger.evaluateOnCallFrame",
    "inspector.cdp-request:Debugger.getScriptSource",
    "inspector.cdp-request:Debugger.pause",
    "inspector.cdp-request:Debugger.removeBreakpoint",
    "inspector.cdp-request:Debugger.resume",
    "inspector.cdp-request:Debugger.setBreakpointByUrl",
    "inspector.cdp-request:Debugger.stepInto",
    "inspector.cdp-request:Debugger.stepOut",
    "inspector.cdp-request:Debugger.stepOver",
    "inspector.cdp-request:Log.enable",
    "inspector.cdp-request:Network.disable",
    "inspector.cdp-request:Network.enable",
    "inspector.cdp-request:Network.getResponseBody",
    "inspector.cdp-request:Page.enable",
    "inspector.cdp-request:Runtime.enable",
    "inspector.cdp-request:Runtime.evaluate",
    "inspector.cdp-request:Runtime.runIfWaitingForDebugger",
    "inspector.debugger-enable",
    "inspector.debugger-eval",
    "inspector.debugger-get-script-source",
    "inspector.debugger-get-scripts",
    "inspector.debugger-next-event",
    "inspector.debugger-pause",
    "inspector.debugger-remove-breakpoint",
    "inspector.debugger-resume",
    "inspector.debugger-set-breakpoint",
  ],
  "REVIEWED_INSPECTOR_NATIVE_NAMES",
);

const REVIEWED_CLI_NAMES = reviewedNameSet(
  [
    "agent",
    "argument-conflict:ibex%20compat:log:json",
    "argument-parser:ibex%20build:file:utf8-string",
    "argument-parser:ibex%20build:outdir:os-path",
    "argument-parser:ibex%20capsec%20audit:args:utf8-string",
    "argument-parser:ibex%20capsec%20audit:file:utf8-string",
    "argument-parser:ibex%20compat:jobs:unsigned-integer-usize",
    "argument-parser:ibex%20compat:module:utf8-string",
    "argument-parser:ibex%20compat:section:utf8-string",
    "argument-parser:ibex%20compat:test:utf8-string",
    "argument-parser:ibex%20compat:timeout:unsigned-integer-u64",
    "argument-parser:ibex%20eval:code:utf8-string",
    "argument-parser:ibex%20policy%20check:entry:os-path",
    "argument-parser:ibex%20policy%20check:mode:utf8-string",
    "argument-parser:ibex%20policy%20check:out:os-path",
    "argument-parser:ibex%20policy%20generate:entry:os-path",
    "argument-parser:ibex%20policy%20generate:mode:utf8-string",
    "argument-parser:ibex%20policy%20generate:out:os-path",
    "argument-parser:ibex%20run:args:utf8-string",
    "argument-parser:ibex%20run:file:utf8-string",
    "argument-parser:ibex%20run:inspect_host:utf8-string",
    "argument-parser:ibex%20run:inspect_port:unsigned-integer-u16",
    "argument-parser:ibex:allow:utf8-string",
    "argument-parser:ibex:args:utf8-string",
    "argument-parser:ibex:capsec_armed_snapshot:os-path",
    "argument-parser:ibex:capsec_arming_identity:os-path",
    "argument-parser:ibex:deny:utf8-string",
    "argument-parser:ibex:eval_code:utf8-string",
    "argument-parser:ibex:file:utf8-string",
    "argument-parser:ibex:inspect_host:utf8-string",
    "argument-parser:ibex:inspect_port:unsigned-integer-u16",
    "argument-parser:ibex:max_http_header_size:unsigned-integer-usize",
    "argument-parser:ibex:policy:os-path",
    "argument-parser:ibex:print_eval:utf8-string",
    "argument-parser:ibex:project_root:os-path",
    "argument-parser:ibex:stack_size:utf8-string",
    "bench",
    "build",
    "capsec",
    "command:ibex",
    "command:ibex%20build",
    "command:ibex%20capsec",
    "command:ibex%20capsec%20audit",
    "command:ibex%20compat",
    "command:ibex%20completions",
    "command:ibex%20debug",
    "command:ibex%20debug%20modules",
    "command:ibex%20eval",
    "command:ibex%20policy",
    "command:ibex%20policy%20check",
    "command:ibex%20policy%20generate",
    "command:ibex%20repl",
    "command:ibex%20run",
    "command:ibex%20self-test",
    "command:ibex%20version",
    "compat",
    "completions",
    "create",
    "debug",
    "doctor",
    "eval",
    "exec",
    "export",
    "facet",
    "init",
    "install",
    "lint",
    "mcp",
    "new",
    "option-name:ibex%20build:outdir:--outdir",
    "option-name:ibex%20compat:all:--all",
    "option-name:ibex%20compat:failed:--failed",
    "option-name:ibex%20compat:jobs:--jobs",
    "option-name:ibex%20compat:jobs:-j",
    "option-name:ibex%20compat:json:--json",
    "option-name:ibex%20compat:log:--log",
    "option-name:ibex%20compat:log_color:--log-color",
    "option-name:ibex%20compat:log_no_skip:--log-no-skip",
    "option-name:ibex%20compat:module:--module",
    "option-name:ibex%20compat:no_retry:--no-retry",
    "option-name:ibex%20compat:quick:--quick",
    "option-name:ibex%20compat:report:--report",
    "option-name:ibex%20compat:section:--section",
    "option-name:ibex%20compat:strict:--strict",
    "option-name:ibex%20compat:test:--test",
    "option-name:ibex%20compat:test:-t",
    "option-name:ibex%20compat:timeout:--timeout",
    "option-name:ibex%20compat:update_expectations:--update-expectations",
    "option-name:ibex%20policy%20check:entry:--entry",
    "option-name:ibex%20policy%20check:mode:--mode",
    "option-name:ibex%20policy%20check:out:--out",
    "option-name:ibex%20policy%20generate:entry:--entry",
    "option-name:ibex%20policy%20generate:mode:--mode",
    "option-name:ibex%20policy%20generate:out:--out",
    "option-name:ibex%20run:inspect:--inspect",
    "option-name:ibex%20run:inspect_host:--inspect-host",
    "option-name:ibex%20run:inspect_open:--inspect-open",
    "option-name:ibex%20run:inspect_pause:--inspect-pause",
    "option-name:ibex%20run:inspect_port:--inspect-port",
    "option-name:ibex%20run:inspect_wait:--inspect-wait",
    "option-name:ibex%20run:keep_alive:--keep-alive",
    "option-name:ibex%20run:watch:--watch",
    "option-name:ibex:allow:--allow",
    "option-name:ibex:allow_all:--allow-all",
    "option-name:ibex:allow_env_endowments:--allow-env-endowments",
    "option-name:ibex:bundle_format:--bundle-format",
    "option-name:ibex:capsec:--capsec",
    "option-name:ibex:capsec_allow_advisory:--allow-advisory-attribution",
    "option-name:ibex:capsec_allow_advisory:--capsec-allow-advisory",
    "option-name:ibex:capsec_armed_snapshot:--capsec-armed-snapshot",
    "option-name:ibex:capsec_arming_identity:--capsec-arming-identity",
    "option-name:ibex:compat:--compat",
    "option-name:ibex:completion_bash:--completion-bash",
    "option-name:ibex:deny:--deny",
    "option-name:ibex:engine:--engine",
    "option-name:ibex:eval_code:--eval",
    "option-name:ibex:eval_code:-e",
    "option-name:ibex:expose_internals:--expose-internals",
    "option-name:ibex:inspect:--inspect",
    "option-name:ibex:inspect_host:--inspect-host",
    "option-name:ibex:inspect_open:--inspect-open",
    "option-name:ibex:inspect_pause:--inspect-pause",
    "option-name:ibex:inspect_port:--inspect-port",
    "option-name:ibex:inspect_wait:--inspect-wait",
    "option-name:ibex:keep_alive:--keep-alive",
    "option-name:ibex:lockdown:--lockdown",
    "option-name:ibex:max_http_header_size:--max-http-header-size",
    "option-name:ibex:policy:--policy",
    "option-name:ibex:print_eval:--print",
    "option-name:ibex:print_eval:-p",
    "option-name:ibex:project_root:--project-root",
    "option-name:ibex:stack_size:--stack-size",
    "option-name:ibex:version:--version",
    "option-name:ibex:version:-V",
    "option-name:ibex:version:-v",
    "option-name:ibex:watch:--watch",
    "option:ibex%20build:outdir",
    "option:ibex%20build:outdir:action:Set",
    "option:ibex%20build:outdir:arity:1:1",
    "option:ibex%20build:outdir:value-name:OUTDIR",
    "option:ibex%20compat:all",
    "option:ibex%20compat:all:action:SetTrue",
    "option:ibex%20compat:all:arity:0:0",
    "option:ibex%20compat:all:default-missing:true",
    "option:ibex%20compat:all:default:false",
    "option:ibex%20compat:all:value-name:ALL",
    "option:ibex%20compat:failed",
    "option:ibex%20compat:failed:action:SetTrue",
    "option:ibex%20compat:failed:arity:0:0",
    "option:ibex%20compat:failed:default-missing:true",
    "option:ibex%20compat:failed:default:false",
    "option:ibex%20compat:failed:value-name:FAILED",
    "option:ibex%20compat:jobs",
    "option:ibex%20compat:jobs:action:Set",
    "option:ibex%20compat:jobs:arity:1:1",
    "option:ibex%20compat:jobs:value-name:N",
    "option:ibex%20compat:json",
    "option:ibex%20compat:json:action:SetTrue",
    "option:ibex%20compat:json:arity:0:0",
    "option:ibex%20compat:json:default-missing:true",
    "option:ibex%20compat:json:default:false",
    "option:ibex%20compat:json:value-name:JSON",
    "option:ibex%20compat:log",
    "option:ibex%20compat:log:action:SetTrue",
    "option:ibex%20compat:log:arity:0:0",
    "option:ibex%20compat:log:default-missing:true",
    "option:ibex%20compat:log:default:false",
    "option:ibex%20compat:log:value-name:LOG",
    "option:ibex%20compat:log_color",
    "option:ibex%20compat:log_color:action:SetTrue",
    "option:ibex%20compat:log_color:arity:0:0",
    "option:ibex%20compat:log_color:default-missing:true",
    "option:ibex%20compat:log_color:default:false",
    "option:ibex%20compat:log_color:value-name:LOG_COLOR",
    "option:ibex%20compat:log_no_skip",
    "option:ibex%20compat:log_no_skip:action:SetTrue",
    "option:ibex%20compat:log_no_skip:arity:0:0",
    "option:ibex%20compat:log_no_skip:default-missing:true",
    "option:ibex%20compat:log_no_skip:default:false",
    "option:ibex%20compat:log_no_skip:value-name:LOG_NO_SKIP",
    "option:ibex%20compat:module",
    "option:ibex%20compat:module:action:Set",
    "option:ibex%20compat:module:arity:1:1",
    "option:ibex%20compat:module:value-name:MODULE",
    "option:ibex%20compat:no_retry",
    "option:ibex%20compat:no_retry:action:SetTrue",
    "option:ibex%20compat:no_retry:arity:0:0",
    "option:ibex%20compat:no_retry:default-missing:true",
    "option:ibex%20compat:no_retry:default:false",
    "option:ibex%20compat:no_retry:value-name:NO_RETRY",
    "option:ibex%20compat:quick",
    "option:ibex%20compat:quick:action:SetTrue",
    "option:ibex%20compat:quick:arity:0:0",
    "option:ibex%20compat:quick:default-missing:true",
    "option:ibex%20compat:quick:default:false",
    "option:ibex%20compat:quick:value-name:QUICK",
    "option:ibex%20compat:report",
    "option:ibex%20compat:report:action:SetTrue",
    "option:ibex%20compat:report:arity:0:0",
    "option:ibex%20compat:report:default-missing:true",
    "option:ibex%20compat:report:default:false",
    "option:ibex%20compat:report:value-name:REPORT",
    "option:ibex%20compat:section",
    "option:ibex%20compat:section:action:Set",
    "option:ibex%20compat:section:arity:1:1",
    "option:ibex%20compat:section:value-name:SECTION",
    "option:ibex%20compat:strict",
    "option:ibex%20compat:strict:action:SetTrue",
    "option:ibex%20compat:strict:arity:0:0",
    "option:ibex%20compat:strict:default-missing:true",
    "option:ibex%20compat:strict:default:false",
    "option:ibex%20compat:strict:value-name:STRICT",
    "option:ibex%20compat:test",
    "option:ibex%20compat:test:action:Append",
    "option:ibex%20compat:test:arity:1:1",
    "option:ibex%20compat:test:value-name:FILTER",
    "option:ibex%20compat:timeout",
    "option:ibex%20compat:timeout:action:Set",
    "option:ibex%20compat:timeout:arity:1:1",
    "option:ibex%20compat:timeout:value-name:MS",
    "option:ibex%20compat:update_expectations",
    "option:ibex%20compat:update_expectations:action:SetTrue",
    "option:ibex%20compat:update_expectations:arity:0:0",
    "option:ibex%20compat:update_expectations:default-missing:true",
    "option:ibex%20compat:update_expectations:default:false",
    "option:ibex%20compat:update_expectations:value-name:UPDATE_EXPECTATIONS",
    "option:ibex%20policy%20check:entry",
    "option:ibex%20policy%20check:entry:action:Set",
    "option:ibex%20policy%20check:entry:arity:1:1",
    "option:ibex%20policy%20check:entry:value-name:ENTRY",
    "option:ibex%20policy%20check:mode",
    "option:ibex%20policy%20check:mode:action:Set",
    "option:ibex%20policy%20check:mode:arity:1:1",
    "option:ibex%20policy%20check:mode:value-name:MODE",
    "option:ibex%20policy%20check:out",
    "option:ibex%20policy%20check:out:action:Set",
    "option:ibex%20policy%20check:out:arity:1:1",
    "option:ibex%20policy%20check:out:value-name:OUT",
    "option:ibex%20policy%20generate:entry",
    "option:ibex%20policy%20generate:entry:action:Set",
    "option:ibex%20policy%20generate:entry:arity:1:1",
    "option:ibex%20policy%20generate:entry:value-name:ENTRY",
    "option:ibex%20policy%20generate:mode",
    "option:ibex%20policy%20generate:mode:action:Set",
    "option:ibex%20policy%20generate:mode:arity:1:1",
    "option:ibex%20policy%20generate:mode:value-name:MODE",
    "option:ibex%20policy%20generate:out",
    "option:ibex%20policy%20generate:out:action:Set",
    "option:ibex%20policy%20generate:out:arity:1:1",
    "option:ibex%20policy%20generate:out:value-name:OUT",
    "option:ibex%20run:inspect",
    "option:ibex%20run:inspect:action:SetTrue",
    "option:ibex%20run:inspect:arity:0:0",
    "option:ibex%20run:inspect:default-missing:true",
    "option:ibex%20run:inspect:default:false",
    "option:ibex%20run:inspect:value-name:INSPECT",
    "option:ibex%20run:inspect_host",
    "option:ibex%20run:inspect_host:action:Set",
    "option:ibex%20run:inspect_host:arity:1:1",
    "option:ibex%20run:inspect_host:value-name:INSPECT_HOST",
    "option:ibex%20run:inspect_open",
    "option:ibex%20run:inspect_open:action:SetTrue",
    "option:ibex%20run:inspect_open:arity:0:0",
    "option:ibex%20run:inspect_open:default-missing:true",
    "option:ibex%20run:inspect_open:default:false",
    "option:ibex%20run:inspect_open:value-name:INSPECT_OPEN",
    "option:ibex%20run:inspect_pause",
    "option:ibex%20run:inspect_pause:action:SetTrue",
    "option:ibex%20run:inspect_pause:arity:0:0",
    "option:ibex%20run:inspect_pause:default-missing:true",
    "option:ibex%20run:inspect_pause:default:false",
    "option:ibex%20run:inspect_pause:value-name:INSPECT_PAUSE",
    "option:ibex%20run:inspect_port",
    "option:ibex%20run:inspect_port:action:Set",
    "option:ibex%20run:inspect_port:arity:1:1",
    "option:ibex%20run:inspect_port:value-name:INSPECT_PORT",
    "option:ibex%20run:inspect_wait",
    "option:ibex%20run:inspect_wait:action:SetTrue",
    "option:ibex%20run:inspect_wait:arity:0:0",
    "option:ibex%20run:inspect_wait:default-missing:true",
    "option:ibex%20run:inspect_wait:default:false",
    "option:ibex%20run:inspect_wait:value-name:INSPECT_WAIT",
    "option:ibex%20run:keep_alive",
    "option:ibex%20run:keep_alive:action:SetTrue",
    "option:ibex%20run:keep_alive:arity:0:0",
    "option:ibex%20run:keep_alive:default-missing:true",
    "option:ibex%20run:keep_alive:default:false",
    "option:ibex%20run:keep_alive:value-name:KEEP_ALIVE",
    "option:ibex%20run:watch",
    "option:ibex%20run:watch:action:SetTrue",
    "option:ibex%20run:watch:arity:0:0",
    "option:ibex%20run:watch:default-missing:true",
    "option:ibex%20run:watch:default:false",
    "option:ibex%20run:watch:value-name:WATCH",
    "option:ibex:allow",
    "option:ibex:allow:action:Append",
    "option:ibex:allow:arity:1:1",
    "option:ibex:allow:value-name:CAPABILITY",
    "option:ibex:allow_all",
    "option:ibex:allow_all:action:SetTrue",
    "option:ibex:allow_all:arity:0:0",
    "option:ibex:allow_all:default-missing:true",
    "option:ibex:allow_all:default:false",
    "option:ibex:allow_all:value-name:ALLOW_ALL",
    "option:ibex:allow_env_endowments",
    "option:ibex:allow_env_endowments:action:SetTrue",
    "option:ibex:allow_env_endowments:arity:0:0",
    "option:ibex:allow_env_endowments:default-missing:true",
    "option:ibex:allow_env_endowments:default:false",
    "option:ibex:allow_env_endowments:value-name:ALLOW_ENV_ENDOWMENTS",
    "option:ibex:bundle_format",
    "option:ibex:bundle_format:action:Set",
    "option:ibex:bundle_format:arity:1:1",
    "option:ibex:bundle_format:default:esm",
    "option:ibex:bundle_format:enum:cjs",
    "option:ibex:bundle_format:enum:esm",
    "option:ibex:bundle_format:value-name:BUNDLE_FORMAT",
    "option:ibex:capsec",
    "option:ibex:capsec:action:Set",
    "option:ibex:capsec:arity:1:1",
    "option:ibex:capsec:default:auto",
    "option:ibex:capsec:enum-alias:enforce:capability",
    "option:ibex:capsec:enum-alias:enforce:strict",
    "option:ibex:capsec:enum:audit",
    "option:ibex:capsec:enum:auto",
    "option:ibex:capsec:enum:enforce",
    "option:ibex:capsec:enum:permissive",
    "option:ibex:capsec:value-name:CAPSEC",
    "option:ibex:capsec_allow_advisory",
    "option:ibex:capsec_allow_advisory:action:SetTrue",
    "option:ibex:capsec_allow_advisory:arity:0:0",
    "option:ibex:capsec_allow_advisory:default-missing:true",
    "option:ibex:capsec_allow_advisory:default:false",
    "option:ibex:capsec_allow_advisory:value-name:CAPSEC_ALLOW_ADVISORY",
    "option:ibex:capsec_armed_snapshot",
    "option:ibex:capsec_armed_snapshot:action:Set",
    "option:ibex:capsec_armed_snapshot:arity:1:1",
    "option:ibex:capsec_armed_snapshot:value-name:FILE",
    "option:ibex:capsec_arming_identity",
    "option:ibex:capsec_arming_identity:action:Set",
    "option:ibex:capsec_arming_identity:arity:1:1",
    "option:ibex:capsec_arming_identity:value-name:FILE",
    "option:ibex:compat",
    "option:ibex:compat:action:Set",
    "option:ibex:compat:arity:1:1",
    "option:ibex:compat:enum:bun",
    "option:ibex:compat:value-name:MODE",
    "option:ibex:completion_bash",
    "option:ibex:completion_bash:action:SetTrue",
    "option:ibex:completion_bash:arity:0:0",
    "option:ibex:completion_bash:default-missing:true",
    "option:ibex:completion_bash:default:false",
    "option:ibex:completion_bash:value-name:COMPLETION_BASH",
    "option:ibex:deny",
    "option:ibex:deny:action:Append",
    "option:ibex:deny:arity:1:1",
    "option:ibex:deny:value-name:CAPABILITY",
    "option:ibex:engine",
    "option:ibex:engine:action:Set",
    "option:ibex:engine:arity:1:1",
    "option:ibex:engine:default:hermes",
    "option:ibex:engine:enum:hermes",
    "option:ibex:engine:value-name:ENGINE",
    "option:ibex:eval_code",
    "option:ibex:eval_code:action:Set",
    "option:ibex:eval_code:arity:1:1",
    "option:ibex:eval_code:value-name:CODE",
    "option:ibex:expose_internals",
    "option:ibex:expose_internals:action:SetTrue",
    "option:ibex:expose_internals:arity:0:0",
    "option:ibex:expose_internals:default-missing:true",
    "option:ibex:expose_internals:default:false",
    "option:ibex:expose_internals:value-name:EXPOSE_INTERNALS",
    "option:ibex:inspect",
    "option:ibex:inspect:action:SetTrue",
    "option:ibex:inspect:arity:0:0",
    "option:ibex:inspect:default-missing:true",
    "option:ibex:inspect:default:false",
    "option:ibex:inspect:value-name:INSPECT",
    "option:ibex:inspect_host",
    "option:ibex:inspect_host:action:Set",
    "option:ibex:inspect_host:arity:1:1",
    "option:ibex:inspect_host:value-name:INSPECT_HOST",
    "option:ibex:inspect_open",
    "option:ibex:inspect_open:action:SetTrue",
    "option:ibex:inspect_open:arity:0:0",
    "option:ibex:inspect_open:default-missing:true",
    "option:ibex:inspect_open:default:false",
    "option:ibex:inspect_open:value-name:INSPECT_OPEN",
    "option:ibex:inspect_pause",
    "option:ibex:inspect_pause:action:SetTrue",
    "option:ibex:inspect_pause:arity:0:0",
    "option:ibex:inspect_pause:default-missing:true",
    "option:ibex:inspect_pause:default:false",
    "option:ibex:inspect_pause:value-name:INSPECT_PAUSE",
    "option:ibex:inspect_port",
    "option:ibex:inspect_port:action:Set",
    "option:ibex:inspect_port:arity:1:1",
    "option:ibex:inspect_port:value-name:INSPECT_PORT",
    "option:ibex:inspect_wait",
    "option:ibex:inspect_wait:action:SetTrue",
    "option:ibex:inspect_wait:arity:0:0",
    "option:ibex:inspect_wait:default-missing:true",
    "option:ibex:inspect_wait:default:false",
    "option:ibex:inspect_wait:value-name:INSPECT_WAIT",
    "option:ibex:keep_alive",
    "option:ibex:keep_alive:action:SetTrue",
    "option:ibex:keep_alive:arity:0:0",
    "option:ibex:keep_alive:default-missing:true",
    "option:ibex:keep_alive:default:false",
    "option:ibex:keep_alive:value-name:KEEP_ALIVE",
    "option:ibex:lockdown",
    "option:ibex:lockdown:action:SetTrue",
    "option:ibex:lockdown:arity:0:0",
    "option:ibex:lockdown:default-missing:true",
    "option:ibex:lockdown:default:false",
    "option:ibex:lockdown:value-name:LOCKDOWN",
    "option:ibex:max_http_header_size",
    "option:ibex:max_http_header_size:action:Set",
    "option:ibex:max_http_header_size:arity:1:1",
    "option:ibex:max_http_header_size:value-name:BYTES",
    "option:ibex:policy",
    "option:ibex:policy:action:Set",
    "option:ibex:policy:arity:1:1",
    "option:ibex:policy:value-name:POLICY",
    "option:ibex:print_eval",
    "option:ibex:print_eval:action:Set",
    "option:ibex:print_eval:arity:1:1",
    "option:ibex:print_eval:value-name:CODE",
    "option:ibex:project_root",
    "option:ibex:project_root:action:Set",
    "option:ibex:project_root:arity:1:1",
    "option:ibex:project_root:value-name:DIR",
    "option:ibex:stack_size",
    "option:ibex:stack_size:action:Set",
    "option:ibex:stack_size:arity:1:1",
    "option:ibex:stack_size:value-name:SIZE",
    "option:ibex:version",
    "option:ibex:version:action:SetTrue",
    "option:ibex:version:arity:0:0",
    "option:ibex:version:default-missing:true",
    "option:ibex:version:default:false",
    "option:ibex:version:value-name:VERSION",
    "option:ibex:watch",
    "option:ibex:watch:action:SetTrue",
    "option:ibex:watch:arity:0:0",
    "option:ibex:watch:default-missing:true",
    "option:ibex:watch:default:false",
    "option:ibex:watch:value-name:WATCH",
    "policy",
    "positional:ibex%20build:file",
    "positional:ibex%20build:file:action:Set",
    "positional:ibex%20build:file:arity:1:1",
    "positional:ibex%20build:file:value-name:FILE",
    "positional:ibex%20capsec%20audit:args",
    "positional:ibex%20capsec%20audit:args:action:Append",
    "positional:ibex%20capsec%20audit:args:arity:0:unbounded",
    "positional:ibex%20capsec%20audit:args:value-name:ARGS",
    "positional:ibex%20capsec%20audit:file",
    "positional:ibex%20capsec%20audit:file:action:Set",
    "positional:ibex%20capsec%20audit:file:arity:1:1",
    "positional:ibex%20capsec%20audit:file:value-name:FILE",
    "positional:ibex%20completions:shell",
    "positional:ibex%20completions:shell:action:Set",
    "positional:ibex%20completions:shell:arity:1:1",
    "positional:ibex%20completions:shell:enum:bash",
    "positional:ibex%20completions:shell:enum:elvish",
    "positional:ibex%20completions:shell:enum:fish",
    "positional:ibex%20completions:shell:enum:powershell",
    "positional:ibex%20completions:shell:enum:zsh",
    "positional:ibex%20completions:shell:value-name:SHELL",
    "positional:ibex%20eval:code",
    "positional:ibex%20eval:code:action:Set",
    "positional:ibex%20eval:code:arity:1:1",
    "positional:ibex%20eval:code:value-name:CODE",
    "positional:ibex%20run:args",
    "positional:ibex%20run:args:action:Append",
    "positional:ibex%20run:args:arity:0:unbounded",
    "positional:ibex%20run:args:value-name:ARGS",
    "positional:ibex%20run:file",
    "positional:ibex%20run:file:action:Set",
    "positional:ibex%20run:file:arity:1:1",
    "positional:ibex%20run:file:value-name:FILE",
    "positional:ibex:args",
    "positional:ibex:args:action:Append",
    "positional:ibex:args:arity:0:unbounded",
    "positional:ibex:args:value-name:ARGS",
    "positional:ibex:file",
    "positional:ibex:file:action:Set",
    "positional:ibex:file:arity:1:1",
    "positional:ibex:file:value-name:FILE",
    "repl",
    "run",
    "self-test",
    "start",
    "test",
    "verify",
    "version",
  ],
  "REVIEWED_CLI_NAMES",
);

const REVIEWED_LOADER_NAMES = reviewedNameSet(
  [
    "builtin-module",
    "commonjs-module",
    "dynamic-import",
    "empty-specifier-rejection",
    "entry:dynamic-import",
    "entry:exact-require",
    "entry:global-import",
    "entry:global-require",
    "entry:import-module",
    "entry:load",
    "entry:load-internal",
    "entry:local-require",
    "entry:module-dynamic-import",
    "entry:require-resolve",
    "entry:resolve-path",
    "esm-module",
    "external-calls:cache",
    "external-calls:load",
    "external-calls:resolution",
    "external-calls:subprocess",
    "external-calls:transform",
    "function:javascript:__exactResolvePath",
    "function:javascript:_createNodeTestModule",
    "function:javascript:_getStreamBuiltins",
    "function:javascript:_loadNamedStreamInternal",
    "function:javascript:_resolveAbortError",
    "function:javascript:builtinCacheKeyFor",
    "function:javascript:checkImportGate",
    "function:javascript:compileFallbackSource",
    "function:javascript:compileModuleBody",
    "function:javascript:createEventTargetModule",
    "function:javascript:getDebugModuleSourceLimit",
    "function:javascript:grantCapabilities",
    "function:javascript:idToModuleId",
    "function:javascript:importImpl",
    "function:javascript:isCompleteStaticImportStatement",
    "function:javascript:isSameModule",
    "function:javascript:load",
    "function:javascript:loadInternal",
    "function:javascript:looksLikeCompleteModuleStatement",
    "function:javascript:looksLikeModuleSyntax",
    "function:javascript:makeWindowsCryptoModule",
    "function:javascript:moduleDynamicImport",
    "function:javascript:packagePrincipalFor",
    "function:javascript:pushDebugModuleSource",
    "function:javascript:resolveModulePath",
    "function:javascript:restoreModuleId",
    "function:javascript:runFallbackModule",
    "function:javascript:splitInlineModuleStatements",
    "function:javascript:stripModuleStatementComments",
    "function:javascript:stripViteImportQuery",
    "function:javascript:transformDynamicImport",
    "function:javascript:transformImportMeta",
    "function:javascript:wrapAsyncModule",
    "function:rust:build_builtin_registry",
    "function:rust:builtin_module_debug_entries",
    "function:rust:is_builtin_specifier",
    "function:rust:load_module_source",
    "function:rust:load_source",
    "function:rust:load_source_bytes",
    "function:rust:module_cache_key",
    "function:rust:module_kind_from_path",
    "function:rust:normalize_import_target",
    "function:rust:package_name_and_root_in_node_modules",
    "function:rust:package_root_in_node_modules",
    "function:rust:pick_package_import_path",
    "function:rust:resolve",
    "function:rust:resolve_meta",
    "function:rust:resolve_meta_from_bound_package",
    "function:rust:resolve_package_import",
    "function:rust:resolve_package_import_target",
    "function:rust:resolve_transpile_cache_dir",
    "function:rust:resolve_with_oxc",
    "function:rust:resolve_with_oxc_at",
    "function:rust:transpile_module",
    "import-needs",
    "import-policy-bare",
    "import-policy-resolved-path",
    "install",
    "internal-module",
    "internal-route:_stream_duplex",
    "internal-route:_stream_passthrough",
    "internal-route:_stream_readable",
    "internal-route:_stream_transform",
    "internal-route:_stream_writable",
    "internal-route:_tls_common",
    "internal-route:assert/strict",
    "internal-route:bun:internal-for-testing",
    "internal-route:dns/promises",
    "internal-route:internal/assert/myers_diff",
    "internal-route:internal/async_hooks",
    "internal-route:internal/child_process",
    "internal-route:internal/crypto/util",
    "internal-route:internal/crypto/x509",
    "internal-route:internal/errors",
    "internal-route:internal/event_target",
    "internal-route:internal/fs/utils",
    "internal-route:internal/http",
    "internal-route:internal/js_stream_socket",
    "internal-route:internal/linkedlist",
    "internal-route:internal/net",
    "internal-route:internal/options",
    "internal-route:internal/readline/utils",
    "internal-route:internal/streams/add-abort-signal",
    "internal-route:internal/streams/compose",
    "internal-route:internal/streams/destroy",
    "internal-route:internal/streams/duplex",
    "internal-route:internal/streams/end-of-stream",
    "internal-route:internal/streams/from",
    "internal-route:internal/streams/legacy",
    "internal-route:internal/streams/operators",
    "internal-route:internal/streams/passthrough",
    "internal-route:internal/streams/pipeline",
    "internal-route:internal/streams/readable",
    "internal-route:internal/streams/state",
    "internal-route:internal/streams/transform",
    "internal-route:internal/streams/utils",
    "internal-route:internal/streams/writable",
    "internal-route:internal/test/binding",
    "internal-route:internal/timers",
    "internal-route:internal/url",
    "internal-route:internal/util",
    "internal-route:internal/util/debuglog",
    "internal-route:internal/util/inspect",
    "internal-route:readline/promises",
    "internal-route:stream/consumers",
    "internal-route:stream/promises",
    "internal-route:test",
    "json-module",
    "kind:builtin",
    "kind:commonjs",
    "kind:esm",
    "kind:json",
    "kind:native-addon",
    "kind:wasm",
    "lazy-installer:__exactEnsureChildProcess:child_process",
    "lazy-installer:__exactEnsureChildProcess:node:child_process",
    "lazy-installer:__exactEnsureDns:dns",
    "lazy-installer:__exactEnsureDns:dns/promises",
    "lazy-installer:__exactEnsureDns:node:dns",
    "lazy-installer:__exactEnsureDns:node:dns/promises",
    "lazy-installer:__exactEnsureFs:fs",
    "lazy-installer:__exactEnsureFs:fs/promises",
    "lazy-installer:__exactEnsureFs:node:fs",
    "lazy-installer:__exactEnsureFs:node:fs/promises",
    "lazy-installer:__exactEnsureFs:node:path",
    "lazy-installer:__exactEnsureFs:node:path/posix",
    "lazy-installer:__exactEnsureFs:node:path/win32",
    "lazy-installer:__exactEnsureFs:path",
    "lazy-installer:__exactEnsureFs:path/posix",
    "lazy-installer:__exactEnsureFs:path/win32",
    "lazy-installer:__exactEnsureHttp:http",
    "lazy-installer:__exactEnsureHttp:http2",
    "lazy-installer:__exactEnsureHttp:https",
    "lazy-installer:__exactEnsureHttp:node:http",
    "lazy-installer:__exactEnsureHttp:node:http2",
    "lazy-installer:__exactEnsureHttp:node:https",
    "lazy-installer:__exactEnsureNet:dgram",
    "lazy-installer:__exactEnsureNet:net",
    "lazy-installer:__exactEnsureNet:node:dgram",
    "lazy-installer:__exactEnsureNet:node:net",
    "lazy-installer:__exactEnsureNet:node:tls",
    "lazy-installer:__exactEnsureNet:tls",
    "lazy-installer:__exactEnsureSqlite:better-sqlite3",
    "lazy-installer:__exactEnsureSqlite:bun:sqlite",
    "lazy-installer:__exactEnsureSqlite:exact:sqlite",
    "lazy-installer:__exactEnsureSqlite:node:sqlite",
    "lazy-installer:__exactEnsureSqlite:sqlite",
    "lazy-installer:__exactEnsureStreamEnhance:node:stream",
    "lazy-installer:__exactEnsureStreamEnhance:node:stream/web",
    "lazy-installer:__exactEnsureStreamEnhance:stream",
    "lazy-installer:__exactEnsureStreamEnhance:stream/web",
    "lazy-installer:__exactEnsureWebCrypto:crypto",
    "lazy-installer:__exactEnsureWebCrypto:node:crypto",
    "native-addon-module",
    "native-resolve",
    "operation:cache:canonicalize",
    "operation:cache:command-new",
    "operation:cache:create_dir_all",
    "operation:cache:env-temp_dir",
    "operation:cache:env-var",
    "operation:cache:metadata",
    "operation:cache:new",
    "operation:cache:process-id",
    "operation:cache:read",
    "operation:cache:read_dir",
    "operation:cache:read_to_string",
    "operation:cache:remove_dir_all",
    "operation:cache:remove_file",
    "operation:cache:rename",
    "operation:cache:status",
    "operation:cache:write",
    "operation:load:canonicalize",
    "operation:load:command-new",
    "operation:load:create_dir_all",
    "operation:load:env-temp_dir",
    "operation:load:env-var",
    "operation:load:metadata",
    "operation:load:new",
    "operation:load:process-id",
    "operation:load:read",
    "operation:load:read_dir",
    "operation:load:read_to_string",
    "operation:load:remove_dir_all",
    "operation:load:remove_file",
    "operation:load:rename",
    "operation:load:status",
    "operation:load:write",
    "operation:resolution:canonicalize",
    "operation:resolution:command-new",
    "operation:resolution:create_dir_all",
    "operation:resolution:env-current_dir",
    "operation:resolution:env-temp_dir",
    "operation:resolution:env-var",
    "operation:resolution:metadata",
    "operation:resolution:new",
    "operation:resolution:process-id",
    "operation:resolution:read",
    "operation:resolution:read_dir",
    "operation:resolution:read_to_string",
    "operation:resolution:remove_dir_all",
    "operation:resolution:remove_file",
    "operation:resolution:rename",
    "operation:resolution:status",
    "operation:resolution:write",
    "operation:subprocess:command-new",
    "operation:subprocess:status",
    "operation:transform:canonicalize",
    "operation:transform:command-new",
    "operation:transform:create_dir_all",
    "operation:transform:env-temp_dir",
    "operation:transform:env-var",
    "operation:transform:metadata",
    "operation:transform:new",
    "operation:transform:process-id",
    "operation:transform:read",
    "operation:transform:read_dir",
    "operation:transform:read_to_string",
    "operation:transform:remove_dir_all",
    "operation:transform:remove_file",
    "operation:transform:rename",
    "operation:transform:status",
    "operation:transform:write",
    "oxc-on-disk-resolution",
    "package-compile",
    "package-principal",
    "private-package-import",
    "require-resolve",
    "route:cache:rust:cache_tag",
    "route:cache:rust:compute_transpile_tooling_hash",
    "route:cache:rust:directory_size",
    "route:cache:rust:enforce_transpile_cache_quota",
    "route:cache:rust:ensure_transpile_cache_dir",
    "route:cache:rust:find_js_runner",
    "route:cache:rust:format_oxc_errors",
    "route:cache:rust:from_value",
    "route:cache:rust:module_cache_key",
    "route:cache:rust:output_has_esm_module_syntax",
    "route:cache:rust:oxc_target",
    "route:cache:rust:program_has_top_level_await",
    "route:cache:rust:prune_transpile_cache_to_limit",
    "route:cache:rust:publish_transpile_artifact",
    "route:cache:rust:read_transpile_cache",
    "route:cache:rust:resolve_transpile_cache_dir",
    "route:cache:rust:run_transpile_command",
    "route:cache:rust:run_transpile_override",
    "route:cache:rust:run_transpile_subprocess",
    "route:cache:rust:selected_engine_cache_tag",
    "route:cache:rust:selected_transform_engine",
    "route:cache:rust:sha256_hex",
    "route:cache:rust:touch_transpile_artifact",
    "route:cache:rust:transpile_cache_dir",
    "route:cache:rust:transpile_cache_is_valid",
    "route:cache:rust:transpile_override_identity",
    "route:cache:rust:transpile_script_path",
    "route:cache:rust:transpile_source_to_cjs",
    "route:cache:rust:transpile_to_cjs",
    "route:cache:rust:transpile_tooling_hash",
    "route:cache:rust:transpile_with_oxc",
    "route:cache:rust:transpile_with_swc",
    "route:cache:rust:unique_staged_transpile_input",
    "route:cache:rust:unique_tmp_path",
    "route:cache:rust:wait_for_transpile_test_barrier",
    "route:load:rust:cache_tag",
    "route:load:rust:compute_transpile_tooling_hash",
    "route:load:rust:contains_using_keyword",
    "route:load:rust:directory_size",
    "route:load:rust:enforce_transpile_cache_quota",
    "route:load:rust:ensure_transpile_cache_dir",
    "route:load:rust:find_js_runner",
    "route:load:rust:format_oxc_errors",
    "route:load:rust:from_value",
    "route:load:rust:load_module_source",
    "route:load:rust:load_source",
    "route:load:rust:module_cache_key",
    "route:load:rust:needs_js_downlevel",
    "route:load:rust:needs_transpile",
    "route:load:rust:output_has_esm_module_syntax",
    "route:load:rust:oxc_target",
    "route:load:rust:program_has_top_level_await",
    "route:load:rust:prune_transpile_cache_to_limit",
    "route:load:rust:publish_transpile_artifact",
    "route:load:rust:read_transpile_cache",
    "route:load:rust:resolve_transpile_cache_dir",
    "route:load:rust:run_transpile_command",
    "route:load:rust:run_transpile_override",
    "route:load:rust:run_transpile_subprocess",
    "route:load:rust:scan_balanced_region",
    "route:load:rust:scan_block_scoped_loop_closures",
    "route:load:rust:selected_engine_cache_tag",
    "route:load:rust:selected_transform_engine",
    "route:load:rust:sha256_hex",
    "route:load:rust:skip_ws_and_comments",
    "route:load:rust:source_needs_async_downlevel",
    "route:load:rust:source_needs_downlevel",
    "route:load:rust:source_needs_for_of_scoping_fix",
    "route:load:rust:source_needs_loop_scope_downlevel",
    "route:load:rust:touch_transpile_artifact",
    "route:load:rust:transpile_cache_dir",
    "route:load:rust:transpile_cache_is_valid",
    "route:load:rust:transpile_module",
    "route:load:rust:transpile_override_identity",
    "route:load:rust:transpile_script_path",
    "route:load:rust:transpile_source_to_cjs",
    "route:load:rust:transpile_target_for_source",
    "route:load:rust:transpile_to_cjs",
    "route:load:rust:transpile_tooling_hash",
    "route:load:rust:transpile_with_oxc",
    "route:load:rust:transpile_with_swc",
    "route:load:rust:unique_staged_transpile_input",
    "route:load:rust:unique_tmp_path",
    "route:load:rust:wait_for_transpile_test_barrier",
    "route:resolution:rust:cache_tag",
    "route:resolution:rust:compute_transpile_tooling_hash",
    "route:resolution:rust:contains_using_keyword",
    "route:resolution:rust:directory_size",
    "route:resolution:rust:enforce_transpile_cache_quota",
    "route:resolution:rust:ensure_transpile_cache_dir",
    "route:resolution:rust:find_js_runner",
    "route:resolution:rust:find_package_root",
    "route:resolution:rust:format_oxc_errors",
    "route:resolution:rust:from_value",
    "route:resolution:rust:load_module_source",
    "route:resolution:rust:load_source",
    "route:resolution:rust:module_cache_key",
    "route:resolution:rust:module_kind_from_path",
    "route:resolution:rust:needs_js_downlevel",
    "route:resolution:rust:needs_transpile",
    "route:resolution:rust:normalize_import_target",
    "route:resolution:rust:output_has_esm_module_syntax",
    "route:resolution:rust:oxc_target",
    "route:resolution:rust:package_name_and_root_in_node_modules",
    "route:resolution:rust:package_name_from_bare_specifier",
    "route:resolution:rust:package_root_in_node_modules",
    "route:resolution:rust:package_version_for",
    "route:resolution:rust:pick_package_import_path",
    "route:resolution:rust:program_has_top_level_await",
    "route:resolution:rust:prune_transpile_cache_to_limit",
    "route:resolution:rust:publish_transpile_artifact",
    "route:resolution:rust:read_package_manifest",
    "route:resolution:rust:read_transpile_cache",
    "route:resolution:rust:resolve",
    "route:resolution:rust:resolve_meta",
    "route:resolution:rust:resolve_package_import",
    "route:resolution:rust:resolve_package_import_target",
    "route:resolution:rust:resolve_transpile_cache_dir",
    "route:resolution:rust:resolve_with_oxc",
    "route:resolution:rust:resolve_with_oxc_at",
    "route:resolution:rust:run_transpile_command",
    "route:resolution:rust:run_transpile_override",
    "route:resolution:rust:run_transpile_subprocess",
    "route:resolution:rust:scan_balanced_region",
    "route:resolution:rust:scan_block_scoped_loop_closures",
    "route:resolution:rust:selected_engine_cache_tag",
    "route:resolution:rust:selected_transform_engine",
    "route:resolution:rust:sha256_hex",
    "route:resolution:rust:skip_ws_and_comments",
    "route:resolution:rust:source_needs_async_downlevel",
    "route:resolution:rust:source_needs_downlevel",
    "route:resolution:rust:source_needs_for_of_scoping_fix",
    "route:resolution:rust:source_needs_loop_scope_downlevel",
    "route:resolution:rust:touch_transpile_artifact",
    "route:resolution:rust:transpile_cache_dir",
    "route:resolution:rust:transpile_cache_is_valid",
    "route:resolution:rust:transpile_module",
    "route:resolution:rust:transpile_override_identity",
    "route:resolution:rust:transpile_script_path",
    "route:resolution:rust:transpile_source_to_cjs",
    "route:resolution:rust:transpile_target_for_source",
    "route:resolution:rust:transpile_to_cjs",
    "route:resolution:rust:transpile_tooling_hash",
    "route:resolution:rust:transpile_with_oxc",
    "route:resolution:rust:transpile_with_swc",
    "route:resolution:rust:unique_staged_transpile_input",
    "route:resolution:rust:unique_tmp_path",
    "route:resolution:rust:wait_for_transpile_test_barrier",
    "route:subprocess:rust:find_js_runner",
    "route:subprocess:rust:run_transpile_subprocess",
    "route:transform:rust:cache_tag",
    "route:transform:rust:compute_transpile_tooling_hash",
    "route:transform:rust:directory_size",
    "route:transform:rust:enforce_transpile_cache_quota",
    "route:transform:rust:ensure_transpile_cache_dir",
    "route:transform:rust:find_js_runner",
    "route:transform:rust:format_oxc_errors",
    "route:transform:rust:from_value",
    "route:transform:rust:module_cache_key",
    "route:transform:rust:output_has_esm_module_syntax",
    "route:transform:rust:oxc_target",
    "route:transform:rust:program_has_top_level_await",
    "route:transform:rust:prune_transpile_cache_to_limit",
    "route:transform:rust:publish_transpile_artifact",
    "route:transform:rust:read_transpile_cache",
    "route:transform:rust:resolve_transpile_cache_dir",
    "route:transform:rust:run_transpile_command",
    "route:transform:rust:run_transpile_override",
    "route:transform:rust:run_transpile_subprocess",
    "route:transform:rust:selected_engine_cache_tag",
    "route:transform:rust:selected_transform_engine",
    "route:transform:rust:sha256_hex",
    "route:transform:rust:touch_transpile_artifact",
    "route:transform:rust:transpile_cache_dir",
    "route:transform:rust:transpile_cache_is_valid",
    "route:transform:rust:transpile_module",
    "route:transform:rust:transpile_override_identity",
    "route:transform:rust:transpile_script_path",
    "route:transform:rust:transpile_source_to_cjs",
    "route:transform:rust:transpile_to_cjs",
    "route:transform:rust:transpile_tooling_hash",
    "route:transform:rust:transpile_with_oxc",
    "route:transform:rust:transpile_with_swc",
    "route:transform:rust:unique_staged_transpile_input",
    "route:transform:rust:unique_tmp_path",
    "route:transform:rust:wait_for_transpile_test_barrier",
    "transform-engine:oxc",
    "transform-engine:swc",
    "unknown-exact-rejection",
    "unsupported-node-rejection",
    "wasm-module",
  ],
  "REVIEWED_LOADER_NAMES",
);

const REVIEWED_STARTUP_NAMES = reviewedNameSet(
  [
    "capability-hardening-seal",
    "compartment-registry-install",
    "eager-native-seal",
    "env:<dynamic>:cpp:::environ",
    "env:<dynamic>:cpp:GetEnvironmentStringsW",
    "env:<dynamic>:cpp:_NSGetEnviron",
    "env:<dynamic>:cpp:getenv",
    "env:<dynamic>:javascript:process-binding-flow",
    "env:<dynamic>:javascript:process.env",
    "env:<dynamic>:javascript:process.env[]",
    "env:<dynamic>:javascript:process[]",
    "env:<dynamic>:rust:env::var",
    "env:<dynamic>:rust:env::var_os",
    "env:<dynamic>:rust:env::vars",
    "env:<dynamic>:rust:env_flag_enabled",
    "env:<dynamic>:rust:runtime_env",
    "env:<dynamic>:rust:timeout_from_env",
    "env:COLORTERM",
    "env:COLUMNS",
    "env:COMSPEC",
    "env:EXACT_ALLOW_INSECURE_CRYPTO",
    "env:EXACT_ANDROID_CACHE_DIR",
    "env:EXACT_ANDROID_CODE_CACHE_DIR",
    "env:EXACT_ANDROID_EXTERNAL_FILES_DIR",
    "env:EXACT_ANDROID_FILES_DIR",
    "env:EXACT_ANDROID_NO_BACKUP_FILES_DIR",
    "env:EXACT_BUNDLER_TIMEOUT_MS",
    "env:EXACT_CDP_LOG",
    "env:EXACT_CLUSTER_ID",
    "env:EXACT_CLUSTER_WORKER",
    "env:EXACT_COMPAT_BUN",
    "env:EXACT_COMPAT_EXECUTABLE",
    "env:EXACT_COMPAT_EXEC_ARGV",
    "env:EXACT_COMPAT_TEST",
    "env:EXACT_DEBUG_EMIT_LISTENER",
    "env:EXACT_EXECUTABLE",
    "env:EXACT_HERMESC_TIMEOUT_MS",
    "env:EXACT_HERMES_TOOL_DIR",
    "env:EXACT_IPC_FD",
    "env:EXACT_IPC_SERIALIZATION",
    "env:EXACT_LOOP_TRACE",
    "env:EXACT_PIPELINE_DEBUG",
    "env:EXACT_PIPELINE_STATE_DEBUG",
    "env:EXACT_POLICY",
    "env:EXACT_QUIET",
    "env:EXACT_RAW_ARGV0",
    "env:EXACT_REPO_ROOT",
    "env:EXACT_RUNTIME_TRANSFORM",
    "env:EXACT_SECURITY_LOG",
    "env:EXACT_TEST_SECTION",
    "env:EXACT_TRANSPILE_SCRIPT",
    "env:EXACT_WATCH_SHUTDOWN_TIMEOUT_MS",
    "env:EXACT_WINHTTP_ENABLE_HTTP2",
    "env:EXACT_WPT_FIXTURE_CLOSE_SEMANTICS",
    "env:EXACT_WPT_TRUST_LOOPBACK_TLS",
    "env:EX_BOOTSTRAP_GLOBALS_HBC",
    "env:EX_BOOTSTRAP_GLOBALS_SOURCE",
    "env:EX_COMPAT_POLYFILLS_HBC",
    "env:EX_COMPAT_POLYFILLS_SOURCE",
    "env:EX_CONSOLE_ENHANCE_HBC",
    "env:EX_CONSOLE_ENHANCE_SOURCE",
    "env:EX_DISABLE_BYTECODE_SANITY_CHECK",
    "env:EX_EXACT_GLOBAL_HBC",
    "env:EX_EXACT_GLOBAL_SOURCE",
    "env:EX_FORM_DATA_HBC",
    "env:EX_FORM_DATA_SOURCE",
    "env:EX_IPC_LISTENER_HBC",
    "env:EX_IPC_LISTENER_SOURCE",
    "env:EX_LAZY_GETTERS_HBC",
    "env:EX_LAZY_GETTERS_SOURCE",
    "env:EX_MODULE_LOADER_HBC",
    "env:EX_MODULE_LOADER_SOURCE",
    "env:EX_NO_BYTECODE",
    "env:EX_NO_DISK_RUNTIME_FALLBACK",
    "env:EX_PROCESS_COMPAT_FIX_HBC",
    "env:EX_PROCESS_COMPAT_FIX_SOURCE",
    "env:EX_REPL_PROMPT",
    "env:EX_SHARED_RUNTIME_BUNDLE_SOURCE",
    "env:EX_SKIP_STARTUP_BOOTSTRAP_GLOBALS",
    "env:EX_SKIP_STARTUP_COMPAT_POLYFILLS",
    "env:EX_SKIP_STARTUP_CONSOLE_ENHANCE",
    "env:EX_SKIP_STARTUP_CONSOLE_INIT",
    "env:EX_SKIP_STARTUP_EXACT_GLOBAL",
    "env:EX_SKIP_STARTUP_HOST_FUNCTIONS",
    "env:EX_SKIP_STARTUP_LAZY_GETTERS",
    "env:EX_SKIP_STARTUP_MODULE_LOADER",
    "env:EX_SKIP_STARTUP_MODULE_LOADER_SCRIPT",
    "env:EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE",
    "env:EX_STARTUP_TRACE",
    "env:EX_STREAM_ENHANCE_HBC",
    "env:EX_STREAM_ENHANCE_SOURCE",
    "env:EX_WEB_CRYPTO_HBC",
    "env:EX_WEB_CRYPTO_SOURCE",
    "env:EX_WEB_STORAGE_HBC",
    "env:EX_WEB_STORAGE_SOURCE",
    "env:EX_WEB_STREAMS_POLYFILL",
    "env:EX_WEB_STREAMS_POLYFILL_HBC",
    "env:EX_WEB_STREAMS_POLYFILL_SOURCE",
    "env:FORCE_COLOR",
    "env:HOME",
    "env:HOST",
    "env:HOSTNAME",
    "env:IBEX_AWAIT_UNWRAP_TIMEOUT_MS",
    "env:IBEX_BUNDLE_CACHE_MAX_BYTES",
    "env:IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT",
    "env:IBEX_CAPSEC_ALLOW_ADVISORY",
    "env:IBEX_CAPSEC_RECIPE_CATALOG",
    "env:IBEX_CDP_LOG",
    "env:IBEX_DNS_SERVER",
    "env:IBEX_HERMESC_TIMEOUT_MS",
    "env:IBEX_HERMES_TOOL_DIR",
    "env:IBEX_HTTP_MAX_REQUEST_BODY_BYTES",
    "env:IBEX_LOOP_TRACE",
    "env:IBEX_NO_BYTECODE",
    "env:IBEX_NO_DISK_RUNTIME_FALLBACK",
    "env:IBEX_POLICY",
    "env:IBEX_QUIET",
    "env:IBEX_REPL_PROMPT",
    "env:IBEX_REPO_ROOT",
    "env:IBEX_RUNTIME_TRANSFORM",
    "env:IBEX_STARTUP_TRACE",
    "env:IBEX_SUPPRESS_CONSOLE_MIRROR",
    "env:IBEX_TEST_ARMED_CREATE_PAUSE_MS",
    "env:IBEX_TEST_ARMED_DENY_OPEN_COMMIT",
    "env:IBEX_TEST_FS_WORKER_MAX_QUEUE",
    "env:IBEX_TEST_FS_WORKER_THROW_ENQUEUE",
    "env:IBEX_TEST_HBC_COMPILE_BARRIER",
    "env:IBEX_TEST_TRANSPILE_INPUT_BARRIER",
    "env:IBEX_TRANSPILE_CACHE_MAX_BYTES",
    "env:IBEX_WATCH_SHUTDOWN_TIMEOUT_MS",
    "env:LINES",
    "env:NODE_CHANNEL_FD",
    "env:NODE_DEBUG",
    "env:NODE_ENV",
    "env:NODE_EXTRA_CA_CERTS",
    "env:NODE_PENDING_DEPRECATION",
    "env:NODE_TLS_REJECT_UNAUTHORIZED",
    "env:NODE_UNIQUE_ID",
    "env:NO_COLOR",
    "env:PATH",
    "env:RES_OPTIONS",
    "env:TEMP",
    "env:TERM",
    "env:TMP",
    "env:TMPDIR",
    "env:TZ",
    "env:USERNAME",
    "env:USERPROFILE",
    "env:WPT_SERVER_URL",
    "env:__exactEnvProxy",
    "evaluation:__has_include:18ool1z:process-exit-marker",
    "evaluation:__has_include:18ool1z:stream-enhance",
    "evaluation:__has_include:18ool1z:stream-stability-patch",
    "evaluation:defined:13e9rgh:promise-unwrap",
    "evaluation:ex_hermes_debugger_eval:cdp",
    "evaluation:installFetchGlobals:windows-fetch-shim",
    "evaluation:installWebSocketGlobals:windows-websocket-shim",
    "evaluation:translation-unit-fallback:capability-hardening",
    "evaluation:translation-unit-fallback:cdp",
    "evaluation:translation-unit-fallback:compartment-registry",
    "evaluation:translation-unit-fallback:eager-install-seal",
    "evaluation:translation-unit-fallback:form-data",
    "evaluation:translation-unit-fallback:freeze-seal",
    "evaluation:translation-unit-fallback:fs-handle",
    "evaluation:translation-unit-fallback:lockdown",
    "evaluation:translation-unit-fallback:web-crypto",
    "evaluation:translation-unit-fallback:web-storage",
    "freeze-seal",
    "globals-install",
    "install-route:defined:13e9rgh:installFsHostFunctions",
    "install-route:env_flag_enabled:0jb9qqi:installWebStreamsPolyfill",
    "install-route:ex_hermes_create_impl:installGlobals",
    "install-route:ex_worklet_create:installWorkletGlobals",
    "install-route:installAndroidHostFunctions:installAndroidCameraBridge",
    "install-route:installAndroidHostFunctions:installAndroidEnvironmentGlobals",
    "install-route:installAndroidHostFunctions:installAndroidLocationBridge",
    "install-route:installChildProcessHostFunctions:installUnsupportedJsonFn",
    "install-route:installCryptoHostFunctions:installDnsHostFunctions",
    "install-route:installCryptoHostFunctions:installZlibHostFunctions",
    "install-route:installDnsHostFunctions:installUnsupportedGlobal",
    "install-route:installFsHostFunctions:installSync",
    "install-route:installGlobals:installAndroidHostFunctions",
    "install-route:installGlobals:installConsoleGlobals",
    "install-route:installGlobals:installTimerGlobals",
    "install-route:installModuleLoader:installSharedRuntimeBundle",
    "install-route:installNetHostFunctions:installTlsHostFunctions",
    "install-route:installNetHostFunctions:installUnsupportedModule",
    "install-route:installUnsupportedModule:installUnsupportedGlobal",
    "install-route:translation-unit-fallback:installChildProcessHostFunctions",
    "install-route:translation-unit-fallback:installCryptoHostFunctions",
    "install-route:translation-unit-fallback:installDnsHostFunctions",
    "install-route:translation-unit-fallback:installFetchGlobals",
    "install-route:translation-unit-fallback:installFsHostFunctions",
    "install-route:translation-unit-fallback:installHttpHostFunctions",
    "install-route:translation-unit-fallback:installIpcListenerPatch",
    "install-route:translation-unit-fallback:installLegacyLazyBootstrapGetters",
    "install-route:translation-unit-fallback:installModuleLoader",
    "install-route:translation-unit-fallback:installNetHostFunctions",
    "install-route:translation-unit-fallback:installOsInfoGlobals",
    "install-route:translation-unit-fallback:installProcessSetup",
    "install-route:translation-unit-fallback:installSqliteHostFunctions",
    "install-route:translation-unit-fallback:installWebSocketGlobals",
    "installer:installAndroidCameraBridge",
    "installer:installAndroidEnvironmentGlobals",
    "installer:installAndroidHostFunctions",
    "installer:installAndroidLocationBridge",
    "installer:installChildProcessHostFunctions",
    "installer:installConsoleGlobals",
    "installer:installCryptoHostFunctions",
    "installer:installDnsHostFunctions",
    "installer:installFetchGlobals",
    "installer:installFsHostFunctions",
    "installer:installGlobals",
    "installer:installHttpHostFunctions",
    "installer:installIpcListenerPatch",
    "installer:installLegacyLazyBootstrapGetters",
    "installer:installModuleLoader",
    "installer:installNetHostFunctions",
    "installer:installOsInfoGlobals",
    "installer:installProcessSetup",
    "installer:installSharedRuntimeBundle",
    "installer:installSqliteHostFunctions",
    "installer:installTimerGlobals",
    "installer:installTlsHostFunctions",
    "installer:installUnsupportedGlobal",
    "installer:installUnsupportedModule",
    "installer:installWebSocketGlobals",
    "installer:installWebStreamsPolyfill",
    "installer:installWorkletGlobals",
    "installer:installZlibHostFunctions",
    "installer:installZlibStreamHostFunctions",
    "legacy-lazy-bootstrap",
    "legacy-process-compat",
    "lockdown-install",
    "module-loader-install",
    "runtime-create",
    "scheduler-principal-capture",
    "script:bootstrap",
    "script:bytecode",
    "script:capability-hardening",
    "script:cdp",
    "script:compartment-registry",
    "script:compat-polyfills",
    "script:console",
    "script:eager-install-seal",
    "script:eval",
    "script:exact-global",
    "script:form-data",
    "script:freeze-seal",
    "script:fs-handle",
    "script:ipc-listener",
    "script:lazy-getters",
    "script:lockdown",
    "script:module-loader",
    "script:process-compat-fix",
    "script:process-exit-marker",
    "script:promise-unwrap",
    "script:shared-runtime-bundle",
    "script:stream-enhance",
    "script:stream-stability-patch",
    "script:web-crypto",
    "script:web-storage",
    "script:web-streams-polyfill",
    "script:windows-fetch-shim",
    "script:windows-websocket-shim",
    "shared-runtime-install",
    "web-streams-install",
  ],
  "REVIEWED_STARTUP_NAMES",
);

const ACTION_STAGES = Object.freeze({
  "clipboard:read": ["requested", "commit", "delivery"],
  "clipboard:write": ["requested", "commit"],
  "device:camera": ["requested", "discovery", "commit", "delivery", "repeat"],
  "device:location": ["requested", "discovery", "commit", "delivery", "repeat"],
  "device:microphone": [
    "requested",
    "discovery",
    "commit",
    "delivery",
    "repeat",
  ],
  "env:read": ["requested", "commit"],
  "env:write": ["requested", "commit"],
  "fs:list": ["requested", "discovery"],
  "fs:read": ["commit", "repeat"],
  "fs:watch": ["requested", "discovery", "commit", "delivery", "repeat"],
  "fs:write": ["commit", "repeat"],
  "network:connect": ["requested", "candidate", "commit", "repeat"],
  "network:fetch": ["requested", "candidate", "commit", "delivery"],
  "network:listen": ["requested", "commit", "delivery", "repeat"],
  "network:resolve": ["requested", "discovery", "delivery"],
  "process:spawn": ["requested", "discovery", "commit", "delivery"],
  "stdio:query": ["requested", "commit"],
  "stdio:raw": ["requested", "commit"],
  "stdio:read": ["requested", "commit", "repeat"],
  "stdio:write": ["requested", "commit", "repeat"],
  "sys:read": ["requested", "commit"],
});

const FAMILY_BARRIERS = Object.freeze({
  device: {
    authorizeBefore: ["broker-request", "device-open", "first-delivery"],
    recheckAt: ["broker-change", "delivery"],
    cancelAt: ["negative-generation-change", "device-identity-mismatch"],
  },
  environment: {
    authorizeBefore: ["environment-access"],
    recheckAt: [],
    cancelAt: ["negative-generation-change"],
  },
  filesystem: {
    authorizeBefore: ["path-discovery", "object-open", "first-use"],
    recheckAt: ["object-use"],
    cancelAt: ["negative-generation-change", "object-identity-mismatch"],
  },
  loader: {
    authorizeBefore: ["module-resolution", "source-read", "module-admission"],
    recheckAt: ["dynamic-import"],
    cancelAt: ["negative-generation-change", "object-identity-mismatch"],
  },
  network: {
    authorizeBefore: ["route-selection", "dns", "connect-or-bind", "first-io"],
    recheckAt: ["candidate", "redirect", "reconnect", "delivery"],
    cancelAt: ["negative-generation-change", "peer-mismatch"],
  },
  process: {
    authorizeBefore: ["executable-discovery", "child-configuration", "spawn"],
    recheckAt: ["child-io"],
    cancelAt: ["negative-generation-change", "executable-identity-mismatch"],
  },
  stdio: {
    authorizeBefore: ["stdio-access"],
    recheckAt: ["stdio-use"],
    cancelAt: ["negative-generation-change", "source-identity-mismatch"],
  },
  system: {
    authorizeBefore: ["system-information-read"],
    recheckAt: [],
    cancelAt: ["negative-generation-change"],
  },
});

function utf8Compare(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

export function reviewedNativeOperationNames() {
  return [...REVIEWED_NATIVE_OPERATION_NAMES].sort(utf8Compare);
}

export function reviewedCallbackProducerNames() {
  return [...REVIEWED_CALLBACK_PRODUCER_NAMES].sort(utf8Compare);
}

export function reviewedBuiltinRootNames() {
  return [...REVIEWED_BUILTIN_ROOT_NAMES].sort(utf8Compare);
}

export function reviewedBuiltinExportNames() {
  return [...REVIEWED_BUILTIN_EXPORT_NAMES].sort(utf8Compare);
}

export function reviewedGlobalApiNames() {
  return [...REVIEWED_GLOBAL_API_NAMES].sort(utf8Compare);
}

export function reviewedHostAbiNames() {
  return [...REVIEWED_HOST_ABI_NAMES];
}

export function reviewedInspectorNativeNames() {
  return [...REVIEWED_INSPECTOR_NATIVE_NAMES];
}

export function reviewedCliNames() {
  return [...REVIEWED_CLI_NAMES];
}

export function reviewedLoaderNames() {
  return [...REVIEWED_LOADER_NAMES];
}

export function reviewedStartupNames() {
  return [...REVIEWED_STARTUP_NAMES];
}

/** Fail generation when a reviewed name silently disappears from discovery. */
export function assertReviewedSurfaceInventory(surfaces) {
  const names = (predicate) =>
    new Set(surfaces.filter(predicate).map((surface) => surface.name));
  const inventories = [
    [
      "builtin roots",
      REVIEWED_BUILTIN_ROOT_NAMES,
      names(
        (row) => row.kind === "builtin" && row.metadata?.surfaceType !== "export",
      ),
    ],
    [
      "builtin exports",
      REVIEWED_BUILTIN_EXPORT_NAMES,
      names(
        (row) => row.kind === "builtin" && row.metadata?.surfaceType === "export",
      ),
    ],
    [
      "private native operations",
      REVIEWED_NATIVE_OPERATION_NAMES,
      names(
        (row) =>
          row.kind === "native-op" &&
          !row.name.startsWith("inspector.") &&
          (row.metadata?.surfaceType !== "global-api" ||
            row.metadata?.surfaceTypes?.includes("private-native-operation")),
      ),
    ],
    [
      "callback producers",
      REVIEWED_CALLBACK_PRODUCER_NAMES,
      names(
        (row) =>
          row.kind === "callback" &&
          row.metadata?.evidenceType === "push-runtime-callback-producer",
      ),
    ],
    [
      "global APIs",
      REVIEWED_GLOBAL_API_NAMES,
      names((row) => row.metadata?.surfaceType === "global-api"),
    ],
    ["host ABIs", REVIEWED_HOST_ABI_NAMES, names((row) => row.kind === "host-abi")],
    [
      "inspector natives",
      REVIEWED_INSPECTOR_NATIVE_NAMES,
      names((row) => row.kind === "native-op" && row.name.startsWith("inspector.")),
    ],
    ["CLI surfaces", REVIEWED_CLI_NAMES, names((row) => row.kind === "cli")],
    ["loader surfaces", REVIEWED_LOADER_NAMES, names((row) => row.kind === "loader")],
    ["startup surfaces", REVIEWED_STARTUP_NAMES, names((row) => row.kind === "startup")],
  ];
  for (const [label, reviewed, discovered] of inventories) {
    const missing = [...reviewed].filter((name) => !discovered.has(name));
    if (missing.length) {
      throw new Error(
        `${label}: reviewed surfaces missing from discovery [${missing.sort(utf8Compare).join(", ")}]`,
      );
    }
  }
}

export function canonicalStringSet(values) {
  return [...new Set(values)].sort(utf8Compare);
}

export function logicalBranchConditionsOverlap(left, right) {
  const leftByFact = new Map(
    left.map((condition) => [condition.fact, condition.equals]),
  );
  return !right.some(
    (condition) =>
      leftByFact.has(condition.fact) &&
      leftByFact.get(condition.fact) !== condition.equals,
  );
}

function fnv1a32(value) {
  let hash = 0x811c9dc5;
  for (const byte of Buffer.from(value, "utf8")) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(36).padStart(7, "0");
}

function stableComponent(value, fallback = "surface") {
  const component = String(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, ".")
    .replace(/^\.+|\.+$/gu, "")
    .replace(/\.{2,}/gu, ".");
  return component || fallback;
}

function enforcementSemanticShape(edge) {
  if (edge.classification !== "effects") return null;
  return {
    classification: edge.classification,
    effects: edge.effects,
    principalSources: edge.principalSources,
    effectOwnerSource: edge.effectOwnerSource,
    gate: edge.gate,
    effectMode: edge.effectMode,
    logicalBranches: edge.logicalBranches,
    lifetimeContract: edge.lifetimeContract,
    barriers: edge.barriers,
  };
}

/**
 * Identify the actual source-backed effect boundary independently of the API
 * alias that routes to it. Sharing is deliberately conservative: two rows
 * collapse only when their exact reviewed source refs, target branch, backend,
 * disposition, and complete semantic decision shape are identical.
 */
export function enforcementBranchIdentity(edge, branch) {
  if (edge.classification !== "effects") {
    return {
      id: branch.branchId,
      key: JSON.stringify(["surface-branch", branch.branchId]),
      routeKind: "surface-branch",
    };
  }
  const sourceRefs = canonicalStringSet(
    branch.enforcementRoute?.sourceRefs ?? branch.sourceRefs ?? [],
  );
  const terminalObservedKey =
    branch.enforcementRoute?.terminalObservedKey ??
    `${edge.surface.kind}:${edge.surface.name}`;
  const key = JSON.stringify({
    terminalObservedKey,
    sourceRefs,
    targetVariant: branch.targetVariant,
    targetApplicability: branch.targetApplicability,
    backend: branch.backend ?? null,
    implementationDisposition: branch.implementationDisposition ?? null,
    stubDisposition: branch.stubDisposition ?? null,
    semantics: enforcementSemanticShape(edge),
  });
  const anchor = stableComponent(sourceRefs[0] ?? "effect-boundary")
    .slice(-64)
    .replace(/^\.+/u, "") || "effect.boundary";
  return {
    id: validateStableId(
      `enforcement.${anchor}.${fnv1a32(key)}`,
      "enforcement branch id",
    ),
    key,
    routeKind:
      branch.enforcementRoute?.kind ?? "exact-source-and-semantics",
  };
}

export function stableIdForSurface(surface) {
  const observedKey = surface.observedKey ?? `${surface.kind}:${surface.name}`;
  const readable = stableComponent(surface.name)
    .slice(0, 72)
    .replace(/\.$/u, "");
  return `surface.${stableComponent(surface.kind)}.${readable}.${fnv1a32(observedKey)}`;
}

function validateSurface(surface) {
  if (!surface || typeof surface !== "object")
    throw new Error("observed surface must be an object");
  if (!SURFACE_KINDS.has(surface.kind)) {
    throw new Error(
      `unsupported observed surface kind ${String(surface.kind)}`,
    );
  }
  if (typeof surface.name !== "string" || surface.name.length === 0) {
    throw new Error("observed surface name must be a non-empty string");
  }
  const expectedKey = `${surface.kind}:${surface.name}`;
  if (
    surface.observedKey !== undefined &&
    surface.observedKey !== expectedKey
  ) {
    throw new Error(
      `${surface.observedKey}: observedKey must equal ${expectedKey}`,
    );
  }
  if (!Array.isArray(surface.sourceRefs) || surface.sourceRefs.length === 0) {
    throw new Error(`${expectedKey}: sourceRefs must be a non-empty array`);
  }
  return { ...surface, observedKey: expectedKey };
}

function definitionsArray(definitions) {
  if (Array.isArray(definitions)) return definitions;
  if (Array.isArray(definitions?.definitions)) return definitions.definitions;
  if (definitions instanceof Map) return [...definitions.values()];
  throw new Error("capability definitions must be an array, dataset, or Map");
}

function normalizationProfilesArray(rules) {
  if (Array.isArray(rules?.normalizationProfiles))
    return rules.normalizationProfiles;
  throw new Error("policy rules lack normalizationProfiles");
}

export function prepareCoverageContext({ definitions, rules }) {
  const definitionRows = definitionsArray(definitions);
  const definitionsById = new Map();
  for (const definition of definitionRows) {
    if (definitionsById.has(definition.id)) {
      throw new Error(`duplicate capability definition ${definition.id}`);
    }
    definitionsById.set(definition.id, definition);
  }

  const normalizationsById = new Map();
  for (const profile of normalizationProfilesArray(rules)) {
    if (normalizationsById.has(profile.id)) {
      throw new Error(`duplicate normalization profile ${profile.id}`);
    }
    normalizationsById.set(profile.id, profile);
  }

  const rationalesById = new Map();
  for (const rationale of rules?.classifierRules?.nonCapabilityRationales ??
    []) {
    if (rationalesById.has(rationale.id)) {
      throw new Error(`duplicate non-capability rationale ${rationale.id}`);
    }
    rationalesById.set(rationale.id, rationale);
  }

  return {
    definitions: definitionRows,
    definitionsById,
    normalizationsById,
    rationalesById,
    rules,
    prepared: true,
  };
}

function preparedContext(context) {
  return context?.prepared ? context : prepareCoverageContext(context);
}

export function derivePositiveSources(definition) {
  const sources = ["ambient-root", "static-floor"];
  if (definition.channels?.handle) sources.push("handle");
  if (definition.channels?.dynamic && !definition.staticOnly)
    sources.push("session");
  if (definition.channels?.synthesis) sources.push("implicit-self");
  return canonicalStringSet(sources);
}

export function deriveEffectTemplate(action, context, options = {}) {
  const prepared = preparedContext(context);
  const definition = prepared.definitionsById.get(action);
  if (!definition)
    throw new Error(`coverage references unknown action ${action}`);
  if (definition.lifecycle !== "authorable") {
    throw new Error(`effect coverage action ${action} is not authorable`);
  }
  const normalization = prepared.normalizationsById.get(
    definition.normalizationProfile,
  );
  if (!normalization) {
    throw new Error(
      `${action}: unknown normalization profile ${definition.normalizationProfile}`,
    );
  }
  if (!normalization.selector || !normalization.occurrence) {
    throw new Error(
      `${action}: normalization profile ${definition.normalizationProfile} is incomplete`,
    );
  }
  const stages = options.stages ?? ACTION_STAGES[action];
  if (!stages?.length)
    throw new Error(`${action}: no coverage stages are defined`);
  return {
    cap: action,
    selectorNormalizer: normalization.selector,
    occurrenceNormalizer: normalization.occurrence,
    stages: [...stages],
    positiveSources: derivePositiveSources(definition),
  };
}

function surfaceSearchText(surface) {
  const metadata = surface.metadata ?? {};
  return [
    surface.name,
    metadata.sourceKey,
    metadata.root,
    metadata.commandClass,
    metadata.family,
    metadata.exportName,
    ...(metadata.specifiers ?? []),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
}

function compactName(surface) {
  return surface.name.toLowerCase().replace(/[^a-z0-9]+/gu, "");
}

function effectSpec(actions, family, implementationOwner, options = {}) {
  return {
    classification: "effects",
    actions: canonicalStringSet(actions),
    family,
    implementationOwner,
    effectMode: options.effectMode ?? "conjunctive",
    logicalBranches: options.logicalBranches,
    refinementOwner: options.refinementOwner,
    rationale: options.rationale,
    lifetimeContract: options.lifetimeContract ?? "operation",
    principalSources: options.principalSources,
    effectOwnerSource: options.effectOwnerSource,
    gate: options.gate,
    barriers: options.barriers,
    stagesByAction: options.stagesByAction,
  };
}

function conditionalEffectSpec(
  actions,
  family,
  refinementOwner,
  rationale,
  options = {},
) {
  return effectSpec(actions, family, refinementOwner, {
    ...options,
    effectMode: "conditional-unrefined",
    refinementOwner,
    rationale,
  });
}

function conditionalBranchEffectSpec(
  branches,
  family,
  implementationOwner,
  options = {},
) {
  if (!Array.isArray(branches) || branches.length < 2) {
    throw new Error(
      "conditional effect specification requires at least two branches",
    );
  }
  return effectSpec(
    branches.flatMap((branch) => branch.actions),
    family,
    implementationOwner,
    {
      ...options,
      effectMode: "conditional",
      logicalBranches: branches,
    },
  );
}

function filesystemOpenEffectSpec(options = {}) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "read",
        when: [{ fact: "filesystem.open.access", equals: "read" }],
        actions: ["fs:list", "fs:read"],
      },
      {
        id: "read-write",
        when: [{ fact: "filesystem.open.access", equals: "read-write" }],
        actions: ["fs:list", "fs:read", "fs:write"],
      },
      {
        id: "write",
        when: [{ fact: "filesystem.open.access", equals: "write" }],
        actions: ["fs:list", "fs:write"],
      },
    ],
    "filesystem",
    "WP5",
    { lifetimeContract: "file-handle", ...options },
  );
}

function filesystemPathOrDescriptorEffectSpec(actions) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "descriptor",
        when: [{ fact: "filesystem.input.kind", equals: "descriptor" }],
        actions,
        principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
        effectOwnerSource: "descriptor-owner",
      },
      {
        id: "path",
        when: [{ fact: "filesystem.input.kind", equals: "path" }],
        actions,
      },
    ],
    "filesystem",
    "WP5",
    { lifetimeContract: "file-handle" },
  );
}

function filesystemPathDispatcherEffectSpec() {
  const branch = (id, actions) => ({
    id,
    when: [{ fact: "filesystem.path.operation", equals: id }],
    actions,
  });
  return conditionalBranchEffectSpec(
    [
      branch("access-read", ["fs:list"]),
      branch("access-write", ["fs:write"]),
      branch("chmod", ["fs:list", "fs:write"]),
      branch("chown", ["fs:list", "fs:write"]),
      branch("copy", ["fs:read", "fs:write"]),
      branch("link", ["fs:read", "fs:write"]),
      branch("mkdir", ["fs:list", "fs:write"]),
      branch("mkdtemp", ["fs:list", "fs:write"]),
      branch("readdir", ["fs:list"]),
      branch("readlink", ["fs:read"]),
      branch("realpath", ["fs:list"]),
      branch("rename", ["fs:list", "fs:write"]),
      branch("rmdir", ["fs:list", "fs:write"]),
      branch("statfs", ["fs:list"]),
      branch("symlink", ["fs:list", "fs:write"]),
      branch("truncate", ["fs:list", "fs:write"]),
      branch("unlink", ["fs:list", "fs:write"]),
      branch("utime", ["fs:list", "fs:write"]),
    ],
    "filesystem",
    "WP5",
  );
}

function filesystemDescriptorDispatcherEffectSpec() {
  const branch = (id, actions) => ({
    id,
    when: [{ fact: "filesystem.descriptor.operation", equals: id }],
    actions,
    principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
    effectOwnerSource: "descriptor-owner",
  });
  return conditionalBranchEffectSpec(
    [
      branch("durability-read", ["fs:read"]),
      branch("durability-write", ["fs:write"]),
      branch("metadata-write", ["fs:write"]),
    ],
    "filesystem",
    "WP5",
    { lifetimeContract: "file-handle" },
  );
}

const SQLITE_RETAINED_OPTIONS = Object.freeze({
  lifetimeContract: "file-handle",
  effectOwnerSource: "descriptor-owner",
  principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
});

function sqliteOpenEffectSpec() {
  const branch = (id, actions) => ({
    id,
    when: [{ fact: "sqlite.open.mode", equals: id }],
    actions,
  });
  return conditionalBranchEffectSpec(
    [
      branch("file-read", ["fs:list", "fs:read"]),
      branch("file-read-write", ["fs:list", "fs:read", "fs:write"]),
      branch("memory", []),
    ],
    "filesystem",
    "WP5",
    { lifetimeContract: "file-handle" },
  );
}

function sqliteReadEffectSpec() {
  const branch = (id, actions) => ({
    id,
    when: [{ fact: "sqlite.storage.kind", equals: id }],
    actions,
  });
  return conditionalBranchEffectSpec(
    [branch("file", ["fs:read"]), branch("memory", [])],
    "filesystem",
    "WP5",
    SQLITE_RETAINED_OPTIONS,
  );
}

function sqliteStatementEffectSpec() {
  const branch = (id, actions) => ({
    id,
    when: [{ fact: "sqlite.statement.effect", equals: id }],
    actions,
  });
  return conditionalBranchEffectSpec(
    [
      branch("file-read", ["fs:read"]),
      branch("file-read-write", ["fs:read", "fs:write"]),
      branch("memory", []),
    ],
    "filesystem",
    "WP5",
    SQLITE_RETAINED_OPTIONS,
  );
}

function sqliteCloseEffectSpec() {
  const branch = (id, actions) => ({
    id,
    when: [{ fact: "sqlite.close.effect", equals: id }],
    actions,
  });
  return conditionalBranchEffectSpec(
    [branch("none", []), branch("write", ["fs:write"])],
    "filesystem",
    "WP5",
    SQLITE_RETAINED_OPTIONS,
  );
}

function resolverConfigLoadEffectSpec() {
  const branch = (id, actions) => ({
    id,
    when: [{ fact: "filesystem.resolver-config", equals: id }],
    actions,
  });
  return conditionalBranchEffectSpec(
    [branch("absent", []), branch("present", ["fs:list", "fs:read"])],
    "filesystem",
    "WP5",
  );
}

function filesystemStreamConstructionEffectSpec(action) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "descriptor",
        when: [{ fact: "filesystem.stream.input", equals: "descriptor" }],
        actions: [],
        principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
        effectOwnerSource: "descriptor-owner",
      },
      {
        id: "path",
        when: [{ fact: "filesystem.stream.input", equals: "path" }],
        actions: ["fs:list", action],
      },
    ],
    "filesystem",
    "WP5",
    { lifetimeContract: "file-handle" },
  );
}

function filesystemStreamUseEffectSpec(action, openingOnly) {
  const retained = {
    principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
    effectOwnerSource: "descriptor-owner",
  };
  return conditionalBranchEffectSpec(
    [
      {
        id: "descriptor",
        when: [{ fact: "filesystem.stream.backing", equals: "descriptor" }],
        actions: openingOnly ? [] : [action],
        ...retained,
      },
      {
        id: "path",
        when: [{ fact: "filesystem.stream.backing", equals: "path" }],
        actions: ["fs:list", action],
        ...retained,
      },
    ],
    "filesystem",
    "WP5",
    { lifetimeContract: "file-handle", ...retained },
  );
}

const NETWORK_RETAINED_OPTIONS = Object.freeze({
  lifetimeContract: "socket-stream",
  effectOwnerSource: "descriptor-owner",
  principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
});

function optionalNetworkEffectSpec(action, fact, options = {}) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "active",
        when: [{ fact, equals: "active" }],
        actions: [action],
      },
      {
        id: "metadata",
        when: [{ fact, equals: "metadata" }],
        actions: [],
      },
    ],
    "network",
    "WP6",
    { ...NETWORK_RETAINED_OPTIONS, ...options },
  );
}

function retainedNetworkOriginEffectSpec(
  actions,
  fact = "network.retained.origin",
) {
  const branches = [
    {
      id: "metadata",
      when: [{ fact, equals: "metadata" }],
      actions: [],
    },
  ];
  if (actions.includes("network:connect")) {
    branches.push({
      id: "outbound",
      when: [{ fact, equals: "outbound" }],
      actions: ["network:connect"],
    });
  }
  if (actions.includes("network:listen")) {
    branches.push({
      id: "accepted",
      when: [{ fact, equals: "accepted" }],
      actions: ["network:listen"],
    });
  }
  return conditionalBranchEffectSpec(
    branches,
    "network",
    "WP6",
    NETWORK_RETAINED_OPTIONS,
  );
}

function dnsResolverEffectSpec(fact) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "custom-udp",
        when: [{ fact, equals: "custom-udp" }],
        actions: ["network:connect", "network:listen", "network:resolve"],
      },
      {
        id: "system",
        when: [{ fact, equals: "system" }],
        actions: ["network:resolve"],
      },
    ],
    "network",
    "WP6",
    { lifetimeContract: "operation" },
  );
}

function udpSendEffectSpec() {
  return conditionalBranchEffectSpec(
    [
      {
        id: "already-bound",
        when: [{ fact: "network.udp.bind-state", equals: "already-bound" }],
        actions: ["network:connect"],
      },
      {
        id: "implicit-bind",
        when: [{ fact: "network.udp.bind-state", equals: "implicit-bind" }],
        actions: ["network:connect", "network:listen"],
      },
    ],
    "network",
    "WP6",
    NETWORK_RETAINED_OPTIONS,
  );
}

function inetOrUnixNetworkEffectSpec(action, pathAction, fact) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "inet",
        when: [{ fact, equals: "inet" }],
        actions: [action],
      },
      {
        id: "unix",
        when: [{ fact, equals: "unix" }],
        actions: [pathAction, action],
      },
    ],
    "network",
    "WP6",
    {
      lifetimeContract:
        action === "network:listen" ? "listener" : "socket-stream",
    },
  );
}

function optionalPayloadNetworkEffectSpec(action, fact) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "payload",
        when: [{ fact, equals: "payload" }],
        actions: [action],
      },
      {
        id: "release",
        when: [{ fact, equals: "release" }],
        actions: [],
      },
    ],
    "network",
    "WP6",
    NETWORK_RETAINED_OPTIONS,
  );
}

function environmentSelectedNetworkEffectSpec(action, fact, options = {}) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "set",
        when: [{ fact, equals: "set" }],
        actions: ["env:read", action],
      },
      {
        id: "unset",
        when: [{ fact, equals: "unset" }],
        actions: [],
      },
    ],
    "network",
    "WP6",
    options,
  );
}

function androidMediaOperationEffectSpec(fact) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "camera",
        when: [{ fact, equals: "camera" }],
        actions: ["device:camera"],
      },
      {
        id: "microphone",
        when: [{ fact, equals: "microphone" }],
        actions: ["device:microphone"],
      },
    ],
    "device",
    "WP8",
    { lifetimeContract: "operation" },
  );
}

function intlHostDefaultsEffectSpec() {
  return conditionalBranchEffectSpec(
    [
      {
        id: "explicit",
        when: [{ fact: "system.intl.defaults", equals: "explicit" }],
        actions: [],
      },
      {
        id: "host-default",
        when: [{ fact: "system.intl.defaults", equals: "host-default" }],
        actions: ["sys:read"],
      },
    ],
    "system",
    "WP7",
  );
}

function retainedStdioEffectSpec(fact, variants, options = {}) {
  return conditionalBranchEffectSpec(
    variants.map(([id, actions]) => ({
      id,
      when: [{ fact, equals: id }],
      actions,
    })),
    "stdio",
    "WP7",
    {
      lifetimeContract: "socket-stream",
      effectOwnerSource: "descriptor-owner",
      principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
      ...options,
    },
  );
}

function readlineConstructionEffectSpec() {
  return retainedStdioEffectSpec("stdio.readline.streams", [
    ["input", ["stdio:read"]],
    ["input-output", ["stdio:read", "stdio:write"]],
    ["terminal-input", ["stdio:raw", "stdio:read"]],
    ["terminal-input-output", ["stdio:raw", "stdio:read", "stdio:write"]],
  ]);
}

function readlineOperationEffectSpec(fact = "stdio.readline.operation") {
  return retainedStdioEffectSpec(fact, [
    ["memory", []],
    ["input", ["stdio:read"]],
    ["output", ["stdio:write"]],
    ["input-output", ["stdio:read", "stdio:write"]],
  ]);
}

function ttyDirectionEffectSpec() {
  return retainedStdioEffectSpec("stdio.tty.direction", [
    ["input", ["stdio:read"]],
    ["output", ["stdio:write"]],
  ]);
}

function debugLogEffectSpec() {
  return conditionalBranchEffectSpec(
    [
      {
        id: "disabled",
        when: [{ fact: "stdio.debuglog.state", equals: "disabled" }],
        actions: ["env:read"],
      },
      {
        id: "enabled",
        when: [{ fact: "stdio.debuglog.state", equals: "enabled" }],
        actions: ["env:read", "stdio:write"],
      },
    ],
    "stdio",
    "WP7",
  );
}

function dynamicEnvironmentPropertyEffectSpec() {
  return conditionalBranchEffectSpec(
    [
      {
        id: "read",
        when: [{ fact: "environment.property.operation", equals: "read" }],
        actions: ["env:read"],
      },
      {
        id: "write",
        when: [{ fact: "environment.property.operation", equals: "write" }],
        actions: ["env:write"],
      },
    ],
    "environment",
    "WP7",
  );
}

function environmentValueEffectSpec(actions, domain, fact, options = {}) {
  const baseline = actions.filter((action) => action === "env:read");
  const branches = [
    {
      id: "absent",
      when: [{ fact, equals: "absent" }],
      actions: baseline,
    },
    {
      id: "present",
      when: [{ fact, equals: "present" }],
      actions,
    },
  ];
  if (actions.includes("env:write")) {
    branches.push({
      id: "propagated",
      when: [{ fact, equals: "propagated" }],
      actions,
    });
  }
  return conditionalBranchEffectSpec(branches, domain, "WP7", options);
}

function dynamicEnvironmentAccessEffectSpec(actions) {
  if (actions.length === 1) {
    return effectSpec(actions, "environment", "WP7");
  }
  const variants = [];
  if (actions.includes("env:read")) variants.push(["read", ["env:read"]]);
  if (actions.includes("env:write")) {
    variants.push(["write", ["env:write"]], ["unset", ["env:write"]]);
  }
  return conditionalBranchEffectSpec(
    variants.map(([id, branchActions]) => ({
      id,
      when: [{ fact: "environment.dynamic-access.direction", equals: id }],
      actions: branchActions,
    })),
    "environment",
    "WP7",
  );
}

function environmentEnumerationEffectSpec() {
  return conditionalBranchEffectSpec(
    [
      {
        id: "empty",
        when: [{ fact: "environment.enumeration", equals: "empty" }],
        actions: [],
      },
      {
        id: "nonempty",
        when: [{ fact: "environment.enumeration", equals: "nonempty" }],
        actions: ["env:read"],
      },
    ],
    "environment",
    "WP7",
  );
}

function processLaunchEffectSpec() {
  return conditionalBranchEffectSpec(
    [
      {
        id: "direct-isolated",
        when: [{ fact: "process.launch.mode", equals: "direct-isolated" }],
        actions: ["process:spawn"],
      },
      {
        id: "searched-isolated",
        when: [{ fact: "process.launch.mode", equals: "searched-isolated" }],
        actions: ["fs:list", "process:spawn"],
      },
      {
        id: "explicit-environment",
        when: [{ fact: "process.launch.mode", equals: "explicit-environment" }],
        actions: ["env:read", "env:write", "fs:list", "process:spawn"],
      },
      {
        id: "inherited-descriptors",
        when: [
          { fact: "process.launch.mode", equals: "inherited-descriptors" },
        ],
        actions: [
          "env:read",
          "env:write",
          "fs:list",
          "process:spawn",
          "stdio:read",
          "stdio:write",
        ],
      },
    ],
    "process",
    "WP7",
    { lifetimeContract: "child-process" },
  );
}

function loaderSourceSelectionEffectSpec(options) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "builtin-or-memory",
        when: [{ fact: "loader.source.kind", equals: "builtin-or-memory" }],
        actions: [],
      },
      {
        id: "metadata",
        when: [{ fact: "loader.source.kind", equals: "metadata" }],
        actions: ["fs:list"],
      },
      {
        id: "on-disk",
        when: [{ fact: "loader.source.kind", equals: "on-disk" }],
        actions: ["fs:list", "fs:read"],
      },
    ],
    "loader",
    "WP7",
    options,
  );
}

function fullLoaderEffectSpec(options) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "builtin-or-memory",
        when: [{ fact: "loader.execution.route", equals: "builtin-or-memory" }],
        actions: [],
      },
      {
        id: "disk-source",
        when: [{ fact: "loader.execution.route", equals: "disk-source" }],
        actions: ["fs:list", "fs:read"],
      },
      {
        id: "cached-transform",
        when: [{ fact: "loader.execution.route", equals: "cached-transform" }],
        actions: ["env:read", "fs:list", "fs:read", "fs:write"],
      },
      {
        id: "external-transform",
        when: [
          { fact: "loader.execution.route", equals: "external-transform" },
        ],
        actions: [
          "env:read",
          "fs:list",
          "fs:read",
          "fs:write",
          "process:spawn",
          "stdio:read",
          "stdio:write",
        ],
      },
    ],
    "loader",
    "WP7",
    { ...options, lifetimeContract: "child-process" },
  );
}

function loaderToolingEffectSpec(options) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "embedded-tool",
        when: [{ fact: "loader.tooling.source", equals: "embedded-tool" }],
        actions: ["fs:list", "fs:read"],
      },
      {
        id: "environment-tool",
        when: [{ fact: "loader.tooling.source", equals: "environment-tool" }],
        actions: ["env:read", "fs:list", "fs:read"],
      },
    ],
    "loader",
    "WP7",
    options,
  );
}

function loaderCacheEffectSpec(options, includeRead) {
  const diskActions = [
    "fs:list",
    ...(includeRead ? ["fs:read"] : []),
    "fs:write",
  ];
  return conditionalBranchEffectSpec(
    [
      {
        id: "default-cache",
        when: [{ fact: "loader.cache.location", equals: "default-cache" }],
        actions: diskActions,
      },
      {
        id: "environment-cache",
        when: [{ fact: "loader.cache.location", equals: "environment-cache" }],
        actions: ["env:read", ...diskActions],
      },
    ],
    "loader",
    "WP7",
    options,
  );
}

function loaderExecutableRouteEffectSpec(options) {
  return conditionalBranchEffectSpec(
    [
      {
        id: "direct",
        when: [{ fact: "loader.executable.route", equals: "direct" }],
        actions: ["fs:list"],
      },
      {
        id: "environment",
        when: [{ fact: "loader.executable.route", equals: "environment" }],
        actions: ["env:read", "fs:list"],
      },
    ],
    "loader",
    "WP7",
    options,
  );
}

function closedSpec(action, implementationOwner, rationale) {
  return { classification: "closed", action, implementationOwner, rationale };
}

function nonCapabilitySpec(rationaleId, implementationOwner = "WP1") {
  return { classification: "non-capability", rationaleId, implementationOwner };
}

const BUILTIN_ROOT_RUNTIME_MUTATION_SOURCES = new Set([
  "exact_crypto",
  "exact_process",
  "legacy_stream_duplex",
  "legacy_stream_passthrough",
  "legacy_stream_readable",
  "legacy_stream_transform",
  "legacy_stream_writable",
  "node_assert",
  "node_async_hooks",
  "node_child_process",
  "node_cluster",
  "node_dgram",
  "node_domain",
  "node_events",
  "node_http",
  "node_http2",
  "node_https",
  "node_net",
  "node_perf_hooks",
  "node_readline",
  "node_stream",
  "node_stream_promises",
  "node_stream_web",
  "node_tls",
  "node_tty",
  "node_url",
  "node_zlib",
  "url_alias",
  "ws",
]);

const BUILTIN_ROOT_SYSTEM_READ_SOURCES = new Set([
  "node_constants",
  "node_fs",
  "node_fs_promises",
  "node_os",
]);

const BUILTIN_ROOT_ENVIRONMENT_READ_SOURCES = new Set([
  "node_util",
  "node_util_types_alias",
  "util_types_alias",
]);

function builtinModuleInitializationClassification(source) {
  if (source === "node_dns" || source === "node_dns_promises") {
    return resolverConfigLoadEffectSpec();
  }
  if (source === "node_diagnostics_channel") {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "The diagnostics-channel module exposes a process-wide named publish/subscribe registry without principal isolation.",
    );
  }
  if (BUILTIN_ROOT_RUNTIME_MUTATION_SOURCES.has(source)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Loading this builtin mutates process-wide hooks, globals, registries, or shared runtime state directly or through an eager dependency.",
    );
  }
  if (BUILTIN_ROOT_SYSTEM_READ_SOURCES.has(source)) {
    return effectSpec(["sys:read"], "system", "WP7");
  }
  if (BUILTIN_ROOT_ENVIRONMENT_READ_SOURCES.has(source)) {
    return effectSpec(["env:read"], "environment", "WP7");
  }
  return null;
}

function builtinExportClassification(surface) {
  const source = String(surface.metadata?.sourceKey ?? "").toLowerCase();
  const exported = String(surface.metadata?.exportName ?? "").toLowerCase();
  // Some CommonJS facades expose the same API both directly and beneath a
  // `default` object.  Strip only that scanner-produced alias so the closed
  // semantic families below classify the operation, rather than the export
  // spelling.
  const api = exported.replace(/^default\./u, "");
  const name = api.replace(/[^a-z0-9]+/gu, "");

  if (source === "node_diagnostics_channel") {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Named diagnostics channels publish package-controlled data to subscribers in a process-wide registry.",
    );
  }

  if (source === "node_async_hooks" || source === "node_domain") {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Async hooks and domains observe or mutate process-wide callback and execution context state.",
    );
  }

  if (
    (source === "node_cluster" || source === "node_module") &&
    exported === "default"
  ) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "The default namespace exposes mutable process-wide runtime registries and configuration.",
    );
  }

  if (!exported || exported === "default") {
    const moduleInitialization =
      builtinModuleInitializationClassification(source);
    if (moduleInitialization) return moduleInitialization;
    if (source === "exact_sqlite" && exported === "default") {
      return sqliteOpenEffectSpec();
    }
    return nonCapabilitySpec("module-reachability-only", "WP7");
  }

  if (source === "exact_clipboard") {
    if (/read/u.test(name))
      return effectSpec(["clipboard:read"], "device", "WP8");
    if (/write/u.test(name))
      return effectSpec(["clipboard:write"], "device", "WP8");
  }

  if (source === "exact_http") {
    if (/serve/u.test(name)) {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "listener",
      });
    }
  }

  if (source === "exact_process") {
    if (/^(?:chdir)$/u.test(name)) {
      return closedSpec(
        "process:cwd",
        "WP7",
        "Process-global cwd mutation is closed.",
      );
    }
    if (/^(?:kill)$/u.test(name)) {
      return closedSpec(
        "process:signal",
        "WP7",
        "Package process signaling is closed.",
      );
    }
    if (/umask/u.test(name)) {
      return closedSpec(
        "process:umask",
        "WP7",
        "Process-global umask access is closed.",
      );
    }
    if (/^(?:binding)$/u.test(name)) {
      return closedSpec(
        "ffi:load",
        "WP7",
        "Private native binding lookup is closed.",
      );
    }
    if (/^(?:channel)$/u.test(name)) {
      return closedSpec("ipc:channel", "WP7", "Ambient process IPC is closed.");
    }
    if (/^(?:execve)$/u.test(name)) {
      return processLaunchEffectSpec();
    }
    if (/^(?:env)$/u.test(name)) {
      return closedSpec(
        "env:process-write",
        "WP7",
        "The process.env object permits mutation of shared process environment state, so reachability remains closed until reads and writes are separately mediated.",
      );
    }
    if (/^(?:stdin)$/u.test(name))
      return effectSpec(["stdio:read"], "stdio", "WP7");
    if (
      /cwd|get(?:euid|egid|uid|gid|groups)|argv|execargv|release|version/u.test(
        name,
      )
    ) {
      return effectSpec(["sys:read"], "system", "WP7");
    }
    if (/hrtime/u.test(name)) return nonCapabilitySpec("ordinary-time", "WP1");
    if (/^emitwarning$/u.test(name)) {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "process.emitWarning publishes through the shared process warning-listener registry.",
      );
    }
    if (
      /^(?:uncaughtcapturecb|addlistener|hasuncaughtexceptioncapturecallback|off|setuncaughtexceptioncapturecallback|setsourcemapsenabled|title)$/u.test(
        name,
      )
    ) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Process-wide listener, exception, source-map, and title state is shared runtime control and remains closed until isolated mediation exists.",
      );
    }
    if (/uncaught|listener|warning|sourcemap/u.test(name)) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
  }

  if (source === "exact_sqlite") {
    if (/^(?:constants|sqliteerror|sqliteerrorconstructor)$/u.test(name)) {
      return nonCapabilitySpec("module-reachability-only", "WP5");
    }
    if (
      /^(?:checkclosed|databasecheckclosed|statementcheckfinalized|statementnormalizeparams|statementas|statementcolumntypes|statementdeclaredtypes|statementnative|statementtostring|databaseintransaction|intransaction|deserialize)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP5");
    }
    if (/^(?:close|databaseclose)$/u.test(name)) {
      return sqliteCloseEffectSpec();
    }
    if (/^statementfinalize$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP5");
    }
    if (
      /^(?:databaseenablecrsqlite|databaseloadextension|enablecrsqlite|loadextension)$/u.test(
        name,
      )
    ) {
      return closedSpec(
        "ffi:load",
        "WP7",
        "SQLite extension loading is closed with the other native-extension escape surfaces.",
      );
    }
    if (/^(?:databasehandle|handle)$/u.test(name)) {
      return closedSpec(
        "ffi:load",
        "WP7",
        "Exposing the native SQLite handle is closed until native handle escape has a dedicated gate.",
      );
    }
    if (
      /^(?:databasequery|databaseprepare|databasegetchanges|databasegetdbversion|databasegetsiteid|databaseserialize|getchanges|getdbversion|getsiteid|prepare|query|serialize|statementall|statementget|statementvalues)$/u.test(
        name,
      )
    ) {
      return sqliteReadEffectSpec();
    }
    if (/^(?:database|open)$/u.test(name)) {
      return sqliteOpenEffectSpec();
    }
    if (
      /^(?:applychanges|databaseapplychanges|databaseexec|databasefilecontrol|databasemarkascrr|databaserun|databasetransaction|exec|filecontrol|markascrr|run|statement|statementconstructor|statementrecordexecution|statementrun|transaction)$/u.test(
        name,
      )
    ) {
      return sqliteStatementEffectSpec();
    }
  }

  if (source === "node_fs" || source === "node_fs_promises") {
    if (/^readstream(?:constructor)?$/u.test(name)) {
      return filesystemStreamConstructionEffectSpec("fs:read");
    }
    if (/^writestream(?:constructor)?$/u.test(name)) {
      return filesystemStreamConstructionEffectSpec("fs:write");
    }
    if (/^readstream\.(?:_read|open)$/u.test(api)) {
      return filesystemStreamUseEffectSpec("fs:read", api.endsWith(".open"));
    }
    if (/^readstream\.(?:close|destroy)$/u.test(api)) {
      return nonCapabilitySpec("authority-release", "WP5");
    }
    if (/^writestream\.(?:_final|_write|_writev|open)$/u.test(api)) {
      return filesystemStreamUseEffectSpec("fs:write", api.endsWith(".open"));
    }
    if (/^writestream\.(?:_emitclose|close|destroy)$/u.test(api)) {
      return nonCapabilitySpec("authority-release", "WP5");
    }
    if (
      /^(?:constants|promises|dir|dirent|fswatcher|stats|filehandle|fok|rok|wok|xok)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("module-reachability-only", "WP7");
    }
    if (/^unwatchfile$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "fs.unwatchFile mutates the process-wide path watcher registry and can cancel listeners owned by another principal.",
      );
    }
    if (/watch/u.test(name)) {
      return effectSpec(["fs:list", "fs:watch"], "filesystem", "WP5", {
        lifetimeContract: "watch",
      });
    }
    if (/^opendir(?:sync)?$/u.test(name)) {
      return effectSpec(["fs:list"], "filesystem", "WP5", {
        lifetimeContract: "file-handle",
      });
    }
    if (/open/u.test(name)) {
      return filesystemOpenEffectSpec();
    }
    if (/copy|^cp(?:sync)?$|^link(?:sync)?$/u.test(name)) {
      return effectSpec(["fs:read", "fs:write"], "filesystem", "WP5");
    }
    if (/readlink|readfile|^read(?:sync|v|vsync)?$|sendfile/u.test(name)) {
      return effectSpec(["fs:read"], "filesystem", "WP5", {
        lifetimeContract: /readstream/u.test(name)
          ? "file-handle"
          : "operation",
      });
    }
    if (/access|exists|stat|lstat|readdir|opendir|realpath|glob/u.test(name)) {
      return effectSpec(["fs:list"], "filesystem", "WP5");
    }
    if (/^createreadstream$/u.test(name)) {
      return filesystemStreamConstructionEffectSpec("fs:read");
    }
    if (/^createwritestream$/u.test(name)) {
      return filesystemStreamConstructionEffectSpec("fs:write");
    }
    if (/close/u.test(name))
      return nonCapabilitySpec("authority-release", "WP5");
    if (
      /write|append|chmod|chown|mkdir|mkdtemp|rm|rmdir|unlink|rename|symlink|truncate|utimes|lutimes|fdatasync|fsync/u.test(
        name,
      )
    ) {
      return effectSpec(["fs:write"], "filesystem", "WP5", {
        lifetimeContract: /^f|^write|^append/u.test(name)
          ? "file-handle"
          : "operation",
      });
    }
    if (/^(?:dirnextentry|dirread|dirreadsync)$/u.test(name)) {
      return effectSpec(["fs:list"], "filesystem", "WP5", {
        lifetimeContract: "file-handle",
      });
    }
    if (/^(?:filehandleread|filehandlereadv)$/u.test(name)) {
      return effectSpec(["fs:read"], "filesystem", "WP5", {
        lifetimeContract: "file-handle",
      });
    }
    if (/^filehandlefd$/u.test(name)) {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "Raw live file-descriptor export is closed until descriptor ownership and transfer are authenticated.",
      );
    }
    if (
      /^(?:dirpath|direntisblockdevice|direntischaracterdevice|direntisdirectory|direntisfifo|direntisfile|direntissocket|direntissymboliclink|tounixtimestamp)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP5");
    }
    if (/^(?:filehandleemit|filehandleon)$/u.test(name)) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP5");
    }
  }

  if (source === "node_child_process") {
    if (
      /^(?:spawn|spawnsync|exec|execsync|execfile|execfilesync|fork)$/u.test(
        name,
      )
    ) {
      return processLaunchEffectSpec();
    }
    if (/^childprocessspawn$/u.test(name)) {
      return processLaunchEffectSpec();
    }
    if (/^childprocesskill$/u.test(name)) {
      return closedSpec(
        "process:signal",
        "WP7",
        "Child-process signaling is closed.",
      );
    }
    if (
      /^childprocess(?:send|completeipcsendentry|enqueueipcpacket|failpendingipcsends|finalizedisconnect|flushipcsendqueue|ipcwritechunk|scheduleipcflush)$/u.test(
        name,
      )
    ) {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "Child-process IPC and its internal queue operations are closed.",
      );
    }
    if (/^childprocessdisconnect$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP7");
    }
    if (/^childprocess(?:ref|unref)$/u.test(name)) {
      return nonCapabilitySpec("authority-control-plane", "WP7");
    }
    if (/^childprocess$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP7");
    }
  }

  if (source === "node_dns" || source === "node_dns_promises") {
    if (
      /^(?:lookup|lookupservice|resolve|resolve4|resolve6|resolveany|resolvecaa|resolvecname|resolvemx|resolvenaptr|resolvens|resolveptr|resolvesoa|resolvesrv|resolvetxt|reverse)$/u.test(
        name,
      )
    ) {
      if (/^(?:lookup|lookupservice)$/u.test(name)) {
        return effectSpec(["network:resolve"], "network", "WP6");
      }
      return dnsResolverEffectSpec("network.dns.module-resolver");
    }
    if (/^(?:setservers|setdefaultresultorder)$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Module-level DNS server and result-order setters mutate resolver defaults shared by other principals.",
      );
    }
    if (
      /^resolver(?:resolve|resolve4|resolve6|resolveany|resolvecaa|resolvecname|resolvemx|resolvenaptr|resolvens|resolveptr|resolvesoa|resolvesrv|resolvetxt|reverse)$/u.test(
        name,
      )
    ) {
      return dnsResolverEffectSpec("network.dns.resolver");
    }
    if (/^resolvercancel$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    if (/^resolver(?:getservers|setlocaladdress|setservers)$/u.test(name)) {
      return nonCapabilitySpec("authority-control-plane", "WP6");
    }
    if (
      /^(?:resolver|promises|addrgetnetworkparams|badfamily|badflags|badhints|badname|badquery|badresp|badstr|cancelled|connrefused|destruction|eof|file|formerr|loadiphlpapi|nodata|nomem|noname|notfound|notimp|notinitialized|refused|servfail|timeout|getdefaultresultorder|getservers)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP6");
    }
  }

  if (source === "node_http" || source === "node_https") {
    if (/^(?:request|get)$/u.test(name)) {
      return effectSpec(["network:connect"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (/^(?:createserver|server)$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP6");
    }
    if (source === "node_http") {
      if (/^(?:globalagent|parsers|setmaxidlehttpparsers)$/u.test(name)) {
        return closedSpec(
          "runtime:inspect",
          "WP7",
          "The HTTP global agent, parser pool, and parser-pool limit are shared process-wide runtime state.",
        );
      }
      if (/^agentdestroy$/u.test(name)) {
        return nonCapabilitySpec("authority-release", "WP6");
      }
      if (api === "clientrequest._abortsignallistener") {
        return nonCapabilitySpec("authority-release", "WP6");
      }
      if (/^agent(?:\.|$)/u.test(api)) {
        return optionalNetworkEffectSpec(
          "network:connect",
          "network.http-agent.operation",
        );
      }
      if (/^clientrequest(?:abort|destroy)$/u.test(name)) {
        return nonCapabilitySpec("authority-release", "WP6");
      }
      if (/^clientrequestcleartimeout$/u.test(name)) {
        return nonCapabilitySpec("authority-control-plane", "WP6");
      }
      if (/^clientrequest(?:\.|$)/u.test(api)) {
        return optionalNetworkEffectSpec(
          "network:connect",
          "network.http-client-request.operation",
        );
      }
      if (/^(?:incomingmessage|outgoingmessage|websocket)(?:\.|$)/u.test(api)) {
        return retainedNetworkOriginEffectSpec(
          ["network:connect", "network:listen"],
          "network.http-message.origin",
        );
      }
      if (
        /^server(?:close|closeallconnections|closeidleconnections)$/u.test(name)
      ) {
        return nonCapabilitySpec("authority-release", "WP6");
      }
      if (/^server(?:ref|unref)$/u.test(name)) {
        return nonCapabilitySpec("authority-control-plane", "WP6");
      }
      if (/^serverconstructor$/u.test(name)) {
        return nonCapabilitySpec("unbound-owned-resource", "WP6");
      }
      if (/^serverlisten$/u.test(name)) {
        return effectSpec(["network:listen"], "network", "WP6", {
          lifetimeContract: "listener",
        });
      }
      if (/^server(?:\.|$)/u.test(api)) {
        return optionalNetworkEffectSpec(
          "network:listen",
          "network.http-server.operation",
          { lifetimeContract: "listener" },
        );
      }
      if (/^(?:serverincomingmessage|serverresponse)(?:\.|$)/u.test(api)) {
        return optionalNetworkEffectSpec(
          "network:listen",
          "network.http-server-message.operation",
        );
      }
      if (
        /^(?:closeevent|httpparser|messageevent|methods|statuscodes|kconnectionscheckinginterval|khighwatermark|ktimeout|maxheadersize|checkinvalidheaderchar|checkishttptoken|validateheadername|validateheadervalue)$/u.test(
          name,
        )
      ) {
        return nonCapabilitySpec("pure-in-memory-compute", "WP6");
      }
    } else {
      if (/^globalagent$/u.test(name)) {
        return closedSpec(
          "runtime:inspect",
          "WP7",
          "The HTTPS global agent is a shared process-wide connection pool and mutable runtime registry.",
        );
      }
      if (/^agent(?:\.|$)/u.test(api)) {
        return optionalNetworkEffectSpec(
          "network:connect",
          "network.https-agent.operation",
        );
      }
      if (/^server(?:\.|$)/u.test(api)) {
        if (/^serverconstructor$/u.test(name)) {
          return nonCapabilitySpec("unbound-owned-resource", "WP6");
        }
        return optionalNetworkEffectSpec(
          "network:listen",
          "network.https-server.operation",
          { lifetimeContract: "listener" },
        );
      }
    }
  }

  if (source === "node_http2") {
    if (/^connect$/u.test(name)) {
      return effectSpec(["network:connect"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (/^(?:createserver|createsecureserver)$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP6");
    }
    if (/^performserverhandshake$/u.test(name)) {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "listener",
      });
    }
    if (/^(?:http2serverrequest|http2serverresponse)(?:\.|$)/u.test(api)) {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (
      /^(?:constants|getdefaultsettings|getpackedsettings|getunpackedsettings|sensitiveheaders)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP6");
    }
  }

  if (source === "node_net") {
    if (/^(?:connect|createconnection)$/u.test(name)) {
      return inetOrUnixNetworkEffectSpec(
        "network:connect",
        "fs:read",
        "network.connect.address-kind",
      );
    }
    if (/^createserver$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP6");
    }
    if (/^serverlisten$/u.test(name)) {
      return inetOrUnixNetworkEffectSpec(
        "network:listen",
        "fs:write",
        "network.listen.address-kind",
      );
    }
    if (/^server(?:close)$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    if (/^server(?:ref|unref)$/u.test(name)) {
      return nonCapabilitySpec("authority-control-plane", "WP6");
    }
    if (/^(?:server|serverconstructor)$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP6");
    }
    if (/^server(?:\.|$)/u.test(api)) {
      return optionalNetworkEffectSpec(
        "network:listen",
        "network.net-server.operation",
        { lifetimeContract: "listener" },
      );
    }
    if (/^(?:socket|stream)connect$/u.test(name)) {
      return inetOrUnixNetworkEffectSpec(
        "network:connect",
        "fs:read",
        "network.socket.connect.address-kind",
      );
    }
    if (/^(?:socket|stream)(?:close|destroy|resetanddestroy)$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    if (/^(?:socket|stream)(?:ref|unref)$/u.test(name)) {
      return nonCapabilitySpec("authority-control-plane", "WP6");
    }
    if (/^(?:socket|stream)\._abortlistener$/u.test(api)) {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    if (
      /^(?:socket|stream)\.(?:_connecting|buffersize|byteswritten|readablehighwatermark|writablecorked|writableended|writablehighwatermark|writablelength|writableneeddrain)$/u.test(
        api,
      )
    ) {
      return retainedNetworkOriginEffectSpec(
        ["network:connect", "network:listen"],
        "network.socket.metadata-origin",
      );
    }
    if (/^(?:socket|stream)$/u.test(name)) {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "Net Socket/Stream construction can adopt raw fd, handle, or _handle options; the no-argument allocation branch must be split before it can remain non-capability.",
      );
    }
    if (/^(?:socket|stream)(?:\.|$)/u.test(api)) {
      return retainedNetworkOriginEffectSpec(
        ["network:connect", "network:listen"],
        "network.socket.operation-origin",
      );
    }
    if (
      /^blocklist(?:\.|$)/u.test(api) ||
      /^(?:socketaddress|normalizeargs|isip|isipv4|isipv6|getdefaultautoselectfamily|getdefaultautoselectfamilyattempttimeout)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP6");
    }
    if (/^setdefaultautoselectfamily(?:attempttimeout)?$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Default connection-family selection mutates process-wide network behavior shared by other principals.",
      );
    }
  }

  if (source === "node_dgram") {
    if (/createsocket/u.test(name))
      return nonCapabilitySpec("unbound-owned-resource", "WP6");
    if (/^socketbind$/u.test(name)) {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (/^socket(?:connect|send|sendto)$/u.test(name)) {
      return udpSendEffectSpec();
    }
    if (/^socketstartrecv$/u.test(name)) {
      return retainedNetworkOriginEffectSpec(
        ["network:connect", "network:listen"],
        "network.udp.receive-origin",
      );
    }
    if (/^socket(?:fromfd|getfd)$/u.test(name)) {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "Raw descriptor adoption and exposure are closed until descriptor transfer is authenticated.",
      );
    }
    if (/^socket(?:close|disconnect)$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    if (/^socketaddmembership$/u.test(name)) {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (/^socketaddsourcespecificmembership$/u.test(name)) {
      // The current compatibility implementation validates bound state but
      // performs no native membership operation.
      return nonCapabilitySpec("pure-in-memory-compute", "WP6");
    }
    if (/^socketdropmembership$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    if (/^socketdropsourcespecificmembership$/u.test(name)) {
      // Like its add counterpart, this is currently only a bound-state check.
      return nonCapabilitySpec("pure-in-memory-compute", "WP6");
    }
    if (
      /^socket(?:ref|unref|setbroadcast|setmulticastinterface|setmulticastloopback|setmulticastttl|setrecvbuffersize|setsendbuffersize|setttl)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("authority-control-plane", "WP6");
    }
    if (
      /^socket(?:address|constructor|getrecvbuffersize|getsendbuffersize|remoteaddress)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP6");
    }
    if (/^socket$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP6");
    }
  }

  if (source === "node_cluster") {
    if (/^fork$/u.test(name)) {
      return processLaunchEffectSpec();
    }
    if (/^disconnect$/u.test(name)) {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "cluster.disconnect enumerates the process-wide worker registry and disconnects shared child IPC channels.",
      );
    }
    if (/^(?:setupmaster|setupprimary)$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Cluster setup mutates process-wide defaults used by subsequent worker creation.",
      );
    }
    if (
      /^(?:nextworkerid|schedulingpolicy|settings|worker|workers)$/u.test(name)
    ) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Cluster worker registries, identifiers, scheduling policy, and settings are shared mutable process state.",
      );
    }
    if (/^(?:schednone|schedrr|ismaster|isprimary|isworker)$/u.test(name)) {
      return nonCapabilitySpec("runtime-bootstrap-state", "WP7");
    }
  }

  if (source === "node_console" && /^console$/u.test(name)) {
    return nonCapabilitySpec("module-reachability-only", "WP7");
  }

  if (source === "node_tls") {
    if (/^setdefaultcacertificates$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Changing the default CA certificate set mutates shared process-wide TLS trust state.",
      );
    }
    if (/^connect$/u.test(name)) {
      return effectSpec(["network:connect"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (/^(?:createserver|server)$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP6");
    }
  }

  if (source === "ws") {
    if (/^(?:websocket|createwebsocketstream)$/u.test(name)) {
      return effectSpec(["network:connect"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (/server|websocketserver/u.test(name)) {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "listener",
      });
    }
  }

  if (source === "node_os") {
    if (/^setpriority$/u.test(name)) {
      return closedSpec(
        "process:priority",
        "WP7",
        "Process priority mutation is closed.",
      );
    }
    if (!/^(?:constants|eol|devnull)$/u.test(name)) {
      return effectSpec(["sys:read"], "system", "WP7");
    }
    return nonCapabilitySpec("pure-in-memory-compute", "WP7");
  }

  if (source === "node_readline") {
    if (/clearline|clearscreendown|cursorto|movecursor/u.test(name)) {
      return effectSpec(["stdio:write"], "stdio", "WP7");
    }
    if (/^(?:createinterface|interface|interfaceconstructor)$/u.test(name)) {
      return readlineConstructionEffectSpec();
    }
    if (/^emitkeypressevents$/u.test(name)) {
      return readlineOperationEffectSpec("stdio.readline.keypress-streams");
    }
    if (/^interfaceresume$/u.test(name)) {
      return retainedStdioEffectSpec("stdio.readline.resume-state", [
        ["paused", []],
        ["readable", ["stdio:read"]],
      ]);
    }
    if (/^interface(?:close|pause)$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP7");
    }
    if (/^interface\._on(?:abortsignal|close|error)$/u.test(api)) {
      return nonCapabilitySpec("authority-release", "WP7");
    }
    if (/^interface\._on(?:data|end|keypress)$/u.test(api)) {
      return readlineOperationEffectSpec("stdio.readline.delivery-streams");
    }
    if (/^interface(?:\.|$)/u.test(api)) {
      return readlineOperationEffectSpec();
    }
    if (/^(?:csi|promises)$/u.test(name)) {
      return nonCapabilitySpec("module-reachability-only", "WP7");
    }
  }

  if (source === "node_tty") {
    if (/setrawmode/u.test(name))
      return effectSpec(["stdio:raw"], "stdio", "WP7");
    if (/isatty/u.test(name))
      return effectSpec(["stdio:query"], "stdio", "WP7");
    if (/readstream|writestream/u.test(name)) {
      return ttyDirectionEffectSpec();
    }
  }

  if (source === "node_util" && /^log$/u.test(name)) {
    return effectSpec(["stdio:write"], "stdio", "WP7");
  }

  if (source === "node_v8") {
    if (/heap|setflags/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "V8 heap/runtime inspection is closed.",
      );
    }
    if (/^(?:cacheddataversiontag|deserialize|serialize)$/u.test(name)) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP1");
    }
  }

  if (source === "node_perf_hooks") {
    if (/monitor|histogram|eventloop|timerify/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Runtime performance inspection is closed.",
      );
    }
    if (/performance/u.test(name))
      return nonCapabilitySpec("ordinary-time", "WP1");
    if (/^constants$/u.test(name))
      return nonCapabilitySpec("pure-in-memory-compute", "WP1");
  }

  if (source === "node_trace_events") {
    return closedSpec("runtime:inspect", "WP7", "Runtime tracing is closed.");
  }

  if (source === "node_tls") {
    if (/^tlssocketconnect$/u.test(name)) {
      return effectSpec(["network:connect"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (/^tlssocket(?:close|destroy)$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    if (/^tlssocket(?:ref|unref)$/u.test(name)) {
      return nonCapabilitySpec("authority-control-plane", "WP6");
    }
    if (/^tlssocket$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP6");
    }
    if (
      /^tlssocket\.(?:connecting|destroyed|localaddress|localfamily|localport|readable|remoteaddress|remotefamily|remoteport|writable)$/u.test(
        api,
      )
    ) {
      return retainedNetworkOriginEffectSpec(
        ["network:connect", "network:listen"],
        "network.tls-socket.metadata-origin",
      );
    }
    if (/^tlssocket(?:\.|$)/u.test(api)) {
      return retainedNetworkOriginEffectSpec(
        ["network:connect", "network:listen"],
        "network.tls-socket.operation-origin",
      );
    }
    if (/^serverconstructor$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP6");
    }
    if (
      /^(?:securecontext|clientreneglimit|clientrenegwindow|defaultciphers|defaultecdhcurve|defaultmaxversion|defaultminversion|checkserveridentity|convertalpnprotocols|createsecurecontext|getcacertificates|getciphers|rootcertificates|translatepeercertificate)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP6");
    }
    if (/^setdefaultcacertificates$/u.test(name)) {
      return nonCapabilitySpec("authority-control-plane", "WP6");
    }
  }

  if (source === "ws") {
    if (/^websocketterminate$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    if (/^websocket(?:close|ping|pong|send|sendframe)$/u.test(name)) {
      return retainedNetworkOriginEffectSpec(
        ["network:connect", "network:listen"],
        "network.websocket.output-origin",
      );
    }
    if (
      /^websocket(?:appenddata|delivermessage|exceedmaxpayload|handleframe|handletransportclose|processbuffer|startreading)$/u.test(
        name,
      )
    ) {
      return retainedNetworkOriginEffectSpec(
        ["network:connect", "network:listen"],
        "network.websocket.input-origin",
      );
    }
    if (
      /^(?:closed|closing|connecting|open|websocketclosed|websocketclosing|websocketconnecting|websocketopen|websocketbinarytype|websocketreadystate)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP6");
    }
  }

  if (source === "exact_crypto") {
    if (/random|rng|prng|uuid|generate(?:key|prime)|encapsulate/u.test(name)) {
      return nonCapabilitySpec("ordinary-randomness", "WP1");
    }
    if (/^setengine$/u.test(name)) {
      return closedSpec(
        "ffi:load",
        "WP7",
        "Loading an external crypto engine is closed.",
      );
    }
    if (/^(?:setfips|fips)$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "FIPS mode setters and the writable fips export mutate crypto behavior shared by the process.",
      );
    }
    if (/^secureheapused$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Secure heap inspection is closed.",
      );
    }
    // These are the closed computational families and top-level algorithms in
    // exact:crypto. New top-level APIs do not inherit this classification.
    if (
      /^(?:certificate|cipher|cipheriv|decipher|decipheriv|diffiehellman(?:group)?|ecdh|hash|hmac|keyobject|sign|verify|x509certificate)(?:[a-z0-9]*)$/u.test(
        name,
      ) ||
      /^(?:argon2|checkprime|checkprimesync|constants|createcipher|createcipheriv|createdecipher|createdecipheriv|creatediffiehellman|creatediffiehellmangroup|createecdh|createhash|createhmac|createprivatekey|createpublickey|createsecretkey|createsign|createverify|decapsulate|getcipherinfo|getciphers|getcurves|getdiffiehellman|getfips|gethashes|hash|hkdf|hkdfsync|pbkdf2|pbkdf2sync|privatedecrypt|privateencrypt|publicdecrypt|publicencrypt|scrypt|scryptsync|subtle|timingsafeequal|verify|webcrypto)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP1");
    }
  }
  if (source === "node_zlib")
    return nonCapabilitySpec("internal-data-transform", "WP1");

  if (source === "internal_fs_utils") {
    if (/^syncwritestream$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP5");
    }
    if (/^syncwritestreamwrite$/u.test(name)) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP5");
    }
    if (
      /^(?:bigintstats(?:isblockdevice|ischaracterdevice|isdirectory|isfifo|isfile|issocket|issymboliclink)?|getdirent|getdirents|isfd|isfilemode|kminpoolspace|stringtoflags|topathiffileurl|validatefd|validateoffsetlengthread|validateoffsetlengthwrite|validatermoptionssync|validatermdiroptions)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP5");
    }
  }

  if (source === "node_events") {
    if (/^eventemitter$/u.test(name)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP8");
    }
    if (/^eventemitterasyncresource/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "EventEmitterAsyncResource construction and emission participate in the shared async-hook registry.",
      );
    }
    if (
      /^(?:capturerejections|defaultmaxlisteners|setmaxlisteners|eventemitterevents|eventemittermaxlisteners|eventemittersetmaxlisteners|defaultevents|defaultsetmaxlisteners)$/u.test(
        name,
      ) ||
      /^(?:default|eventemitter)\.(?:_events|_maxlisteners|setmaxlisteners)$/u.test(
        exported,
      )
    ) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "EventEmitter static/default settings and prototype defaults mutate behavior shared across principals.",
      );
    }
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }

  if (
    source === "node_stream" ||
    source === "node_stream_consumers" ||
    source === "node_stream_promises" ||
    source === "node_stream_web"
  ) {
    return nonCapabilitySpec("retained-object-wrapper", "WP8");
  }

  if (source === "node_timers" || source === "node_timers_promises") {
    if (/^clear(?:immediate|interval|timeout)$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Timer cancellation accepts a process-global sequential identifier without authenticating the timer owner.",
      );
    }
    if (/close|unenroll/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP8");
    }
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }

  if (source === "node_module") {
    if (/^(?:cache|extensions|pathcache|globalpaths)$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Module caches, extension hooks, path caches, and global search paths are mutable process-wide loader state.",
      );
    }
    if (/^module$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "The Module constructor object directly exposes process-wide caches, extension hooks, and global search paths.",
      );
    }
    if (/^createrequire$/u.test(name)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "createRequire returns a function exposing shared require.cache and main-module state.",
      );
    }
    if (/^(?:nodemodulepaths|builtinmodules|isbuiltin|wrap)$/u.test(name)) {
      return nonCapabilitySpec("module-reachability-only", "WP7");
    }
  }

  if (
    source === "node_assert" ||
    source === "node_buffer" ||
    source === "node_constants" ||
    source === "node_path" ||
    source === "node_punycode" ||
    source === "node_querystring" ||
    source === "node_string_decoder" ||
    source === "node_url"
  ) {
    return nonCapabilitySpec("pure-in-memory-compute", "WP1");
  }

  if (source === "node_util") {
    if (/^debuglog$/u.test(name)) {
      return debugLogEffectSpec();
    }
    if (
      /^(?:textdecoder|textencoder|errnomap|extend|callbackify|deprecate|format|formatwithoptions|getsystemerrorname|inherits|inspect|isdeepstrictequal|parseargs|promisify|types)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP1");
    }
  }

  if (source === "exact_process" && /^off$/u.test(name)) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }

  return null;
}

const REVIEWED_BUILTIN_INHERITED_SHAPE_ID =
  "sha256-93cea4f43ae03d6bd8594c30d94af07b2c1c415793947f2aec25fca93af0de72";

function builtinClassification(surface) {
  const isExport = surface.metadata?.surfaceType === "export";
  const inheritedShape = isExport && surface.metadata?.inheritedShape === true;
  const reviewedInheritedShape =
    inheritedShape &&
    surface.metadata?.inheritedShapeReviewId ===
      REVIEWED_BUILTIN_INHERITED_SHAPE_ID &&
    Array.isArray(surface.metadata?.semanticRoles) &&
    surface.metadata.semanticRoles.includes("inherited-export-shape");
  if (
    (inheritedShape && !reviewedInheritedShape) ||
    (isExport &&
      !REVIEWED_BUILTIN_EXPORT_NAMES.has(surface.name) &&
      !reviewedInheritedShape) ||
    (!isExport && !REVIEWED_BUILTIN_ROOT_NAMES.has(surface.name))
  ) {
    return null;
  }
  if (
    reviewedInheritedShape &&
    /\[\[dynamic-table:inherited-[a-f0-9]+-properties\]\]/u.test(
      String(surface.metadata?.exportName ?? ""),
    )
  ) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "The exact inherited property source is not statically enumerable; the reviewed sentinel keeps its entire reachable prototype shape closed.",
    );
  }
  const source = String(surface.metadata?.sourceKey ?? "").toLowerCase();
  // Escape-module membership comes from the scanner's exact source key. Do
  // not infer it from substrings in an unrelated export such as
  // `DiffieHellman`, `toPathIfFileURL`, or `ZSTD_c_nbWorkers`.
  if (source === "node_inspector") {
    return closedSpec(
      "inspector:activate",
      "WP7",
      "Inspector reachability is closed until authenticated activation and runtime-inspection gates exist.",
    );
  }
  if (source === "node_vm") {
    return closedSpec(
      "vm:evaluate",
      "WP7",
      "Package-controlled VM evaluation is closed in the initial profile.",
    );
  }
  if (source === "node_worker_threads") {
    return closedSpec(
      "worker:create",
      "WP7",
      "Worker creation is closed until principal and callback attribution are preserved.",
    );
  }
  if (source === "node_wasi") {
    return closedSpec(
      "wasi:instantiate",
      "WP7",
      "WASI instantiation is closed in the initial profile.",
    );
  }
  if (source === "ffi" || source === "native_addon" || source === "node_ffi") {
    return closedSpec(
      "ffi:load",
      "WP7",
      "Native extension loading is closed in the initial profile.",
    );
  }
  if (isExport) {
    return builtinExportClassification(surface);
  }
  const moduleInitialization =
    builtinModuleInitializationClassification(source);
  if (moduleInitialization) return moduleInitialization;
  return nonCapabilitySpec("module-reachability-only", "WP7");
}

function callbackClassification(surface) {
  const name = surface.name.toLowerCase();

  if (
    new Set([
      "android-platform-event",
      "host-call-async-resolve",
      "ios-dispatch",
      "ios-dispatch-debug-context",
      "ios-module-dispatch",
      "ios-module-sync",
      "worklet-measure",
      "worklet-scheduled-drain",
    ]).has(name)
  ) {
    return closedSpec(
      "ipc:channel",
      "WP8",
      "Embedder and worklet callback data channels remain closed until their typed payload and attribution are proved.",
    );
  }

  if (name === "websocket-context-release") {
    return nonCapabilitySpec("authority-release", "WP8");
  }

  if (name === "callback.queue-enqueue") {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }

  if (
    new Set([
      "android-animation-frame",
      "dns-async-delivery",
      "fetch-delivery",
      "filesystem-async-delivery",
      "http-wait-delivery",
      "http-writable-delivery",
      "microtask-drain",
      "native-principal-restore",
      "next-tick-drain",
      "queue-drain",
      "queue-enqueue",
      "signal-delivery",
      "timer-invoke",
      "watchdog-heartbeat",
      "websocket-binary-delivery",
      "websocket-bytes-sent-delivery",
      "websocket-close-delivery",
      "websocket-error-delivery",
      "websocket-open-delivery",
      "websocket-text-delivery",
    ]).has(name)
  ) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }

  const producerMatch =
    /^producer:src\/engine\/hermes_runtime(?:_(?:android|crypto|dns|fetch|fs|fs_windows|http|websocket))?\.cc:(.+):pushruntimecallback$/u.exec(
      name,
    );
  if (
    producerMatch &&
    REVIEWED_CALLBACK_PRODUCER_NAMES.has(surface.name) &&
    surface.metadata?.evidenceType === "push-runtime-callback-producer" &&
    surface.metadata?.producer === "pushRuntimeCallback" &&
    Number.isInteger(surface.metadata?.occurrenceCount) &&
    surface.metadata.occurrenceCount > 0 &&
    String(surface.metadata?.enclosingDefinition ?? "").toLowerCase() ===
      producerMatch[1]
  ) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }

  return null;
}

function loaderClassification(surface) {
  const name = surface.name.toLowerCase();
  const loaderOptions = {
    principalSources: ["loader-referrer"],
    effectOwnerSource: "loader-referrer",
    gate: "loader-admission",
  };
  const fullLoaderEffects = () => fullLoaderEffectSpec(loaderOptions);

  // Escape hatches precede both source-derived function and kind families.
  if (/wasi|wasm/u.test(name)) {
    return closedSpec(
      "wasi:instantiate",
      "WP7",
      "Wasm/WASI loader escape surfaces are closed.",
    );
  }
  if (/native[_ .-]?addon|nativeaddon|ffi|dlopen/u.test(name)) {
    return closedSpec(
      "ffi:load",
      "WP7",
      "Native addon loading is closed in the initial profile.",
    );
  }
  if (/inspector|debugger|debug|cdp/u.test(name)) {
    return closedSpec(
      "inspector:activate",
      "WP7",
      "Inspector loader reachability is closed.",
    );
  }
  if (/worker|worklet/u.test(name)) {
    return closedSpec(
      "worker:create",
      "WP7",
      "Worker loader reachability is closed until principal isolation is proved.",
    );
  }
  if (/eval|bytecode/u.test(name)) {
    return closedSpec(
      "vm:evaluate",
      "WP7",
      "Ad-hoc loader evaluation and bytecode entry are closed.",
    );
  }

  // These rows prove that a loader category reaches an external-call site;
  // the qualified operation rows below carry the actual effect classification.
  if (name.startsWith("external-calls:")) {
    return nonCapabilitySpec("module-reachability-only", "WP7");
  }

  if (name.startsWith("entry:")) {
    if (/^entry:(?:require-resolve|resolve-path)$/u.test(name)) {
      return loaderSourceSelectionEffectSpec(loaderOptions);
    }
    if (name === "entry:load-internal") {
      return nonCapabilitySpec("module-reachability-only", "WP7");
    }
    return fullLoaderEffects(
      "Loader entry points may resolve and read source, populate the transpile cache, and invoke an environment-selected transform process.",
    );
  }

  if (name.startsWith("internal-route:")) {
    return nonCapabilitySpec("module-reachability-only", "WP7");
  }

  if (name.startsWith("lazy-installer:")) {
    return nonCapabilitySpec("authority-control-plane", "WP4");
  }

  if (name.startsWith("transform-engine:")) {
    return nonCapabilitySpec("internal-data-transform", "WP1");
  }

  if (name.startsWith("operation:")) {
    const operation = name.split(":").at(-1);
    if (/^(?:canonicalize|metadata|read_dir)$/u.test(operation)) {
      return effectSpec(["fs:list"], "loader", "WP7", loaderOptions);
    }
    if (/^(?:read|read_to_string)$/u.test(operation)) {
      return effectSpec(["fs:read"], "loader", "WP7", loaderOptions);
    }
    if (
      /^(?:create|create_dir_all|remove_dir_all|remove_file|rename|write)$/u.test(
        operation,
      )
    ) {
      return effectSpec(
        ["fs:list", "fs:write"],
        "loader",
        "WP7",
        loaderOptions,
      );
    }
    if (operation === "env-var") {
      return effectSpec(["env:read"], "environment", "WP7");
    }
    if (/^(?:env-current_dir|env-temp_dir|process-id)$/u.test(operation)) {
      return effectSpec(["sys:read"], "system", "WP7");
    }
    if (/^(?:command-new|new)$/u.test(operation)) {
      return nonCapabilitySpec("unbound-owned-resource", "WP7");
    }
    if (operation === "status") {
      return fullLoaderEffects(
        "Command.status commits an environment-selected transform subprocess with inherited stdio.",
      );
    }
    return null;
  }

  if (name.startsWith("route:")) {
    const functionName = name.split(":").at(-1);
    if (
      /^(?:cache_tag|contains_using_keyword|format_oxc_errors|from_value|is_builtin_specifier|module_kind_from_path|needs_js_downlevel|needs_transpile|output_has_esm_module_syntax|oxc_target|package_name_and_root_in_node_modules|package_name_from_bare_specifier|package_root_in_node_modules|pick_package_import_path|program_has_top_level_await|scan_balanced_region|scan_block_scoped_loop_closures|sha256_hex|skip_ws_and_comments|source_needs_async_downlevel|source_needs_downlevel|source_needs_for_of_scoping_fix|source_needs_loop_scope_downlevel|transpile_source_to_cjs|transpile_target_for_source|transpile_to_cjs|transpile_with_oxc|transpile_with_swc|unique_staged_transpile_input|unique_tmp_path)$/u.test(
        functionName,
      )
    ) {
      return nonCapabilitySpec("internal-data-transform", "WP1");
    }
    if (
      /^(?:selected_engine_cache_tag|selected_transform_engine)$/u.test(
        functionName,
      )
    ) {
      return effectSpec(["env:read"], "environment", "WP7");
    }
    if (
      /^(?:find_package_root|normalize_import_target|transpile_cache_is_valid)$/u.test(
        functionName,
      )
    ) {
      return effectSpec(["fs:list"], "loader", "WP7", loaderOptions);
    }
    if (
      /^(?:read_package_manifest|package_version_for|resolve_meta|resolve_meta_from_bound_package|resolve_package_import|resolve_package_import_target|resolve_with_oxc|resolve_with_oxc_at)$/u.test(
        functionName,
      )
    ) {
      return loaderSourceSelectionEffectSpec(loaderOptions);
    }
    if (
      /^(?:compute_transpile_tooling_hash|module_cache_key|transpile_override_identity|transpile_tooling_hash)$/u.test(
        functionName,
      )
    ) {
      return loaderToolingEffectSpec(loaderOptions);
    }
    if (functionName === "ensure_transpile_cache_dir") {
      return effectSpec(
        ["fs:list", "fs:write"],
        "loader",
        "WP7",
        loaderOptions,
      );
    }
    if (
      /^(?:directory_size|enforce_transpile_cache_quota|prune_transpile_cache_to_limit|publish_transpile_artifact)$/u.test(
        functionName,
      )
    ) {
      return effectSpec(
        ["fs:list", "fs:read", "fs:write"],
        "loader",
        "WP7",
        loaderOptions,
      );
    }
    if (functionName === "read_transpile_cache") {
      return effectSpec(["fs:read"], "loader", "WP7", loaderOptions);
    }
    if (functionName === "touch_transpile_artifact") {
      return effectSpec(["fs:write"], "loader", "WP7", loaderOptions);
    }
    if (
      /^(?:resolve_transpile_cache_dir|transpile_cache_dir)$/u.test(
        functionName,
      )
    ) {
      return loaderCacheEffectSpec(loaderOptions, false);
    }
    if (/^(?:find_js_runner|transpile_script_path)$/u.test(functionName)) {
      return loaderExecutableRouteEffectSpec(loaderOptions);
    }
    if (
      /^(?:load_module_source|load_source|load_source_bytes|resolve|run_transpile_command|run_transpile_override|run_transpile_subprocess|transpile_module)$/u.test(
        functionName,
      )
    ) {
      return fullLoaderEffects(
        "This transitive loader route may resolve/read source, update the cache, and invoke an environment-selected transform subprocess.",
      );
    }
    if (functionName === "wait_for_transpile_test_barrier") {
      return effectSpec(
        ["env:read", "fs:list", "fs:read", "fs:write"],
        "loader",
        "WP7",
        loaderOptions,
      );
    }
    return null;
  }

  if (name.startsWith("kind:")) {
    if (/^kind:(?:builtin|commonjs|esm|json)$/u.test(name)) {
      return nonCapabilitySpec("module-reachability-only", "WP7");
    }
    return null;
  }

  if (name.startsWith("function:")) {
    if (
      new Set([
        "function:javascript:importimpl",
        "function:javascript:load",
        "function:javascript:moduledynamicimport",
        "function:rust:load_module_source",
        "function:rust:load_source",
        "function:rust:load_source_bytes",
        "function:rust:resolve_meta_from_bound_package",
        "function:rust:resolve",
        "function:rust:resolve_with_oxc_at",
      ]).has(name)
    ) {
      return fullLoaderEffectSpec(loaderOptions);
    }
    if (name === "function:rust:is_builtin_specifier") {
      return nonCapabilitySpec("module-reachability-only", "WP7");
    }
    if (name === "function:rust:normalize_import_target") {
      return effectSpec(["fs:list"], "loader", "WP7", loaderOptions);
    }
    if (
      new Set([
        "function:rust:module_cache_key",
        "function:rust:resolve_transpile_cache_dir",
      ]).has(name)
    ) {
      return loaderCacheEffectSpec(loaderOptions, true);
    }
    if (name === "function:rust:transpile_module") {
      return fullLoaderEffectSpec(loaderOptions);
    }
    if (
      new Set([
        "function:javascript:checkimportgate",
        "function:javascript:grantcapabilities",
        "function:javascript:packageprincipalfor",
      ]).has(name)
    ) {
      return nonCapabilitySpec("authority-control-plane", "WP3");
    }
    if (
      new Set([
        "function:javascript:__exactresolvepath",
        "function:javascript:resolvemodulepath",
        "function:rust:package_name_and_root_in_node_modules",
        "function:rust:package_root_in_node_modules",
        "function:rust:pick_package_import_path",
        "function:rust:resolve_meta",
        "function:rust:resolve_meta_from_bound_package",
        "function:rust:resolve_package_import",
        "function:rust:resolve_package_import_target",
        "function:rust:resolve_with_oxc",
        "function:rust:resolve_with_oxc_at",
      ]).has(name)
    ) {
      return loaderSourceSelectionEffectSpec(loaderOptions);
    }
    if (
      new Set([
        "function:javascript:_createnodetestmodule",
        "function:javascript:_getstreambuiltins",
        "function:javascript:_loadnamedstreaminternal",
        "function:javascript:_resolveaborterror",
        "function:javascript:builtincachekeyfor",
        "function:javascript:compilefallbacksource",
        "function:javascript:compilemodulebody",
        "function:javascript:createeventtargetmodule",
        "function:javascript:idtomoduleid",
        "function:javascript:iscompletestaticimportstatement",
        "function:javascript:issamemodule",
        "function:javascript:loadinternal",
        "function:javascript:lookslikecompletemodulestatement",
        "function:javascript:lookslikemodulesyntax",
        "function:javascript:makewindowscryptomodule",
        "function:javascript:restoremoduleid",
        "function:javascript:runfallbackmodule",
        "function:javascript:splitinlinemodulestatements",
        "function:javascript:stripmodulestatementcomments",
        "function:javascript:stripviteimportquery",
        "function:javascript:transformdynamicimport",
        "function:javascript:transformimportmeta",
        "function:javascript:wrapasyncmodule",
        "function:rust:build_builtin_registry",
        "function:rust:is_builtin_specifier",
        "function:rust:module_kind_from_path",
      ]).has(name)
    ) {
      return nonCapabilitySpec("module-reachability-only", "WP7");
    }
    return null;
  }

  if (
    new Set([
      "commonjs-module",
      "dynamic-import",
      "esm-module",
      "json-module",
      "native-resolve",
      "oxc-on-disk-resolution",
      "private-package-import",
      "require-resolve",
    ]).has(name)
  ) {
    return loaderSourceSelectionEffectSpec(loaderOptions);
  }
  if (
    new Set([
      "import-needs",
      "import-policy-bare",
      "import-policy-resolved-path",
      "install",
      "package-principal",
    ]).has(name)
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP3");
  }
  if (
    new Set([
      "builtin-module",
      "empty-specifier-rejection",
      "internal-module",
      "package-compile",
      "unknown-exact-rejection",
      "unsupported-node-rejection",
    ]).has(name)
  ) {
    return nonCapabilitySpec("module-reachability-only", "WP7");
  }
  return null;
}

function cliClassification(surface) {
  const name = surface.name.toLowerCase();

  if (name.includes("debug%20modules")) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "The debug modules command exposes runtime module-source and cache state.",
    );
  }
  if (
    /^(?:debug|command:ibex%20debug)$/u.test(name) ||
    name.includes("inspect")
  ) {
    return closedSpec(
      "inspector:activate",
      "WP7",
      "The production inspector command is closed pending authenticated activation.",
    );
  }
  if (
    /^(?:eval|repl|command:ibex%20eval|command:ibex%20repl)$/u.test(name) ||
    /:(?:eval_code|print_eval):/u.test(name) ||
    name.startsWith("positional:ibex%20eval:")
  ) {
    return closedSpec(
      "vm:evaluate",
      "WP7",
      "Ad-hoc CLI evaluation and REPL entry are closed.",
    );
  }

  if (
    /:(?:allow_all|allow_env_endowments|capsec_allow_advisory|expose_internals|lockdown)(?::|$)/u.test(
      name,
    ) ||
    /:capsec:(?:default:auto|enum:(?:audit|auto|permissive))/u.test(name)
  ) {
    return closedSpec(
      "runtime:inspect",
      "WP9",
      "Public weakening, ambient endowment, internal exposure, or incomplete security-mode selection is closed by the enforced-default profile.",
    );
  }

  if (
    name === "policy" ||
    name.startsWith("command:ibex%20policy") ||
    /option(?:-name)?:ibex:(?:allow|deny|policy|capsec)(?::|$)/u.test(name)
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP3");
  }

  // Every remaining approved row is a command route or parser-only shape
  // (option spelling, arity, value name/action/default, or closed enum member).
  return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
}

const CLOSED_STARTUP_ENVIRONMENT_CONTROLS = new Set([
  "EXACT_ALLOW_INSECURE_CRYPTO",
  "EXACT_WPT_TRUST_LOOPBACK_TLS",
  "EX_DISABLE_BYTECODE_SANITY_CHECK",
  "EX_SKIP_STARTUP_BOOTSTRAP_GLOBALS",
  "EX_SKIP_STARTUP_COMPAT_POLYFILLS",
  "EX_SKIP_STARTUP_CONSOLE_ENHANCE",
  "EX_SKIP_STARTUP_CONSOLE_INIT",
  "EX_SKIP_STARTUP_EXACT_GLOBAL",
  "EX_SKIP_STARTUP_HOST_FUNCTIONS",
  "EX_SKIP_STARTUP_LAZY_GETTERS",
  "EX_SKIP_STARTUP_MODULE_LOADER",
  "EX_SKIP_STARTUP_MODULE_LOADER_SCRIPT",
  "EX_SKIP_STARTUP_SHARED_RUNTIME_BUNDLE",
  "IBEX_CAPSEC_ALLOW_ADVISORY",
  "NODE_TLS_REJECT_UNAUTHORIZED",
]);

const HARNESS_STARTUP_ENVIRONMENT_CONTROLS = new Set([
  "EXACT_COMPAT_BUN",
  "EXACT_COMPAT_EXEC_ARGV",
  "EXACT_COMPAT_TEST",
  "EXACT_RAW_ARGV0",
  "EXACT_TEST_ID",
  "EXACT_TEST_MODULE",
  "EXACT_TEST_SECTION",
  "EXACT_WPT_FIXTURE_CLOSE_SEMANTICS",
  "IBEX_CAPSEC_ADAPTER_EVIDENCE_OUTPUT",
  "IBEX_CAPSEC_RECIPE_CATALOG",
  "IBEX_TEST_ARMED_CREATE_PAUSE_MS",
  "IBEX_TEST_ARMED_DENY_OPEN_COMMIT",
  "IBEX_TEST_FS_WORKER_MAX_QUEUE",
  "IBEX_TEST_FS_WORKER_THROW_ENQUEUE",
  "IBEX_TEST_HBC_COMPILE_BARRIER",
  "IBEX_TEST_TRANSPILE_INPUT_BARRIER",
]);

const BOOTSTRAP_STARTUP_ENVIRONMENT_CONTROLS = new Set([
  "EXACT_BUNDLER_TIMEOUT_MS",
  "EXACT_CDP_LOG",
  "EXACT_HERMESC_TIMEOUT_MS",
  "EXACT_IPC_SERIALIZATION",
  "EXACT_LOOP_TRACE",
  "EXACT_QUIET",
  "EX_BOOTSTRAP_GLOBALS_HBC",
  "EX_BOOTSTRAP_GLOBALS_SOURCE",
  "EX_COMPAT_POLYFILLS_HBC",
  "EX_COMPAT_POLYFILLS_SOURCE",
  "EX_CONSOLE_ENHANCE_HBC",
  "EX_CONSOLE_ENHANCE_SOURCE",
  "EX_EXACT_GLOBAL_HBC",
  "EX_EXACT_GLOBAL_SOURCE",
  "EX_FORM_DATA_HBC",
  "EX_FORM_DATA_SOURCE",
  "EX_IPC_LISTENER_HBC",
  "EX_IPC_LISTENER_SOURCE",
  "EX_LAZY_GETTERS_HBC",
  "EX_LAZY_GETTERS_SOURCE",
  "EX_MODULE_LOADER_HBC",
  "EX_MODULE_LOADER_SOURCE",
  "EX_NO_BYTECODE",
  "EX_NO_DISK_RUNTIME_FALLBACK",
  "EX_PROCESS_COMPAT_FIX_HBC",
  "EX_PROCESS_COMPAT_FIX_SOURCE",
  "EX_REPL_PROMPT",
  "EX_SHARED_RUNTIME_BUNDLE_SOURCE",
  "EX_STARTUP_TRACE",
  "EX_STREAM_ENHANCE_HBC",
  "EX_STREAM_ENHANCE_SOURCE",
  "EX_WEB_CRYPTO_HBC",
  "EX_WEB_CRYPTO_SOURCE",
  "EX_WEB_STORAGE_HBC",
  "EX_WEB_STORAGE_SOURCE",
  "EX_WEB_STREAMS_POLYFILL",
  "EX_WEB_STREAMS_POLYFILL_HBC",
  "EX_WEB_STREAMS_POLYFILL_SOURCE",
  "IBEX_AWAIT_UNWRAP_TIMEOUT_MS",
  "IBEX_CDP_LOG",
  "IBEX_HERMESC_TIMEOUT_MS",
  "IBEX_LOOP_TRACE",
  "IBEX_NO_BYTECODE",
  "IBEX_NO_DISK_RUNTIME_FALLBACK",
  "IBEX_QUIET",
  "IBEX_REPL_PROMPT",
  "IBEX_STARTUP_TRACE",
  "IBEX_WATCH_SHUTDOWN_TIMEOUT_MS",
  "EXACT_WATCH_SHUTDOWN_TIMEOUT_MS",
  "EXACT_CLUSTER_ID",
  "EXACT_CLUSTER_WORKER",
  "NODE_UNIQUE_ID",
]);

const FILE_STARTUP_ENVIRONMENT_CONTROLS = new Set([
  "EXACT_POLICY",
  "EXACT_REPO_ROOT",
  "IBEX_POLICY",
  "IBEX_REPO_ROOT",
  "NODE_EXTRA_CA_CERTS",
]);

const MUTABLE_ANDROID_STARTUP_PATHS = new Set([
  "EXACT_ANDROID_CACHE_DIR",
  "EXACT_ANDROID_CODE_CACHE_DIR",
  "EXACT_ANDROID_EXTERNAL_FILES_DIR",
  "EXACT_ANDROID_FILES_DIR",
  "EXACT_ANDROID_NO_BACKUP_FILES_DIR",
]);

const DIAGNOSTIC_STARTUP_ENVIRONMENT_CONTROLS = new Set([
  "EXACT_DEBUG_EMIT_LISTENER",
  "EXACT_PIPELINE_DEBUG",
  "EXACT_PIPELINE_STATE_DEBUG",
  "EXACT_SECURITY_LOG",
  "IBEX_SUPPRESS_CONSOLE_MIRROR",
  "NODE_DEBUG",
]);

const ORDINARY_STARTUP_ENVIRONMENT_READS = new Set([
  "CI",
  "HOME",
  "HOST",
  "HOSTNAME",
  "IBEX_BUNDLE_CACHE_MAX_BYTES",
  "IBEX_TRANSPILE_CACHE_MAX_BYTES",
  "NODE_ENV",
  "TEMP",
  "TEST",
  "TMP",
  "TMPDIR",
  "USERNAME",
  "USERPROFILE",
]);

const RUNTIME_TRANSFORM_ENVIRONMENT_CONTROLS = new Set([
  "EXACT_RUNTIME_TRANSFORM",
  "IBEX_RUNTIME_TRANSFORM",
]);

function startupEnvironmentClassification(surface) {
  if (surface.name.startsWith("env:<dynamic>:")) {
    if (
      surface.metadata?.evidenceType !==
        "dynamic-runtime-environment-sentinel" ||
      surface.metadata?.dynamic !== true ||
      !Array.isArray(surface.metadata?.accessDirections) ||
      surface.metadata.accessDirections.length === 0
    ) {
      return null;
    }
    const actions = [];
    if (surface.metadata.accessDirections.includes("read")) {
      actions.push("env:read");
    }
    if (
      surface.metadata.accessDirections.includes("write") ||
      surface.metadata.accessDirections.includes("unset")
    ) {
      actions.push("env:write");
    }
    if (actions.length === 0) return null;
    return dynamicEnvironmentAccessEffectSpec(actions);
  }

  if (surface.name === "env:__exactEnvProxy") {
    if (
      surface.metadata?.evidenceType !== "static-runtime-environment-control" ||
      !surface.metadata?.accessDirections?.includes("read")
    ) {
      return null;
    }
    return closedSpec(
      "runtime:inspect",
      "WP9",
      "The process.env proxy marker can suppress value-normalization wrapping and is closed under the enforced-default profile.",
    );
  }

  const match = /^env:([A-Za-z][A-Za-z0-9_]*)$/u.exec(surface.name);
  if (!match) return null;
  const authoredEnvironmentName = match[1];
  const environmentName = authoredEnvironmentName.toUpperCase();
  const accessDirections = surface.metadata?.accessDirections ?? [];
  const writesEnvironment =
    accessDirections.includes("write") || accessDirections.includes("unset");

  if (CLOSED_STARTUP_ENVIRONMENT_CONTROLS.has(environmentName)) {
    return closedSpec(
      "runtime:inspect",
      "WP9",
      `${environmentName} can weaken, widen, or replace shared runtime security and trust behavior.`,
    );
  }
  if (
    environmentName === "EXACT_IPC_FD" ||
    environmentName === "NODE_CHANNEL_FD" ||
    environmentName === "EXACT_IPC_SERIALIZATION"
  ) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      `${environmentName} adopts an ambient inherited descriptor as the process IPC channel.`,
    );
  }
  if (
    new Set(["EXACT_COMPAT_EXEC_ARGV", "EXACT_QUIET", "EXACT_RAW_ARGV0"]).has(
      environmentName,
    ) &&
    writesEnvironment
  ) {
    return environmentValueEffectSpec(
      [
        ...(accessDirections.includes("read") ? ["env:read"] : []),
        "env:write",
        ...(environmentName === "EXACT_QUIET" ? ["stdio:write"] : []),
      ],
      environmentName === "EXACT_QUIET" ? "stdio" : "environment",
      `environment.startup.${environmentName.toLowerCase()}`,
    );
  }
  if (HARNESS_STARTUP_ENVIRONMENT_CONTROLS.has(environmentName)) {
    if (writesEnvironment) {
      return environmentValueEffectSpec(
        ["env:read", "env:write"],
        "environment",
        `environment.startup.${environmentName.toLowerCase()}`,
      );
    }
    return nonCapabilitySpec("runtime-bootstrap-state", "WP9");
  }
  if (RUNTIME_TRANSFORM_ENVIRONMENT_CONTROLS.has(environmentName)) {
    return nonCapabilitySpec("authority-control-plane", "WP7");
  }
  if (BOOTSTRAP_STARTUP_ENVIRONMENT_CONTROLS.has(environmentName)) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }
  if (MUTABLE_ANDROID_STARTUP_PATHS.has(environmentName)) {
    if (accessDirections.length > 0 && !accessDirections.includes("read")) {
      return effectSpec(["env:write"], "environment", "WP7");
    }
    return environmentValueEffectSpec(
      ["env:read", "env:write", "fs:list", "fs:read", "fs:write"],
      "loader",
      `environment.startup.${environmentName.toLowerCase()}`,
    );
  }
  if (FILE_STARTUP_ENVIRONMENT_CONTROLS.has(environmentName)) {
    return environmentValueEffectSpec(
      ["env:read", "fs:list", "fs:read"],
      "loader",
      `environment.startup.${environmentName.toLowerCase()}`,
    );
  }
  if (DIAGNOSTIC_STARTUP_ENVIRONMENT_CONTROLS.has(environmentName)) {
    return environmentValueEffectSpec(
      ["env:read", "stdio:write"],
      "stdio",
      `environment.startup.${environmentName.toLowerCase()}`,
    );
  }
  if (
    new Set([
      "COLORTERM",
      "FORCE_COLOR",
      "NODE_PENDING_DEPRECATION",
      "NO_COLOR",
      "TERM",
    ]).has(environmentName)
  ) {
    return environmentValueEffectSpec(
      ["env:read", "stdio:write"],
      "stdio",
      `environment.startup.${environmentName.toLowerCase()}`,
    );
  }
  if (environmentName === "COLUMNS" || environmentName === "LINES") {
    return environmentValueEffectSpec(
      ["env:read", "stdio:query"],
      "stdio",
      `environment.startup.${environmentName.toLowerCase()}`,
    );
  }
  if (ORDINARY_STARTUP_ENVIRONMENT_READS.has(environmentName)) {
    return writesEnvironment
      ? environmentValueEffectSpec(
          ["env:read", "env:write"],
          "environment",
          `environment.startup.${environmentName.toLowerCase()}`,
        )
      : effectSpec(["env:read"], "environment", "WP7");
  }
  if (environmentName === "IBEX_HTTP_MAX_REQUEST_BODY_BYTES") {
    return environmentSelectedNetworkEffectSpec(
      "network:listen",
      "network.environment.http-max-request-body",
      { lifetimeContract: "listener" },
    );
  }
  if (environmentName === "EXACT_TRANSPILE_SCRIPT") {
    return environmentValueEffectSpec(
      ["env:read", "fs:list", "fs:read", "process:spawn"],
      "loader",
      "environment.startup.exact_transpile_script",
      { lifetimeContract: "child-process" },
    );
  }
  if (
    environmentName === "EXACT_HERMES_TOOL_DIR" ||
    environmentName === "IBEX_HERMES_TOOL_DIR"
  ) {
    return environmentValueEffectSpec(
      ["env:read", "fs:list", "process:spawn"],
      "process",
      `environment.startup.${environmentName.toLowerCase()}`,
      { lifetimeContract: "child-process" },
    );
  }
  if (
    environmentName === "EXACT_EXECUTABLE" ||
    environmentName === "EXACT_COMPAT_EXECUTABLE" ||
    environmentName === "COMSPEC"
  ) {
    return environmentValueEffectSpec(
      [
        "env:read",
        ...(writesEnvironment ? ["env:write"] : []),
        "fs:list",
        "process:spawn",
      ],
      "process",
      `environment.startup.${environmentName.toLowerCase()}`,
      { lifetimeContract: "child-process" },
    );
  }
  if (environmentName === "PATH") {
    return environmentValueEffectSpec(
      ["env:read", "fs:list", "process:spawn"],
      "process",
      "environment.startup.path",
      { lifetimeContract: "child-process" },
    );
  }
  if (
    environmentName === "IBEX_DNS_SERVER" ||
    environmentName === "RES_OPTIONS"
  ) {
    return environmentSelectedNetworkEffectSpec(
      "network:resolve",
      `network.environment.${environmentName.toLowerCase().replaceAll("_", "-")}`,
    );
  }
  if (environmentName === "EXACT_WINHTTP_ENABLE_HTTP2") {
    return environmentSelectedNetworkEffectSpec(
      "network:fetch",
      "network.environment.exact-winhttp-enable-http2",
      { lifetimeContract: "socket-stream" },
    );
  }
  if (environmentName === "IBEX_BIN") {
    return environmentValueEffectSpec(
      ["env:read", "fs:list", "process:spawn"],
      "process",
      "environment.startup.ibex_bin",
      { lifetimeContract: "child-process" },
    );
  }
  if (environmentName === "TZ") {
    return environmentValueEffectSpec(
      ["env:read", "sys:read"],
      "system",
      "environment.startup.tz",
    );
  }
  if (environmentName === "WPT_SERVER_URL") {
    return environmentSelectedNetworkEffectSpec(
      "network:fetch",
      "network.environment.wpt-server-url",
      { lifetimeContract: "socket-stream" },
    );
  }
  return null;
}

function startupClassification(surface) {
  const name = surface.name.toLowerCase();

  if (surface.name.startsWith("env:")) {
    return startupEnvironmentClassification(surface);
  }

  if (surface.metadata?.evidenceType === "startup-evaluation-route") {
    const fallbackMatch =
      /^evaluation:translation-unit-fallback:(capability-hardening|cdp|compartment-registry|eager-install-seal|form-data|freeze-seal|fs-handle|lockdown|web-crypto|web-storage)$/u.exec(
        name,
      );
    if (fallbackMatch) {
      const label = fallbackMatch[1];
      if (
        surface.metadata?.structuralFallback !== "translation-unit" ||
        surface.metadata?.caller !== "translation-unit-fallback" ||
        surface.metadata?.sourceUrl !== `<${label}>`
      ) {
        return null;
      }
      if (label === "cdp") {
        return closedSpec(
          "inspector:activate",
          "WP7",
          "The structurally recovered CDP startup evaluator installs inspector reachability and remains closed.",
        );
      }
      if (label === "form-data") {
        return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
      }
      return nonCapabilitySpec("authority-control-plane", "WP4");
    }
    if (name === "evaluation:ex_hermes_debugger_eval:cdp") {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "The CDP evaluation route executes debugger-controlled source in the inspected runtime.",
      );
    }
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }

  if (surface.metadata?.evidenceType === "startup-installer-call-route") {
    const fallbackMatch =
      /^install-route:translation-unit-fallback:(installChildProcessHostFunctions|installCryptoHostFunctions|installDnsHostFunctions|installFetchGlobals|installFsHostFunctions|installHttpHostFunctions|installIpcListenerPatch|installLegacyLazyBootstrapGetters|installModuleLoader|installNetHostFunctions|installOsInfoGlobals|installProcessSetup|installSqliteHostFunctions|installWebSocketGlobals)$/u.exec(
        surface.name,
      );
    if (fallbackMatch) {
      const installer = fallbackMatch[1];
      if (
        surface.metadata?.structuralFallback !== "translation-unit" ||
        surface.metadata?.caller !== "translation-unit-fallback" ||
        surface.metadata?.installer !== installer
      ) {
        return null;
      }
      if (installer === "installIpcListenerPatch") {
        return closedSpec(
          "ipc:channel",
          "WP7",
          "The structurally recovered IPC listener installer remains closed until its channel and attribution are typed.",
        );
      }
      return nonCapabilitySpec("authority-control-plane", "WP4");
    }
    return nonCapabilitySpec("authority-control-plane", "WP4");
  }

  // Startup evaluation and escape surfaces precede reviewed installer/script
  // families so a dangerous suffix cannot inherit a bootstrap rationale.
  if (/inspector|debugger|cdp/u.test(name)) {
    return closedSpec(
      "inspector:activate",
      "WP7",
      "Inspector startup is closed until its exact target cells are proved.",
    );
  }
  if (/native[_ .-]?addon|nativeaddon|ffi|dlopen/u.test(name)) {
    return closedSpec("ffi:load", "WP7", "Native addon startup is closed.");
  }
  if (/wasi|wasm/u.test(name)) {
    return closedSpec("wasi:instantiate", "WP7", "WASI startup is closed.");
  }
  if (/worker|worklet/u.test(name)) {
    return closedSpec(
      "worker:create",
      "WP7",
      "Worker/worklet startup is closed until principal isolation is proved.",
    );
  }
  if (/eval|bytecode/u.test(name)) {
    return closedSpec(
      "vm:evaluate",
      "WP7",
      "Startup eval and bytecode execution are closed until authenticated entry binding is proved.",
    );
  }
  if (/ipc/u.test(name)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Startup IPC listener installation is closed until its channel is typed and attributed.",
    );
  }

  if (name.startsWith("installer:")) {
    if (
      new Set([
        "installer:installandroidcamerabridge",
        "installer:installandroidenvironmentglobals",
        "installer:installandroidhostfunctions",
        "installer:installandroidlocationbridge",
        "installer:installchildprocesshostfunctions",
        "installer:installconsoleglobals",
        "installer:installcryptohostfunctions",
        "installer:installdnshostfunctions",
        "installer:installfetchglobals",
        "installer:installfshostfunctions",
        "installer:installglobals",
        "installer:installhttphostfunctions",
        "installer:installlegacylazybootstrapgetters",
        "installer:installmoduleloader",
        "installer:installnethostfunctions",
        "installer:installosinfoglobals",
        "installer:installprocesssetup",
        "installer:installsharedruntimebundle",
        "installer:installsqlitehostfunctions",
        "installer:installtimerglobals",
        "installer:installtlshostfunctions",
        "installer:installunsupportedglobal",
        "installer:installunsupportedmodule",
        "installer:installwebsocketglobals",
        "installer:installwebstreamspolyfill",
        "installer:installzlibhostfunctions",
        "installer:installzlibstreamhostfunctions",
      ]).has(name)
    ) {
      return nonCapabilitySpec("authority-control-plane", "WP4");
    }
    return null;
  }

  if (name.startsWith("script:")) {
    if (
      new Set([
        "script:capability-hardening",
        "script:compartment-registry",
        "script:eager-install-seal",
        "script:exact-global",
        "script:freeze-seal",
        "script:fs-handle",
        "script:lazy-getters",
        "script:lockdown",
        "script:module-loader",
        "script:web-crypto",
        "script:web-storage",
      ]).has(name)
    ) {
      return nonCapabilitySpec("authority-control-plane", "WP4");
    }
    if (
      new Set([
        "script:bootstrap",
        "script:compat-polyfills",
        "script:console",
        "script:form-data",
        "script:process-compat-fix",
        "script:process-exit-marker",
        "script:promise-unwrap",
        "script:shared-runtime-bundle",
        "script:stream-enhance",
        "script:stream-stability-patch",
        "script:web-streams-polyfill",
        "script:windows-fetch-shim",
        "script:windows-websocket-shim",
      ]).has(name)
    ) {
      return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
    }
    return null;
  }

  if (name === "scheduler-principal-capture") {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }
  if (
    new Set([
      "capability-hardening-seal",
      "compartment-registry-install",
      "eager-native-seal",
      "freeze-seal",
      "lockdown-install",
    ]).has(name)
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP4");
  }
  if (
    new Set([
      "globals-install",
      "legacy-lazy-bootstrap",
      "legacy-process-compat",
      "module-loader-install",
      "runtime-create",
      "shared-runtime-install",
      "web-streams-install",
    ]).has(name)
  ) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }
  return null;
}

function isDualRoleGlobalNativeOperation(surface) {
  return (
    surface.kind === "native-op" &&
    Array.isArray(surface.metadata?.surfaceTypes) &&
    surface.metadata.surfaceTypes.includes("global-api") &&
    surface.metadata.surfaceTypes.includes("private-native-operation")
  );
}

function privateNativeOperationView(surface) {
  const metadata = {
    ...surface.metadata,
    surfaceType: "private-native-operation",
  };
  delete metadata.surfaceTypes;
  delete metadata.semanticRoles;
  return { ...surface, metadata };
}

function reconcileDualRoleSpecifications(surface, globalSpec, nativeSpec) {
  if (!globalSpec || !nativeSpec) return null;
  if (JSON.stringify(globalSpec) !== JSON.stringify(nativeSpec)) {
    throw new Error(
      `${surface.observedKey}: global API and private native-operation classifications disagree`,
    );
  }
  return nativeSpec;
}

const REVIEWED_SHARED_RUNTIME_INHERITED_SHAPE_ID =
  "sha256-c9c7018e05cebdc8e26bb9d46773b3c06643cfa84cec49d86a401d30a1e7e430";

function reviewedInheritedGlobalShape(surface) {
  return Boolean(
    surface.metadata?.inheritedShape === true &&
    surface.metadata?.inheritedShapeReviewId ===
      REVIEWED_SHARED_RUNTIME_INHERITED_SHAPE_ID &&
    Array.isArray(surface.metadata?.semanticRoles) &&
    surface.metadata.semanticRoles.includes("inherited-global-shape"),
  );
}

function reviewedDynamicGlobalCallShape(surface) {
  const evidence = String(surface.metadata?.dynamicNamespaceEvidence ?? "");
  const memberName = String(surface.metadata?.memberName ?? "");
  const match = memberName.match(
    /(?:^|\.)\[\[dynamic-table:call-result-([a-f0-9]{12})-properties\]\]$/u,
  );
  const root = String(surface.metadata?.dynamicNamespaceRoot ?? "");
  const [globalName, ...memberSegments] = root.split(".");
  const reviewedRoot = globalName
    ? reviewedGlobalSurfaceName(globalName, memberSegments.join("."))
    : "";
  return Boolean(
    match &&
    /^sha256-[a-f0-9]{64}$/u.test(evidence) &&
    evidence.slice("sha256-".length, "sha256-".length + 12) === match[1] &&
    surface.metadata?.dynamicNamespace === true &&
    new Set(["iife-call-result", "opaque-call-result"]).has(
      surface.metadata?.dynamicNamespaceKind,
    ) &&
    Array.isArray(surface.metadata?.semanticRoles) &&
    surface.metadata.semanticRoles.includes("dynamic-call-result-shape") &&
    REVIEWED_GLOBAL_API_NAMES.has(reviewedRoot),
  );
}

function globalApiClassification(surface, dualNativeSpecification = null) {
  const authoredGlobalName = String(surface.metadata?.globalName ?? "");
  const authoredMember = String(surface.metadata?.memberName ?? "");
  const expectedExportName = authoredMember
    ? `${authoredGlobalName}.${authoredMember}`
    : authoredGlobalName;
  const internalGlobal = authoredGlobalName.startsWith("__");
  const dualRole = isDualRoleGlobalNativeOperation(surface);
  const expectedSurfaceName =
    internalGlobal || dualRole
      ? expectedExportName
      : `global:${expectedExportName}`;
  if (
    !authoredGlobalName ||
    surface.metadata?.exportName !== expectedExportName ||
    surface.name !== expectedSurfaceName
  ) {
    return null;
  }
  if (reviewedDynamicGlobalCallShape(surface)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "The exact IIFE call result has a source-bound dynamic property sentinel and remains closed until its returned namespace is enumerated.",
    );
  }
  if (dualRole) {
    const roles = surface.metadata?.semanticRoles;
    if (
      !Array.isArray(roles) ||
      !roles.includes("global-api-installation") ||
      !roles.includes("private-native-operation")
    ) {
      return null;
    }
    return dualNativeSpecification;
  }
  const globalName = authoredGlobalName.toLowerCase();
  const member = authoredMember.toLowerCase();
  const dynamicHostOverlay =
    Array.isArray(surface.metadata?.memberKinds) &&
    surface.metadata.memberKinds.includes("dynamic-table") &&
    Array.isArray(surface.metadata?.semanticRoles) &&
    surface.metadata.semanticRoles.includes("host-object-overlay");

  if (
    reviewedInheritedGlobalShape(surface) &&
    Array.isArray(surface.metadata?.memberKinds) &&
    surface.metadata.memberKinds.includes("inherited-shape") &&
    /^\[\[dynamic-table:inherited-[a-z0-9-]+-properties\]\]$/u.test(
      authoredMember,
    )
  ) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "The external base-class property domain is represented by a reviewed inherited-shape sentinel and remains closed until exact authored members replace it.",
    );
  }

  if (
    (globalName === "process" &&
      /^(?:\[\[dynamic-table:host-process-(?:own|prototype)-properties\]\])$/u.test(
        member,
      )) ||
    (globalName === "intl" &&
      member === "[[dynamic-table:host-intl-properties]]") ||
    (globalName === "__exacthostnavigator" &&
      member === "[[dynamic-table:host-navigator-properties]]")
  ) {
    if (!dynamicHostOverlay) return null;
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Opaque host-object overlays remain closed until the scanner and runtime replace them with exact typed member rows.",
    );
  }

  if (
    globalName === "process" &&
    member === "env.[[dynamic-table:host-process-env-properties]]"
  ) {
    if (!dynamicHostOverlay) return null;
    return dynamicEnvironmentPropertyEffectSpec();
  }

  if (globalName === "intl") {
    if (member === "") {
      return nonCapabilitySpec("module-reachability-only", "WP7");
    }
    return intlHostDefaultsEffectSpec();
  }

  if (globalName === "[[dynamic-table:native-global-name]]") {
    const roles = surface.metadata?.semanticRoles;
    if (
      member !== "" ||
      !Array.isArray(roles) ||
      !roles.includes("runtime-property-overlay")
    ) {
      return null;
    }
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "An opaque native global-name table cannot prove which callable or shared object becomes reachable.",
    );
  }

  if (/^(?:badly|failed|ok)$/u.test(globalName)) {
    if (
      member !== "" ||
      surface.metadata?.semanticRole !== "harness-only-compat-global"
    ) {
      return null;
    }
    return nonCapabilitySpec("runtime-bootstrap-state", "WP9");
  }

  if (/^(?:__dirname|__filename)$/u.test(globalName)) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }
  if (/^__exact(?:allownativessyntax|compateval)$/u.test(globalName)) {
    return closedSpec(
      "vm:evaluate",
      "WP7",
      "Compatibility evaluation and native-syntax switches are closed with the other dynamic-code surfaces.",
    );
  }
  if (
    /^__exact(?:debugmodulesource|debugmodulesources|memorydebug|memorydebugstate|finalversions)/u.test(
      globalName,
    )
  ) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Debug source, heap, sample, and runtime-version globals expose process-wide diagnostic state.",
    );
  }
  if (/^__exact(?:accessibilitysnapshot|appearancestate)$/u.test(globalName)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Embedder accessibility and appearance mirrors disclose external application state through a shared object.",
    );
  }
  if (/^__exactaccessibilitystate$/u.test(globalName)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "The accessibility state object contains process-wide listeners, timers, and mutable snapshots.",
    );
  }
  if (
    /^__exact(?:accessibilitychanged|localechanged|windownotifymediachange|windownotifyresize)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }
  if (/^__exactunhandledrejectionhandler$/u.test(globalName)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "The rejection handler invokes the shared process-wide rejection-listener registry.",
    );
  }
  if (/^__exactandroidcamerametadata$/u.test(globalName)) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }
  if (/^__exactandroidlocation$/u.test(globalName)) {
    return effectSpec(["device:location"], "device", "WP8");
  }
  if (/^__exact(?:androidstoragepaths|localesnapshot)$/u.test(globalName)) {
    return effectSpec(["sys:read"], "system", "WP7");
  }
  if (/^__exactlocalestate$/u.test(globalName)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "The locale state object contains process-wide listeners, overrides, timers, and snapshots.",
    );
  }
  if (/^__exacthostnavigator$/u.test(globalName) && member === "") {
    return effectSpec(["sys:read"], "system", "WP7");
  }
  if (/^__exactrequire$/u.test(globalName)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "The private require object exposes shared loader caches and main-module state.",
    );
  }
  if (/^__originalpromise$/u.test(globalName)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "The saved original Promise implementation can bypass patched callback-attribution behavior.",
    );
  }
  if (
    /^__exact(?:kchannelhandlekey|nativewrapstate|streamwrapstate|synctrackedipclistenersafterdispatch|installasyncipclistenerpatch|installprocessipcbootstrap)$/u.test(
      globalName,
    )
  ) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Private descriptor maps and IPC bootstrap state are shared ambient channels.",
    );
  }
  if (/^__exactsignalwatchsync$/u.test(globalName)) {
    return closedSpec(
      "process:signal",
      "WP7",
      "Signal watcher synchronization installs and resets process-global signal handlers.",
    );
  }
  if (/^__exactsignal(?:names|numbers)map$/u.test(globalName)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Mutable signal-name and number maps configure shared process signal behavior.",
    );
  }
  if (/^__exactisreadablestream$/u.test(globalName)) {
    return nonCapabilitySpec("pure-in-memory-compute", "WP1");
  }
  if (
    /^__exact(?:ensurefilesystemmodule|reapplycompatpolyfills)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP4");
  }
  if (
    /^__exact(?:entryfileconsumed|hasdecompressionunhandledfilter|installreadablestreamiteratorcompat|loadtimings|processcompatfixran|processcompatfixsawprocess|readablestreamcompatiteratorpatchscheduled|runtime|streamwrapreadbytesorerrorindex|uveofvalue|webstreamspolyfillloaded)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }

  if (
    /^(?:addEventListener|dispatchEvent|removeEventListener)$/iu.test(
      authoredGlobalName,
    )
  ) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }
  if (/^(?:print|log)$/u.test(globalName)) {
    return effectSpec(["stdio:write"], "stdio", "WP7");
  }
  if (/^(?:measure|scheduleonappruntime)$/u.test(globalName)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Worklet-to-application measurement and scheduling are ambient cross-runtime channels.",
    );
  }

  if (authoredGlobalName === "Exact" || authoredGlobalName === "Bun") {
    if (member === "") {
      return nonCapabilitySpec("authority-control-plane", "WP4");
    }
    if (/^(?:\$|spawn|spawnsync)$/u.test(member)) {
      return processLaunchEffectSpec();
    }
    if (member === "fetch") {
      return effectSpec(["network:fetch"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (member === "connect") {
      return effectSpec(["network:connect"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (/^(?:listen|serve)$/u.test(member)) {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "listener",
      });
    }
    if (/^dns(?:\.|$)/u.test(member)) {
      if (member === "dns")
        return nonCapabilitySpec("module-reachability-only", "WP7");
      return effectSpec(["network:resolve"], "network", "WP6");
    }
    if (member === "file") {
      return nonCapabilitySpec("pure-in-memory-compute", "WP5");
    }
    if (member === "write") {
      return effectSpec(["fs:list", "fs:write"], "filesystem", "WP5");
    }
    if (member === "which") {
      return effectSpec(["env:read", "fs:list"], "filesystem", "WP7");
    }
    if (/^(?:resolve|resolvesync)$/u.test(member)) {
      return effectSpec(["fs:list"], "loader", "WP7", {
        principalSources: ["loader-referrer"],
        effectOwnerSource: "loader-referrer",
        gate: "loader-admission",
      });
    }
    if (member === "env") {
      return closedSpec(
        "env:process-write",
        "WP7",
        "The Bun-compatible env object exposes mutable shared process environment state.",
      );
    }
    if (member === "stdin") return effectSpec(["stdio:read"], "stdio", "WP7");
    if (/^(?:stdout|stderr)$/u.test(member)) {
      return effectSpec(["stdio:write"], "stdio", "WP7");
    }
    if (/^accessibility\.addeventlistener$/u.test(member)) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
    if (/^accessibility(?:\.|$)/u.test(member)) {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "Accessibility reads and announcements cross the shared embedder application-state channel.",
      );
    }
    if (member === "locale.addlistener") {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
    if (/^locale(?:\.|$)/u.test(member)) {
      return effectSpec(["sys:read"], "system", "WP7");
    }
    if (/^(?:gc|inspect|unsafe|unsafe\.gcaggressionlevel)$/u.test(member)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Runtime heap inspection and unsafe process-wide controls are closed.",
      );
    }
    if (member === "unsafe.segfault") {
      return closedSpec(
        "process:signal",
        "WP7",
        "The unsafe segfault helper terminates the shared process.",
      );
    }
    if (member === "unsafe.arraybuffertostring") {
      return nonCapabilitySpec("internal-data-transform", "WP1");
    }
    if (member === "setmodulecapabilities") {
      return nonCapabilitySpec("authority-control-plane", "WP8");
    }
    if (
      /^(?:argv|ismainthread|main|origin|platform|revision|version)$/u.test(
        member,
      )
    ) {
      return effectSpec(["sys:read"], "system", "WP7");
    }
    if (/^(?:nanoseconds|sleep|sleepsync)$/u.test(member)) {
      return nonCapabilitySpec("ordinary-time", "WP1");
    }
    if (
      /^(?:cryptohasher(?:\..+)?|hash(?:\..+)?|(?:md5|sha|sha1|sha224|sha256|sha384|sha512)(?:\..+)?|password(?:\..+)?)$/u.test(
        member,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP1");
    }
    if (
      /^(?:deflatesync|gunzipsync|gzipsync|inflatesync|concatarraybuffers|readablestreamto(?:array|arraybuffer|blob|formdata|json|text)|transpiler)$/u.test(
        member,
      )
    ) {
      return nonCapabilitySpec("internal-data-transform", "WP1");
    }
    if (
      /^(?:color|deepequals|deepmatch|enableansicolors|escapehtml|fileurltopath|pathtofileurl|peek|peek\.status|semver|semver\.order|semver\.satisfies|stringwidth)$/u.test(
        member,
      )
    ) {
      return nonCapabilitySpec("pure-in-memory-compute", "WP1");
    }
    return null;
  }

  if (globalName === "exact") {
    if (member === "")
      return nonCapabilitySpec("authority-control-plane", "WP4");
    if (/^runtime(?:\.|$)/u.test(member)) {
      return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
    }
    if (member === "haskernelinspector") {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Kernel-inspector reachability reveals shared runtime diagnostic state.",
      );
    }
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Exact layout, state-mirror, module-dispatch, and hit-test calls are ambient embedder channels.",
    );
  }

  if (globalName === "exactbundle") {
    if (member === "" || member === "installglobals") {
      return nonCapabilitySpec("authority-control-plane", "WP4");
    }
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }

  if (globalName === "ibex") {
    if (
      /^(?:fs\.readhandle\.\[\[return\]\]\.(?:readfilesync|readtextsync))$/u.test(
        member,
      )
    ) {
      return effectSpec(["fs:read"], "filesystem", "WP5", {
        lifetimeContract: "file-handle",
        effectOwnerSource: "descriptor-owner",
        principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
      });
    }
    if (member === "fs.readhandle.[[return]].scoped") {
      return nonCapabilitySpec("authority-control-plane", "WP8");
    }
    if (member === "fs.readhandle.[[return]].revoke") {
      return nonCapabilitySpec("authority-release", "WP8");
    }
    return nonCapabilitySpec("authority-control-plane", "WP8");
  }

  if (globalName === "process") {
    if (member === "")
      return nonCapabilitySpec("module-reachability-only", "WP7");
    if (member === "[[symbol.tostringtag]]") {
      return nonCapabilitySpec("module-reachability-only", "WP7");
    }
    if (/^env(?:\.|$)/u.test(member)) {
      if (member === "env.[[dynamic-table:env-obj-properties]]") {
        return dynamicEnvironmentPropertyEffectSpec();
      }
      return closedSpec(
        "env:process-write",
        "WP7",
        "The process.env object permits mutation of shared process environment state.",
      );
    }
    if (member === "binding") {
      return closedSpec(
        "ffi:load",
        "WP7",
        "Private native binding lookup is closed.",
      );
    }
    if (/^(?:chdir)$/u.test(member)) {
      return closedSpec(
        "process:cwd",
        "WP7",
        "Process cwd mutation is closed.",
      );
    }
    if (/^(?:_umask|umask)$/u.test(member)) {
      return closedSpec(
        "process:umask",
        "WP7",
        "Process umask access and mutation are closed.",
      );
    }
    if (/^(?:setegid|seteuid|setgid|setuid)$/u.test(member)) {
      return closedSpec(
        "process:identity",
        "WP7",
        "Process identity mutation is closed.",
      );
    }
    if (/^(?:_kill|abort|exit|exit\.__exacthostexit|kill)$/u.test(member)) {
      return closedSpec(
        "process:signal",
        "WP7",
        "Process signaling and termination are closed.",
      );
    }
    if (member === "execve") {
      return processLaunchEffectSpec();
    }
    if (
      /^(?:channel(?:\.|$)|connected|disconnect|send|\[\[dynamic-table:(?:channel-handle-key|exact-channel-handle-key|k-channel-handle)\]\](?:\.|$))/u.test(
        member,
      )
    ) {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "Process IPC channels and raw channel handles are shared ambient communication endpoints.",
      );
    }
    if (
      /^(?:_getactivehandles|_getactiverequests|report(?:\..+)?|mainmodule)$/u.test(
        member,
      )
    ) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Active-handle, report, and main-module surfaces inspect shared runtime state.",
      );
    }
    if (
      /^(?:_uncaughtexceptionhandler|_unhandledrejectionhandler|domain|addlistener|emit|emitwarning|eventnames|getmaxlisteners|hasuncaughtexceptioncapturecallback|listenercount|listeners|off|on|once|prependlistener|prependoncelistener|rawlisteners|removealllisteners|removelistener|setmaxlisteners|setuncaughtexceptioncapturecallback)$/u.test(
        member,
      )
    ) {
      return closedSpec(
        /^(?:emit|emitwarning)$/u.test(member)
          ? "ipc:channel"
          : "runtime:inspect",
        "WP7",
        "Process event and exception-handler surfaces use a shared process-wide listener registry.",
      );
    }
    if (/^(?:nexttick)$/u.test(member)) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
    if (/^(?:hrtime|hrtime\.bigint)$/u.test(member)) {
      return nonCapabilitySpec("ordinary-time", "WP1");
    }
    if (member === "openstdin") {
      return effectSpec(["stdio:read"], "stdio", "WP7");
    }
    const stdioMatch = /^(stdin|stdout|stderr)(?:\.(.+))?$/u.exec(member);
    if (stdioMatch) {
      const descriptor = stdioMatch[1];
      const operation = stdioMatch[2] ?? "";
      if (operation === "") {
        return effectSpec(
          [descriptor === "stdin" ? "stdio:read" : "stdio:write"],
          "stdio",
          "WP7",
        );
      }
      if (operation === "fd") {
        return closedSpec(
          "ipc:channel",
          "WP7",
          "Raw stdio descriptor export is closed until descriptor transfer and ownership are authenticated.",
        );
      }
      if (/^(?:read|resume|setencoding)$/u.test(operation)) {
        return effectSpec(["stdio:read"], "stdio", "WP7", {
          lifetimeContract: "file-handle",
        });
      }
      if (operation === "write") {
        return effectSpec(["stdio:write"], "stdio", "WP7", {
          lifetimeContract: "file-handle",
        });
      }
      if (/^(?:addlistener|emit|on|once|removelistener)$/u.test(operation)) {
        return nonCapabilitySpec("callback-attribution-carrier", "WP8");
      }
      if (
        /^(?:cork|destroy|end|pause|pipe|ref|uncork|unref)$/u.test(operation)
      ) {
        return closedSpec(
          "runtime:inspect",
          "WP7",
          "Mutating a shared process stdio stream can disrupt other principals or transfer its endpoint.",
        );
      }
      return effectSpec(["stdio:query"], "stdio", "WP7");
    }
    if (/^(?:title|exitcode|_exactexiting)$/u.test(member)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Process title and exit-state properties are shared mutable runtime state.",
      );
    }
    if (
      /^(?:__exactasyncipclistenerpatch|__exactlateipclistenerpatch|__exactprocessipcbootstrapinstalled|__exactstreampinned|__exactstreamstabilitypatched)$/u.test(
        member,
      )
    ) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Private process compatibility and IPC patch markers are shared mutable runtime state.",
      );
    }
    if (
      /^(?:allowednodeenvironmentflags|arch|argv|argv0|assert|availablememory|browser|config(?:\..+)?|constrainedmemory|constructor\.prototype|cpuusage|cwd|debugport|execargv|execpath|features(?:\..+)?|getactiveresourcesinfo|getegid|geteuid|getgid|getgroups|getuid|memoryusage(?:\..+)?|nodeprecation|pid|platform|ppid|release(?:\..+)?|resourceusage|throwdeprecation|tracedeprecation|uptime|version|versions)$/u.test(
        member,
      )
    ) {
      return effectSpec(["sys:read"], "system", "WP7");
    }
    return null;
  }

  if (globalName === "indexeddb") {
    if (member === "cmp") {
      return nonCapabilitySpec("pure-in-memory-compute", "WP1");
    }
    if (member === "databases") {
      return closedSpec(
        "storage:read",
        "WP7",
        "IndexedDB database enumeration is closed until namespaces are principal-isolated.",
      );
    }
    if (/^(?:|deletedatabase|open)$/u.test(member)) {
      return closedSpec(
        "storage:persist",
        "WP7",
        "IndexedDB database creation, deletion, and reachability are closed until namespaces and quotas are principal-isolated.",
      );
    }
    return null;
  }
  if (globalName === "idbkeyrange") {
    return nonCapabilitySpec("pure-in-memory-compute", "WP1");
  }
  if (/^(?:idbrequest|idbopendbrequest)$/u.test(globalName)) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }
  if (
    /^(?:idbcursor|idbcursorwithvalue|idbdatabase|idbindex|idbobjectstore|idbtransaction)$/u.test(
      globalName,
    )
  ) {
    if (
      /^(?:addeventlistener|removeeventlistener|onabort|onblocked|onclose|oncomplete|onerror|onsuccess|onupgradeneeded|onversionchange)$/u.test(
        member,
      )
    ) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
    if (/^(?:close|abort|_abortwith|_release)$/u.test(member)) {
      return nonCapabilitySpec("authority-release", "WP8");
    }
    if (
      /(?:add|put|update|delete|clear|create|commit|exec|save|rollback|backfill|migrate|ensuretable|ensureindex|transactionfinished|upgradetransaction|noteexplicitkey|nextautoincrement|beforecommit|enqueueop|start)$/u.test(
        member,
      )
    ) {
      return closedSpec(
        "storage:write",
        "WP7",
        "IndexedDB mutation is closed until backing stores, transactions, and namespaces are principal-isolated.",
      );
    }
    if (member === "") {
      return closedSpec(
        "storage:persist",
        "WP7",
        "IndexedDB retained object reachability is closed until namespace and ownership isolation are proved.",
      );
    }
    return closedSpec(
      "storage:read",
      "WP7",
      "IndexedDB metadata, cursor, index, object-store, and transaction reads are closed until namespaces are principal-isolated.",
    );
  }

  if (/^(?:broadcastchannel|messagechannel|messageport)$/u.test(globalName)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Global messaging channels are closed until endpoints, payloads, and principal attribution are typed.",
    );
  }

  if (
    /^(?:closeevent|errorevent|filereader|focusevent|keyboardevent|messageevent|progressevent|promiserejectionevent|promise)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }

  if (
    /^(?:compressionstream|decompressionstream|textdecoderstream|textencoder|textencoderstream)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("internal-data-transform", "WP1");
  }

  if (
    globalName === "readablestream" &&
    member === "[[return]].__exactreadablestreamiteratorpatched"
  ) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }
  if (
    globalName === "readablestream" &&
    /^(?:\[\[return\]\]\.(?:getreader|tee|values))$/u.test(member)
  ) {
    return nonCapabilitySpec("retained-object-wrapper", "WP8");
  }

  if (
    /^(?:readablebytestreamcontroller|readablestream|readablestreambyobreader|readablestreambyobrequest|readablestreamdefaultcontroller|readablestreamdefaultreader|transformstream|transformstreamdefaultcontroller|writablestream|writablestreamdefaultcontroller|writablestreamdefaultwriter)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("retained-object-wrapper", "WP8");
  }

  if (globalName === "eventsource") {
    if (member === "") {
      return effectSpec(["network:fetch"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (member === "close") {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    if (/^on/u.test(member)) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
    return nonCapabilitySpec("retained-object-wrapper", "WP8");
  }

  if (globalName === "websocket") {
    if (member === "") {
      return effectSpec(["network:connect"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (member === "close") {
      return optionalPayloadNetworkEffectSpec(
        "network:connect",
        "network.websocket.close-kind",
      );
    }
    if (
      /^(?:send|_connectnative|_pauseincoming|_resumeincoming|_sendnative|_queuesend|_setincomingflowcontrol)$/u.test(
        member,
      )
    ) {
      return effectSpec(["network:connect"], "network", "WP6", {
        lifetimeContract: "socket-stream",
        effectOwnerSource: "descriptor-owner",
        principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
      });
    }
    if (
      /^(?:_callEventHandler|_calleventhandler|_enqueueeventtask|_handle|_on|on)/u.test(
        member,
      )
    ) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
    return nonCapabilitySpec("retained-object-wrapper", "WP8");
  }

  if (globalName === "websocketstream") {
    if (member === "") {
      return effectSpec(["network:connect"], "network", "WP6", {
        lifetimeContract: "socket-stream",
      });
    }
    if (/^(?:close|_initiateclose|_finishwritableclose)$/u.test(member)) {
      return optionalPayloadNetworkEffectSpec(
        "network:connect",
        "network.websocket-stream.close-kind",
      );
    }
    if (/^(?:_drainresolvedwrites|_syncreadablebackpressure)$/u.test(member)) {
      return effectSpec(["network:connect"], "network", "WP6", {
        lifetimeContract: "socket-stream",
        effectOwnerSource: "descriptor-owner",
        principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
      });
    }
    if (/^(?:_handle|_reject|_resolve|_error|_close)/u.test(member)) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
    return nonCapabilitySpec("retained-object-wrapper", "WP8");
  }

  if (globalName === "websocketerror") {
    return nonCapabilitySpec("retained-object-wrapper", "WP8");
  }

  if (globalName === "worklet") {
    if (member === "clamp" || member === "lerp") {
      return nonCapabilitySpec("pure-in-memory-compute", "WP1");
    }
    if (member === "sharedvalue") {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "Worklet shared values are a cross-runtime communication channel.",
      );
    }
    return closedSpec(
      "worker:create",
      "WP7",
      "Worklet global reachability is closed until worker principal isolation is proved.",
    );
  }

  if (
    /^(?:arraybuffer|clipboarditem|headers|iterator|urlpattern)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("pure-in-memory-compute", "WP1");
  }
  if (globalName === "atomics") {
    return nonCapabilitySpec("retained-object-wrapper", "WP8");
  }
  if (globalName === "videoframe") {
    if (member === "close" || member === "[[return]].close") {
      return nonCapabilitySpec("authority-release", "WP8");
    }
    return nonCapabilitySpec("internal-data-transform", "WP1");
  }
  if (globalName === "console") {
    if (member === "")
      return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
    return effectSpec(["stdio:write"], "stdio", "WP7");
  }
  if (globalName === "crypto") {
    if (/^(?:getrandomvalues|randomuuid)$/u.test(member)) {
      return nonCapabilitySpec("ordinary-randomness", "WP1");
    }
    if (member === "" || member === "subtle") {
      return nonCapabilitySpec("module-reachability-only", "WP1");
    }
    return nonCapabilitySpec("pure-in-memory-compute", "WP1");
  }
  if (globalName === "mediaquerylist") {
    if (
      /^(?:addeventlistener|addlistener|onchange|removeeventlistener|removelistener)$/u.test(
        member,
      )
    ) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
    return effectSpec(["sys:read"], "system", "WP7");
  }
  if (globalName === "mediaquerylistevent") {
    return effectSpec(["sys:read"], "system", "WP7");
  }

  if (/^(?:import|importmodule|require)$/u.test(globalName)) {
    if (globalName === "require" && /^(?:cache|main)$/u.test(member)) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "require.cache and require.main expose shared mutable loader state.",
      );
    }
    if (globalName === "require" && member === "resolve.paths") {
      return nonCapabilitySpec("pure-in-memory-compute", "WP7");
    }
    if (globalName === "require" && member === "resolve") {
      return loaderSourceSelectionEffectSpec({
        principalSources: ["loader-referrer"],
        effectOwnerSource: "loader-referrer",
        gate: "loader-admission",
      });
    }
    if (member === "") {
      return fullLoaderEffectSpec({
        principalSources: ["loader-referrer"],
        effectOwnerSource: "loader-referrer",
        gate: "loader-admission",
      });
    }
    return null;
  }

  if (globalName === "webstreamspolyfill") {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }
  if (
    member === "[[symbol.tostringtag]]" &&
    /^(?:caches|localstorage|process|sessionstorage)$/u.test(globalName)
  ) {
    return nonCapabilitySpec("module-reachability-only", "WP7");
  }

  if (/^(?:localstorage|sessionstorage)$/u.test(globalName)) {
    if (member === "persistence") {
      return closedSpec(
        "storage:persist",
        "WP7",
        "Shared persistent web storage is closed until package namespaces and quota are isolated.",
      );
    }
    if (/^(?:setitem|removeitem|clear)$/u.test(member)) {
      return closedSpec(
        "storage:write",
        "WP7",
        "Web-storage mutation is closed until package namespaces are isolated.",
      );
    }
    if (/^(?:|getitem|key|length)$/u.test(member)) {
      return closedSpec(
        "storage:read",
        "WP7",
        "Web-storage reads are closed until package namespaces are isolated.",
      );
    }
    return null;
  }

  const reviewedEvaluator = Object.hasOwn(
    REVIEWED_HERMES_EVALUATORS,
    authoredGlobalName,
  )
    ? REVIEWED_HERMES_EVALUATORS[authoredGlobalName]
    : null;
  if (reviewedEvaluator !== null) {
    const metadata = surface.metadata;
    const sourceKeys = metadata.sourceKeys ?? [metadata.sourceKey];
    if (
      metadata.memberName !== null ||
      metadata.sourceKey !== reviewedEvaluator.sourceKey ||
      JSON.stringify(sourceKeys) !==
        JSON.stringify(reviewedEvaluator.sourceKeys) ||
      metadata.evidenceType !== "hermes-evaluator-reachability" ||
      metadata.engineIdentityReviewId !== REVIEWED_HERMES_EVALUATOR_REVIEW_ID ||
      metadata.lockdownTamingDigest !==
        REVIEWED_HERMES_LOCKDOWN_TAMING_DIGEST ||
      JSON.stringify(metadata.engineProfileIds) !==
        JSON.stringify(REVIEWED_HERMES_EVALUATOR_PROFILE_IDS) ||
      metadata.tamingEvidence !== "kLockdownJS" ||
      metadata.reachability !== reviewedEvaluator.reachability ||
      !hasReviewedHermesEvaluatorBranches(metadata) ||
      !Array.isArray(metadata.moduleSpecifiers) ||
      metadata.moduleSpecifiers.length !== 0
    ) {
      return null;
    }
    return closedSpec(
      "vm:evaluate",
      "WP7",
      "Dynamic global code evaluation is closed by the initial profile and lockdown.",
    );
  }
  if (globalName === "gc") {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Explicit runtime GC control is closed.",
    );
  }
  if (/^(?:import|importmodule|require)$/u.test(globalName)) {
    return nonCapabilitySpec("module-reachability-only", "WP7");
  }
  if (/^(?:clearimmediate|cleartimeout|clearinterval)$/u.test(globalName)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Timer cancellation accepts a process-global sequential identifier without authenticating the timer owner.",
    );
  }
  if (
    /^(?:queuemicrotask|settimeout|setinterval|setimmediate|cleartimeout|clearinterval|clearimmediate)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }

  if (globalName === "fetch" && member === "") {
    return effectSpec(["network:fetch"], "network", "WP6", {
      lifetimeContract: "socket-stream",
    });
  }

  if (/^(?:eventsource)$/u.test(globalName) && member === "") {
    return effectSpec(["network:fetch"], "network", "WP6", {
      lifetimeContract: "socket-stream",
    });
  }
  if (/^(?:websocket|websocketstream)$/u.test(globalName) && member === "") {
    return effectSpec(["network:connect"], "network", "WP6", {
      lifetimeContract: "socket-stream",
    });
  }
  if (
    /^(?:broadcastchannel|messagechannel|messageport)$/u.test(globalName) &&
    member === ""
  ) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Global messaging channels are closed until endpoints, payloads, and principal attribution are typed.",
    );
  }
  if (
    /^(?:indexeddb|idbcursor|idbcursorwithvalue|idbdatabase|idbindex|idbkeyrange|idbobjectstore|idbopendbrequest|idbrequest|idbtransaction)$/u.test(
      globalName,
    ) &&
    member === ""
  ) {
    return closedSpec(
      "storage:persist",
      "WP7",
      "IndexedDB reachability is closed until package namespaces, quotas, and persistent backing objects are isolated.",
    );
  }
  if (
    /^(?:matchmedia|mediaquerylist|mediaquerylistevent|navigator)$/u.test(
      globalName,
    ) &&
    member === ""
  ) {
    return effectSpec(["sys:read"], "system", "WP7");
  }
  if (
    /^(?:readablebytestreamcontroller|readablestream|readablestreambyobreader|readablestreambyobrequest|readablestreamdefaultcontroller|readablestreamdefaultreader|transformstream|transformstreamdefaultcontroller|writablestream|writablestreamdefaultcontroller|writablestreamdefaultwriter)$/u.test(
      globalName,
    ) &&
    member === ""
  ) {
    return nonCapabilitySpec("retained-object-wrapper", "WP8");
  }
  if (
    /^(?:closeevent|errorevent|filereader|focusevent|keyboardevent|messageevent|progressevent|promiserejectionevent|requestanimationframe|requestidlecallback)$/u.test(
      globalName,
    ) &&
    member === ""
  ) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }
  if (
    /^(?:cancelanimationframe|cancelidlecallback)$/u.test(globalName) &&
    member === ""
  ) {
    return nonCapabilitySpec("authority-release", "WP8");
  }
  if (
    /^(?:atomics|clipboarditem|compressionstream|decompressionstream|headers|textdecoderstream|textencoder|textencoderstream|urlpattern|videoframe|websocketerror)$/u.test(
      globalName,
    ) &&
    member === ""
  ) {
    return nonCapabilitySpec(
      /compression|textencoder|textdecoder/u.test(globalName)
        ? "internal-data-transform"
        : "pure-in-memory-compute",
      "WP1",
    );
  }
  if (globalName === "process" && member === "") {
    return nonCapabilitySpec("module-reachability-only", "WP7");
  }
  if (/^(?:self|window)$/u.test(globalName) && member === "") {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }

  if (globalName === "cache") {
    if (/^(?:add|addall)$/u.test(member)) {
      return closedSpec(
        "storage:write",
        "WP7",
        "Cache.add/addAll would fetch and then mutate the shared cache namespace; closing storage write prevents the fetch branch from running until WP7 can refine both effects.",
      );
    }
    if (/^(?:delete|put)$/u.test(member)) {
      return closedSpec(
        "storage:write",
        "WP7",
        "Shared Cache mutation is closed until cache namespaces are isolated by principal.",
      );
    }
    if (/^(?:keys|match|matchall)$/u.test(member)) {
      return closedSpec(
        "storage:read",
        "WP7",
        "Shared Cache reads are closed until cache namespaces are isolated by principal.",
      );
    }
    if (member === "") {
      return closedSpec(
        "storage:persist",
        "WP7",
        "Cache construction/reachability is closed until ownership and namespace isolation are explicit.",
      );
    }
    return null;
  }
  if (/^(?:caches|cachestorage)$/u.test(globalName)) {
    if (/^(?:|delete|open)$/u.test(member)) {
      return closedSpec(
        "storage:persist",
        "WP7",
        "CacheStorage namespace creation, deletion, and reachability are closed until principal isolation is proved.",
      );
    }
    if (/^(?:has|keys|match)$/u.test(member)) {
      return closedSpec(
        "storage:read",
        "WP7",
        "CacheStorage namespace reads are closed until principal isolation is proved.",
      );
    }
    return null;
  }

  if (globalName === "crypto") {
    if (/^(?:getrandomvalues|randomuuid)$/u.test(member)) {
      return nonCapabilitySpec("ordinary-randomness", "WP1");
    }
    if (member === "")
      return nonCapabilitySpec("module-reachability-only", "WP1");
    return null;
  }

  if (
    /^(?:date|performance|performanceentry|performancemark|performancemeasure|performanceobserver|performanceresourcetiming)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("ordinary-time", "WP1");
  }

  if (/^(?:exact|bun)$/u.test(globalName) && member === "") {
    return nonCapabilitySpec("authority-control-plane", "WP4");
  }
  if (/^(?:global|console)$/u.test(globalName) && member === "") {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }

  if (
    /^(?:abortcontroller|abortsignal|customevent|event|eventtarget)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }

  if (
    /^(?:createexternalizablestring|createexternalizabletwobytestring|externalizestring|isonebytestring)$/u.test(
      globalName,
    ) &&
    member === ""
  ) {
    return nonCapabilitySpec("internal-data-transform", "WP1");
  }

  // Closed, deterministic in-memory platform families. Membership is by the
  // reviewed global constructor, never by an arbitrary terminal fallback.
  if (
    /^(?:atob|bigint64array|biguint64array|blob|btoa|buffer|bytelengthqueuingstrategy|countqueuingstrategy|cryptokey|dataview|domexception|file|float16array|float32array|float64array|formdata|int8array|int16array|int32array|request|response|sharedarraybuffer|subtlecrypto|textdecoder|uint8array|uint8clampedarray|uint16array|uint32array|url|urlsearchparams|structuredclone)$/u.test(
      globalName,
    )
  ) {
    return nonCapabilitySpec("pure-in-memory-compute", "WP1");
  }

  return null;
}

function androidHostAbiClassification(name) {
  if (name === "ex_android_initialize") {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }

  const jniPrefix = "jni:dev.ibex.runtime.IbexNetworking.";
  if (name.startsWith(jniPrefix)) {
    // Exact reviewed-name approval precedes this classifier. These JNI calls
    // only deliver a result/event for an operation authorized at its Java
    // request boundary; they must preserve attribution across that delivery.
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }

  const javaPrefix = "java:dev.ibex.runtime.IbexNetworking.";
  if (!name.startsWith(javaPrefix)) return null;
  const operation = name.slice(javaPrefix.length);

  if (/^(?:getApplicationContext|initialize)$/u.test(operation)) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }
  if (
    /^(?:CameraHostProvider\.cameraHostCall|cameraHostCall)$/u.test(operation)
  ) {
    return androidMediaOperationEffectSpec(
      "device.android-camera-host.operation",
    );
  }
  if (
    /^(?:DialogHostProvider\.dialog|accessibilityFlags|appState|dialog|drainPlatformEvents|initialURL|notifyActivityPaused|notifyActivityResumed|notifyActivityStarted|notifyActivityStopped|notifyDeepLink|notifyNewIntent|postAnimationFrame)$/u.test(
      operation,
    )
  ) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Android application, lifecycle, accessibility, dialog, deep-link, and frame-event routes are ambient embedder channels until their payloads and attribution are typed.",
    );
  }
  if (operation === "fetch") {
    return effectSpec(["network:fetch"], "network", "WP6", {
      lifetimeContract: "socket-stream",
    });
  }
  if (operation === "cancelFetch") {
    return nonCapabilitySpec("authority-release", "WP6");
  }
  if (operation === "connectWebSocket") {
    return effectSpec(["network:connect"], "network", "WP6", {
      lifetimeContract: "socket-stream",
    });
  }
  if (operation === "sendWebSocket") {
    return effectSpec(["network:connect"], "network", "WP6", {
      lifetimeContract: "socket-stream",
      effectOwnerSource: "descriptor-owner",
      principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
    });
  }
  if (operation === "closeWebSocket") {
    return optionalPayloadNetworkEffectSpec(
      "network:connect",
      "network.android-websocket.close-kind",
    );
  }
  if (
    /^(?:pauseWebSocket|resumeWebSocket|setWebSocketFlowControlled)$/u.test(
      operation,
    )
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP6");
  }
  if (operation === "dnsQuery") {
    return effectSpec(["network:resolve"], "network", "WP6");
  }
  if (operation === "clipboardReadText") {
    return effectSpec(["clipboard:read"], "device", "WP8");
  }
  if (operation === "clipboardWriteText") {
    return effectSpec(["clipboard:write"], "device", "WP8");
  }
  if (
    /^(?:getCurrentLocation|isLocationServicesEnabled|locationPermissionStatus)$/u.test(
      operation,
    )
  ) {
    return effectSpec(["device:location"], "device", "WP8");
  }
  if (
    /^(?:localeTags|platformVersion|screenInfo|storagePaths|uses24HourClock)$/u.test(
      operation,
    )
  ) {
    return effectSpec(["sys:read"], "system", "WP7");
  }
  if (operation === "setCameraHostProvider") {
    return nonCapabilitySpec("authority-control-plane", "WP8");
  }
  if (operation === "setClient") {
    return nonCapabilitySpec("authority-control-plane", "WP6");
  }
  if (operation === "setDialogHostProvider") {
    return nonCapabilitySpec("authority-control-plane", "WP7");
  }
  return null;
}

function abiEscapeClassification(name) {
  const abiName = name.toLowerCase();
  if (abiName === "ex_hermes_create_diagnostic") {
    return closedSpec(
      "vm:evaluate",
      "WP7",
      "The explicitly diagnostic unarmed runtime constructor is outside every production profile.",
    );
  }
  if (/^ex_hermes_debugger_/u.test(abiName)) {
    return closedSpec(
      /_(?:eval|get_script_source|get_scripts|next_event)$/u.test(abiName)
        ? "runtime:inspect"
        : "inspector:activate",
      "WP7",
      "Debugger ABI access is closed in the initial profile.",
    );
  }
  if (/(?:^|_)(?:native_addon|ffi|dlopen)(?:_|$)/u.test(abiName)) {
    return closedSpec(
      "ffi:load",
      "WP7",
      "Native extension ABI access is closed in the initial profile.",
    );
  }
  if (/(?:^|_)worker(?:_|$)/u.test(abiName)) {
    return closedSpec(
      "worker:create",
      "WP7",
      "Worker creation through a public ABI is closed until principal isolation is proved.",
    );
  }
  if (/(?:^|_)(?:wasi|wasm)(?:_|$)/u.test(abiName)) {
    return closedSpec(
      "wasi:instantiate",
      "WP7",
      "WASI instantiation through a public ABI is closed.",
    );
  }
  if (/(?:^|_)(?:eval|bytecode)(?:_|$)/u.test(abiName)) {
    return closedSpec(
      "vm:evaluate",
      "WP7",
      "Public ABI evaluation remains closed until authenticated entry binding is proved.",
    );
  }
  if (/(?:^|_)(?:write_file|file_write)(?:_|$)/u.test(abiName)) {
    return effectSpec(["fs:write"], "filesystem", "WP5");
  }
  if (/(?:^|_)(?:read_file|file_read)(?:_|$)/u.test(abiName)) {
    return effectSpec(["fs:read"], "filesystem", "WP5");
  }
  return null;
}

function embedderAbiClassification(name) {
  if (/^exhermes/u.test(name)) {
    if (
      new Set([
        "exhermesdispatchevent",
        "exhermesemitmoduleevent",
        "exhermesemitmoduleviewevent",
        "exhermesresolvehostcall",
        "exhermessethostcall",
        "exhermessethostcallasync",
        "exhermessetkernelhandle",
      ]).has(name)
    ) {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "Generic embedder event, host-call, and handle transfer is closed.",
      );
    }
    if (
      new Set(["exhermesgc", "exhermesgetgcstats", "exhermesgetheapinfo"]).has(
        name,
      )
    ) {
      return closedSpec(
        "runtime:inspect",
        "WP7",
        "Runtime heap and GC inspection is closed.",
      );
    }
    if (name === "exhermesnowms") {
      return nonCapabilitySpec("ordinary-time", "WP1");
    }
    if (new Set(["exhermesdestroy", "exhermesfreestring"]).has(name)) {
      return nonCapabilitySpec("authority-release", "WP8");
    }
    if (
      new Set([
        "exhermescreate",
        "exhermescreatearmed",
        "exhermesenginebinarypath",
        "exhermesenginemappedobject",
      ]).has(name)
    ) {
      return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
    }
    if (
      name === "exhermescurrentprincipalid" ||
      name === "exhermescurrentruntimenonce"
    ) {
      return nonCapabilitySpec("authority-control-plane", "WP8");
    }
    if (
      new Set([
        "exhermescallbackbacklog",
        "exhermescurrentruntimenonce",
        "exhermeshaspendingtasks",
        "exhermesnexttimer",
        "exhermesnotifycallback",
        "exhermespoll",
        "exhermesschedulewatchdogheartbeat",
        "exhermessetdispatchcallback",
        "exhermessetdispatchwithdebugcontextcallback",
        "exhermessethostwakehook",
        "exhermessetmoduledispatchcallback",
        "exhermessetmodulesynccallback",
      ]).has(name)
    ) {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
    if (name === "exhermessetkeepaliveonasyncerror") {
      return nonCapabilitySpec("authority-control-plane", "WP8");
    }
    return null;
  }

  if (/^exworklet/u.test(name)) {
    if (name === "exworkletdestroy") {
      return nonCapabilitySpec("authority-release", "WP8");
    }
    if (
      new Set(["exworkletcreate", "exworkletinstall", "exworkletinvoke"]).has(
        name,
      )
    ) {
      return closedSpec(
        "worker:create",
        "WP7",
        "Worklet creation, installation, and invocation are closed until principal isolation is proved.",
      );
    }
    if (
      new Set([
        "exworkletbindsharedvalues",
        "exworkletdrainlogs",
        "exworkletdrainscheduled",
        "exworkletsetmeasurecallback",
      ]).has(name)
    ) {
      return closedSpec(
        "ipc:channel",
        "WP7",
        "Worklet shared state, callback registration, and drain channels are closed.",
      );
    }
    if (new Set(["exworkletgeneration", "exworkletsetgeneration"]).has(name)) {
      return nonCapabilitySpec("authority-control-plane", "WP8");
    }
    return null;
  }

  return null;
}

function hostAbiClassification(name) {
  if (!name.startsWith("exhost")) return null;

  if (
    /^(?:exhostauthorizetypedfsstack|exhostauthorizetypednetworkstack|exhostauthorizetypedudpdatagramstack|exhostclaimarmedcontext|exhostclaimdiagnosticcontext|exhostcheckcapability|exhostcheckcapabilitynofollowfinal|exhostcheckcapabilitystack|exhostcheckcapabilitystacknofollowfinal|exhostcheckhandlemint|exhostcheckimport|exhostentercontext|exhostevaluatetypeddecision|exhostgrantcapability|exhosthandlecheck|exhosthandlecreate|exhosthandlerevoke|exhosthandlescoped|exhosthasdeputyclasses|exhostisallowall|exhostisarmed|exhostlegacyauthorizationcacheable|exhostlegacyauthorizationgeneration|exhostlogevent|exhostpermissionrequest|exhostpermissionrevoke|exhostpermissionstatus|exhostregistermodulepackage|exhostreleasecontext|exhostrestorecontext|exhosttypeddynamicgrant|exhosttypeddynamicrevoke|exhosttypedgenerations|exhosttypedhandlemint|exhosttypedhandlerevoke)$/u.test(
      name,
    )
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP8");
  }
  if (
    new Set([
      "exhostarmedendowments",
      "exhostinstallarmed",
      "exhostmatchesarmedsnapshotdigest",
    ]).has(name)
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP4");
  }
  if (name === "exhostconsolelog") {
    return effectSpec(["stdio:write"], "stdio", "WP7", {
      effectOwnerSource: "innermost-nontransparent-frame",
      principalSources: ["frame-set", "schedule-time"],
    });
  }
  if (name === "exhostconsoleflush") {
    // The writer was authorized when its line was enqueued. Flush only waits
    // for that asynchronous queue to drain; it neither selects a descriptor
    // nor performs a second write on the caller's behalf.
    return nonCapabilitySpec("callback-attribution-carrier", "WP7");
  }
  if (name === "exhostenvget") {
    return effectSpec(["env:read"], "environment", "WP7");
  }
  if (/^exhostfree(?:buffer|string)$/u.test(name)) {
    return nonCapabilitySpec("authority-release", "WP8");
  }

  if (/^exhostfs/u.test(name)) {
    const descriptorOptions =
      /(?:fstat|fssync|pread|pwrite|fsread$|fswrite$)/u.test(name)
        ? {
            effectOwnerSource: "descriptor-owner",
            principalSources: [
              "descriptor-owner",
              "frame-set",
              "schedule-time",
            ],
            lifetimeContract: "file-handle",
          }
        : {};
    if (/^exhostfsclose$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP5");
    }
    if (/^exhostfslasterror$/u.test(name)) {
      return nonCapabilitySpec("internal-data-transform", "WP5");
    }
    if (/^exhostfsseek$/u.test(name)) {
      return nonCapabilitySpec("authority-control-plane", "WP5");
    }
    if (/^exhostfsopen$/u.test(name)) {
      return filesystemOpenEffectSpec();
    }
    if (/^exhostfscopy(?:exclusive)?$/u.test(name)) {
      return effectSpec(["fs:read", "fs:write"], "filesystem", "WP5");
    }
    if (/^exhostfs(?:access|fstat|lstat|readdir|realpath|stat|statfs)$/u.test(name)) {
      return effectSpec(["fs:list"], "filesystem", "WP5", descriptorOptions);
    }
    if (/^exhostfs(?:pread|read)$/u.test(name)) {
      return effectSpec(["fs:read"], "filesystem", "WP5", descriptorOptions);
    }
    if (
      /^exhostfs(?:append|chmod|mkdir|mkdirrecursiveresult|mkdtemp|pwrite|rename|rmdir|sync|truncate|unlink|utimes|write)$/u.test(
        name,
      )
    ) {
      return effectSpec(
        Object.keys(descriptorOptions).length > 0
          ? ["fs:write"]
          : ["fs:list", "fs:write"],
        "filesystem",
        "WP5",
        descriptorOptions,
      );
    }
    return null;
  }

  if (/^exhosthttp/u.test(name)) {
    if (name === "exhosthttpserve") {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "listener",
      });
    }
    if (/^exhosthttp(?:cleanup_runtime|cleanupruntime|close)$/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    if (
      /^exhosthttp(?:haspendingrequests|hasreferenced|isreferenced|setref)$/u.test(
        name,
      )
    ) {
      return nonCapabilitySpec("authority-control-plane", "WP8");
    }
    if (
      /^exhosthttp(?:address|awaitwritable|awaitwritableowned|drain|poll|readbody|respond|respondabort|respondchunk|respondchunktry|respondend|respondendtry|respondjson|respondstream|respondstring|respondtext|wait|waitowned)$/u.test(
        name,
      )
    ) {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "listener",
        effectOwnerSource: "descriptor-owner",
        principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
      });
    }
    return null;
  }

  if (name === "exhostmoduleresolve") {
    return effectSpec(["fs:list", "fs:read"], "loader", "WP7", {
      principalSources: ["loader-referrer"],
      effectOwnerSource: "loader-referrer",
      gate: "loader-admission",
    });
  }
  if (name === "exhostmoduleresolvemeta") {
    return effectSpec(["fs:list"], "loader", "WP7", {
      principalSources: ["loader-referrer"],
      effectOwnerSource: "loader-referrer",
      gate: "loader-admission",
    });
  }
  if (name === "exhostrandomfill") {
    return nonCapabilitySpec("ordinary-randomness", "WP1");
  }
  if (name === "exhosttimenowms") {
    return nonCapabilitySpec("ordinary-time", "WP1");
  }
  if (/^exhost(?:init|install|version)$/u.test(name)) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }
  if (/^exhostsqlite/u.test(name)) {
    if (/close|finalize/u.test(name)) {
      return nonCapabilitySpec("authority-release", "WP5");
    }
    if (/expandedsql|intransaction/u.test(name)) {
      return nonCapabilitySpec("authority-control-plane", "WP5");
    }
    if (/all|get|values/u.test(name)) {
      return sqliteReadEffectSpec();
    }
    if (/open/u.test(name)) return sqliteOpenEffectSpec();
    if (/prepare/u.test(name)) return sqliteReadEffectSpec();
    if (/exec|run/u.test(name)) return sqliteStatementEffectSpec();
  }
  return null;
}

function nativeEscapeClassification(text) {
  if (/inspector|debugger|cdp/u.test(text)) {
    return closedSpec(
      /evaluate|eval|script|memory|next[-_ ]?event|responsebody|runtimeinspect/u.test(
        text,
      )
        ? "runtime:inspect"
        : "inspector:activate",
      "WP7",
      "Inspector and runtime-inspection surfaces are closed in the initial profile.",
    );
  }
  if (/(?:^|[^a-z])wasi|wasi(?:$|[^a-z])|wasm/u.test(text)) {
    return closedSpec(
      "wasi:instantiate",
      "WP7",
      "WASI instantiation is closed in the initial profile.",
    );
  }
  if (/worker|worklet/u.test(text)) {
    return closedSpec(
      "worker:create",
      "WP7",
      "Worker/worklet creation is closed until principal isolation is proved.",
    );
  }
  if (/\bvm\b|vmevaluate|evalincontext|runincontext/u.test(text)) {
    return closedSpec(
      "vm:evaluate",
      "WP7",
      "Unattributed VM evaluation is closed in the initial profile.",
    );
  }
  if (/ffi|native[_ -]?addon|nativeaddon|dlopen/u.test(text)) {
    return closedSpec(
      "ffi:load",
      "WP7",
      "Native extension loading is closed in the initial profile.",
    );
  }
  if (/ipc|sendmsg|recvmsg/u.test(text)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Ambient or exported IPC channels are closed in the initial profile.",
    );
  }
  return null;
}

function nativeNetworkBackendClassification(name) {
  if (name === "native_fetch_cancel" || name === "native_ws_destroy") {
    return nonCapabilitySpec("authority-release", "WP6");
  }
  if (name === "native_fetch_perform") {
    return effectSpec(["network:fetch"], "network", "WP6", {
      lifetimeContract: "socket-stream",
    });
  }
  if (name === "native_ws_connect") {
    return effectSpec(["network:connect"], "network", "WP6", {
      lifetimeContract: "socket-stream",
    });
  }
  if (name === "native_ws_send") {
    return effectSpec(["network:connect"], "network", "WP6", {
      lifetimeContract: "socket-stream",
      effectOwnerSource: "descriptor-owner",
      principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
    });
  }
  if (name === "native_ws_close") {
    return optionalPayloadNetworkEffectSpec(
      "network:connect",
      "network.native-websocket.close-kind",
    );
  }
  if (
    /^(?:native_ws_pause|native_ws_resume|native_ws_set_flow_controlled)$/u.test(
      name,
    )
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP6");
  }
  if (name === "native_ws_has_active") {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP6");
  }
  return null;
}

function classifyConcreteSurface(surface) {
  const text = surfaceSearchText(surface);
  const name = compactName(surface);

  if (Object.hasOwn(surface.metadata ?? {}, "coverage")) {
    throw new Error(
      `${surface.observedKey}: source metadata cannot override semantic coverage classification`,
    );
  }
  if (surface.kind === "builtin") return builtinClassification(surface);
  if (surface.kind === "callback") {
    return callbackClassification(surface);
  }
  if (surface.kind === "loader") {
    if (!REVIEWED_LOADER_NAMES.has(surface.name)) return null;
    return loaderClassification(surface);
  }
  if (surface.kind === "cli") {
    if (!REVIEWED_CLI_NAMES.has(surface.name)) return null;
    return cliClassification(surface);
  }
  if (surface.kind === "startup") {
    if (!REVIEWED_STARTUP_NAMES.has(surface.name)) return null;
    return startupClassification(surface);
  }
  if (surface.metadata?.surfaceType === "global-api") {
    const inheritedShape = surface.metadata?.inheritedShape === true;
    const reviewedInheritedShape = reviewedInheritedGlobalShape(surface);
    const reviewedDynamicCallShape = reviewedDynamicGlobalCallShape(surface);
    if (inheritedShape && !reviewedInheritedShape) return null;
    if (
      !REVIEWED_GLOBAL_API_NAMES.has(surface.name) &&
      !reviewedInheritedShape &&
      !reviewedDynamicCallShape
    )
      return null;
    if (isDualRoleGlobalNativeOperation(surface)) {
      if (!REVIEWED_NATIVE_OPERATION_NAMES.has(surface.name)) return null;
      const nativeSpecification = classifyConcreteSurface(
        privateNativeOperationView(surface),
      );
      return reconcileDualRoleSpecifications(
        surface,
        globalApiClassification(surface, nativeSpecification),
        nativeSpecification,
      );
    }
    return globalApiClassification(surface);
  }
  if (surface.kind === "host-abi") {
    if (!REVIEWED_HOST_ABI_NAMES.has(surface.name)) return null;
    if (surface.name === "ex_hermes_current_runtime_nonce") {
      return nonCapabilitySpec("callback-attribution-carrier", "WP8");
    }
    if (surface.name === "ex_hermes_engine_mapped_object") {
      return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
    }
    if (surface.name === "ex_host_http_await_writable_owned") {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "listener",
        effectOwnerSource: "descriptor-owner",
        principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
      });
    }
    if (surface.name === "ex_host_http_wait_owned") {
      return effectSpec(["network:listen"], "network", "WP6", {
        lifetimeContract: "listener",
        effectOwnerSource: "descriptor-owner",
        principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
      });
    }
    if (surface.name === "ex_host_http_cleanup_runtime") {
      return nonCapabilitySpec("authority-release", "WP6");
    }
    const android = androidHostAbiClassification(surface.name);
    if (android) return android;
    const escape = abiEscapeClassification(surface.name);
    if (escape) return escape;
    const embedder = embedderAbiClassification(name);
    if (embedder) return embedder;
    return hostAbiClassification(name);
  }
  if (surface.kind === "native-op") {
    if (surface.name.startsWith("inspector.")) {
      if (!REVIEWED_INSPECTOR_NATIVE_NAMES.has(surface.name)) return null;
      return nativeEscapeClassification(text);
    }
    if (!REVIEWED_NATIVE_OPERATION_NAMES.has(surface.name)) return null;
    const nativeNetworkBackend = nativeNetworkBackendClassification(
      surface.name,
    );
    if (nativeNetworkBackend) return nativeNetworkBackend;
    const escape = nativeEscapeClassification(text);
    if (escape) return escape;
  }

  // Embedder/application state is an external data channel, not inert
  // bootstrap metadata. Keep it closed until the profile has a typed UI/event
  // effect. OS version is ordinary typed system information.
  if (/osversion/u.test(name)) {
    return effectSpec(["sys:read"], "system", "WP7");
  }
  if (
    /appearancestate|appstate|initialurl|nativedialog|androidgetplatformstate|androiddispatchplatformevent|androiddrainplatformevents|accessibilitysnapshot/u.test(
      name,
    )
  ) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Embedder application state and UI interaction are closed until a typed, attributed data channel exists.",
    );
  }

  // Lazy installers and immutable bootstrap probes change reachability but do
  // not themselves exercise the installed operation's authority.
  if (/ensure/u.test(name)) {
    return nonCapabilitySpec("authority-control-plane", "WP4");
  }
  if (
    /bootstrap|hassharedruntimebundle|suppressruntimebanner|runtimeloaded/u.test(
      name,
    )
  ) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }

  if (/^(?:exact|ibex|exp|compartments)$/u.test(name)) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }

  if (
    /deepfreeze|nativefreeze|nativelockdown|lockeddown|tamed|setcompartment|endowraw/u.test(
      name,
    )
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP8");
  }

  // Generic embedder operations are ambient IPC until an embedder supplies a
  // digest-bound operation registry. The initial profile therefore closes the
  // callable channel rather than inferring authority from arbitrary strings.
  if (
    /^__hostcall(?:async)?$/u.test(surface.name.toLowerCase()) ||
    /hostcallasync/u.test(name)
  ) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Unregistered generic host-call operations are closed as ambient IPC.",
    );
  }

  if (/^sv(?:get|set)$/u.test(name)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Cross-runtime shared-value access is closed until a typed shared-memory channel and ownership model exist.",
    );
  }

  if (
    /^(?:exactuncaughtexceptionhandler|exactunhandledrejectionhandler)$/u.test(
      name,
    )
  ) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Process exception and rejection handlers invoke the shared process-wide listener registry.",
    );
  }
  if (/^exactdispatchpendingsignals$/u.test(name)) {
    return closedSpec(
      "process:signal",
      "WP7",
      "Pending-signal dispatch invokes shared listeners and may reset and re-deliver a signal to the host process.",
    );
  }

  // Closed escape surfaces precede broad filename-family checks.
  if (/inspector|debugger|cdp/u.test(text)) {
    const action = /evaluate|script|memory|responsebody|runtimeinspect/u.test(
      text,
    )
      ? "runtime:inspect"
      : "inspector:activate";
    return closedSpec(
      action,
      "WP7",
      "Inspector and runtime-inspection surfaces are closed in the initial profile.",
    );
  }
  if (/(?:^|[^a-z])wasi|wasi(?:$|[^a-z])/u.test(text)) {
    return closedSpec(
      "wasi:instantiate",
      "WP7",
      "WASI instantiation is closed in the initial profile.",
    );
  }
  if (
    /worker|worklet/u.test(text) &&
    !/schedule|callback|dispatch/u.test(text)
  ) {
    return closedSpec(
      "worker:create",
      "WP7",
      "Worker/worklet creation is closed until principal isolation is proved.",
    );
  }
  if (/\bvm\b|vmevaluate|evalincontext|runincontext/u.test(text)) {
    return closedSpec(
      "vm:evaluate",
      "WP7",
      "Unattributed VM evaluation is closed in the initial profile.",
    );
  }
  if (/ffi|native[_ -]?addon|dlopen/u.test(text)) {
    return closedSpec(
      "ffi:load",
      "WP7",
      "Native extension loading is closed in the initial profile.",
    );
  }
  if (/ipc|sendmsg|recvmsg/u.test(text)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Ambient or exported IPC channels are closed in the initial profile.",
    );
  }

  // Process-global mutations have distinct deny-only definitions.
  if (/setcwd|chdir/u.test(name)) {
    return closedSpec(
      "process:cwd",
      "WP7",
      "Process-global working-directory mutation is closed.",
    );
  }
  if (/processkill|spawnkill|exactkill|^kill$|exhostprocesskill/u.test(name)) {
    return closedSpec(
      "process:signal",
      "WP7",
      "Package-originated process signaling is closed.",
    );
  }
  if (/setuid|setgid|setgroups|setidentity/u.test(name)) {
    return closedSpec(
      "process:identity",
      "WP7",
      "Process identity mutation is closed.",
    );
  }
  if (/setpriority|nice/u.test(name)) {
    return closedSpec(
      "process:priority",
      "WP7",
      "Process priority mutation is closed.",
    );
  }
  if (/setrlimit|processlimit|resourcelimit/u.test(name)) {
    return closedSpec(
      "process:limit",
      "WP7",
      "Process resource-limit mutation is closed.",
    );
  }
  if (/umask/u.test(name)) {
    return closedSpec(
      "process:umask",
      "WP7",
      "Process umask mutation is closed.",
    );
  }
  if (/setenv|putenv|unsetenv|processenvwrite/u.test(name)) {
    return closedSpec(
      "env:process-write",
      "WP7",
      "Shared process-environment mutation is closed.",
    );
  }
  if (/^(?:exactexit|exacthostexit)$/u.test(name)) {
    return closedSpec(
      "process:signal",
      "WP7",
      "Runtime termination exits the shared host process and is not an authority-release operation.",
    );
  }
  if (/^exacttimer(?:ref|unref)$/u.test(name)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Timer ref-state mutation accepts a process-global sequential identifier without authenticating the timer owner.",
    );
  }
  if (/^exacttlsengine/u.test(name)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "TLS engine operations accept process-global sequential identifiers without principal ownership binding, exposing peer, plaintext, and mutable connection state.",
    );
  }
  if (/^exactzlib(?:create|write|params|close)$/u.test(name)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Streaming zlib operations accept process-global sequential identifiers without principal ownership binding.",
    );
  }

  if (/tcpreset/u.test(name)) {
    return nonCapabilitySpec("authority-release", "WP6");
  }
  if (/wsclose/u.test(name)) {
    return optionalPayloadNetworkEffectSpec(
      "network:connect",
      "network.native-operation.websocket-close-kind",
    );
  }

  // Release/cancel paths do not acquire new authority. This check comes after
  // payload-bearing close/reset special cases and before broader families.
  if (
    /freebuffer|freestring|close|dispose|cancel|unref|shutdown|finalize|abort|^exit$|exactexit|hostexit/u.test(
      name,
    )
  ) {
    return nonCapabilitySpec("authority-release", "WP8");
  }

  // Android/iOS device and clipboard boundaries.
  if (/clipboardread/u.test(name)) {
    return effectSpec(["clipboard:read"], "device", "WP8");
  }
  if (/clipboardwrite/u.test(name)) {
    return effectSpec(["clipboard:write"], "device", "WP8");
  }
  if (/camerametadata/u.test(name)) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }
  if (/androidcamerahostcall/u.test(name)) {
    return androidMediaOperationEffectSpec(
      "device.android-camera-native.operation",
    );
  }
  if (/camera/u.test(text)) {
    return effectSpec(["device:camera"], "device", "WP8", {
      lifetimeContract: "operation",
    });
  }
  if (/microphone|audioinput/u.test(text)) {
    return effectSpec(["device:microphone"], "device", "WP8", {
      lifetimeContract: "operation",
    });
  }
  if (
    /location|geolocation/u.test(text) &&
    !/servicesenabled|permissionstatus/u.test(text)
  ) {
    return effectSpec(["device:location"], "device", "WP8", {
      lifetimeContract: "operation",
    });
  }

  if (/getnetworkinterfaces/u.test(name)) {
    return effectSpec(["sys:read"], "system", "WP7");
  }

  // Standalone DNS is not folded into fetch/connect authority.
  if (/dns|lookup|resolveasync|reverseasync/u.test(text)) {
    return effectSpec(["network:resolve"], "network", "WP6");
  }
  if (/nativefetch|fetchrequest|fetchsync/u.test(name)) {
    return effectSpec(["network:fetch"], "network", "WP6", {
      lifetimeContract: "socket-stream",
    });
  }
  if (/httpserve/u.test(name)) {
    return effectSpec(["network:listen"], "network", "WP6", {
      lifetimeContract: "listener",
    });
  }
  if (
    /httpwait|httppoll|httpdrain|httpreadbody|httprespond|httpaddress|httpawaitwritable/u.test(
      name,
    )
  ) {
    return effectSpec(["network:listen"], "network", "WP6", {
      lifetimeContract: "listener",
      effectOwnerSource: "descriptor-owner",
      principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
    });
  }
  if (
    /httpsetref|httphasreferenced|httphaspendingrequests|httpisreferenced/u.test(
      name,
    )
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP8");
  }
  if (/tcpfromfd|udpfromfd|tcpgetfd|udpgetfd/u.test(name)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Raw descriptor adoption and export are closed until descriptor provenance and ownership are authenticated.",
    );
  }
  if (/udpsocket/u.test(name)) {
    return nonCapabilitySpec("unbound-owned-resource", "WP6");
  }
  if (/tcplisten|unixlisten|udplisten|udpbind/u.test(name)) {
    const actions = /unixlisten/u.test(name)
      ? ["fs:write", "network:listen"]
      : ["network:listen"];
    return effectSpec(actions, "network", "WP6", {
      lifetimeContract: "listener",
    });
  }
  if (/tcpaccept|unixaccept|udprecv/u.test(name)) {
    return effectSpec(["network:listen"], "network", "WP6", {
      lifetimeContract: "listener",
      effectOwnerSource: "descriptor-owner",
      principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
    });
  }
  if (
    /^(?:exact|exhost)(?:tcp|udp|unix|ws)/u.test(name) ||
    /unixconnect|websocket|wsconnect|wssend|wsrecv|network|socket/u.test(text)
  ) {
    if (
      /tcp(?:read|write|localaddr|remoteaddr|setkeepalive|setnodelay)|udpaddress/u.test(
        name,
      )
    ) {
      return retainedNetworkOriginEffectSpec(
        ["network:connect", "network:listen"],
        "network.native-descriptor.origin",
      );
    }
    const actions = /unixconnect/u.test(name)
      ? ["fs:read", "network:connect"]
      : ["network:connect"];
    return effectSpec(actions, "network", "WP6", {
      lifetimeContract: "socket-stream",
      effectOwnerSource: /read|write|send|recv|fd|address|poll/u.test(name)
        ? "descriptor-owner"
        : undefined,
      principalSources: /read|write|send|recv|fd|address|poll/u.test(name)
        ? ["descriptor-owner", "frame-set", "schedule-time"]
        : undefined,
    });
  }

  // Child creation composes executable, cwd, environment, and inherited stdio
  // effects into one conjunctive decision set.
  if (/spawnread|spawnrecv/u.test(name)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Child output and IPC reads remain closed until owned anonymous pipes are split from exported IPC channels.",
    );
  }
  if (/spawnwrite|spawnsend/u.test(name)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Child input and IPC writes remain closed until owned anonymous pipes are split from exported IPC channels.",
    );
  }
  if (/spawngetfd/u.test(name)) {
    return closedSpec(
      "ipc:channel",
      "WP7",
      "Raw child descriptor export is closed until endpoint provenance and transfer are typed.",
    );
  }
  if (/spawnpoll/u.test(name)) {
    return effectSpec(["process:spawn"], "process", "WP7", {
      lifetimeContract: "child-process",
      effectOwnerSource: "descriptor-owner",
      principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
    });
  }
  if (/spawn|execsync|childprocess/u.test(text)) {
    return processLaunchEffectSpec();
  }

  // Stdio is separate from generic process and crypto source files.
  if (/stdinread|readstdin/u.test(name)) {
    return effectSpec(["stdio:read"], "stdio", "WP7", {
      effectOwnerSource: "descriptor-owner",
      principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
    });
  }
  if (/setrawmode|stdioraw/u.test(name)) {
    return effectSpec(["stdio:raw"], "stdio", "WP7");
  }
  if (/stdioquery|isatty|fdpollhup/u.test(name)) {
    return effectSpec(["stdio:query"], "stdio", "WP7");
  }
  if (
    /consolelog|stdout|stderr|syncwritestream|^print$|^log$|^write$/u.test(name)
  ) {
    return effectSpec(["stdio:write"], "stdio", "WP7", {
      effectOwnerSource: "descriptor-owner",
      principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
    });
  }

  // Environment and system-information reads are independently typed.
  if (/getallenv/u.test(name)) {
    return environmentEnumerationEffectSpec();
  }
  if (/getenv|envget/u.test(name)) {
    return effectSpec(["env:read"], "environment", "WP7");
  }
  if (/getheapinfo|getgcstats|getsourcecachestats/u.test(name)) {
    return closedSpec(
      "runtime:inspect",
      "WP7",
      "Heap, GC, and source-cache inspection are closed runtime introspection surfaces.",
    );
  }
  if (/signalnumbers/u.test(name)) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }
  if (
    /getcpucount|getfreemem|gettotalmem|getloadavg|getuptime|getuserinfo|gethostname|getnetworkinterfaces|getscreeninfo|getprocessrss|getcwd|platformversion|osrelease|localesnapshot|androidstoragepaths|arch$|platform$|language$|locale$|^uptime$|cpuusage|memoryusage|getuid|getgid|getgroups/u.test(
      name,
    )
  ) {
    return effectSpec(["sys:read"], "system", "WP7");
  }

  if (/which$/u.test(name)) {
    return effectSpec(["env:read", "fs:list"], "filesystem", "WP7");
  }

  // SQLite decomposes into filesystem authority; no sqlite:* positive action
  // survives in the canonical vocabulary.
  if (/sqlite/u.test(text)) {
    if (/close|finalize/u.test(name))
      return nonCapabilitySpec("authority-release", "WP5");
    if (/expandedsql|intransaction/u.test(name)) {
      return nonCapabilitySpec("authority-control-plane", "WP5");
    }
    if (/all|get|values/u.test(name)) {
      return sqliteReadEffectSpec();
    }
    if (/open/u.test(name)) return sqliteOpenEffectSpec();
    if (/prepare/u.test(name)) return sqliteReadEffectSpec();
    return sqliteStatementEffectSpec();
  }

  // Web storage remains closed until native namespace isolation is proved.
  if (/svget|storageget|storageread/u.test(name)) {
    return closedSpec(
      "storage:read",
      "WP7",
      "Storage reads are closed until namespace isolation is proved.",
    );
  }
  if (/svset|storageset|storagewrite/u.test(name)) {
    return closedSpec(
      "storage:write",
      "WP7",
      "Storage writes are closed until namespace isolation is proved.",
    );
  }
  if (/storagepersist|persiststorage/u.test(name)) {
    return closedSpec(
      "storage:persist",
      "WP7",
      "Persistent storage is closed until quota and namespace gates are proved.",
    );
  }

  // Module resolution reads metadata and source from the filesystem.
  if (/moduleresolvemeta|nativeresolvemeta/u.test(name)) {
    return effectSpec(["fs:list"], "loader", "WP7", {
      principalSources: ["loader-referrer"],
      effectOwnerSource: "loader-referrer",
      gate: "loader-admission",
    });
  }
  if (/moduleresolve|nativeresolve/u.test(name)) {
    return effectSpec(["fs:list", "fs:read"], "loader", "WP7", {
      principalSources: ["loader-referrer"],
      effectOwnerSource: "loader-referrer",
      gate: "loader-admission",
    });
  }

  // Filesystem operations. Installer names were handled above.
  if (
    /^exhostfs|^exactfs|^exactaccess$|^exactstat$|readfile|writefile|appendfile|readdir|opendir|readlink|realpath|statfs|lstat|mkdir|mkdtemp|rmdir|unlink|rename|copyfile|^exactlink$|^exhostfslink$|chmod|chown|symlink|truncate|utimes|lutimes/u.test(
      name,
    ) ||
    /\bfs\b/u.test(text)
  ) {
    const descriptorOperation =
      /fd|fstat|fchmod|fchown|fdatasync|fsync|ftruncate|futimes|readv|writev|^exactfs(?:read|write)(?:async)?$|^exhostfs(?:read|write|pread|pwrite|seek|close)$/u.test(
        name,
      );
    const descriptorOptions = descriptorOperation
      ? {
          effectOwnerSource: "descriptor-owner",
          principalSources: ["descriptor-owner", "frame-set", "schedule-time"],
          lifetimeContract: "file-handle",
        }
      : {};
    if (/watch/u.test(name))
      return effectSpec(["fs:list", "fs:watch"], "filesystem", "WP5", {
        lifetimeContract: "watch",
        ...descriptorOptions,
      });
    if (/close|seek/u.test(name))
      return nonCapabilitySpec("authority-control-plane", "WP5");
    if (/fspathasync/u.test(name)) {
      return filesystemPathDispatcherEffectSpec();
    }
    if (/^exactfsfdasync$/u.test(name)) {
      return filesystemDescriptorDispatcherEffectSpec();
    }
    if (/^exactfs(?:readfile|writefile|stat)async$/u.test(name)) {
      const actions = /readfile/u.test(name)
        ? ["fs:read"]
        : /writefile/u.test(name)
          ? ["fs:write"]
          : ["fs:list"];
      return filesystemPathOrDescriptorEffectSpec(actions);
    }
    if (/opendir|readdir|stat|access|realpath/u.test(name)) {
      return effectSpec(["fs:list"], "filesystem", "WP5", descriptorOptions);
    }
    if (/readlink/u.test(name)) {
      return effectSpec(["fs:read"], "filesystem", "WP5", descriptorOptions);
    }
    if (/open/u.test(name)) {
      return filesystemOpenEffectSpec(descriptorOptions);
    }
    if (/copy/u.test(name)) {
      return effectSpec(
        ["fs:read", "fs:write"],
        "filesystem",
        "WP5",
        descriptorOptions,
      );
    }
    if (/^(?:exact|exhostfs)link$/u.test(name)) {
      return effectSpec(
        ["fs:read", "fs:write"],
        "filesystem",
        "WP5",
        descriptorOptions,
      );
    }
    if (
      /write|append|truncate|chmod|chown|mkdir|mkdtemp|rmdir|unlink|rename|link|symlink|utimes|fdatasync|fsync/u.test(
        name,
      )
    ) {
      return effectSpec(
        descriptorOperation ? ["fs:write"] : ["fs:list", "fs:write"],
        "filesystem",
        "WP5",
        descriptorOptions,
      );
    }
    if (/readfile|pread|fsread|readv/u.test(name))
      return effectSpec(["fs:read"], "filesystem", "WP5", descriptorOptions);
    return effectSpec(["fs:list"], "filesystem", "WP5", descriptorOptions);
  }

  // Signals are installed from the crypto compilation unit on Unix.
  if (/trapsignal|resetsignal|pollsignal/u.test(name)) {
    return closedSpec(
      "process:signal",
      "WP7",
      "Process signal control is closed in the initial profile.",
    );
  }

  // Pure crypto/randomness, clocks, and byte transforms are reasoned
  // non-capabilities rather than ambient grants.
  if (/random|getrandomvalues|randomfill/u.test(name)) {
    return nonCapabilitySpec("ordinary-randomness", "WP1");
  }
  if (
    /performancenow|performancetimeorigin|timenow|highres|hrtime/u.test(name)
  ) {
    return nonCapabilitySpec("ordinary-time", "WP1");
  }
  if (
    /zlib|deflate|inflate|brotli|bytestoutf8|stringtoutf8|buffer|encode|decode/u.test(
      text,
    )
  ) {
    return nonCapabilitySpec("internal-data-transform", "WP1");
  }
  if (/tlsengine/u.test(name)) {
    return nonCapabilitySpec("internal-data-transform", "WP1");
  }
  if (
    /crypto|hash|hmac|pbkdf|scrypt|hkdf|aes|rsa|ecdsa|ed25519|x25519|cipher|(?:sign|verify)(?:sync)?$|keypair|importkey|exportkey|ecdh/u.test(
      name,
    )
  ) {
    return nonCapabilitySpec("pure-in-memory-compute", "WP1");
  }

  // Security/control-plane and callback plumbing are critical inventory rows,
  // but the bookkeeping act is not itself an external effect.
  if (
    /capability|permission|handle(?!r)|checkimport|register(?:module)?package|hasdeputyclasses|isallowall|active(module|package)|pendingpackage|principal|security|audit|logevent|grant|revoke/u.test(
      `${name} ${text}`,
    )
  ) {
    return nonCapabilitySpec("authority-control-plane", "WP8");
  }
  if (
    /callback|queue|schedule|dispatch|nexttick|microtask|timer|animationframe|notify|moduleevent|drainplatformevents/u.test(
      `${name} ${text}`,
    )
  ) {
    return nonCapabilitySpec("callback-attribution-carrier", "WP8");
  }
  if (
    /version|init|install|platformstate|appstate|appearance|initialurl|dialog|modulebuiltin|barepackagename|sourcachestats|consoleflush/u.test(
      `${name} ${text}`,
    )
  ) {
    return nonCapabilitySpec("runtime-bootstrap-state", "WP4");
  }

  return null;
}

function defaultPrincipalSources(surface, specification) {
  if (specification.principalSources)
    return canonicalStringSet(specification.principalSources);
  if (surface.kind === "loader") return ["loader-referrer"];
  if (surface.kind === "cli" || surface.kind === "startup") return ["root"];
  return ["frame-set", "schedule-time"];
}

function defaultEffectOwner(surface, specification) {
  if (specification.effectOwnerSource) return specification.effectOwnerSource;
  if (surface.kind === "loader") return "loader-referrer";
  if (surface.kind === "cli" || surface.kind === "startup") return "root";
  return "innermost-nontransparent-frame";
}

function validateStableId(value, label) {
  if (!STABLE_ID_RE.test(value))
    throw new Error(`${label} is not a stable id: ${value}`);
  return value;
}

function semanticEdge(surface, specification, context) {
  const id = validateStableId(
    surface.metadata?.edgeId ?? stableIdForSurface(surface),
    "coverage edge id",
  );
  const semanticSurface = { kind: surface.kind, name: surface.name };
  if (specification.classification === "non-capability") {
    const rationale = context.rationalesById.get(specification.rationaleId);
    if (!rationale) {
      throw new Error(
        `${surface.observedKey}: unknown non-capability rationale ${specification.rationaleId}`,
      );
    }
    return {
      id,
      classification: "non-capability",
      surface: semanticSurface,
      rationaleId: rationale.id,
      rationale: rationale.rationale,
    };
  }
  if (specification.classification === "closed") {
    const definition = context.definitionsById.get(specification.action);
    if (!definition)
      throw new Error(
        `${surface.observedKey}: unknown closed action ${specification.action}`,
      );
    if (definition.lifecycle !== "deny-only") {
      throw new Error(
        `${surface.observedKey}: closed action ${specification.action} is not deny-only`,
      );
    }
    return {
      id,
      classification: "closed",
      surface: semanticSurface,
      cap: specification.action,
      rationale: specification.rationale,
    };
  }
  if (!specification.actions?.length) {
    throw new Error(
      `${surface.observedKey}: effect classification has no actions`,
    );
  }
  const effects = specification.actions
    .map((action) =>
      deriveEffectTemplate(action, context, {
        stages: specification.stagesByAction?.[action],
      }),
    )
    .sort((left, right) => utf8Compare(left.cap, right.cap));
  const barriers =
    specification.barriers ?? FAMILY_BARRIERS[specification.family];
  if (!barriers)
    throw new Error(
      `${surface.observedKey}: unknown coverage family ${specification.family}`,
    );
  if (
    specification.effectMode === "conditional-unrefined" &&
    (!specification.refinementOwner || !specification.rationale)
  ) {
    throw new Error(
      `${surface.observedKey}: conditional effect set lacks refinement owner/rationale`,
    );
  }
  let logicalBranches;
  if (specification.effectMode === "conditional") {
    if (
      !Array.isArray(specification.logicalBranches) ||
      specification.logicalBranches.length < 2
    ) {
      throw new Error(
        `${surface.observedKey}: conditional edge lacks logical branches`,
      );
    }
    const seenIds = new Set();
    const priorConditions = [];
    logicalBranches = specification.logicalBranches
      .map((branch) => {
        const branchId = validateStableId(branch.id, "logical branch id");
        if (seenIds.has(branchId)) {
          throw new Error(
            `${surface.observedKey}: duplicate logical branch ${branchId}`,
          );
        }
        seenIds.add(branchId);
        const when = [...branch.when]
          .map((condition) => ({
            fact: validateStableId(condition.fact, "logical branch fact"),
            equals: validateStableId(
              condition.equals,
              "logical branch fact value",
            ),
          }))
          .sort((left, right) =>
            utf8Compare(
              JSON.stringify([left.fact, left.equals]),
              JSON.stringify([right.fact, right.equals]),
            ),
          );
        const overlaps = priorConditions.some((prior) =>
          logicalBranchConditionsOverlap(prior, when),
        );
        if (overlaps) {
          throw new Error(
            `${surface.observedKey}: overlapping logical branch conditions`,
          );
        }
        priorConditions.push(when);
        const branchBarriers =
          branch.barriers ??
          specification.barriers ??
          FAMILY_BARRIERS[specification.family];
        const branchEffects = canonicalStringSet(branch.actions).map((action) =>
          deriveEffectTemplate(action, context, {
            stages: branch.stagesByAction?.[action],
          }),
        );
        return {
          id: branchId,
          when,
          effects: branchEffects,
          principalSources: canonicalStringSet(
            branch.principalSources ??
              defaultPrincipalSources(surface, specification),
          ),
          effectOwnerSource:
            branch.effectOwnerSource ??
            defaultEffectOwner(surface, specification),
          lifetimeContract:
            branch.lifetimeContract ?? specification.lifetimeContract,
          barriers: {
            authorizeBefore: [...branchBarriers.authorizeBefore],
            recheckAt: [...branchBarriers.recheckAt],
            cancelAt: [...branchBarriers.cancelAt],
          },
        };
      })
      .sort((left, right) => utf8Compare(left.id, right.id));
  }
  return {
    id,
    classification: "effects",
    surface: semanticSurface,
    effects,
    principalSources: defaultPrincipalSources(surface, specification),
    effectOwnerSource: defaultEffectOwner(surface, specification),
    gate:
      specification.gate ??
      (surface.kind === "loader" ? "loader-admission" : "reclassifies"),
    effectMode: specification.effectMode,
    ...(logicalBranches === undefined ? {} : { logicalBranches }),
    ...(specification.effectMode === "conditional-unrefined"
      ? {
          refinementOwner: specification.refinementOwner,
          rationale: specification.rationale,
        }
      : {}),
    atomicityGroup: validateStableId(
      specification.atomicityGroup ?? `${id}.decision`,
      "atomicity group",
    ),
    lifetimeContract: specification.lifetimeContract,
    barriers: {
      authorizeBefore: [...barriers.authorizeBefore],
      recheckAt: [...barriers.recheckAt],
      cancelAt: [...barriers.cancelAt],
    },
  };
}

function normalizedBranchSpecs(surface) {
  const metadata = surface.metadata ?? {};
  const supplied = metadata.branches ?? metadata.alternatives;
  if (!supplied?.length) {
    const targetVariant = metadata.targetVariant ?? "all";
    return [
      {
        id: metadata.branchId ?? "main",
        kind: metadata.branchKind ?? "single",
        targetVariant,
        targetApplicability: targetApplicabilityForVariant(targetVariant),
        sourceRefs: surface.sourceRefs,
        implementationOwner: metadata.implementationOwner,
        fixtureObligations: metadata.fixtureObligations,
      },
    ];
  }
  return supplied.map((branch, index) => {
    if (typeof branch === "string") {
      return {
        id: branch,
        kind: supplied.length > 1 ? "alternative" : "single",
        targetVariant: "all",
        targetApplicability: targetApplicabilityForVariant("all"),
        sourceRefs: surface.sourceRefs,
      };
    }
    const targetVariant = branch.targetVariant ?? "all";
    return {
      id: branch.id ?? branch.name ?? `branch-${index + 1}`,
      kind:
        branch.kind ??
        branch.branchKind ??
        (supplied.length > 1 ? "alternative" : "single"),
      targetVariant,
      targetApplicability: targetApplicabilityForVariant(targetVariant),
      backend: branch.backend,
      implementationDisposition: branch.implementationDisposition,
      stubDisposition: branch.stubDisposition,
      sourceRefs: branch.sourceRefs ?? surface.sourceRefs,
      implementationOwner: branch.implementationOwner,
      fixtureObligations: branch.fixtureObligations,
    };
  });
}

export function expandImplementationBranches(surface, edge, specification) {
  const implementationDispositions = new Set([
    "concrete",
    "degraded-concrete",
    "unsupported-stub",
  ]);
  const stubDispositions = new Set([
    "weak-fallback",
    "contains-weak-fallback",
    "not-structurally-proven",
  ]);
  const seenBranchIds = new Set();
  return normalizedBranchSpecs(surface).map((branch) => {
    if (branch.kind !== "single" && branch.kind !== "alternative") {
      throw new Error(
        `${surface.observedKey}: invalid branch kind ${branch.kind}`,
      );
    }
    const branchId = validateStableId(
      `${edge.id}.${stableComponent(branch.id, "main")}`,
      "implementation branch id",
    );
    if (seenBranchIds.has(branchId)) {
      throw new Error(
        `${surface.observedKey}: duplicate implementation branch ${branchId}`,
      );
    }
    seenBranchIds.add(branchId);
    const sourceRefs = canonicalStringSet(branch.sourceRefs ?? []);
    if (sourceRefs.length === 0)
      throw new Error(`${branchId}: branch has no sourceRefs`);
    const enforcement = enforcementBranchIdentity(edge, {
      ...branch,
      branchId,
      sourceRefs,
    });
    const fixtureObligations = fixtureObligationsForBranch(
      edge,
      enforcement.id,
    );
    if (
      branch.fixtureObligations !== undefined &&
      JSON.stringify(canonicalStringSet(branch.fixtureObligations)) !==
        JSON.stringify(fixtureObligations)
    ) {
      throw new Error(
        `${branchId}: authored fixture obligations disagree with semantic derivation`,
      );
    }
    if (fixtureObligations.length === 0) {
      throw new Error(`${branchId}: branch has no fixture obligations`);
    }
    if (
      branch.implementationDisposition !== undefined &&
      !implementationDispositions.has(branch.implementationDisposition)
    ) {
      throw new Error(
        `${branchId}: unreviewed implementation disposition ${branch.implementationDisposition}`,
      );
    }
    if (
      branch.stubDisposition !== undefined &&
      !stubDispositions.has(branch.stubDisposition)
    ) {
      throw new Error(
        `${branchId}: unreviewed stub disposition ${branch.stubDisposition}`,
      );
    }
    return {
      edgeId: edge.id,
      observedKey: surface.observedKey,
      branchId,
      enforcementBranchId: enforcement.id,
      enforcementRoute: {
        kind: enforcement.routeKind,
        proofPaths: [surface.observedKey],
        proofSourceRefs: sourceRefs,
        sourceRefs,
        terminalObservedKey: surface.observedKey,
      },
      branchKind: branch.kind,
      targetVariant: branch.targetVariant,
      targetApplicability: branch.targetApplicability,
      ...(branch.backend === undefined
        ? {}
        : {
            backend: validateStableId(
              branch.backend,
              "implementation backend id",
            ),
          }),
      ...(branch.implementationDisposition === undefined
        ? {}
        : {
            implementationDisposition: branch.implementationDisposition,
          }),
      ...(branch.stubDisposition === undefined
        ? {}
        : { stubDisposition: branch.stubDisposition }),
      sourceRefs,
      implementationOwner:
        branch.implementationOwner ?? specification.implementationOwner,
      fixtureObligations,
    };
  });
}

export function classifyObservedSurface(inputSurface, context) {
  const surface = validateSurface(inputSurface);
  const prepared = preparedContext(context);
  const specification = classifyConcreteSurface(surface);
  if (!specification) {
    throw new Error(`unclassified observed surface ${surface.observedKey}`);
  }
  const edge = semanticEdge(surface, specification, prepared);
  return {
    edge,
    implementationRows: expandImplementationBranches(
      surface,
      edge,
      specification,
    ),
    definitionIds:
      edge.classification === "effects"
        ? edge.effects.map((effect) => effect.cap)
        : edge.classification === "closed"
          ? [edge.cap]
          : [],
    specification,
  };
}

export function buildDefinitionCoverage(definitions, edges) {
  const rows = definitionsArray(definitions);
  const effectEdgesByAction = new Map();
  const closedEdgesByAction = new Map();
  for (const edge of edges) {
    if (edge.classification === "effects") {
      for (const effect of edge.effects) {
        const ids = effectEdgesByAction.get(effect.cap) ?? [];
        ids.push(edge.id);
        effectEdgesByAction.set(effect.cap, ids);
      }
    } else if (edge.classification === "closed") {
      const ids = closedEdgesByAction.get(edge.cap) ?? [];
      ids.push(edge.id);
      closedEdgesByAction.set(edge.cap, ids);
    }
  }

  return [...rows]
    .sort((left, right) => utf8Compare(left.id, right.id))
    .map((definition) => {
      const effectIds = canonicalStringSet(
        effectEdgesByAction.get(definition.id) ?? [],
      );
      const closedIds = canonicalStringSet(
        closedEdgesByAction.get(definition.id) ?? [],
      );
      if (effectIds.length) {
        return {
          definitionId: definition.id,
          disposition: "covered",
          edgeIds: effectIds,
          rationale: `Covered by ${effectIds.length} observed effect edge${effectIds.length === 1 ? "" : "s"}.`,
        };
      }
      if (closedIds.length) {
        return {
          definitionId: definition.id,
          disposition: "closed",
          edgeIds: closedIds,
          rationale: `Closed by ${closedIds.length} observed surface edge${closedIds.length === 1 ? "" : "s"}.`,
        };
      }
      if (definition.lifecycle === "authorable") {
        return {
          definitionId: definition.id,
          disposition: "unsupported",
          edgeIds: [],
          rationale:
            "No observed surface is classified for this authorable definition.",
        };
      }
      return {
        definitionId: definition.id,
        disposition: "absent",
        edgeIds: [],
        rationale:
          "No observed surface is classified for this deny-only definition.",
      };
    });
}

export function buildCoverageModel(surfaces, { definitions, rules }) {
  if (!Array.isArray(surfaces))
    throw new Error("observed surfaces must be an array");
  const prepared = prepareCoverageContext({ definitions, rules });
  const seenObservedKeys = new Set();
  const seenEdgeIds = new Map();
  const surfaceByObservedKey = new Map();
  const edges = [];
  const implementationRows = [];

  for (const input of [...surfaces].sort((left, right) =>
    utf8Compare(
      left.observedKey ?? `${left.kind}:${left.name}`,
      right.observedKey ?? `${right.kind}:${right.name}`,
    ),
  )) {
    const observedKey = input.observedKey ?? `${input.kind}:${input.name}`;
    if (seenObservedKeys.has(observedKey)) {
      throw new Error(`duplicate observed surface ${observedKey}`);
    }
    seenObservedKeys.add(observedKey);
    surfaceByObservedKey.set(observedKey, input);
    const classification = classifyObservedSurface(input, prepared);
    const priorObservedKey = seenEdgeIds.get(classification.edge.id);
    if (priorObservedKey) {
      throw new Error(
        `coverage edge id collision ${classification.edge.id}: ${priorObservedKey} and ${observedKey}`,
      );
    }
    seenEdgeIds.set(classification.edge.id, observedKey);
    edges.push(classification.edge);
    implementationRows.push(...classification.implementationRows);
  }

  edges.sort((left, right) => utf8Compare(left.id, right.id));
  implementationRows.sort((left, right) => {
    const edgeOrder = utf8Compare(left.edgeId, right.edgeId);
    return edgeOrder || utf8Compare(left.branchId, right.branchId);
  });
  const edgeById = new Map(edges.map((edge) => [edge.id, edge]));
  const terminalRowsByObservedKey = new Map();
  for (const row of implementationRows) {
    const edge = edgeById.get(row.edgeId);
    if (
      edge.classification === "effects" &&
      (edge.surface.kind === "native-op" || edge.surface.kind === "host-abi")
    ) {
      const rows = terminalRowsByObservedKey.get(row.observedKey) ?? [];
      rows.push(row);
      terminalRowsByObservedKey.set(row.observedKey, rows);
    }
  }
  for (const row of implementationRows) {
    const edge = edgeById.get(row.edgeId);
    if (edge.classification !== "effects" || edge.surface.kind !== "builtin") {
      continue;
    }
    const evidence = surfaceByObservedKey.get(row.observedKey)?.metadata
      ?.enforcementRouteEvidence;
    if (
      evidence?.kind !== "static-builtin-call-graph" ||
      evidence.ambiguousCallees?.length !== 0 ||
      !Array.isArray(evidence.paths) ||
      evidence.paths.length === 0 ||
      evidence.terminals?.length !== 1
    ) {
      continue;
    }
    const terminalObservedKey = `native-op:${evidence.terminals[0]}`;
    const candidates = (terminalRowsByObservedKey.get(terminalObservedKey) ?? [])
      .filter((candidate) => {
        const terminalEdge = edgeById.get(candidate.edgeId);
        return (
          JSON.stringify(enforcementSemanticShape(terminalEdge)) ===
            JSON.stringify(enforcementSemanticShape(edge)) &&
          candidate.targetVariant === row.targetVariant &&
          JSON.stringify(candidate.targetApplicability) ===
            JSON.stringify(row.targetApplicability) &&
          (candidate.backend ?? null) === (row.backend ?? null) &&
          (candidate.implementationDisposition ?? null) ===
            (row.implementationDisposition ?? null) &&
          (candidate.stubDisposition ?? null) === (row.stubDisposition ?? null)
        );
      });
    if (candidates.length !== 1) continue;
    const terminal = candidates[0];
    row.enforcementRoute = {
      kind: "static-builtin-call-graph",
      proofPaths: canonicalStringSet(evidence.paths),
      proofSourceRefs: [...row.sourceRefs],
      sourceRefs: [...terminal.sourceRefs],
      terminalObservedKey,
    };
    const enforcement = enforcementBranchIdentity(edge, row);
    row.enforcementBranchId = enforcement.id;
    row.fixtureObligations = fixtureObligationsForBranch(
      edge,
      enforcement.id,
    );
  }
  const enforcementKeys = new Map();
  for (const row of implementationRows) {
    const edge = edgeById.get(row.edgeId);
    const enforcement = enforcementBranchIdentity(edge, row);
    if (enforcement.id !== row.enforcementBranchId) {
      throw new Error(
        `${row.branchId}: enforcement branch identity is not reproducible`,
      );
    }
    const prior = enforcementKeys.get(enforcement.id);
    if (prior !== undefined && prior !== enforcement.key) {
      throw new Error(
        `enforcement branch id collision ${enforcement.id}`,
      );
    }
    enforcementKeys.set(enforcement.id, enforcement.key);
  }
  const coverage = { coverageSchema: COVERAGE_SCHEMA, profile: PROFILE, edges };
  const definitionCoverage = buildDefinitionCoverage(
    prepared.definitions,
    edges,
  );
  return {
    coverage,
    coverageDataset: coverage,
    implementationRows,
    implementations: implementationRows,
    definitionCoverage,
  };
}
