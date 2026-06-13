//#region \0rolldown/runtime.js
var __commonJSMin = (cb, mod) => () => (mod || (cb((mod = { exports: {} }).exports, mod), cb = null), mod.exports);
//#endregion
//#region src/builtins/module.js
var runtimeModuleManifest = (/* @__PURE__ */ __commonJSMin(((exports, module) => {
	const publicBuiltins = Object.freeze([
		{
			"name": "assert",
			"nodeOnly": false
		},
		{
			"name": "assert/strict",
			"nodeOnly": false
		},
		{
			"name": "async_hooks",
			"nodeOnly": false
		},
		{
			"name": "buffer",
			"nodeOnly": false
		},
		{
			"name": "child_process",
			"nodeOnly": false
		},
		{
			"name": "cluster",
			"nodeOnly": false
		},
		{
			"name": "console",
			"nodeOnly": false
		},
		{
			"name": "constants",
			"nodeOnly": false
		},
		{
			"name": "crypto",
			"nodeOnly": false
		},
		{
			"name": "dgram",
			"nodeOnly": false
		},
		{
			"name": "diagnostics_channel",
			"nodeOnly": false
		},
		{
			"name": "dns",
			"nodeOnly": false
		},
		{
			"name": "dns/promises",
			"nodeOnly": false
		},
		{
			"name": "domain",
			"nodeOnly": false
		},
		{
			"name": "events",
			"nodeOnly": false
		},
		{
			"name": "fs",
			"nodeOnly": false
		},
		{
			"name": "fs/promises",
			"nodeOnly": false
		},
		{
			"name": "http",
			"nodeOnly": false
		},
		{
			"name": "http2",
			"nodeOnly": false
		},
		{
			"name": "https",
			"nodeOnly": false
		},
		{
			"name": "inspector",
			"nodeOnly": false
		},
		{
			"name": "inspector/promises",
			"nodeOnly": false
		},
		{
			"name": "module",
			"nodeOnly": false
		},
		{
			"name": "net",
			"nodeOnly": false
		},
		{
			"name": "os",
			"nodeOnly": false
		},
		{
			"name": "path",
			"nodeOnly": false
		},
		{
			"name": "path/posix",
			"nodeOnly": false
		},
		{
			"name": "path/win32",
			"nodeOnly": false
		},
		{
			"name": "perf_hooks",
			"nodeOnly": false
		},
		{
			"name": "process",
			"nodeOnly": false
		},
		{
			"name": "punycode",
			"nodeOnly": false
		},
		{
			"name": "querystring",
			"nodeOnly": false
		},
		{
			"name": "readline",
			"nodeOnly": false
		},
		{
			"name": "readline/promises",
			"nodeOnly": false
		},
		{
			"name": "stream",
			"nodeOnly": false
		},
		{
			"name": "stream/consumers",
			"nodeOnly": false
		},
		{
			"name": "stream/promises",
			"nodeOnly": false
		},
		{
			"name": "stream/web",
			"nodeOnly": false
		},
		{
			"name": "string_decoder",
			"nodeOnly": false
		},
		{
			"name": "sys",
			"nodeOnly": false
		},
		{
			"name": "timers",
			"nodeOnly": false
		},
		{
			"name": "timers/promises",
			"nodeOnly": false
		},
		{
			"name": "tls",
			"nodeOnly": false
		},
		{
			"name": "trace_events",
			"nodeOnly": false
		},
		{
			"name": "tty",
			"nodeOnly": false
		},
		{
			"name": "url",
			"nodeOnly": false
		},
		{
			"name": "util",
			"nodeOnly": false
		},
		{
			"name": "util/types",
			"nodeOnly": false
		},
		{
			"name": "v8",
			"nodeOnly": false
		},
		{
			"name": "vm",
			"nodeOnly": false
		},
		{
			"name": "wasi",
			"nodeOnly": false
		},
		{
			"name": "worker_threads",
			"nodeOnly": false
		},
		{
			"name": "zlib",
			"nodeOnly": false
		}
	]);
	const reservedNodeOnlyBuiltins = Object.freeze(["sqlite", "sea"]);
	const registryEntries = Object.freeze([
		{
			"specifier": "exact:process",
			"sourceKey": "exact_process",
			"moduleBuiltin": false,
			"bundleExternal": true
		},
		{
			"specifier": "exact:crypto",
			"sourceKey": "exact_crypto",
			"moduleBuiltin": false,
			"bundleExternal": true
		},
		{
			"specifier": "exact:clipboard",
			"sourceKey": "exact_clipboard",
			"moduleBuiltin": false,
			"bundleExternal": true
		},
		{
			"specifier": "exact:http",
			"sourceKey": "exact_http",
			"moduleBuiltin": false,
			"bundleExternal": true
		},
		{
			"specifier": "exact:sqlite",
			"sourceKey": "exact_sqlite",
			"moduleBuiltin": false,
			"bundleExternal": true
		},
		{
			"specifier": "bun:sqlite",
			"sourceKey": "exact_sqlite",
			"moduleBuiltin": false,
			"bundleExternal": true
		},
		{
			"specifier": "bun:fs",
			"sourceKey": "node_fs",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:fs",
			"sourceKey": "node_fs",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "fs",
			"sourceKey": "node_fs",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:process",
			"sourceKey": "exact_process",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "process",
			"sourceKey": "exact_process",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "bun:fs/promises",
			"sourceKey": "node_fs_promises",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:fs/promises",
			"sourceKey": "node_fs_promises",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "fs/promises",
			"sourceKey": "node_fs_promises",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "internal/fs/promises",
			"sourceKey": "node_fs_promises",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "node:path",
			"sourceKey": "node_path",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "path",
			"sourceKey": "node_path",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:path/posix",
			"sourceKey": "path_posix_alias",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "path/posix",
			"sourceKey": "path_posix_alias",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:path/win32",
			"sourceKey": "path_win32_alias",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "path/win32",
			"sourceKey": "path_win32_alias",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:crypto",
			"sourceKey": "exact_crypto",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "crypto",
			"sourceKey": "exact_crypto",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:events",
			"sourceKey": "node_events",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "events",
			"sourceKey": "node_events",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:stream",
			"sourceKey": "node_stream",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "stream",
			"sourceKey": "node_stream",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "_stream_readable",
			"sourceKey": "legacy_stream_readable",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "_stream_writable",
			"sourceKey": "legacy_stream_writable",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "_stream_duplex",
			"sourceKey": "legacy_stream_duplex",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "_stream_transform",
			"sourceKey": "legacy_stream_transform",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "_stream_passthrough",
			"sourceKey": "legacy_stream_passthrough",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "node:stream/consumers",
			"sourceKey": "node_stream_consumers",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "stream/consumers",
			"sourceKey": "node_stream_consumers",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:stream/promises",
			"sourceKey": "node_stream_promises",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "stream/promises",
			"sourceKey": "node_stream_promises",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:buffer",
			"sourceKey": "node_buffer",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "buffer",
			"sourceKey": "node_buffer",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:util",
			"sourceKey": "node_util",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "util",
			"sourceKey": "node_util",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "sys",
			"sourceKey": "node_util",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:sys",
			"sourceKey": "node_util",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "util/types",
			"sourceKey": "util_types_alias",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:util/types",
			"sourceKey": "node_util_types_alias",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:timers",
			"sourceKey": "node_timers",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "timers",
			"sourceKey": "node_timers",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:timers/promises",
			"sourceKey": "node_timers_promises",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "timers/promises",
			"sourceKey": "node_timers_promises",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:http",
			"sourceKey": "node_http",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "http",
			"sourceKey": "node_http",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "_http_agent",
			"sourceKey": "node_http",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "_http_common",
			"sourceKey": "node_http",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "_http_server",
			"sourceKey": "node_http",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "_http_outgoing",
			"sourceKey": "node_http",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "_http_incoming",
			"sourceKey": "node_http",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "node:https",
			"sourceKey": "node_https",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "https",
			"sourceKey": "node_https",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:stream/web",
			"sourceKey": "node_stream_web",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "stream/web",
			"sourceKey": "node_stream_web",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:url",
			"sourceKey": "node_url",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "url",
			"sourceKey": "url_alias",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:os",
			"sourceKey": "node_os",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "os",
			"sourceKey": "node_os",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:tty",
			"sourceKey": "node_tty",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "tty",
			"sourceKey": "node_tty",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:assert",
			"sourceKey": "node_assert",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "assert",
			"sourceKey": "node_assert",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:assert/strict",
			"sourceKey": "node_assert",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "assert/strict",
			"sourceKey": "node_assert",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:string_decoder",
			"sourceKey": "node_string_decoder",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "string_decoder",
			"sourceKey": "node_string_decoder",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:querystring",
			"sourceKey": "node_querystring",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "querystring",
			"sourceKey": "node_querystring",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:punycode",
			"sourceKey": "node_punycode",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "punycode",
			"sourceKey": "node_punycode",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:child_process",
			"sourceKey": "node_child_process",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "child_process",
			"sourceKey": "node_child_process",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:readline",
			"sourceKey": "node_readline",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "readline",
			"sourceKey": "node_readline",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:readline/promises",
			"sourceKey": "node_readline",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "readline/promises",
			"sourceKey": "node_readline",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:module",
			"sourceKey": "node_module",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "module",
			"sourceKey": "node_module",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:zlib",
			"sourceKey": "node_zlib",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "zlib",
			"sourceKey": "node_zlib",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:tls",
			"sourceKey": "node_tls",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "tls",
			"sourceKey": "node_tls",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:dns",
			"sourceKey": "node_dns",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "dns",
			"sourceKey": "node_dns",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:dns/promises",
			"sourceKey": "node_dns_promises",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "dns/promises",
			"sourceKey": "node_dns_promises",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "internal/fs/utils",
			"sourceKey": "internal_fs_utils",
			"moduleBuiltin": false,
			"bundleExternal": false
		},
		{
			"specifier": "node:net",
			"sourceKey": "node_net",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "net",
			"sourceKey": "node_net",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:perf_hooks",
			"sourceKey": "node_perf_hooks",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "perf_hooks",
			"sourceKey": "node_perf_hooks",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:async_hooks",
			"sourceKey": "node_async_hooks",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "async_hooks",
			"sourceKey": "node_async_hooks",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:worker_threads",
			"sourceKey": "node_worker_threads",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "worker_threads",
			"sourceKey": "node_worker_threads",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:vm",
			"sourceKey": "node_vm",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "vm",
			"sourceKey": "node_vm",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:console",
			"sourceKey": "node_console",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "console",
			"sourceKey": "node_console",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:cluster",
			"sourceKey": "node_cluster",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "cluster",
			"sourceKey": "node_cluster",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:dgram",
			"sourceKey": "node_dgram",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "dgram",
			"sourceKey": "node_dgram",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:domain",
			"sourceKey": "node_domain",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "domain",
			"sourceKey": "node_domain",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:v8",
			"sourceKey": "node_v8",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "v8",
			"sourceKey": "node_v8",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:constants",
			"sourceKey": "node_constants",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "constants",
			"sourceKey": "node_constants",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "ws",
			"sourceKey": "ws",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:http2",
			"sourceKey": "node_http2",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "http2",
			"sourceKey": "node_http2",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:diagnostics_channel",
			"sourceKey": "node_diagnostics_channel",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "diagnostics_channel",
			"sourceKey": "node_diagnostics_channel",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:trace_events",
			"sourceKey": "node_trace_events",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "trace_events",
			"sourceKey": "node_trace_events",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:inspector",
			"sourceKey": "node_inspector",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "inspector",
			"sourceKey": "node_inspector",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:inspector/promises",
			"sourceKey": "node_inspector",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "inspector/promises",
			"sourceKey": "node_inspector",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "node:wasi",
			"sourceKey": "node_wasi",
			"moduleBuiltin": true,
			"bundleExternal": true
		},
		{
			"specifier": "wasi",
			"sourceKey": "node_wasi",
			"moduleBuiltin": true,
			"bundleExternal": true
		}
	]);
	const staticBootstrapInternalModules = Object.freeze([
		"internal/util/debuglog",
		"internal/linkedlist",
		"internal/util",
		"internal/util/inspect",
		"internal/options",
		"internal/http",
		"internal/net",
		"internal/async_hooks",
		"internal/timers",
		"internal/assert/myers_diff",
		"internal/crypto/util",
		"internal/crypto/x509",
		"internal/url",
		"internal/fs/utils",
		"internal/child_process"
	]);
	const nodeBuiltins = Object.freeze(publicBuiltins.map((entry) => entry.name));
	const moduleBuiltinList = Object.freeze([...nodeBuiltins, ...reservedNodeOnlyBuiltins]);
	const nodeOnlyBuiltinModules = Object.freeze([...publicBuiltins.filter((entry) => entry.nodeOnly).map((entry) => entry.name), ...reservedNodeOnlyBuiltins]);
	const moduleBuiltinRuntimeSpecifiers = Object.freeze(registryEntries.filter((entry) => entry.moduleBuiltin).map((entry) => entry.specifier));
	const bundlerExternalModules = Object.freeze(registryEntries.filter((entry) => entry.bundleExternal).map((entry) => entry.specifier));
	module.exports = Object.freeze({
		bundlerExternalModules,
		moduleBuiltinList,
		moduleBuiltinRuntimeSpecifiers,
		nodeBuiltins,
		nodeOnlyBuiltinModules,
		publicBuiltins,
		registryEntries,
		reservedNodeOnlyBuiltins,
		staticBootstrapInternalModules
	});
})))();
var builtinList = runtimeModuleManifest.moduleBuiltinList.slice();
runtimeModuleManifest.nodeOnlyBuiltinModules.slice();
var builtinRuntimeSpecifiers = runtimeModuleManifest.moduleBuiltinRuntimeSpecifiers;
var builtinSpecifierSet = Object.create(null);
for (var i = 0; i < builtinRuntimeSpecifiers.length; i++) builtinSpecifierSet[builtinRuntimeSpecifiers[i]] = true;
function isBuiltin(specifier) {
	return typeof specifier === "string" && builtinSpecifierSet[specifier] === true;
}
function createRequire(filename) {
	if (typeof filename === "object" && filename !== null && filename.href) filename = filename.href;
	if (typeof filename === "string" && filename.indexOf("file://") === 0) filename = filename.slice(7);
	if (typeof filename === "string") {
		var lastSlash = filename.lastIndexOf("/");
		if (lastSlash >= 0) filename.substring(0, lastSlash);
	}
	var _require = function(specifier) {
		return globalThis.require(specifier);
	};
	_require.resolve = function(specifier) {
		return globalThis.require.resolve(specifier);
	};
	_require.resolve.paths = function(specifier) {
		return globalThis.require.resolve.paths ? globalThis.require.resolve.paths(specifier) : null;
	};
	_require.cache = globalThis.require.cache || {};
	_require.main = globalThis.require.main || void 0;
	return _require;
}
var Module = {
	builtinModules: builtinList.slice(),
	isBuiltin,
	createRequire,
	_cache: {},
	_pathCache: {},
	_extensions: {
		".js": true,
		".json": true,
		".node": true
	},
	globalPaths: [],
	wrap: function(script) {
		return "(function (exports, require, module, __filename, __dirname) { " + script + "\n});";
	},
	_nodeModulePaths: function(from) {
		var parts = from.split("/");
		var dirs = [];
		for (var i = parts.length - 1; i >= 0; i--) {
			if (parts[i] === "node_modules") continue;
			dirs.push(parts.slice(0, i + 1).join("/") + "/node_modules");
		}
		return dirs;
	}
};
module.exports = Module;
module.exports.Module = Module;
module.exports.builtinModules = builtinList.slice();
module.exports.isBuiltin = isBuiltin;
module.exports.createRequire = createRequire;
//#endregion
