var builtinList = [
  'assert', 'assert/strict', 'buffer', 'child_process', 'cluster',
  'console', 'constants', 'crypto', 'dgram', 'dns', 'dns/promises',
  'domain', 'events',
  'fs', 'fs/promises',
  'http', 'http2', 'https', 'inspector', 'module', 'net', 'os', 'path',
  'path/posix', 'path/win32',
  'perf_hooks', 'process', 'punycode', 'querystring', 'readline',
  'readline/promises',
  'stream', 'stream/consumers', 'stream/promises', 'stream/web',
  'string_decoder', 'sys', 'test',
  'timers', 'timers/promises', 'tls', 'trace_events', 'tty', 'url',
  'util', 'util/types',
  'v8', 'vm', 'wasi', 'worker_threads', 'zlib'
];

// Modules that only exist with the node: prefix (not available as bare specifiers)
var nodeOnlyBuiltins = ['test', 'sqlite', 'sea'];

function isBuiltin(specifier) {
  if (typeof specifier !== 'string') return false;
  var name = specifier;
  var hasNodePrefix = name.indexOf('node:') === 0;
  if (hasNodePrefix) name = name.slice(5);
  if (name.indexOf('bun:') === 0) name = name.slice(4);
  // node:-only modules require the prefix
  if (!hasNodePrefix && nodeOnlyBuiltins.indexOf(name) !== -1) return false;
  return builtinList.indexOf(name) !== -1;
}

function createRequire(filename) {
  // Return a require function that resolves relative to filename
  if (typeof filename === 'object' && filename !== null && filename.href) {
    // URL object — convert file:// URL to path
    filename = filename.href;
  }
  if (typeof filename === 'string' && filename.indexOf('file://') === 0) {
    filename = filename.slice(7);
  }
  var parentDir = '';
  if (typeof filename === 'string') {
    var lastSlash = filename.lastIndexOf('/');
    if (lastSlash >= 0) parentDir = filename.substring(0, lastSlash);
    else parentDir = '.';
  }
  // Use the global require but with resolution relative to the given path
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
  _require.main = globalThis.require.main || undefined;
  return _require;
}

var Module = {
  builtinModules: builtinList.slice(),
  isBuiltin: isBuiltin,
  createRequire: createRequire,
  _cache: {},
  _pathCache: {},
  _extensions: { '.js': true, '.json': true, '.node': true },
  globalPaths: [],
  wrap: function(script) {
    return '(function (exports, require, module, __filename, __dirname) { ' + script + '\n});';
  },
  _nodeModulePaths: function(from) {
    var parts = from.split('/');
    var dirs = [];
    for (var i = parts.length - 1; i >= 0; i--) {
      if (parts[i] === 'node_modules') continue;
      dirs.push(parts.slice(0, i + 1).join('/') + '/node_modules');
    }
    return dirs;
  }
};

module.exports = Module;
module.exports.Module = Module;
module.exports.builtinModules = builtinList.slice();
module.exports.isBuiltin = isBuiltin;
module.exports.createRequire = createRequire;
