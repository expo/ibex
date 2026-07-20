var runtimeModuleManifest = require('./helpers/runtime-module-manifest.cjs');
var builtinList = runtimeModuleManifest.moduleBuiltinList.slice();
var nodeOnlyBuiltins = runtimeModuleManifest.nodeOnlyBuiltinModules.slice();
var builtinRuntimeSpecifiers = runtimeModuleManifest.moduleBuiltinRuntimeSpecifiers;
var privateCreateRequire = module && typeof module.__exactCreateRequire === 'function'
  ? module.__exactCreateRequire
  : null;
var builtinSpecifierSet = Object.create(null);
for (var i = 0; i < builtinRuntimeSpecifiers.length; i++) {
  builtinSpecifierSet[builtinRuntimeSpecifiers[i]] = true;
}

function isBuiltin(specifier) {
  return typeof specifier === 'string' && builtinSpecifierSet[specifier] === true;
}

function createRequire(filename) {
  if (privateCreateRequire) {
    return privateCreateRequire(filename);
  }
  // Return a require function that resolves relative to filename
  if (typeof filename === 'object' && filename !== null && filename.href) {
    // URL object — convert file:// URL to path
    filename = filename.href;
  }
  if (typeof filename === 'string' && filename.indexOf('file://') === 0) {
    filename = filename.slice(7);
  }
  filename = String(filename || '');
  var parentDir = '';
  if (typeof filename === 'string') {
    var lastSlash = filename.lastIndexOf('/');
    if (lastSlash >= 0) parentDir = filename.substring(0, lastSlash);
    else parentDir = '.';
  }
  function resolveFromFilename(specifier) {
    if (isBuiltin(specifier) || specifier.indexOf('node:') === 0) return specifier;
    if (specifier.charAt(0) === '.' && parentDir) {
      return globalThis.require.resolve(parentDir + '/' + specifier);
    }
    if (globalThis.require && globalThis.require.resolve) {
      return globalThis.require.resolve(specifier);
    }
    return specifier;
  }

  var _require = function(specifier) {
    if (arguments.length > 1) {
      // Delegate only the argument-count refusal; do not inspect the bag.
      return globalThis.require(specifier, undefined);
    }
    if (isBuiltin(specifier) || specifier.indexOf('node:') === 0) {
      return globalThis.require(specifier);
    }
    return globalThis.require(resolveFromFilename(specifier));
  };
  _require.resolve = function(specifier) {
    if (arguments.length > 1) {
      return globalThis.require.resolve(specifier, undefined);
    }
    return resolveFromFilename(specifier);
  };
  _require.resolve.paths = function(specifier) {
    return globalThis.require.resolve.paths ? globalThis.require.resolve.paths(specifier) : null;
  };
  return _require;
}

var Module = {
  builtinModules: builtinList.slice(),
  isBuiltin: isBuiltin,
  createRequire: createRequire,
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
