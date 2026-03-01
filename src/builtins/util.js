function inherits(constructor, superConstructor) {
  if (typeof constructor !== 'function') {
    var e1 = new TypeError('The "ctor" argument must be of type function. Received ' + (constructor === null ? 'null' : typeof constructor));
    e1.code = 'ERR_INVALID_ARG_TYPE';
    throw e1;
  }
  if (superConstructor === null || (typeof superConstructor !== 'function' && typeof superConstructor !== 'object')) {
    var e2 = new TypeError('The "superCtor" argument must be of type function. Received ' + (superConstructor === null ? 'null' : typeof superConstructor));
    e2.code = 'ERR_INVALID_ARG_TYPE';
    throw e2;
  }
  if (superConstructor.prototype === undefined) {
    var e3 = new TypeError('The "superCtor.prototype" property must be of type object. Received undefined');
    e3.code = 'ERR_INVALID_ARG_TYPE';
    throw e3;
  }
  Object.defineProperty(constructor, 'super_', {
    value: superConstructor,
    writable: true,
    configurable: true,
    enumerable: false,
  });
  Object.setPrototypeOf(constructor.prototype, superConstructor.prototype);
}

function promisify(fn) {
  if (typeof fn !== "function") {
    throw new TypeError("util.promisify requires a function");
  }
  return function() {
    var args = [];
    var i = 0;
    while (i < arguments.length) {
      args.push(arguments[i]);
      i += 1;
    }
    return new Promise(function(resolve, reject) {
      args.push(function(err) {
        if (err) {
          return reject(err);
        }
        if (arguments.length <= 1) return resolve(undefined);
        if (arguments.length === 2) return resolve(arguments[1]);
        var output = [];
        for (var j = 1; j < arguments.length; j++) {
          output.push(arguments[j]);
        }
        return resolve(output);
      });
      try {
        fn.apply(this, args);
      } catch (err) {
        reject(err);
      }
    }.bind(this));
  };
}

function format(value) {
  if (arguments.length === 0) return "";
  if (typeof value !== "string") {
    var parts = [];
    for (var i = 0; i < arguments.length; i++) {
      parts.push(inspect(arguments[i]));
    }
    return parts.join(' ');
  }
  var i = 1;
  var args = arguments;
  var result = value.replace(/%[sdjoO%]/g, function(match) {
    if (match === "%%") return "%";
    if (i >= args.length) return match;
    var arg = args[i];
    i += 1;
    if (match === "%s") return String(arg);
    if (match === "%d") return String(Number(arg));
    if (match === "%j") return JSON.stringify(arg);
    if (match === "%o" || match === "%O") return inspect(arg);
    return match;
  });
  while (i < args.length) {
    result += ' ' + inspect(args[i]);
    i++;
  }
  return result;
}

function log() {
  var now = new Date();
  var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var d = now.getDate();
  var h = now.getHours();
  var m = now.getMinutes();
  var s = now.getSeconds();
  var ts = d + ' ' + months[now.getMonth()] + ' ' +
    (h < 10 ? '0' + h : '' + h) + ':' +
    (m < 10 ? '0' + m : '' + m) + ':' +
    (s < 10 ? '0' + s : '' + s);
  var msg = format.apply(null, arguments);
  if (typeof process !== 'undefined' && process.stdout && typeof process.stdout.write === 'function') {
    process.stdout.write(ts + ' - ' + msg + '\n');
  }
}

function inspect(value, options) {
  var opts = options || {};
  var depth = opts.depth !== undefined ? opts.depth : 2;
  var colors = opts.colors || false;
  var breakLength = opts.breakLength !== undefined ? opts.breakLength : 72;
  var seen = [];
  var cache = new Map();
  var _indentCache = {};
  function _makeIndent(n) {
    if (n <= 0) return '';
    if (_indentCache[n]) return _indentCache[n];
    var s = '';
    for (var i = 0; i < n; i++) s += ' ';
    if (n < 100) _indentCache[n] = s;
    return s;
  }
  function _inspect(val, currentDepth) {
    if (val === null) return 'null';
    if (val === undefined) return 'undefined';
    var t = typeof val;
    if (t === 'string') return "'" + val.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + "'";
    if (t === 'number' || t === 'boolean') return String(val);
    if (t === 'symbol') return val.toString();
    if (t === 'function') {
      var name = val.name || 'anonymous';
      return '[Function: ' + name + ']';
    }
    if (t === 'bigint') return val.toString() + 'n';
    // Object types
    if (seen.indexOf(val) !== -1) return '[Circular]';
    if (cache.has(val)) return cache.get(val);

    // Support util.inspect.custom symbol
    var customInspect = inspect.custom && val[inspect.custom];
    if (typeof customInspect === 'function') {
      var customResult = customInspect.call(val, currentDepth, opts);
      return typeof customResult === 'string' ? customResult : _inspect(customResult, currentDepth);
    }

    seen.push(val);
    var result;
    try {
      if (currentDepth > depth && depth !== null) {
        if (Array.isArray(val)) {
          result = '[Array]';
        } else if (val.constructor && val.constructor.name && val.constructor.name !== 'Object') {
          result = val.constructor.name;
        } else {
          result = '[Object]';
        }
      } else if (Array.isArray(val)) {
        if (val.length === 0) {
          result = '[]';
        } else {
          var items = [];
          for (var i = 0; i < val.length; i++) {
            items.push(_inspect(val[i], currentDepth + 1));
          }
          var singleLine = '[ ' + items.join(', ') + ' ]';
          if (breakLength > 0 && currentDepth < 10 && singleLine.length > breakLength) {
            var indent = _makeIndent((currentDepth + 1) * 2);
            var baseIndent = _makeIndent(currentDepth * 2);
            result = '[\n';
            for (var ai = 0; ai < items.length; ai++) {
              result += indent + items[ai];
              if (ai < items.length - 1) result += ',';
              result += '\n';
            }
            result += baseIndent + ']';
          } else {
            result = singleLine;
          }
        }
      } else if (val instanceof Date) {
        result = val.toISOString();
      } else if (val instanceof RegExp) {
        result = String(val);
      } else if (val instanceof Error) {
        result = '[' + (val.constructor.name || 'Error') + ': ' + val.message + ']';
      } else if (typeof val.constructor === 'function' && val.constructor.name === 'Buffer') {
        result = '<Buffer ' + Array.prototype.slice.call(val, 0, Math.min(val.length, 50)).map(function(b) { return (b < 16 ? '0' : '') + b.toString(16); }).join(' ') + (val.length > 50 ? ' ... ' + (val.length - 50) + ' more bytes' : '') + '>';
      } else {
        // Plain object
        var ctorPrefix = '';
        if (val.constructor && val.constructor.name && val.constructor.name !== 'Object') {
          ctorPrefix = val.constructor.name + ' ';
        }
        var keys = Object.keys(val);
        if (keys.length === 0) {
          result = ctorPrefix + '{}';
        } else {
          var parts = [];
          for (var ki = 0; ki < keys.length; ki++) {
            var k = keys[ki];
            var v;
            try { v = _inspect(val[k], currentDepth + 1); } catch(e) { v = '[Getter/Error]'; }
            parts.push(k + ': ' + v);
          }
          var singleObj = ctorPrefix + '{ ' + parts.join(', ') + ' }';
          if (breakLength > 0 && currentDepth < 10 && singleObj.length > breakLength) {
            var objIndent = _makeIndent((currentDepth + 1) * 2);
            var objBase = _makeIndent(currentDepth * 2);
            result = ctorPrefix + '{\n';
            for (var pi = 0; pi < parts.length; pi++) {
              result += objIndent + parts[pi];
              if (pi < parts.length - 1) result += ',';
              result += '\n';
            }
            result += objBase + '}';
          } else {
            result = singleObj;
          }
        }
      }
    } finally {
      seen.pop();
      if (result !== undefined) {
        cache.set(val, result);
      }
    }

    return result;
  }
  return _inspect(value, 0);
}
inspect.custom = Symbol.for('nodejs.util.inspect.custom');
inspect.styles = {};
inspect.colors = {};
inspect.defaultOptions = { depth: 2, colors: false };

function deprecated(message) {
  return function() {
    if (typeof console !== "undefined" && console.warn) {
      console.warn(message);
    }
    if (typeof deprecated._fn === "function") {
      return deprecated._fn.apply(this, arguments);
    }
    return undefined;
  };
}

var util = {
  inherits: inherits,
  promisify: promisify,
  format: format,
  log: log,
  inspect: inspect,
  deprecate: function(fn, message) {
    if (typeof fn !== "function") return undefined;
    var wrapped = function() {
      if (wrapped._warned !== true && typeof console !== "undefined" && console.warn) {
        console.warn(message);
        wrapped._warned = true;
      }
      return fn.apply(this, arguments);
    };
    return wrapped;
  },
  types: {
    isPromise: function(value) { return value instanceof Promise || (value && typeof value.then === "function"); },
    isModuleNamespaceObject: function(value) {
      if (value === null || typeof value !== "object") return false;
      if (typeof Symbol === 'function' && Symbol.toStringTag && value[Symbol.toStringTag] === "Module") return true;
      return Object.prototype.toString.call(value) === "[object Module]";
    },
    isAsyncFunction: function(value) { return value && value.constructor && value.constructor.name === "AsyncFunction"; },
    isArrayBufferView: function(value) {
      return value && (typeof ArrayBuffer !== "undefined") && ArrayBuffer.isView(value);
    },
    isDate: function(value) { return value instanceof Date; },
    isRegExp: function(value) { return value instanceof RegExp; },
    isSet: function(value) { return typeof Set !== "undefined" && value instanceof Set; },
    isMap: function(value) { return typeof Map !== "undefined" && value instanceof Map; },
    isTypedArray: function(value) {
      return value && (value instanceof Int8Array || value instanceof Uint8Array ||
        value instanceof Uint8ClampedArray || value instanceof Int16Array ||
        value instanceof Uint16Array || value instanceof Int32Array ||
        value instanceof Uint32Array || value instanceof Float32Array ||
        value instanceof Float64Array);
    },
    isNativeError: function(value) { return value instanceof Error; },
    isNumberObject: function(value) { return typeof value === "object" && value instanceof Number; },
    isStringObject: function(value) { return typeof value === "object" && value instanceof String; },
    isBooleanObject: function(value) { return typeof value === "object" && value instanceof Boolean; }
  },
  TextEncoder: typeof TextEncoder !== "undefined" ? TextEncoder : undefined,
  TextDecoder: typeof TextDecoder !== "undefined" ? TextDecoder : undefined,
  callbackify: function(fn) {
    return function() {
      var args = Array.prototype.slice.call(arguments);
      var callback = args.pop();
      fn.apply(this, args).then(
        function(result) { callback(null, result); },
        function(err) { callback(err); }
      );
    };
  },
  isDeepStrictEqual: function(a, b) {
    if (a === b) return true;
    if (typeof a !== typeof b) return false;
    if (a === null || b === null) return false;
    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) return false;
      for (var i = 0; i < a.length; i++) {
        if (!util.isDeepStrictEqual(a[i], b[i])) return false;
      }
      return true;
    }
    if (typeof a === "object") {
      var aKeys = Object.keys(a);
      var bKeys = Object.keys(b);
      if (aKeys.length !== bKeys.length) return false;
      for (var j = 0; j < aKeys.length; j++) {
        if (!Object.prototype.hasOwnProperty.call(b, aKeys[j])) return false;
        if (!util.isDeepStrictEqual(a[aKeys[j]], b[aKeys[j]])) return false;
      }
      return true;
    }
    return false;
  }
};

util.promisify.custom = {};

util.parseArgs = function parseArgs(config) {
  config = config || {};
  var args = config.args || (typeof process !== 'undefined' ? process.argv.slice(2) : []);
  var options = config.options || {};
  var strict = config.strict !== false;
  var allowPositionals = config.allowPositionals !== false;

  var values = {};
  var positionals = [];
  var tokens = [];

  // Initialize defaults
  for (var name in options) {
    if (Object.prototype.hasOwnProperty.call(options, name)) {
      var opt = options[name];
      if (opt.default !== undefined) values[name] = opt.default;
      else if (opt.type === 'boolean') values[name] = false;
      else if (opt.multiple) values[name] = [];
    }
  }

  function findOption(arg) {
    // Check long form
    for (var name in options) {
      if (Object.prototype.hasOwnProperty.call(options, name)) {
        if ('--' + name === arg) return name;
        if (options[name].short && ('-' + options[name].short) === arg) return name;
      }
    }
    return null;
  }

  var i = 0;
  var dashdash = false;
  while (i < args.length) {
    var arg = args[i];
    if (dashdash) { positionals.push(arg); i++; continue; }
    if (arg === '--') { dashdash = true; i++; continue; }
    if (arg.indexOf('--') === 0) {
      var eqIdx = arg.indexOf('=');
      var key, val;
      if (eqIdx !== -1) { key = arg.substring(0, eqIdx); val = arg.substring(eqIdx + 1); }
      else { key = arg; val = undefined; }
      var optName = findOption(key);
      if (!optName && strict) throw new Error('Unknown option: ' + key);
      if (optName) {
        var optDef = options[optName];
        if (optDef.type === 'boolean') {
          val = val !== undefined ? val !== 'false' : true;
        } else if (val === undefined && i + 1 < args.length) {
          i++; val = args[i];
        }
        if (optDef.multiple) {
          if (!values[optName]) values[optName] = [];
          values[optName].push(val);
        } else {
          values[optName] = val;
        }
      }
    } else if (arg.indexOf('-') === 0 && arg.length > 1) {
      var optName2 = findOption(arg);
      if (optName2) {
        var optDef2 = options[optName2];
        if (optDef2.type === 'boolean') {
          if (optDef2.multiple) {
            if (!values[optName2]) values[optName2] = [];
            values[optName2].push(true);
          } else { values[optName2] = true; }
        } else if (i + 1 < args.length) {
          i++;
          if (optDef2.multiple) {
            if (!values[optName2]) values[optName2] = [];
            values[optName2].push(args[i]);
          } else { values[optName2] = args[i]; }
        }
      } else if (strict) { throw new Error('Unknown option: ' + arg); }
      else { positionals.push(arg); }
    } else {
      if (!allowPositionals && strict) throw new Error('Unexpected positional: ' + arg);
      positionals.push(arg);
    }
    i++;
  }

  return { values: values, positionals: positionals };
};

var nodeDebugEnv = (typeof process !== 'undefined' && process.env && process.env.NODE_DEBUG) ? process.env.NODE_DEBUG : '';
var debugNamespaces = {};
(function parseNodeDebugEnv() {
  if (!nodeDebugEnv || typeof nodeDebugEnv !== 'string') return;
  var parts = nodeDebugEnv.split(/[\s,]+/);
  for (var i = 0; i < parts.length; i++) {
    var ns = parts[i] && parts[i].trim();
    if (!ns) continue;
    debugNamespaces[ns.toUpperCase()] = true;
  }
})();

util.debuglog = function debuglog(set) {
  if (typeof set !== 'string' || !set) {
    return function() {};
  }
  var normalized = set.toUpperCase();
  var isEnabled = normalized === 'NODE_DEBUG' || debugNamespaces[normalized] ||
    debugNamespaces['*'] ||
    debugNamespaces[normalized.toLowerCase()] === true;

  if (!isEnabled) {
    return function() {};
  }

  var pid = (typeof process !== 'undefined' && process.pid != null) ? process.pid : 0;
  return function() {
    var args = Array.prototype.slice.call(arguments);
    if (typeof console !== 'undefined' && console.error) {
      args.unshift('[' + set + '] ' + pid + ':');
      console.error.apply(console, args);
    }
  };
};

module.exports = util;
